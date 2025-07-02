/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package mount

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"

	"github.com/containerd/log"
	"github.com/moby/sys/userns"
	"golang.org/x/sys/unix"
)

type mountOpt struct {
	flags   int
	data    []string
	losetup bool
	uidmap  string
	gidmap  string
}

var (
	pagesize              = 4096
	allowedHelperBinaries = []string{"mount.fuse", "mount.fuse3"}
)

func init() {
	pagesize = os.Getpagesize()
}


// Mount to the provided target path.
//
// If m.Type starts with "fuse." or "fuse3.", "mount.fuse" or "mount.fuse3"
// helper binary is called.
func (m *Mount) mount(target string) (err error) {
	for _, helperBinary := range allowedHelperBinaries {
		// helperBinary = "mount.fuse", typePrefix = "fuse."
		typePrefix := strings.TrimPrefix(helperBinary, "mount.") + "."
		if strings.HasPrefix(m.Type, typePrefix) {
			return m.mountWithHelper(helperBinary, typePrefix, target)
		}
	}
	var (
		chdir     string
		recalcOpt bool
		usernsFd  *os.File
		options   = m.Options
	)

	opt := parseMountOptions(options)
	// The only remapping of both GID and UID is supported
	if opt.uidmap != "" && opt.gidmap != "" {
		if usernsFd, err = GetUsernsFD(opt.uidmap, opt.gidmap); err != nil {
			return err
		}
		defer usernsFd.Close()

		// overlay expects lowerdir's to be remapped instead
		if m.Type == "overlay" {
			log.L.Debugf("mount: handling overlay filesystem with idmapping for target=%s", target)
			log.L.Debugf("mount: original options: %v", options)
			
			lowerIdx, lowerDirs := findOverlayLowerdirs(options)
			if lowerIdx == -1 {
				log.L.Errorf("mount: failed to parse overlay lowerdirs from options: %v", options)
				return fmt.Errorf("failed to parse overlay lowerdirs from given options")
			}
			log.L.Debugf("mount: found lowerdirs at index %d: %v", lowerIdx, lowerDirs)
			
			idmappedDirs, userNsCleanUp, err := doPrepareIDMappedOverlay(lowerDirs, int(usernsFd.Fd()))
			defer userNsCleanUp()

			if err != nil {
				log.L.Errorf("mount: failed to prepare idmapped overlay: %v", err)
				return fmt.Errorf("failed to prepare idmapped overlay: %w", err)
			}
			
			// Remove lowerdir from options, we'll handle it via fsconfig as an fd
			// and leave the rest for fsconfig string options
			log.L.Debugf("mount: removing lowerdir option from index %d, remaining options will be: %v", lowerIdx, append(options[:lowerIdx], options[lowerIdx+1:]...))
			options = append(options[:lowerIdx], options[lowerIdx+1:]...)
			opt = parseMountOptions(options)
			log.L.Debugf("mount: parsed mount options after removing lowerdir: flags=0x%x, data=%v", opt.flags, opt.data)
			
			log.L.Debugf("mount: calling mountAtWithIDMapping for overlay mount")
			if err := mountAtWithIDMapping(m.Source, target, m.Type, uintptr(opt.flags), strings.Join(opt.data, ","), idmappedDirs); err != nil {
				log.L.Errorf("mount: mountAtWithIDMapping failed: %v", err)
				return err
			}
			log.L.Debugf("mount: overlay idmapped mount completed successfully")
			return nil
		}
	}

	// avoid hitting one page limit of mount argument buffer
	//
	// NOTE: 512 is a buffer during pagesize check.
	if m.Type == "overlay" && optionsSize(options) >= pagesize-512 {
		chdir, options = compactLowerdirOption(options)
		// recalculate opt in case of lowerdirs have been replaced
		// by idmapped ones OR idmapped mounts' not used/supported.
		if recalcOpt || (opt.uidmap == "" || opt.gidmap == "") {
			opt = parseMountOptions(options)
		}
	}

	// propagation types.
	const ptypes = unix.MS_SHARED | unix.MS_PRIVATE | unix.MS_SLAVE | unix.MS_UNBINDABLE

	// Ensure propagation type change flags aren't included in other calls.
	oflags := opt.flags &^ ptypes

	var loopParams LoopParams
	if opt.losetup {
		loopParams = LoopParams{
			Readonly:  oflags&unix.MS_RDONLY == unix.MS_RDONLY,
			Autoclear: true,
		}
		loopParams.Direct, opt.data = hasDirectIO(opt.data)
	}

	dataInStr := strings.Join(opt.data, ",")
	if len(dataInStr) > pagesize {
		return errors.New("mount options is too long")
	}

	// In the case of remounting with changed data (dataInStr != ""), need to call mount (moby/moby#34077).
	if opt.flags&unix.MS_REMOUNT == 0 || dataInStr != "" {
		// Initial call applying all non-propagation flags for mount
		// or remount with changed data
		source := m.Source
		if opt.losetup {
			loFile, err := setupLoop(m.Source, loopParams)
			if err != nil {
				return err
			}
			defer loFile.Close()

			// Mount the loop device instead
			source = loFile.Name()
		}
		if err := mountAt(chdir, source, target, m.Type, uintptr(oflags), dataInStr); err != nil {
			return err
		}
	}

	if opt.flags&ptypes != 0 {
		// Change the propagation type.
		const pflags = ptypes | unix.MS_REC | unix.MS_SILENT
		if err := unix.Mount("", target, "", uintptr(opt.flags&pflags), ""); err != nil {
			return err
		}
	}

	const broflags = unix.MS_BIND | unix.MS_RDONLY
	if oflags&broflags == broflags {
		// Preserve CL_UNPRIVILEGED "locked" flags of the
		// bind mount target when we remount to make the bind readonly.
		// This is necessary to ensure that
		// bind-mounting "with options" will not fail with user namespaces, due to
		// kernel restrictions that require user namespace mounts to preserve
		// CL_UNPRIVILEGED locked flags.
		var unprivFlags int
		if userns.RunningInUserNS() {
			unprivFlags, err = getUnprivilegedMountFlags(target)
			if err != nil {
				return err
			}
		}
		// Remount the bind to apply read only.
		return unix.Mount("", target, "", uintptr(oflags|unprivFlags|unix.MS_REMOUNT), "")
	}

	// remap non-overlay mount point
	if opt.uidmap != "" && opt.gidmap != "" && m.Type != "overlay" {
		if err := IDMapMountLegacy(target, target, int(usernsFd.Fd())); err != nil {
			return err
		}
	}
	
	return nil
}

// Get the set of mount flags that are set on the mount that contains the given
// path and are locked by CL_UNPRIVILEGED.
//
// From https://github.com/moby/moby/blob/v23.0.1/daemon/oci_linux.go#L430-L460
func getUnprivilegedMountFlags(path string) (int, error) {
	var statfs unix.Statfs_t
	if err := unix.Statfs(path, &statfs); err != nil {
		return 0, err
	}

	// The set of keys come from https://github.com/torvalds/linux/blob/v4.13/fs/namespace.c#L1034-L1048.
	unprivilegedFlags := []int{
		unix.MS_RDONLY,
		unix.MS_NODEV,
		unix.MS_NOEXEC,
		unix.MS_NOSUID,
		unix.MS_NOATIME,
		unix.MS_RELATIME,
		unix.MS_NODIRATIME,
	}

	var flags int
	for flag := range unprivilegedFlags {
		if int(statfs.Flags)&flag == flag {
			flags |= flag
		}
	}

	return flags, nil
}

// idmappedLowerDirs holds file descriptors for idmapped lowerdirs and a mapping to
// the original lowerdir path for debugging / logging
type idmappedLowerDirs struct {
	lowerFds []*os.File
	lowerDirs []string
}

func (i *idmappedLowerDirs) Close() {
	for _, fd := range i.lowerFds {
		if fd != nil {
			fd.Close()
		}
	}
}

func doPrepareIDMappedOverlay(lowerDirs []string, usernsFd int) (*idmappedLowerDirs, func(), error) {
	idmappedDirs := &idmappedLowerDirs{
		lowerFds: make([]*os.File, 0, len(lowerDirs)),
		lowerDirs: lowerDirs,
	}
	
	cleanUp := func() {
		log.L.Debugf("doPrepareIDMappedOverlay: cleaning up %d idmapped fds", len(idmappedDirs.lowerFds))
		idmappedDirs.Close()
	}
	
	for i, lowerDir := range lowerDirs {
		log.L.Debugf("doPrepareIDMappedOverlay: creating idmapped fd for lowerDir[%d]=%s", i, lowerDir)
		idmappedFd, err := IDMapMount(lowerDir, usernsFd)
		if err != nil {
			log.L.Errorf("doPrepareIDMappedOverlay: failed to create idmapped mount for %s: %v", lowerDir, err)
			return nil, cleanUp, fmt.Errorf("failed to create idmapped mount for %s: %w", lowerDir, err)
		}
		log.L.Debugf("doPrepareIDMappedOverlay: successfully created idmapped fd=%d for %s", idmappedFd.Fd(), lowerDir)
		idmappedDirs.lowerFds = append(idmappedDirs.lowerFds, idmappedFd)
	}
	
	log.L.Debugf("doPrepareIDMappedOverlay: successfully prepared all %d idmapped lowerdirs", len(lowerDirs))
	return idmappedDirs, cleanUp, nil
}

// parseMountOptions takes fstab style mount options and parses them for
// use with a standard mount() syscall
func parseMountOptions(options []string) (opt mountOpt) {
	loopOpt := "loop"
	flagsMap := map[string]struct {
		clear bool
		flag  int
	}{
		"async":         {true, unix.MS_SYNCHRONOUS},
		"atime":         {true, unix.MS_NOATIME},
		"bind":          {false, unix.MS_BIND},
		"defaults":      {false, 0},
		"dev":           {true, unix.MS_NODEV},
		"diratime":      {true, unix.MS_NODIRATIME},
		"dirsync":       {false, unix.MS_DIRSYNC},
		"exec":          {true, unix.MS_NOEXEC},
		"mand":          {false, unix.MS_MANDLOCK},
		"noatime":       {false, unix.MS_NOATIME},
		"nodev":         {false, unix.MS_NODEV},
		"nodiratime":    {false, unix.MS_NODIRATIME},
		"noexec":        {false, unix.MS_NOEXEC},
		"nomand":        {true, unix.MS_MANDLOCK},
		"norelatime":    {true, unix.MS_RELATIME},
		"nostrictatime": {true, unix.MS_STRICTATIME},
		"nosuid":        {false, unix.MS_NOSUID},
		"rbind":         {false, unix.MS_BIND | unix.MS_REC},
		"relatime":      {false, unix.MS_RELATIME},
		"remount":       {false, unix.MS_REMOUNT},
		"ro":            {false, unix.MS_RDONLY},
		"rw":            {true, unix.MS_RDONLY},
		"strictatime":   {false, unix.MS_STRICTATIME},
		"suid":          {true, unix.MS_NOSUID},
		"sync":          {false, unix.MS_SYNCHRONOUS},
	}
	for _, o := range options {
		// If the option does not exist in the flags table or the flag
		// is not supported on the platform,
		// then it is a data value for a specific fs type
		if f, exists := flagsMap[o]; exists && f.flag != 0 {
			if f.clear {
				opt.flags &^= f.flag
			} else {
				opt.flags |= f.flag
			}
		} else if o == loopOpt {
			opt.losetup = true
		} else if strings.HasPrefix(o, "uidmap=") {
			opt.uidmap = strings.TrimPrefix(o, "uidmap=")
		} else if strings.HasPrefix(o, "gidmap=") {
			opt.gidmap = strings.TrimPrefix(o, "gidmap=")
		} else {
			opt.data = append(opt.data, o)
		}
	}
	return
}

func hasDirectIO(opts []string) (bool, []string) {
	for idx, opt := range opts {
		if opt == "direct-io" {
			return true, append(opts[:idx], opts[idx+1:]...)
		}
	}
	return false, opts
}

// compactLowerdirOption updates overlay lowdir option and returns the common
// dir among all the lowdirs.
func compactLowerdirOption(opts []string) (string, []string) {
	idx, dirs := findOverlayLowerdirs(opts)
	if idx == -1 || len(dirs) == 1 {
		// no need to compact if there is only one lowerdir
		return "", opts
	}

	// find out common dir
	commondir := longestCommonPrefix(dirs)
	if commondir == "" {
		return "", opts
	}

	// NOTE: the snapshot id is based on digits.
	// in order to avoid to get snapshots/x, should be back to parent dir.
	// however, there is assumption that the common dir is ${root}/io.containerd.v1.overlayfs/snapshots.
	commondir = path.Dir(commondir)
	if commondir == "/" || commondir == "." {
		return "", opts
	}
	commondir = commondir + "/"

	newdirs := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		if len(dir) <= len(commondir) {
			return "", opts
		}
		newdirs = append(newdirs, dir[len(commondir):])
	}

	newopts := copyOptions(opts)
	newopts = append(newopts[:idx], newopts[idx+1:]...)
	newopts = append(newopts, fmt.Sprintf("lowerdir=%s", strings.Join(newdirs, ":")))
	return commondir, newopts
}

// findOverlayLowerdirs returns the index of lowerdir in mount's options and
// all the lowerdir target.
func findOverlayLowerdirs(opts []string) (int, []string) {
	var (
		idx    = -1
		prefix = "lowerdir="
	)

	for i, opt := range opts {
		if strings.HasPrefix(opt, prefix) {
			idx = i
			break
		}
	}

	if idx == -1 {
		return -1, nil
	}
	return idx, strings.Split(opts[idx][len(prefix):], ":")
}

// longestCommonPrefix finds the longest common prefix in the string slice.
func longestCommonPrefix(strs []string) string {
	if len(strs) == 0 {
		return ""
	} else if len(strs) == 1 {
		return strs[0]
	}

	// find out the min/max value by alphabetical order
	min, max := strs[0], strs[0]
	for _, str := range strs[1:] {
		if min > str {
			min = str
		}
		if max < str {
			max = str
		}
	}

	// find out the common part between min and max
	for i := 0; i < len(min) && i < len(max); i++ {
		if min[i] != max[i] {
			return min[:i]
		}
	}
	return min
}

// copyOptions copies the options.
func copyOptions(opts []string) []string {
	if len(opts) == 0 {
		return nil
	}

	acopy := make([]string, len(opts))
	copy(acopy, opts)
	return acopy
}

// optionsSize returns the byte size of options of mount.
func optionsSize(opts []string) int {
	size := 0
	for _, opt := range opts {
		size += len(opt)
	}
	return size
}

// mountAtWithIDMapping creates an overlay mount using fscreate/fsconfig with idmapped lowerdirs
// We can skip some of the page size processing stuff in the future if we go this route since
// that's all about not going over PAGE_SIZE when using the traditional mount() vs fsconfig() calls
func mountAtWithIDMapping(source, target, fstype string, flags uintptr, data string, idmappedDirs *idmappedLowerDirs) error {
	log.L.Debugf("mountAtWithIDMapping: creating %s mount from %s to %s with %d idmapped lowerdirs", fstype, source, target, len(idmappedDirs.lowerFds))
	log.L.Debugf("mountAtWithIDMapping: flags=0x%x, data=%s", flags, data)
	
	log.L.Debugf("mountAtWithIDMapping: calling Fsopen for %s", fstype)
	fsfd, err := unix.Fsopen(fstype, unix.FSOPEN_CLOEXEC)
	if err != nil {
		log.L.Errorf("mountAtWithIDMapping: Fsopen failed for %s: %v", fstype, err)
		return fmt.Errorf("failed to create %s filesystem context: %w", fstype, err)
	}
	log.L.Debugf("mountAtWithIDMapping: Fsopen successful, fsfd=%d", fsfd)
	defer unix.Close(fsfd)

	log.L.Debugf("mountAtWithIDMapping: configuring %d idmapped lowerdirs", len(idmappedDirs.lowerFds))
	for i, lowerFd := range idmappedDirs.lowerFds {
		log.L.Debugf("mountAtWithIDMapping: configuring lowerdir[%d] with fd=%d (original: %s)", i, lowerFd.Fd(), idmappedDirs.lowerDirs[i])
		if err = unix.FsconfigSetFd(fsfd, "lowerdir+", int(lowerFd.Fd())); err != nil {
			log.L.Errorf("mountAtWithIDMapping: FsconfigSetFd failed for lowerdir[%d] fd=%d: %v", i, lowerFd.Fd(), err)
			return fmt.Errorf("failed to configure idmapped lowerdir: %w", err)
		}
		log.L.Debugf("mountAtWithIDMapping: successfully configured lowerdir[%d]", i)
	}

	// Deal with the rest of the options
	if data != "" {
		log.L.Debugf("mountAtWithIDMapping: configuring additional options: %s", data)
		opts := strings.Split(data, ",")
		for _, opt := range opts {
			if opt == "" {
				continue
			}
			log.L.Debugf("mountAtWithIDMapping: processing option: %s", opt)
			if strings.Contains(opt, "=") {
				parts := strings.SplitN(opt, "=", 2)
				log.L.Debugf("mountAtWithIDMapping: setting string option %s=%s", parts[0], parts[1])
				if err = unix.FsconfigSetString(fsfd, parts[0], parts[1]); err != nil {
					log.L.Errorf("mountAtWithIDMapping: FsconfigSetString failed for %s=%s: %v", parts[0], parts[1], err)
					return fmt.Errorf("failed to configure option %s: %w", opt, err)
				}
			} else {
				log.L.Debugf("mountAtWithIDMapping: setting flag option %s", opt)
				if err = unix.FsconfigSetFlag(fsfd, opt); err != nil {
					log.L.Errorf("mountAtWithIDMapping: FsconfigSetFlag failed for %s: %v", opt, err)
					return fmt.Errorf("failed to configure flag %s: %w", opt, err)
				}
			}
			log.L.Debugf("mountAtWithIDMapping: successfully configured option: %s", opt)
		}
	} else {
		log.L.Debugf("mountAtWithIDMapping: no additional options to configure")
	}

	log.L.Debugf("mountAtWithIDMapping: calling FsconfigCreate to create %s filesystem", fstype)
	if err = unix.FsconfigCreate(fsfd); err != nil {
		log.L.Errorf("mountAtWithIDMapping: FsconfigCreate failed: %v", err)
		return fmt.Errorf("failed to create %s filesystem: %w", fstype, err)
	}
	log.L.Debugf("mountAtWithIDMapping: filesystem created successfully")

	log.L.Debugf("mountAtWithIDMapping: calling Fsmount to create mount fd")
	mntfd, err := unix.Fsmount(fsfd, unix.FSMOUNT_CLOEXEC, 0)
	if err != nil {
		log.L.Errorf("mountAtWithIDMapping: Fsmount failed: %v", err)
		return fmt.Errorf("failed to create mount fd: %w", err)
	}
	log.L.Debugf("mountAtWithIDMapping: Fsmount successful, mntfd=%d", mntfd)
	defer unix.Close(mntfd)

	// TODO: remove this paranoia if it we can expect the dir to always exist by this point?
	if _, err := os.Stat(target); err != nil {
		if os.IsNotExist(err) {
			log.L.Debugf("mountAtWithIDMapping: target directory %s does not exist, creating it", target)
			if err = os.MkdirAll(target, 0755); err != nil {
				log.L.Errorf("mountAtWithIDMapping: failed to create target directory %s: %v", target, err)
				return fmt.Errorf("failed to create target directory %s: %w", target, err)
			}
		} else {
			log.L.Errorf("mountAtWithIDMapping: failed to stat target directory %s: %v", target, err)
			return fmt.Errorf("failed to stat target directory %s: %w", target, err)
		}
	}
	
	log.L.Debugf("mountAtWithIDMapping: calling MoveMount to attach mount to %s", target)
	if err = unix.MoveMount(mntfd, "", unix.AT_FDCWD, target, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		log.L.Errorf("mountAtWithIDMapping: MoveMount failed: %v", err)
		log.L.Debugf("mountAtWithIDMapping: MoveMount parameters: mntfd=%d, from_pathname='', to_dirfd=%d, to_pathname='%s', flags=%d", 
			mntfd, unix.AT_FDCWD, target, unix.MOVE_MOUNT_F_EMPTY_PATH)
		return fmt.Errorf("failed to attach %s to %s: %w", fstype, target, err)
	}
	log.L.Debugf("mountAtWithIDMapping: MoveMount successful, %s mount completed at %s", fstype, target)

	return nil
}

func mountAt(chdir string, source, target, fstype string, flags uintptr, data string) error {
	if chdir == "" {
		return unix.Mount(source, target, fstype, flags, data)
	}

	ch := make(chan error, 1)
	go func() {
		runtime.LockOSThread()

		// Do not unlock this thread.
		// If the thread is unlocked go will try to use it for other goroutines.
		// However it is not possible to restore the thread state after CLONE_FS.
		//
		// Once the goroutine exits the thread should eventually be terminated by go.

		if err := unix.Unshare(unix.CLONE_FS); err != nil {
			ch <- err
			return
		}

		if err := unix.Chdir(chdir); err != nil {
			ch <- err
			return
		}

		ch <- unix.Mount(source, target, fstype, flags, data)
	}()
	return <-ch
}

func (m *Mount) mountWithHelper(helperBinary, typePrefix, target string) error {
	// helperBinary: "mount.fuse3"
	// target: "/foo/merged"
	// m.Type: "fuse3.fuse-overlayfs"
	// command: "mount.fuse3 overlay /foo/merged -o lowerdir=/foo/lower2:/foo/lower1,upperdir=/foo/upper,workdir=/foo/work -t fuse-overlayfs"
	args := []string{m.Source, target}
	for _, o := range m.Options {
		args = append(args, "-o", o)
	}
	args = append(args, "-t", strings.TrimPrefix(m.Type, typePrefix))

	infoBeforeMount, err := Lookup(target)
	if err != nil {
		return err
	}

	// cmd.CombinedOutput() may intermittently return ECHILD because of our signal handling in shim.
	// See #4387 and wait(2).
	const retriesOnECHILD = 10
	for i := 0; i < retriesOnECHILD; i++ {
		cmd := exec.Command(helperBinary, args...)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.ECHILD) {
			return fmt.Errorf("mount helper [%s %v] failed: %q: %w", helperBinary, args, string(out), err)
		}
		// We got ECHILD, we are not sure whether the mount was successful.
		// If the mount ID has changed, we are sure we got some new mount, but still not sure it is fully completed.
		// So we attempt to unmount the new mount before retrying.
		infoAfterMount, err := Lookup(target)
		if err != nil {
			return err
		}
		if infoAfterMount.ID != infoBeforeMount.ID {
			_ = unmount(target, 0)
		}
	}
	return fmt.Errorf("mount helper [%s %v] failed with ECHILD (retried %d times)", helperBinary, args, retriesOnECHILD)
}
