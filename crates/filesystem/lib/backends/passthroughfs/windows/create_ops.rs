//! Creation and link operations for the Windows passthrough backend.

use super::*;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    pub(super) fn do_create(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        flags: u32,
        umask: u32,
    ) -> io::Result<(Entry, Option<u64>, OpenOptions)> {
        self.require_writable()?;
        let component = validate_component(name)?;
        let path = self.child_path(parent, name)?;
        let parent_path = path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
        let (parent_file, parent_info) = self.open_verified_handle(
            parent_path,
            windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
            FILE_SHARE_ALL,
            NT_FILE_DIRECTORY_FILE,
        )?;
        if !parent_info.is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        self.quota_ensure_baseline();

        // Validate full Linux flags first (e.g., O_DIRECT, O_RDONLY|O_TRUNC), then create/open
        // the child directly relative to the verified `parent_file` handle (`RootDirectory`)
        // without truncating, so neither a swapped parent nor a planted reparse point can create
        // or truncate a file outside the mount.
        let _ = open_options_from_flags(flags, true)?;
        let wants_trunc = flags & LINUX_O_TRUNC as u32 != 0;
        let access_flags = if wants_trunc {
            flags & !(LINUX_O_CREAT as u32 | LINUX_O_EXCL as u32 | LINUX_O_APPEND as u32)
        } else {
            flags & !(LINUX_O_CREAT as u32 | LINUX_O_EXCL as u32)
        };
        let desired_access = file_ops::access_mask_from_open_flags(access_flags)?;
        let disposition = if flags as i32 & LINUX_O_EXCL != 0 {
            NT_FILE_CREATE
        } else {
            NT_FILE_OPEN_IF
        };
        let (file, created_new) = nt_create_relative(
            &parent_file,
            std::ffi::OsStr::new(component),
            desired_access | windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES,
            FILE_SHARE_ALL,
            disposition,
            FILE_ATTRIBUTE_NORMAL,
            NT_FILE_NON_DIRECTORY_FILE,
        )?;

        let mut info = WinFileInfo::from_handle(&file)?;
        if info.is_dir() {
            return Err(linux_error(LINUX_EISDIR));
        }
        reject_reserved_resolved_name(&file)?;
        if wants_trunc {
            let state = self.dax_files.get(&file)?;
            self.with_file_mappings_suspended(&state, || file.set_len(0).map_err(host_error))?;
            info = WinFileInfo::from_handle(&file)?;
        }

        let data = self.intern_path_with_identity(path.clone(), info.identity)?;
        let target_mode = (info.mode() & S_IFMT) | (mode & !umask & 0o7777);
        if let Err(error) = self.set_virtual_metadata_with_handle(
            data.as_ref(),
            Some(&file),
            ctx.uid,
            ctx.gid,
            target_mode,
            0,
        ) {
            if created_new {
                let _ = std::fs::remove_file(&path);
                self.remove_inode_path(&path);
            }
            return Err(error);
        }

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.handles.write().unwrap().insert(
            handle,
            Arc::new(HandleData {
                inode: data.inode,
                flags,
                file: Mutex::new(file),
                dirty: AtomicBool::new(true),
            }),
        );

        Ok((
            self.entry_from_file_info(&info, data.as_ref())?,
            Some(handle),
            OpenOptions::empty(),
        ))
    }

    pub(super) fn do_mknod(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        self.require_writable()?;
        let path = self.child_path(parent, name)?;
        let parent_path = path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
        let parent_metadata = self.safe_metadata(parent_path)?;
        if !parent_metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        let file_type = mode & S_IFMT;
        if !self.cfg.stat_virtualization_enabled() && file_type != 0 && file_type != S_IFREG {
            return Err(linux_error(LINUX_EOPNOTSUPP));
        }

        let file = StdOpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .map_err(host_error)?;
        reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;

        let metadata = self.safe_metadata(&path)?;
        let data = self.intern_path(path)?;
        let virtual_type = if file_type == 0 { S_IFREG } else { file_type };
        let virtual_mode = virtual_type | (mode & !umask & 0o7777);
        if let Err(error) =
            self.set_virtual_metadata(data.as_ref(), ctx.uid, ctx.gid, virtual_mode, rdev)
        {
            let _ = std::fs::remove_file(data.path());
            self.remove_inode_path(&data.path());
            return Err(error);
        }

        self.entry_from_metadata(&metadata, data.as_ref())
    }

    pub(super) fn do_symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: u64,
        name: &CStr,
    ) -> io::Result<Entry> {
        self.require_writable()?;
        if !self.cfg.stat_virtualization_enabled() {
            return Err(linux_error(LINUX_EOPNOTSUPP));
        }

        let path = self.child_path(parent, name)?;
        let parent_path = path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
        let parent_metadata = self.safe_metadata(parent_path)?;
        if !parent_metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        self.quota_ensure_baseline();

        let mut file = StdOpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .map_err(host_error)?;
        reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;
        let _quota_guard = match self.quota_charge_file_to(&file, linkname.to_bytes().len() as u64)
        {
            Ok(guard) => guard,
            Err(error) => {
                let _ = std::fs::remove_file(&path);
                return Err(error);
            }
        };
        if let Err(error) = file.write_all(linkname.to_bytes()).map_err(host_error) {
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }

        let metadata = self.safe_metadata(&path)?;
        let data = self.intern_path(path)?;
        if let Err(error) =
            self.set_virtual_metadata(data.as_ref(), ctx.uid, ctx.gid, S_IFLNK | 0o777, 0)
        {
            let _ = std::fs::remove_file(data.path());
            self.remove_inode_path(&data.path());
            return Err(error);
        }

        self.entry_from_metadata(&metadata, data.as_ref())
    }

    pub(super) fn do_readlink(&self, inode: u64) -> io::Result<Vec<u8>> {
        if self.cfg.inject_init && inode == INIT_INODE {
            return Err(linux_error(LINUX_EINVAL));
        }

        let data = self.inode(inode)?;
        let metadata = self.safe_metadata(&data.path())?;
        let current = self.current_override(&metadata, data.as_ref())?;
        if current.mode & S_IFMT != S_IFLNK {
            return Err(linux_error(LINUX_EINVAL));
        }

        let mut file = StdOpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(data.path())
            .map_err(host_error)?;
        reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;
        let mut target = Vec::new();
        file.read_to_end(&mut target).map_err(host_error)?;
        Ok(target)
    }

    pub(super) fn do_link(&self, inode: u64, newparent: u64, newname: &CStr) -> io::Result<Entry> {
        self.require_writable()?;
        if self.cfg.inject_init && inode == INIT_INODE {
            return Err(linux_error(LINUX_EACCES));
        }

        let source = self.inode(inode)?;
        self.safe_metadata(&source.path())?;
        let new_path = self.child_path(newparent, newname)?;
        let parent_path = new_path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
        let parent_metadata = self.safe_metadata(parent_path)?;
        if !parent_metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        std::fs::hard_link(source.path(), &new_path).map_err(host_error)?;
        let metadata = self.safe_metadata(&new_path)?;
        let data = self.intern_path(new_path.clone())?;
        let current = self.current_override(&metadata, source.as_ref())?;
        if let Err(error) = self.set_virtual_metadata(
            data.as_ref(),
            current.uid,
            current.gid,
            current.mode,
            current.rdev,
        ) {
            let _ = std::fs::remove_file(&new_path);
            self.remove_inode_path(&new_path);
            return Err(error);
        }

        self.entry_from_metadata(&metadata, data.as_ref())
    }
}
