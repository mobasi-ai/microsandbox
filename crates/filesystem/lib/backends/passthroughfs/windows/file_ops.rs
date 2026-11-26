//! File open operations for the Windows passthrough backend.

use super::*;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    pub(super) fn do_open(
        &self,
        inode: u64,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        if self.cfg.inject_init && inode == INIT_INODE {
            return Ok((Some(INIT_HANDLE), OpenOptions::empty()));
        }
        if open_flags_write(flags) {
            self.require_writable()?;
            self.quota_ensure_baseline();
        }

        let data = self.inode(inode)?;
        // Atomically re-open either the pinned retained handle (without releasing the
        // retained lock across a fallback) or a verified non-truncating handle under root,
        // then acquire the DAX lock on THAT exact handle before truncating.
        let (file, info) = self.open_verified_inode_file(&data, flags)?;
        let cached_size = data
            .readdirplus_size
            .swap(NO_READDIRPLUS_SIZE, Ordering::AcqRel);
        let open_options = if cached_size != NO_READDIRPLUS_SIZE
            && cached_size != info.file_size
            && flags & LINUX_O_TRUNC as u32 == 0
        {
            // Directory enumeration (`FILE_ID_BOTH_DIR_INFO` / `FILE_FULL_DIR_INFO`) can
            // lag behind the live MFT size for files with an open host writer or hard-link
            // update. Returning `FOPEN_DIRECT_IO` on this open bypasses stale `i_size`
            // clamping in Linux FUSE so guest `read()` sees all live bytes.
            OpenOptions::DIRECT_IO
        } else {
            OpenOptions::empty()
        };
        if flags & LINUX_O_TRUNC as u32 != 0 {
            let state = self.dax_files.get(&file)?;
            self.with_file_mappings_suspended(&state, || file.set_len(0).map_err(host_error))?;
        }
        if kill_priv && flags as i32 & LINUX_O_TRUNC != 0 {
            self.clear_priv_bits(data.as_ref())?;
        }
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.handles.write().unwrap().insert(
            handle,
            Arc::new(HandleData {
                inode,
                flags,
                file: Mutex::new(file),
                dirty: AtomicBool::new(flags & LINUX_O_TRUNC as u32 != 0),
            }),
        );
        Ok((Some(handle), open_options))
    }

    /// Atomically re-open an inode's pinned retained handle while holding `data.retained`.
    /// Never falls back to a pathname open and never truncates.
    fn try_reopen_retained(&self, data: &InodeData, desired_access: u32) -> Option<io::Result<File>> {
        use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;

        let retained = data.retained.lock().unwrap();
        let file = retained.as_ref()?;
        Some(reopen_file_handle(
            file,
            desired_access | FILE_READ_ATTRIBUTES,
            FILE_SHARE_ALL,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        ))
    }

    /// Open `data` with explicit Win32 desired access without truncating, verifying root
    /// confinement, non-reparse status, file type, and cached file identity (`ESTALE`).
    pub(super) fn open_verified_inode_file_access(
        &self,
        data: &InodeData,
        desired_access: u32,
        allow_dir: bool,
    ) -> io::Result<(File, WinFileInfo)> {
        if let Some(reopened) = self.try_reopen_retained(data, desired_access) {
            let file = reopened?;
            let info = WinFileInfo::from_handle(&file)?;
            if !allow_dir && info.is_dir() {
                return Err(linux_error(LINUX_EISDIR));
            }
            return Ok((file, info));
        }

        let (file, info) =
            self.open_verified_handle(&data.path(), desired_access, FILE_SHARE_ALL, 0)?;
        if !allow_dir && info.is_dir() {
            return Err(linux_error(LINUX_EISDIR));
        }
        if let (Some(expected), Some(actual)) = (data.identity, info.identity)
            && expected != actual
        {
            return Err(linux_error(LINUX_ESTALE));
        }
        Ok((file, info))
    }

    /// Open `data` using Linux open flags (always stripping `O_TRUNC` so callers truncate
    /// only after verification and DAX suspension).
    pub(super) fn open_verified_inode_file(
        &self,
        data: &InodeData,
        flags: u32,
    ) -> io::Result<(File, WinFileInfo)> {
        let desired_access = access_mask_from_open_flags(flags)?;
        self.open_verified_inode_file_access(data, desired_access, false)
    }
}

/// Map Linux `open(2)` flags (without `O_CREAT`/`O_TRUNC`) to a Win32 desired-access mask
/// suitable for both `StdOpenOptions::access_mode` and `NtCreateFile`.
pub(super) fn access_mask_from_open_flags(flags: u32) -> io::Result<u32> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_APPEND_DATA, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
        FILE_WRITE_ATTRIBUTES,
    };

    let flags = flags as i32;
    if flags & LINUX_O_DIRECT != 0 {
        return Err(linux_error(LINUX_EOPNOTSUPP));
    }
    if flags & (LINUX_O_CREAT | LINUX_O_EXCL) != 0 {
        return Err(linux_error(LINUX_EINVAL));
    }
    if flags & LINUX_O_DIRECTORY != 0 {
        return Err(linux_error(LINUX_EISDIR));
    }

    let accmode = flags & LINUX_O_ACCMODE;
    if flags & LINUX_O_TRUNC != 0 && accmode == 0 {
        return Err(linux_error(LINUX_EACCES));
    }
    let append_only = flags & LINUX_O_APPEND != 0 && flags & LINUX_O_TRUNC == 0;
    let mask = match accmode {
        0 => FILE_GENERIC_READ,
        LINUX_O_WRONLY if append_only => {
            FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | NT_SYNCHRONIZE
        }
        LINUX_O_WRONLY => FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES,
        LINUX_O_RDWR if append_only => {
            FILE_GENERIC_READ | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES
        }
        LINUX_O_RDWR => FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        _ => return Err(linux_error(LINUX_EINVAL)),
    };
    Ok(mask)
}
