//! Directory enumeration helpers for the Windows passthrough backend.

use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::Foundation::{
    ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, ERROR_NOT_SUPPORTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FULL_DIR_INFO, FILE_ID_BOTH_DIR_INFO, FILE_READ_ATTRIBUTES, FileFullDirectoryInfo,
    FileIdBothDirectoryInfo, GetFileInformationByHandleEx,
};

use super::*;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// 64 KiB aligned batch buffer for `GetFileInformationByHandleEx(FileIdBothDirectoryInfo)`.
/// Holds hundreds of entries per Win32/SMB2 `QUERY_DIRECTORY` call while staying well under
/// a single stack/heap page-table chunk.
const DIR_ENUM_BUFFER_U64S: usize = 65_536 / std::mem::size_of::<u64>();

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    pub(super) fn dir_snapshot(
        &self,
        inode: u64,
        handle: u64,
    ) -> io::Result<Arc<Vec<DirSnapshotEntry>>> {
        let handle = self
            .dir_handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|data| data.inode == inode)
            .cloned()
            .ok_or_else(|| linux_error(LINUX_EBADF))?;
        let mut snapshot = handle.snapshot.lock().unwrap();
        if snapshot.is_none() {
            *snapshot = Some(Arc::new(self.dir_entries(inode)?));
        }
        Ok(Arc::clone(snapshot.as_ref().unwrap()))
    }

    pub(super) fn snapshot_entry_attributes(&self, entry: &DirSnapshotEntry) -> io::Result<Entry> {
        if self.cfg.inject_init && entry.inode == INIT_INODE {
            return Ok(init_entry(self.cfg.entry_timeout, self.cfg.attr_timeout));
        }
        let data = self.inode(entry.inode)?;
        if !self.cfg.stat_virtualization_enabled()
            && data.retained.lock().unwrap().is_none()
            && let Some(info) = entry.info
        {
            if !info.is_dir() {
                data.readdirplus_size
                    .store(info.file_size, Ordering::Release);
            }
            return self.entry_from_file_info(&info, data.as_ref());
        }
        let info = self.inode_file_info(&data, None)?;
        self.entry_from_file_info(&info, data.as_ref())
    }

    pub(super) fn dir_entries(&self, inode: u64) -> io::Result<Vec<DirSnapshotEntry>> {
        let data = self.inode(inode)?;
        let dir_path = data.path();
        let (dir_file, dir_info) = self.open_verified_handle(
            &dir_path,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_SHARE_ALL,
            NT_FILE_DIRECTORY_FILE,
        )?;
        if !dir_info.is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }
        if let (Some(expected), Some(actual)) = (data.identity, dir_info.identity)
            && expected != actual
        {
            return Err(linux_error(LINUX_ESTALE));
        }

        let parent_inode = if inode == ROOT_INODE {
            ROOT_INODE
        } else {
            self.parent_entry(data.as_ref())?.inode
        };

        let mut entries = Vec::new();
        entries.push(DirSnapshotEntry {
            inode,
            name: b".".to_vec(),
            offset: 1,
            file_type: DT_DIR,
            info: Some(dir_info),
        });
        entries.push(DirSnapshotEntry {
            inode: parent_inode,
            name: b"..".to_vec(),
            offset: 2,
            file_type: DT_DIR,
            info: (inode == ROOT_INODE).then_some(dir_info),
        });

        if self.cfg.inject_init && inode == ROOT_INODE {
            entries.push(DirSnapshotEntry {
                inode: INIT_INODE,
                name: INIT_NAME.to_vec(),
                offset: entries.len() as u64 + 1,
                file_type: DT_REG,
                info: None,
            });
        }

        let volume_serial = dir_info.identity.map(|(vol, _)| vol).unwrap_or(0);
        if !self.read_dir_entries_batched(&dir_file, &dir_path, volume_serial, &mut entries)? {
            self.read_dir_entries_full_info(&dir_file, &dir_path, &mut entries)?;
        }

        Ok(entries)
    }

    /// Enumerate children of `dir_file` in 64 KiB batches using `FileIdBothDirectoryInfo`,
    /// avoiding per-child `CreateFileW` opens on both local NTFS and SMB3 shares.
    ///
    /// Returns `Ok(true)` when enumeration completed, or `Ok(false)` when the host filesystem
    /// does not support `FileIdBothDirectoryInfo` and the caller should enumerate the same
    /// verified handle via `FileFullDirectoryInfo`.
    fn read_dir_entries_batched(
        &self,
        dir_file: &File,
        dir_path: &Path,
        volume_serial: u32,
        entries: &mut Vec<DirSnapshotEntry>,
    ) -> io::Result<bool> {
        let mut buf = vec![0u64; DIR_ENUM_BUFFER_U64S];
        let buf_bytes_len = buf.len() * std::mem::size_of::<u64>();
        let mut first_batch = true;

        loop {
            // SAFETY: `dir_file` owns a verified directory handle opened with
            // `FILE_LIST_DIRECTORY`, and `buf` is 8-byte aligned with exact byte capacity.
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    dir_file.as_raw_handle(),
                    FileIdBothDirectoryInfo,
                    buf.as_mut_ptr().cast(),
                    buf_bytes_len as u32,
                )
            };
            if ok == 0 {
                let error = io::Error::last_os_error();
                let code = error.raw_os_error().map(|c| c as u32);
                if code == Some(ERROR_NO_MORE_FILES)
                    || (first_batch && code == Some(ERROR_FILE_NOT_FOUND as u32))
                {
                    return Ok(true);
                }
                if first_batch
                    && matches!(
                        code,
                        Some(
                            ERROR_INVALID_FUNCTION
                                | ERROR_NOT_SUPPORTED
                                | ERROR_INVALID_PARAMETER
                        )
                    )
                {
                    return Ok(false);
                }
                return Err(host_error(error));
            }
            first_batch = false;

            let base = buf.as_ptr().cast::<u8>();
            let mut offset = 0usize;
            let header_size = std::mem::size_of::<FILE_ID_BOTH_DIR_INFO>();
            let name_field_offset = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
            let align = std::mem::align_of::<FILE_ID_BOTH_DIR_INFO>();

            loop {
                if !offset.is_multiple_of(align)
                    || offset.saturating_add(header_size) > buf_bytes_len
                {
                    return Err(linux_error(LINUX_EIO));
                }
                // SAFETY: `offset` is aligned and in bounds of `buf` for `FILE_ID_BOTH_DIR_INFO`.
                let info = unsafe { &*base.add(offset).cast::<FILE_ID_BOTH_DIR_INFO>() };
                let record_end = if info.NextEntryOffset == 0 {
                    buf_bytes_len
                } else {
                    let Some(next) = offset.checked_add(info.NextEntryOffset as usize) else {
                        return Err(linux_error(LINUX_EIO));
                    };
                    if next <= offset || next > buf_bytes_len {
                        return Err(linux_error(LINUX_EIO));
                    }
                    next
                };
                let name_bytes = info.FileNameLength as usize;
                if !name_bytes.is_multiple_of(2)
                    || offset
                        .saturating_add(name_field_offset)
                        .saturating_add(name_bytes)
                        > record_end
                {
                    return Err(linux_error(LINUX_EIO));
                }
                // SAFETY: `FileName` is UTF-16LE (`u16`), `name_field_offset` is 2-byte aligned,
                // and `name_bytes` was bounds-checked against `record_end` above.
                let name_units = unsafe {
                    std::slice::from_raw_parts(
                        base.add(offset + name_field_offset).cast::<u16>(),
                        name_bytes / 2,
                    )
                };
                let os_name = OsString::from_wide(name_units);
                let entry_info = WinFileInfo::from_dir_entry(
                    info.FileAttributes,
                    info.CreationTime,
                    info.LastAccessTime,
                    info.LastWriteTime,
                    info.EndOfFile,
                    valid_file_identity(volume_serial, info.FileId as u64),
                );
                self.push_enumerated_child(dir_file, dir_path, &os_name, entry_info, entries)?;

                if info.NextEntryOffset == 0 {
                    break;
                }
                offset = record_end;
            }
        }
    }

    /// Fallback enumeration on the SAME verified `dir_file` handle (never re-opening by
    /// pathname) for filesystems that do not support `FileIdBothDirectoryInfo`.
    pub(super) fn read_dir_entries_full_info(
        &self,
        dir_file: &File,
        dir_path: &Path,
        entries: &mut Vec<DirSnapshotEntry>,
    ) -> io::Result<()> {
        let mut buf = vec![0u64; DIR_ENUM_BUFFER_U64S];
        let buf_bytes_len = buf.len() * std::mem::size_of::<u64>();
        let mut first_batch = true;

        loop {
            // SAFETY: `dir_file` owns the verified directory handle and `buf` is 8-byte aligned.
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    dir_file.as_raw_handle(),
                    FileFullDirectoryInfo,
                    buf.as_mut_ptr().cast(),
                    buf_bytes_len as u32,
                )
            };
            if ok == 0 {
                let error = io::Error::last_os_error();
                let code = error.raw_os_error().map(|c| c as u32);
                if code == Some(ERROR_NO_MORE_FILES)
                    || (first_batch && code == Some(ERROR_FILE_NOT_FOUND as u32))
                {
                    return Ok(());
                }
                return Err(host_error(error));
            }
            first_batch = false;

            let base = buf.as_ptr().cast::<u8>();
            let mut offset = 0usize;
            let header_size = std::mem::size_of::<FILE_FULL_DIR_INFO>();
            let name_field_offset = std::mem::offset_of!(FILE_FULL_DIR_INFO, FileName);
            let align = std::mem::align_of::<FILE_FULL_DIR_INFO>();

            loop {
                if !offset.is_multiple_of(align)
                    || offset.saturating_add(header_size) > buf_bytes_len
                {
                    return Err(linux_error(LINUX_EIO));
                }
                // SAFETY: `offset` is aligned and in bounds of `buf` for `FILE_FULL_DIR_INFO`.
                let info = unsafe { &*base.add(offset).cast::<FILE_FULL_DIR_INFO>() };
                let record_end = if info.NextEntryOffset == 0 {
                    buf_bytes_len
                } else {
                    let Some(next) = offset.checked_add(info.NextEntryOffset as usize) else {
                        return Err(linux_error(LINUX_EIO));
                    };
                    if next <= offset || next > buf_bytes_len {
                        return Err(linux_error(LINUX_EIO));
                    }
                    next
                };
                let name_bytes = info.FileNameLength as usize;
                if !name_bytes.is_multiple_of(2)
                    || offset
                        .saturating_add(name_field_offset)
                        .saturating_add(name_bytes)
                        > record_end
                {
                    return Err(linux_error(LINUX_EIO));
                }
                // SAFETY: `FileName` is UTF-16LE (`u16`) and bounds-checked against `record_end`.
                let name_units = unsafe {
                    std::slice::from_raw_parts(
                        base.add(offset + name_field_offset).cast::<u16>(),
                        name_bytes / 2,
                    )
                };
                let os_name = OsString::from_wide(name_units);
                let entry_info = WinFileInfo::from_dir_entry(
                    info.FileAttributes,
                    info.CreationTime,
                    info.LastAccessTime,
                    info.LastWriteTime,
                    info.EndOfFile,
                    None,
                );
                self.push_enumerated_child(dir_file, dir_path, &os_name, entry_info, entries)?;

                if info.NextEntryOffset == 0 {
                    break;
                }
                offset = record_end;
            }
        }
    }

    pub(super) fn push_enumerated_child(
        &self,
        dir_file: &File,
        dir_path: &Path,
        os_name: &std::ffi::OsStr,
        mut entry_info: WinFileInfo,
        entries: &mut Vec<DirSnapshotEntry>,
    ) -> io::Result<()> {
        let Some(name_str) = os_name.to_str() else {
            // Skip lone-surrogate host names so one unrepresentable sibling does not break
            // the entire listing.
            return Ok(());
        };
        if name_str == "."
            || name_str == ".."
            || is_reserved_name(name_str)
            || is_windows_device_name(name_str)
            || entry_info.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Ok(());
        }
        let name_buffer = format!("{name_str}\0");
        let c_name = CStr::from_bytes_with_nul(name_buffer.as_bytes())
            .map_err(|_| linux_error(LINUX_EINVAL))?;
        validate_component(c_name)?;

        let child_path = dir_path.join(name_str);
        if entry_info.identity.is_none() && self.supports_hard_links {
            // Query identity relative to the already-verified `dir_file` handle.
            match nt_open_relative(dir_file, os_name, FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, 0)
                .and_then(|file| WinFileInfo::from_handle(&file))
            {
                Ok(verified) => entry_info = verified,
                Err(error)
                    if matches!(error.raw_os_error(), Some(LINUX_ELOOP | LINUX_ENOENT)) =>
                {
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }

        let child = self.intern_path_with_identity(child_path, entry_info.identity)?;
        let file_type = if self.cfg.stat_virtualization_enabled() {
            let info = self.inode_file_info(&child, None)?;
            let st = self.stat_from_file_info(&info, child.as_ref())?;
            dirent_type_from_mode(st.st_mode)
        } else if entry_info.is_dir() {
            DT_DIR
        } else {
            DT_REG
        };

        entries.push(DirSnapshotEntry {
            inode: child.inode,
            name: c_name.to_bytes().to_vec(),
            offset: entries.len() as u64 + 1,
            file_type,
            info: Some(entry_info),
        });
        Ok(())
    }

    pub(super) fn parent_entry(&self, data: &InodeData) -> io::Result<Entry> {
        let path = data.path();
        let parent_path = path.parent().unwrap_or(&self.root);
        let parent_path = if data.inode == ROOT_INODE || !parent_path.starts_with(&self.root) {
            self.root.clone()
        } else {
            parent_path.to_path_buf()
        };
        self.entry_for_path(parent_path)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn borrowed_dir_entry(entry: &DirSnapshotEntry) -> DirEntry<'_> {
    DirEntry {
        ino: entry.inode,
        offset: entry.offset,
        type_: entry.file_type,
        name: &entry.name,
    }
}

pub(super) fn snapshot_dir_entry(entry: &DirSnapshotEntry) -> DirEntry<'static> {
    DirEntry {
        ino: entry.inode,
        offset: entry.offset,
        type_: entry.file_type,
        name: leak_name(&entry.name),
    }
}
