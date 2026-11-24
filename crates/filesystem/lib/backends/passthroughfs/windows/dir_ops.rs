//! Directory enumeration helpers for the Windows passthrough backend.

use super::*;

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
        let metadata = self.inode_metadata(&data)?;
        self.entry_from_metadata(&metadata, data.as_ref())
    }

    pub(super) fn dir_entries(&self, inode: u64) -> io::Result<Vec<DirSnapshotEntry>> {
        let data = self.inode(inode)?;
        let metadata = self.safe_metadata(&data.path())?;
        if !metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        let mut entries = Vec::new();
        entries.push(DirSnapshotEntry {
            inode,
            name: b".".to_vec(),
            offset: 1,
            file_type: DT_DIR,
        });
        entries.push(DirSnapshotEntry {
            inode: ROOT_INODE,
            name: b"..".to_vec(),
            offset: 2,
            file_type: DT_DIR,
        });

        if self.cfg.inject_init && inode == ROOT_INODE {
            entries.push(DirSnapshotEntry {
                inode: INIT_INODE,
                name: INIT_NAME.to_vec(),
                offset: entries.len() as u64 + 1,
                file_type: DT_REG,
            });
        }

        for entry in std::fs::read_dir(data.path()).map_err(host_error)? {
            let entry = entry.map_err(host_error)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| linux_error(LINUX_EINVAL))?;
            if is_reserved_name(name) {
                continue;
            }
            let name_buffer = format!("{name}\0");
            let name = CStr::from_bytes_with_nul(name_buffer.as_bytes())
                .map_err(|_| linux_error(LINUX_EINVAL))?;
            validate_component(name)?;

            let path = entry.path();
            // A rejected reparse point must not hide its ordinary siblings.
            // Direct lookup and access still enforce the same reparse guard.
            let metadata = match self.safe_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.raw_os_error() == Some(LINUX_ELOOP) => continue,
                Err(error) => return Err(error),
            };
            let child = self.intern_path(path)?;
            let full_entry = self.entry_from_metadata(&metadata, child.as_ref())?;
            entries.push(DirSnapshotEntry {
                inode: child.inode,
                name: name.to_bytes().to_vec(),
                offset: entries.len() as u64 + 1,
                file_type: dirent_type_from_mode(full_entry.attr.st_mode),
            });
        }

        Ok(entries)
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
