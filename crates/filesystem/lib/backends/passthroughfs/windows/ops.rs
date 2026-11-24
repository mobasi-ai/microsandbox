//! DynFileSystem callback table for the Windows passthrough backend.

use super::dir_ops::{borrowed_dir_entry, snapshot_dir_entry};
use super::*;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl DynFileSystem for PassthroughFs {
    fn request_error(&self, inode: u64) -> Option<i32> {
        // FUSE speaks Linux errno values even when the host is Windows.
        self.invalid_inodes
            .read()
            .unwrap()
            .contains(&inode)
            .then_some(116)
    }

    fn capture_state(&self) -> io::Result<Vec<u8>> {
        mobility::capture(self)
    }

    fn validate_state(&self, state: &[u8]) -> io::Result<()> {
        mobility::prepare(self, state).map(drop)
    }

    fn restore_state(&self, state: &[u8]) -> io::Result<()> {
        mobility::restore(self, state)
    }

    fn init(&self, _capable: FsOptions) -> io::Result<FsOptions> {
        self.insert_root()?;
        Ok(FsOptions::empty())
    }

    fn destroy(&self) {
        self.handles.write().unwrap().clear();
        self.dir_handles.write().unwrap().clear();
        self.inodes.write().unwrap().by_inode.clear();
        self.inodes.write().unwrap().by_path.clear();
        self.inodes.write().unwrap().by_identity.clear();
    }

    fn lookup(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        self.do_lookup(parent, name)
            .map(|entry| self.record_owned_entry(entry))
    }

    fn forget(&self, _ctx: Context, inode: u64, count: u64) {
        self.forget_owned(inode, count);
    }

    fn batch_forget(&self, _ctx: Context, requests: Vec<(u64, u64)>) {
        for (inode, count) in requests {
            self.forget_owned(inode, count);
        }
    }

    fn getattr(
        &self,
        _ctx: Context,
        inode: u64,
        handle: Option<u64>,
    ) -> io::Result<(stat64, Duration)> {
        self.do_getattr(inode, handle)
    }

    fn setattr(
        &self,
        _ctx: Context,
        inode: u64,
        attr: stat64,
        handle: Option<u64>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        self.do_setattr(inode, attr, handle, valid)
    }

    fn readlink(&self, _ctx: Context, inode: u64) -> io::Result<Vec<u8>> {
        self.do_readlink(inode)
    }

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: u64,
        name: &CStr,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        self.do_symlink(ctx, linkname, parent, name)
            .map(|entry| self.record_owned_entry(entry))
    }

    #[allow(clippy::too_many_arguments)]
    fn mknod(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        self.do_mknod(ctx, parent, name, mode, rdev, umask)
            .map(|entry| self.record_owned_entry(entry))
    }

    fn mkdir(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        umask: u32,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        self.require_writable()?;
        let path = self.child_path(parent, name)?;
        let parent_path = path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
        let parent_metadata = self.safe_metadata(parent_path)?;
        if !parent_metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        std::fs::create_dir(&path).map_err(host_error)?;
        let entry = self.entry_for_path(path)?;
        let data = self.inode(entry.inode)?;
        if let Err(error) = self.set_virtual_metadata(
            data.as_ref(),
            ctx.uid,
            ctx.gid,
            S_IFDIR | (mode & !umask & 0o7777),
            0,
        ) {
            let _ = std::fs::remove_dir(data.path());
            self.remove_inode_path(&data.path());
            return Err(error);
        }
        self.entry_for_path(data.path())
            .map(|entry| self.record_owned_entry(entry))
    }

    fn unlink(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        self.require_writable()?;
        let path = self.child_path(parent, name)?;
        let info = self.open_verified_file_info(&path)?;
        if info.is_dir() {
            return Err(linux_error(LINUX_EISDIR));
        }

        self.unlink_file(&path)
    }

    fn rmdir(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        self.require_writable()?;
        let path = self.child_path(parent, name)?;
        let info = self.open_verified_file_info(&path)?;
        if !info.is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        std::fs::remove_dir(&path).map_err(host_error)?;
        if let Some(store) = &self.stat_store {
            store.remove(&path)?;
        }
        self.remove_inode_path(&path);
        Ok(())
    }

    fn rename(
        &self,
        _ctx: Context,
        olddir: u64,
        oldname: &CStr,
        newdir: u64,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        self.require_writable()?;
        if flags & (RENAME_EXCHANGE | RENAME_WHITEOUT) != 0 {
            return Err(linux_error(LINUX_EOPNOTSUPP));
        }

        let old_path = self.child_path(olddir, oldname)?;
        let old_info = self.open_verified_file_info(&old_path)?;
        let new_path = self.child_path(newdir, newname)?;
        let new_parent = new_path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
        let parent_info = self.open_verified_file_info(new_parent)?;
        if !parent_info.is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }
        match self.open_verified_file_info(&new_path) {
            Ok(new_info) => {
                if flags & RENAME_NOREPLACE != 0 {
                    return Err(linux_error(LINUX_EEXIST));
                }
                if let (Some(old_id), Some(new_id)) = (old_info.identity, new_info.identity)
                    && old_id == new_id
                {
                    // POSIX rename of two aliases of one inode is a namespace no-op,
                    // only when both sides report known, non-sentinel file identities.
                    return Ok(());
                }
            }
            Err(error) if error.raw_os_error() == Some(LINUX_ENOENT) => {}
            Err(error) => return Err(error),
        }

        self.rename_file(&old_path, &new_path)
    }

    fn link(&self, _ctx: Context, inode: u64, newparent: u64, newname: &CStr) -> io::Result<Entry> {
        self.do_link(inode, newparent, newname)
            .map(|entry| self.record_owned_entry(entry))
    }

    fn open(
        &self,
        _ctx: Context,
        inode: u64,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        self.do_open(inode, kill_priv, flags)
    }

    fn create(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        _kill_priv: bool,
        flags: u32,
        umask: u32,
        _extensions: Extensions,
    ) -> io::Result<(Entry, Option<u64>, OpenOptions)> {
        self.do_create(ctx, parent, name, mode, flags, umask)
            .map(|(entry, handle, options)| (self.record_owned_entry(entry), handle, options))
    }

    fn read(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        w: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        if self.cfg.inject_init && inode == INIT_INODE && handle == INIT_HANDLE {
            let init_file = self
                .init_file
                .as_ref()
                .ok_or_else(|| linux_error(LINUX_EBADF))?
                .lock()
                .unwrap();
            return w
                .write_from(&init_file, size as usize, offset)
                .map_err(host_error);
        }

        let handle = self.handle(inode, handle)?;
        if !open_flags_readable(handle.flags) {
            return Err(linux_error(LINUX_EBADF));
        }
        let file = handle.file.lock().unwrap();
        w.write_from(&file, size as usize, offset)
            .map_err(host_error)
    }

    fn write(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        r: &mut dyn ZeroCopyReader,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        kill_priv: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        self.require_writable()?;
        let handle = self.handle(inode, handle)?;
        if !open_flags_writable(handle.flags) {
            return Err(linux_error(LINUX_EBADF));
        }

        let data = self.inode(inode)?;
        // Query identity without holding the handle lock while waiting for the
        // host-file lock (another alias may already be operating on this file).
        let state = self.dax_files.get(&handle.file.lock().unwrap())?;
        let _operation = state.operation.lock().unwrap_or_else(|p| p.into_inner());
        let file = handle.file.lock().unwrap();
        let old_len = file.metadata().map_err(host_error)?.len();
        let offset = if handle.flags & LINUX_O_APPEND as u32 != 0 {
            old_len
        } else {
            offset
        };
        let _quota_guard =
            self.quota_charge_growth(old_len, offset.saturating_add(size as u64))?;
        handle.dirty.store(true, Ordering::Release);
        let result = r.read_to(&file, size as usize, offset).map_err(host_error);
        // Even a failed write may have extended the file before reporting an
        // error. Keep existing DAX readers coherent in either case.
        drop(file);
        let privileges = if kill_priv {
            self.clear_priv_bits(data.as_ref())
        } else {
            Ok(())
        };
        let refresh = if state.has_mappings() {
            self.map_windows
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .refresh_file(&state)
        } else {
            Ok(())
        };
        // Attempt both cleanup and refresh even after a partially failed write.
        privileges?;
        refresh?;
        result
    }

    fn flush(&self, _ctx: Context, inode: u64, handle: u64, _lock_owner: u64) -> io::Result<()> {
        if self.cfg.inject_init && inode == INIT_INODE && handle == INIT_HANDLE {
            return Ok(());
        }

        let handle = self.handle(inode, handle)?;
        // A read-only handle has no buffered writes to persist. On Windows, flush
        // maps to FlushFileBuffers, which requires the handle to hold GENERIC_WRITE
        // and returns ERROR_ACCESS_DENIED on a read-only handle. That surfaces as a
        // spurious EACCES on the guest close() of any read. Skip flush for read-only
        // handles: there is nothing to sync.
        if !open_flags_write(handle.flags) {
            return Ok(());
        }
        if self.dax_files.has_any_writable() {
            let dax = {
                let file = handle.file.lock().unwrap();
                self.dax_files.lookup_writable(&file)?
            };
            if let Some(state) = dax.state
                && state.has_writable_mappings()
            {
                let _operation = state.operation.lock().unwrap_or_else(|p| p.into_inner());
                let still_mapped = self
                    .map_windows
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .flush_writable_views(&state)?;
                if still_mapped || dax.dirty || handle.dirty.load(Ordering::Acquire) {
                    let file = handle.file.lock().unwrap();
                    file.sync_data().map_err(host_error)?;
                    handle.dirty.store(false, Ordering::Release);
                }
                if !still_mapped {
                    self.dax_files.clear_writable_dirty(dax.identity);
                }
                return Ok(());
            }
            if dax.dirty {
                let file = handle.file.lock().unwrap();
                file.sync_data().map_err(host_error)?;
                handle.dirty.store(false, Ordering::Release);
                self.dax_files.clear_writable_dirty(dax.identity);
                return Ok(());
            }
        }
        let file = handle.file.lock().unwrap();
        if !handle.dirty.load(Ordering::Acquire) {
            return Ok(());
        }
        file.sync_data().map_err(host_error)?;
        handle.dirty.store(false, Ordering::Release);
        Ok(())
    }

    fn fsync(&self, _ctx: Context, inode: u64, datasync: bool, handle: u64) -> io::Result<()> {
        if self.cfg.inject_init && inode == INIT_INODE && handle == INIT_HANDLE {
            return Ok(());
        }

        let handle = self.handle(inode, handle)?;
        if self.dax_files.has_any_writable() {
            let dax = {
                let file = handle.file.lock().unwrap();
                self.dax_files.lookup_writable(&file)?
            };
            if let Some(state) = dax.state
                && state.has_writable_mappings()
            {
                let _operation = state.operation.lock().unwrap_or_else(|p| p.into_inner());
                let still_mapped = self
                    .map_windows
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .flush_writable_views(&state)?;
                let file = handle.file.lock().unwrap();
                if datasync {
                    file.sync_data().map_err(host_error)?;
                } else {
                    file.sync_all().map_err(host_error)?;
                }
                handle.dirty.store(false, Ordering::Release);
                if !still_mapped {
                    self.dax_files.clear_writable_dirty(dax.identity);
                }
                return Ok(());
            }
        }
        let file = handle.file.lock().unwrap();
        if datasync {
            file.sync_data().map_err(host_error)?;
        } else {
            file.sync_all().map_err(host_error)?;
        }
        handle.dirty.store(false, Ordering::Release);
        Ok(())
    }

    fn release(
        &self,
        _ctx: Context,
        inode: u64,
        _flags: u32,
        handle: u64,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        if self.cfg.inject_init && inode == INIT_INODE && handle == INIT_HANDLE {
            return Ok(());
        }

        let mut handles = self.handles.write().unwrap();
        let result = match handles.remove(&handle) {
            Some(data) if data.inode == inode => Ok(()),
            Some(data) => {
                handles.insert(handle, data);
                Err(linux_error(LINUX_EBADF))
            }
            None => Err(linux_error(LINUX_EBADF)),
        };
        drop(handles);
        if result.is_ok() {
            self.reap_owned_inode(inode);
        }
        result
    }

    fn statfs(&self, _ctx: Context, _inode: u64) -> io::Result<statvfs64> {
        if let Some(quota) = &self.quota {
            return Ok(super::super::quota::quota_statvfs(
                quota.baseline(),
                quota.limit(),
                quota.used(),
            ));
        }

        Ok(statvfs64 {
            f_bsize: 4096,
            f_frsize: 4096,
            f_blocks: 1,
            f_bfree: 0,
            f_bavail: 0,
            f_files: self.inodes.read().unwrap().by_inode.len() as u64,
            f_ffree: 0,
            f_namemax: 255,
        })
    }

    fn setxattr(
        &self,
        _ctx: Context,
        _inode: u64,
        _name: &CStr,
        _value: &[u8],
        _flags: u32,
    ) -> io::Result<()> {
        Err(linux_error(LINUX_EOPNOTSUPP))
    }

    fn getxattr(
        &self,
        _ctx: Context,
        _inode: u64,
        _name: &CStr,
        _size: u32,
    ) -> io::Result<GetxattrReply> {
        Err(linux_error(LINUX_ENODATA))
    }

    fn listxattr(&self, _ctx: Context, _inode: u64, size: u32) -> io::Result<ListxattrReply> {
        if size == 0 {
            Ok(ListxattrReply::Count(0))
        } else {
            Ok(ListxattrReply::Names(Vec::new()))
        }
    }

    fn removexattr(&self, _ctx: Context, _inode: u64, _name: &CStr) -> io::Result<()> {
        Err(linux_error(LINUX_ENODATA))
    }

    fn opendir(
        &self,
        _ctx: Context,
        inode: u64,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        if flags & LINUX_O_DIRECT as u32 != 0 {
            return Err(linux_error(LINUX_EOPNOTSUPP));
        }
        if self.cfg.inject_init && inode == INIT_INODE {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        let data = self.inode(inode)?;
        let info = self.open_verified_file_info(&data.path())?;
        if !info.is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.dir_handles.write().unwrap().insert(
            handle,
            Arc::new(DirHandle {
                inode,
                flags,
                snapshot: Mutex::new(None),
            }),
        );
        Ok((Some(handle), OpenOptions::empty()))
    }

    fn readdir(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        _size: u32,
        offset: u64,
    ) -> io::Result<Vec<DirEntry<'static>>> {
        let snapshot = self.dir_snapshot(inode, handle)?;
        let start = snapshot.partition_point(|entry| entry.offset <= offset);
        Ok(snapshot[start..].iter().map(snapshot_dir_entry).collect())
    }

    fn readdir_for_each(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        _size: u32,
        offset: u64,
        add_entry: &mut AddDirEntry<'_>,
    ) -> io::Result<()> {
        let snapshot = self.dir_snapshot(inode, handle)?;
        let start = snapshot.partition_point(|entry| entry.offset <= offset);
        for entry in &snapshot[start..] {
            if add_entry(borrowed_dir_entry(entry))? == 0 {
                break;
            }
        }
        Ok(())
    }

    fn readdirplus(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        _size: u32,
        offset: u64,
    ) -> io::Result<Vec<(DirEntry<'static>, Entry)>> {
        let snapshot = self.dir_snapshot(inode, handle)?;
        let start = snapshot.partition_point(|entry| entry.offset <= offset);
        let entries = snapshot[start..]
            .iter()
            .map(|entry| {
                let full = self.snapshot_entry_attributes(entry)?;
                Ok((snapshot_dir_entry(entry), full))
            })
            .collect::<io::Result<Vec<_>>>()?;
        for (dir_entry, entry) in &entries {
            if dir_entry.name != b"." && dir_entry.name != b".." {
                self.record_owned_lookup(entry.inode);
            }
        }
        Ok(entries)
    }

    fn readdirplus_for_each(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        _size: u32,
        offset: u64,
        add_entry: &mut AddDirEntryPlus<'_>,
    ) -> io::Result<()> {
        let snapshot = self.dir_snapshot(inode, handle)?;
        let start = snapshot.partition_point(|entry| entry.offset <= offset);
        for entry in &snapshot[start..] {
            let full = self.snapshot_entry_attributes(entry)?;
            let id = full.inode;
            let is_dot = entry.name == b"." || entry.name == b"..";
            if add_entry(borrowed_dir_entry(entry), full)? == 0 {
                break;
            }
            if !is_dot {
                self.record_owned_lookup(id);
            }
        }
        Ok(())
    }

    fn fsyncdir(&self, _ctx: Context, inode: u64, _datasync: bool, handle: u64) -> io::Result<()> {
        self.dir_handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|data| data.inode == inode)
            .map(|_| ())
            .ok_or_else(|| linux_error(LINUX_EBADF))
    }

    fn releasedir(&self, _ctx: Context, inode: u64, _flags: u32, handle: u64) -> io::Result<()> {
        let mut handles = self.dir_handles.write().unwrap();
        let result = match handles.remove(&handle) {
            Some(data) if data.inode == inode => Ok(()),
            Some(data) => {
                handles.insert(handle, data);
                Err(linux_error(LINUX_EBADF))
            }
            None => Err(linux_error(LINUX_EBADF)),
        };
        drop(handles);
        if result.is_ok() && self.cfg.owned_checkpoint.is_some() {
            let ids = self
                .inodes
                .read()
                .unwrap()
                .by_inode
                .keys()
                .copied()
                .collect::<Vec<_>>();
            for id in ids {
                self.reap_owned_inode(id);
            }
        }
        result
    }

    fn access(&self, _ctx: Context, inode: u64, mask: u32) -> io::Result<()> {
        if self.cfg.readonly && mask & LINUX_ACCESS_W_OK != 0 {
            return Err(linux_error(LINUX_EACCES));
        }
        if self.cfg.inject_init && inode == INIT_INODE {
            return Ok(());
        }

        let data = self.inode(inode)?;
        let info = self.open_verified_file_info(&data.path())?;
        let st = self.stat_from_file_info(&info, data.as_ref())?;
        check_access(_ctx, &st, mask)
    }

    #[allow(clippy::too_many_arguments)]
    fn setupmapping(
        &self,
        _ctx: Context,
        inode: u64,
        _handle: u64,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        host_shm_base: u64,
        shm_size: u64,
        map_sender: &Option<
            crossbeam_channel::Sender<msb_krun_utils::worker_message::WorkerMessage>,
        >,
    ) -> io::Result<()> {
        self.do_setupmapping(
            inode,
            foffset,
            len,
            flags,
            moffset,
            host_shm_base,
            shm_size,
            map_sender,
        )
    }

    fn removemapping(
        &self,
        _ctx: Context,
        requests: Vec<crate::RemovemappingOne>,
        host_shm_base: u64,
        shm_size: u64,
        map_sender: &Option<
            crossbeam_channel::Sender<msb_krun_utils::worker_message::WorkerMessage>,
        >,
    ) -> io::Result<()> {
        self.do_removemapping(&requests, host_shm_base, shm_size, map_sender)
    }
}
