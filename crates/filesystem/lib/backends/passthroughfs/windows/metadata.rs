//! Attribute operations for the Windows passthrough backend.

use super::*;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    pub(super) fn inode_metadata(&self, data: &InodeData) -> io::Result<std::fs::Metadata> {
        if let Some(file) = data.retained.lock().unwrap().as_ref() {
            file.metadata().map_err(host_error)
        } else {
            self.safe_metadata(&data.path())
        }
    }

    /// Verify that an already-open handle belongs to `path` under `self.root` with zero
    /// intermediate reparse points and exact UTF-16 case agreement.
    ///
    /// Returns `Ok(true)` when the kernel's normalized NT path matches `root_nt_path + rel_parts`
    /// exactly, `Ok(false)` when handle-relative component traversal from `self.root` is required
    /// (case mismatch, 8.3 alias, or `GetFinalPathNameByHandleW` unavailable/denied on SMB), and
    /// `Err(LINUX_ELOOP)` immediately if the handle resolved outside `self.root`.
    pub(super) fn verify_handle_under_root(
        &self,
        file: &File,
        rel_parts: &[&std::ffi::OsStr],
    ) -> io::Result<bool> {
        let Some(root_nt) = self.root_nt_path.as_deref() else {
            return Ok(false);
        };
        let Ok(final_nt) = final_nt_path_by_handle(file) else {
            return Ok(false);
        };
        if nt_path_matches_expected(&final_nt, root_nt, rel_parts) {
            return Ok(true);
        }
        if !nt_path_under_root(&final_nt, root_nt) {
            return Err(linux_error(LINUX_ELOOP));
        }
        Ok(false)
    }

    /// Open `path` by walking component-by-component directly from the mount-pinned
    /// `self.root_handle` using `NtCreateFile(RootDirectory, FILE_OPEN_REPARSE_POINT)`.
    /// Never re-opens `self.root` by pathname and never trusts an earlier unverified handle.
    pub(super) fn open_handle_from_root_relative(
        &self,
        rel_parts: &[&std::ffi::OsStr],
        desired_access: u32,
        share_access: u32,
        extra_options: u32,
    ) -> io::Result<(File, WinFileInfo)> {
        use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;

        if rel_parts.is_empty() {
            let root_file = nt_open_relative(
                &self.root_handle,
                std::ffi::OsStr::new(""),
                desired_access | FILE_READ_ATTRIBUTES,
                share_access,
                extra_options,
            )?;
            let root_info = WinFileInfo::from_handle(&root_file)?;
            if !root_info.is_dir() {
                return Err(linux_error(LINUX_ENOTDIR));
            }
            return Ok((root_file, root_info));
        }

        let mut current: Option<File> = None;
        let last_index = rel_parts.len() - 1;
        for (idx, part) in rel_parts.iter().enumerate() {
            let parent_handle = current.as_ref().unwrap_or(&self.root_handle);
            let is_last = idx == last_index;
            let hop_access = if is_last {
                desired_access | FILE_READ_ATTRIBUTES
            } else {
                FILE_READ_ATTRIBUTES | FILE_TRAVERSE
            };
            let hop_options = if is_last {
                extra_options
            } else {
                NT_FILE_DIRECTORY_FILE
            };
            let next = nt_open_relative(parent_handle, part, hop_access, share_access, hop_options)?;
            let next_info = WinFileInfo::from_handle(&next)?;
            reject_reserved_resolved_name(&next)?;
            if is_last {
                return Ok((next, next_info));
            }
            if !next_info.is_dir() {
                return Err(linux_error(LINUX_ENOTDIR));
            }
            current = Some(next);
        }
        unreachable!("rel_parts is non-empty")
    }

    /// Open `path` once with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`
    /// (never truncating), verify exact confinement via `GetFinalPathNameByHandleW` on the fast
    /// path, and fall back to anchored handle-relative `NtCreateFile` traversal (discarding the
    /// fast-path handle) whenever exact verification cannot be established.
    pub(super) fn open_verified_handle(
        &self,
        path: &Path,
        desired_access: u32,
        share_access: u32,
        extra_options: u32,
    ) -> io::Result<(File, WinFileInfo)> {
        use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;

        let rel_parts = lexical_relative_under_root(&self.root, path)?;
        if self.root_nt_path.is_some() {
            match StdOpenOptions::new()
                .access_mode(desired_access | FILE_READ_ATTRIBUTES)
                .share_mode(share_access)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
                .open(path)
            {
                Ok(file) => {
                    let info = WinFileInfo::from_handle(&file)?;
                    if self.verify_handle_under_root(&file, &rel_parts)? {
                        return Ok((file, info));
                    }
                    // Discard the unverified handle and re-open strictly relative to `self.root`.
                    drop(file);
                }
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(ERROR_PATH_NOT_FOUND | ERROR_FILENAME_EXCED_RANGE)
                    ) =>
                {
                    // Fall through to handle-relative traversal so broken intermediate
                    // reparse points report ELOOP rather than ENOENT and >260-char paths
                    // without a verbatim `\\?\` prefix still resolve via `NtCreateFile`.
                }
                Err(error) => return Err(host_error(error)),
            }
        }
        self.open_handle_from_root_relative(&rel_parts, desired_access, share_access, extra_options)
    }

    /// Open `path` once with `FILE_READ_ATTRIBUTES | FILE_FLAG_OPEN_REPARSE_POINT`, collect
    /// metadata + link count + file identity in one `GetFileInformationByHandle` call, and verify
    /// root confinement and absence of intermediate reparse points.
    pub(super) fn open_verified_file_info(&self, path: &Path) -> io::Result<WinFileInfo> {
        use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;

        self.open_verified_handle(path, FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, 0)
            .map(|(_, info)| info)
    }

    pub(super) fn inode_file_info(
        &self,
        data: &InodeData,
        handle: Option<u64>,
    ) -> io::Result<WinFileInfo> {
        if let Some(file) = data.retained.lock().unwrap().as_ref() {
            let info = WinFileInfo::from_handle(file)?;
            data.readdirplus_size
                .store(NO_READDIRPLUS_SIZE, Ordering::Release);
            return Ok(info);
        }
        if let Some(fh) = handle
            && let Ok(open_handle) = self.handle(data.inode, fh)
        {
            let file = open_handle.file.lock().unwrap();
            let info = WinFileInfo::from_handle(&file)?;
            data.readdirplus_size
                .store(NO_READDIRPLUS_SIZE, Ordering::Release);
            return Ok(info);
        }
        let info = self.open_verified_file_info(&data.path())?;
        if let (Some(expected), Some(actual)) = (data.identity, info.identity)
            && expected != actual
        {
            return Err(linux_error(LINUX_ESTALE));
        }
        data.readdirplus_size
            .store(NO_READDIRPLUS_SIZE, Ordering::Release);
        Ok(info)
    }

    pub(super) fn stat_from_file_info(
        &self,
        info: &WinFileInfo,
        data: &InodeData,
    ) -> io::Result<stat64> {
        let mut st = info.to_host_stat(data.inode);
        if !self.cfg.stat_virtualization_enabled() {
            return Ok(st);
        }

        if let Some(override_stat) = owned_metadata::read_retained_stat(data)? {
            apply_override_stat(&mut st, override_stat);
            return Ok(st);
        }

        if let Some(store) = &self.stat_store
            && data.retained.lock().unwrap().is_none()
        {
            if let Some(override_stat) = store.read(&data.path())? {
                apply_override_stat(&mut st, override_stat);
            } else if let Some((uid, gid)) = self.cfg.default_owner {
                st.st_uid = uid;
                st.st_gid = gid;
            }
            return Ok(st);
        }

        let virtual_meta = data.virtual_meta.read().unwrap();
        st.st_uid = virtual_meta.uid;
        st.st_gid = virtual_meta.gid;
        st.st_mode = virtual_meta.mode.unwrap_or_else(|| info.mode());
        st.st_rdev = virtual_meta.rdev;
        if let Some((uid, gid)) = self.cfg.default_owner
            && virtual_meta.mode.is_none()
        {
            st.st_uid = uid;
            st.st_gid = gid;
        }
        Ok(st)
    }

    pub(super) fn entry_from_file_info(
        &self,
        info: &WinFileInfo,
        data: &InodeData,
    ) -> io::Result<Entry> {
        Ok(Entry {
            inode: data.inode,
            generation: 0,
            attr: self.stat_from_file_info(info, data)?,
            attr_flags: 0,
            attr_timeout: self.cfg.attr_timeout,
            entry_timeout: self.cfg.entry_timeout,
        })
    }

    pub(super) fn safe_metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        ensure_lexically_under_root(&self.root, path)?;
        safe_metadata_under_root(&self.root, path)
    }

    pub(super) fn stat_from_metadata(
        &self,
        metadata: &std::fs::Metadata,
        data: &InodeData,
    ) -> io::Result<stat64> {
        if !self.cfg.stat_virtualization_enabled() {
            return self.stat_link_count(host_stat_from_metadata(metadata, data.inode), data);
        }

        if let Some(override_stat) = owned_metadata::read_retained_stat(data)? {
            let mut st = host_stat_from_metadata(metadata, data.inode);
            apply_override_stat(&mut st, override_stat);
            return self.stat_link_count(st, data);
        }

        if let Some(store) = &self.stat_store
            && data.retained.lock().unwrap().is_none()
        {
            let mut st = host_stat_from_metadata(metadata, data.inode);
            if let Some(override_stat) = store.read(&data.path())? {
                apply_override_stat(&mut st, override_stat);
            } else if let Some((uid, gid)) = self.cfg.default_owner {
                // No per-file override: a host-created file. Present the
                // configured default owner instead of the raw 0:0.
                st.st_uid = uid;
                st.st_gid = gid;
            }
            return self.stat_link_count(st, data);
        }

        // Storeless path (e.g. relaxed mode with no persistent stat store):
        // virtual metadata lives only in memory. A host-created file the guest
        // never touched has no virtual mode set, so present the configured
        // default owner instead of the raw 0:0 from the default VirtualMetadata.
        let mut st = stat_from_metadata(metadata, data);
        if let Some((uid, gid)) = self.cfg.default_owner
            && data.virtual_meta.read().unwrap().mode.is_none()
        {
            st.st_uid = uid;
            st.st_gid = gid;
        }
        self.stat_link_count(st, data)
    }

    pub(super) fn entry_from_metadata(
        &self,
        metadata: &std::fs::Metadata,
        data: &InodeData,
    ) -> io::Result<Entry> {
        Ok(Entry {
            inode: data.inode,
            generation: 0,
            attr: self.stat_from_metadata(metadata, data)?,
            attr_flags: 0,
            attr_timeout: self.cfg.attr_timeout,
            entry_timeout: self.cfg.entry_timeout,
        })
    }

    pub(super) fn current_override(
        &self,
        metadata: &std::fs::Metadata,
        data: &InodeData,
    ) -> io::Result<OverrideStat> {
        if let Some(stat) = owned_metadata::read_retained_stat(data)? {
            return Ok(stat);
        }
        if let Some(store) = &self.stat_store
            && data.retained.lock().unwrap().is_none()
            && let Some(override_stat) = store.read(&data.path())?
        {
            return Ok(override_stat);
        }

        if self.stat_store.is_some() && data.retained.lock().unwrap().is_none() {
            // No stored entry yet: a host-created file. Seed the mutation
            // baseline with the configured default owner (falling back to 0:0)
            // so a later setattr persists that owner instead of resetting it to
            // root — matching the read path in `stat_from_metadata`.
            let (uid, gid) = self.cfg.default_owner.unwrap_or((0, 0));
            return Ok(OverrideStat::new(uid, gid, mode_from_metadata(metadata), 0));
        }

        let virtual_meta = data.virtual_meta.read().unwrap();
        // Storeless host-created file (no virtual mode set): baseline its owner
        // to default_owner too, so a partial setattr does not collapse it to 0:0.
        let (uid, gid) = match self.cfg.default_owner {
            Some(owner) if virtual_meta.mode.is_none() => owner,
            _ => (virtual_meta.uid, virtual_meta.gid),
        };
        Ok(OverrideStat {
            version: OVERRIDE_VERSION,
            _pad: [0; 3],
            uid,
            gid,
            mode: virtual_meta
                .mode
                .unwrap_or_else(|| mode_from_metadata(metadata)),
            rdev: virtual_meta.rdev.try_into().unwrap_or(u32::MAX),
        })
    }

    pub(super) fn set_virtual_metadata(
        &self,
        data: &InodeData,
        uid: u32,
        gid: u32,
        mode: u32,
        rdev: u32,
    ) -> io::Result<()> {
        self.set_virtual_metadata_with_handle(data, None, uid, gid, mode, rdev)
    }

    pub(super) fn set_virtual_metadata_with_handle(
        &self,
        data: &InodeData,
        verified_file: Option<&File>,
        uid: u32,
        gid: u32,
        mode: u32,
        rdev: u32,
    ) -> io::Result<()> {
        if self.cfg.stat_virtualization_enabled() {
            let mut meta = data.virtual_meta.write().unwrap();
            meta.uid = uid;
            meta.gid = gid;
            meta.mode = Some(mode);
            meta.rdev = u64::from(rdev);
        }

        let stat = OverrideStat::new(uid, gid, mode, rdev);
        let retained_stat = owned_metadata::write_retained_stat(data, stat)?;
        if let Some(store) = &self.stat_store
            && !retained_stat
            && data.retained.lock().unwrap().is_none()
        {
            store.write(&data.path(), uid, gid, mode, rdev)?;
        }
        self.propagate_sidecar_stat(data, stat)?;

        if (self.cfg.mirror_host_permissions() || !self.cfg.stat_virtualization_enabled())
            && mirror_eligible_type(mode & S_IFMT)
        {
            if let Some(file) = verified_file {
                let mut permissions = file.metadata().map_err(host_error)?.permissions();
                permissions.set_readonly(mode & 0o222 == 0);
                file.set_permissions(permissions).map_err(host_error)?;
            } else if let Some(file) = data.retained.lock().unwrap().as_ref() {
                let mut permissions = file.metadata().map_err(host_error)?.permissions();
                permissions.set_readonly(mode & 0o222 == 0);
                file.set_permissions(permissions).map_err(host_error)?;
            } else {
                apply_host_permissions(&data.path(), mode)?;
            }
        }

        Ok(())
    }

    pub(super) fn clear_priv_bits(&self, data: &InodeData) -> io::Result<()> {
        let metadata = self.inode_metadata(data)?;
        let current = self.current_override(&metadata, data)?;
        let mode = current.mode & !(S_ISUID | S_ISGID);
        if mode != current.mode {
            self.set_virtual_metadata(data, current.uid, current.gid, mode, current.rdev)?;
        }
        Ok(())
    }

    pub(super) fn do_getattr(
        &self,
        inode: u64,
        handle: Option<u64>,
    ) -> io::Result<(stat64, Duration)> {
        if self.cfg.inject_init && inode == INIT_INODE {
            return Ok((init_stat(), self.cfg.attr_timeout));
        }

        let data = self.inode(inode)?;
        let info = self.inode_file_info(&data, handle)?;
        Ok((
            self.stat_from_file_info(&info, data.as_ref())?,
            self.cfg.attr_timeout,
        ))
    }

    pub(super) fn do_setattr(
        &self,
        inode: u64,
        attr: stat64,
        handle: Option<u64>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        if self.cfg.inject_init && inode == INIT_INODE {
            return Err(linux_error(LINUX_EACCES));
        }
        if valid.intersects(
            SetattrValid::SIZE
                | SetattrValid::MODE
                | SetattrValid::UID
                | SetattrValid::GID
                | SetattrValid::ATIME
                | SetattrValid::MTIME
                | SetattrValid::ATIME_NOW
                | SetattrValid::MTIME_NOW
                | SetattrValid::CTIME,
        ) {
            self.require_writable()?;
        }

        let data = self.inode(inode)?;
        let metadata = self.inode_metadata(&data)?;
        if metadata.file_type().is_dir() && valid.contains(SetattrValid::SIZE) {
            return Err(linux_error(LINUX_EISDIR));
        }

        if valid.contains(SetattrValid::SIZE) {
            self.quota_ensure_baseline();
            let size: u64 = attr
                .st_size
                .try_into()
                .map_err(|_| linux_error(LINUX_EINVAL))?;

            if let Some(handle) = handle {
                let handle = self.handle(inode, handle)?;
                let state = self.dax_files.get(&handle.file.lock().unwrap())?;
                self.with_file_mappings_suspended(&state, || {
                    let file = handle.file.lock().unwrap();
                    let _quota_guard = self.quota_charge_growth(metadata.len(), size)?;
                    handle.dirty.store(true, Ordering::Release);
                    file.set_len(size).map_err(host_error)
                })?;
            } else {
                let (file, _) = self.open_verified_inode_file(&data, LINUX_O_WRONLY as u32)?;
                let state = self.dax_files.get(&file)?;
                self.with_file_mappings_suspended(&state, || {
                    let old_len = WinFileInfo::from_handle(&file)?.file_size;
                    let _quota_guard = self.quota_charge_growth(old_len, size)?;
                    file.set_len(size).map_err(host_error)?;
                    file.sync_data().map_err(host_error)
                })?;
            }
        }

        let kill_priv = valid.intersects(SetattrValid::UID | SetattrValid::GID)
            || (valid.contains(SetattrValid::SIZE) && valid.contains(SetattrValid::KILL_SUIDGID));
        if valid.intersects(SetattrValid::MODE | SetattrValid::UID | SetattrValid::GID) {
            if !self.cfg.stat_virtualization_enabled()
                && valid.intersects(SetattrValid::UID | SetattrValid::GID)
            {
                return Err(linux_error(LINUX_EPERM));
            }

            let current = self.current_override(&metadata, data.as_ref())?;
            let uid = if valid.contains(SetattrValid::UID) {
                attr.st_uid
            } else {
                current.uid
            };
            let gid = if valid.contains(SetattrValid::GID) {
                attr.st_gid
            } else {
                current.gid
            };
            let mode = if valid.contains(SetattrValid::MODE) {
                (current.mode & S_IFMT) | (attr.st_mode & !S_IFMT)
            } else {
                current.mode
            };
            let mode = if kill_priv {
                mode & !(S_ISUID | S_ISGID)
            } else {
                mode
            };
            self.set_virtual_metadata(data.as_ref(), uid, gid, mode, current.rdev)?;
        } else if kill_priv {
            self.clear_priv_bits(data.as_ref())?;
        }

        if valid.intersects(
            SetattrValid::ATIME
                | SetattrValid::MTIME
                | SetattrValid::ATIME_NOW
                | SetattrValid::MTIME_NOW,
        ) {
            let times = build_file_times(attr, valid)?;
            if let Some(handle) = handle {
                let handle = self.handle(inode, handle)?;
                let file = handle.file.lock().unwrap();
                handle.dirty.store(true, Ordering::Release);
                file.set_times(times).map_err(host_error)?;
            } else {
                use windows_sys::Win32::Storage::FileSystem::FILE_WRITE_ATTRIBUTES;

                let (file, _) =
                    self.open_verified_inode_file_access(&data, FILE_WRITE_ATTRIBUTES, true)?;
                file.set_times(times).map_err(host_error)?;
            }
        }

        self.do_getattr(inode, handle)
    }
}
