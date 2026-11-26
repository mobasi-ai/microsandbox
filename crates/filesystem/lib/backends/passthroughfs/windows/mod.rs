//! Windows passthrough filesystem backend.
//!
//! This backend is owned by microsandbox and is used instead of libkrun's
//! platform passthrough implementation. It exposes a host directory through
//! virtio-fs while keeping guest metadata private and rejecting Windows path
//! features that could escape the mount root.

use std::collections::BTreeMap;
use std::ffi::{CStr, OsString};
use std::fs::{File, FileTimes, OpenOptions as StdOpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::agentd::agentd_bytes;
use crate::{
    AddDirEntry, AddDirEntryPlus, Context, DirEntry, DynFileSystem, Entry, Extensions, FsOptions,
    GetxattrReply, ListxattrReply, OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
    stat64, statvfs64,
};

mod builder;
mod create_ops;
mod dax;
mod dir_ops;
mod file_ops;
mod inode;
mod memory_mapping;
mod metadata;
mod mobility;
mod ops;
mod owned_metadata;
mod remove_ops;
mod stat_store;

use dax::{DaxFiles, DaxWindows};
use inode::{DirHandle, DirSnapshotEntry, HandleData, InodeData, InodeTable};
pub(super) use owned_metadata::{
    capture_owned_metadata, clear_owned_payload_metadata, owned_component, restore_owned_metadata,
};

pub use builder::{HostPermissions, PassthroughConfig, StatVirtualization};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const ROOT_INODE: u64 = 1;
const INIT_INODE: u64 = 2;
const INIT_HANDLE: u64 = 0;
const INIT_NAME: &[u8] = b"init.krun";
const FALLBACK_METADATA_DIR_NAME: &str = ".msb_override_stat";
const METADATA_ROOT_NAME: &str = "__root";
const METADATA_STAT_NAME: &str = "stat.bin";
const ADS_STREAM_NAME: &str = "msb.override_stat";
const ADS_PROBE_STREAM_NAME: &str = "msb._probe";

const DT_UNKNOWN: u32 = 0;
const DT_FIFO: u32 = 1;
const DT_CHR: u32 = 2;
const DT_DIR: u32 = 4;
const DT_BLK: u32 = 6;
const DT_REG: u32 = 8;
const DT_LNK: u32 = 10;
const DT_SOCK: u32 = 12;

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFIFO: u32 = 0o010000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const S_IFSOCK: u32 = 0o140000;
const S_ISUID: u32 = 0o4000;
const S_ISGID: u32 = 0o2000;

const LINUX_EPERM: i32 = 1;
const LINUX_ENOENT: i32 = 2;
const LINUX_EIO: i32 = 5;
const LINUX_EBADF: i32 = 9;
const LINUX_EACCES: i32 = 13;
const LINUX_EBUSY: i32 = 16;
const LINUX_EEXIST: i32 = 17;
const LINUX_EXDEV: i32 = 18;
const LINUX_ENOTDIR: i32 = 20;
const LINUX_EISDIR: i32 = 21;
const LINUX_EINVAL: i32 = 22;
#[cfg(test)]
const LINUX_ENOSPC: i32 = 28;
const LINUX_EROFS: i32 = 30;
const LINUX_ENOTEMPTY: i32 = 39;
const LINUX_ELOOP: i32 = 40;
const LINUX_ENODATA: i32 = 61;
const LINUX_ESTALE: i32 = 116;
const LINUX_EOPNOTSUPP: i32 = 95;
const LINUX_ENOSYS: i32 = 38;

const LINUX_O_ACCMODE: i32 = 0o3;
const LINUX_O_WRONLY: i32 = 0o1;
const LINUX_O_RDWR: i32 = 0o2;
const LINUX_O_CREAT: i32 = 0o100;
const LINUX_O_EXCL: i32 = 0o200;
const LINUX_O_TRUNC: i32 = 0o1000;
const LINUX_O_APPEND: i32 = 0o2000;

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const LINUX_O_DIRECTORY: i32 = 0x4000;
#[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
const LINUX_O_DIRECTORY: i32 = 0x10000;

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const LINUX_O_DIRECT: i32 = 0x10000;
#[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
const LINUX_O_DIRECT: i32 = 0x4000;

const LINUX_ACCESS_W_OK: u32 = 0o2;
const LINUX_ACCESS_X_OK: u32 = 0o1;
const LINUX_ACCESS_R_OK: u32 = 0o4;

const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;
const RENAME_WHITEOUT: u32 = 4;

const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
const FILE_TRAVERSE: u32 = 0x0000_0020;
const FILE_SHARE_READ_WRITE: u32 = 0x0000_0001 | 0x0000_0002;
const FILE_SHARE_ALL: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004;
const NT_SYNCHRONIZE: u32 = 0x0010_0000;
const NT_FILE_OPEN: u32 = 0x0000_0001;
const NT_FILE_CREATE: u32 = 0x0000_0002;
const NT_FILE_OPEN_IF: u32 = 0x0000_0003;
const NT_FILE_CREATED: usize = 2;
const NT_FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const NT_FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const NT_FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const NT_FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x0000_4000;
const NT_FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const NT_OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const FILE_INVALID_FILE_ID: u64 = u64::MAX;
const NO_READDIRPLUS_SIZE: u64 = u64::MAX;

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PATH_NOT_FOUND: i32 = 3;
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_NOT_SAME_DEVICE: i32 = 17;
const ERROR_SHARING_VIOLATION: i32 = 32;
const ERROR_FILE_EXISTS: i32 = 80;
const ERROR_INVALID_NAME: i32 = 123;
const ERROR_DIR_NOT_EMPTY: i32 = 145;
const ERROR_ALREADY_EXISTS: i32 = 183;
const ERROR_FILENAME_EXCED_RANGE: i32 = 206;
const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;

const WINDOWS_TICKS_PER_SECOND: u64 = 10_000_000;
const WINDOWS_TO_UNIX_EPOCH_SECONDS: u64 = 11_644_473_600;
const OVERRIDE_VERSION: u8 = 1;
const OVERRIDE_SIZE: usize = std::mem::size_of::<OverrideStat>();

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Windows passthrough filesystem backend.
pub struct PassthroughFs {
    cfg: PassthroughConfig,
    root: PathBuf,
    /// Verified directory handle opened once at mount time so handle-relative traversal
    /// (`NtCreateFile`) always anchors to the original mounted root object without reopening
    /// `root` by pathname. Opened without `FILE_SHARE_DELETE` when uncontended so Windows
    /// prevents `root` and its ancestors from being renamed or replaced while mounted.
    root_handle: File,
    /// Normalized NT device path of `root` (without a trailing `\`), populated only when
    /// `root_handle` is pinned against deletion/rename so the fast-path exact UTF-16 prefix
    /// check cannot be invalidated by root replacement.
    root_nt_path: Option<Vec<u16>>,
    /// Whether the backing volume advertises `FILE_SUPPORTS_HARD_LINKS` via
    /// `GetVolumeInformationByHandleW` on `root_handle` at mount time (defaults to `true`
    /// if the volume query fails). When `false` (for example scale-out SMB NAS shares or
    /// FAT/exFAT volumes), directory enumeration skips per-child `nt_open_relative` identity
    /// probes when `FileId` is absent.
    supports_hard_links: bool,
    /// Policy for negotiating `FsOptions::DO_READDIRPLUS`, configured via `MSB_WIN_READDIRPLUS`.
    readdirplus_mode: ReaddirplusMode,
    inodes: RwLock<InodeTable>,
    next_inode: AtomicU64,
    handles: RwLock<BTreeMap<u64, Arc<HandleData>>>,
    dir_handles: RwLock<BTreeMap<u64, Arc<DirHandle>>>,
    next_handle: AtomicU64,
    init_file: Option<Mutex<File>>,
    stat_store: Option<StatStore>,
    quota: Option<super::quota::DirQuota>,
    invalid_inodes: RwLock<std::collections::BTreeSet<u64>>,
    /// Installed DAX mappings, keyed by guest address.
    map_windows: Mutex<DaxWindows>,
    /// Host-file coordination shared by hardlink aliases, separate from worker waits.
    dax_files: DaxFiles,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReaddirplusMode {
    Auto,
    On,
    Off,
}

impl ReaddirplusMode {
    pub(super) fn from_env() -> Self {
        match std::env::var("MSB_WIN_READDIRPLUS") {
            Ok(raw) => Self::parse(&raw),
            Err(_) => Self::Auto,
        }
    }

    pub(super) fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "on" | "1" | "true" => Self::On,
            "off" | "0" | "false" => Self::Off,
            _ => Self::Auto,
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct OverrideStat {
    version: u8,
    _pad: [u8; 3],
    uid: u32,
    gid: u32,
    mode: u32,
    rdev: u32,
}

#[derive(Clone, Debug)]
struct StatStore {
    root: PathBuf,
    backend: StatStoreBackend,
}

#[derive(Clone, Debug)]
enum StatStoreBackend {
    AlternateDataStream,
    Sidecar { dir: PathBuf },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    pub(crate) fn max_state_bytes(&self) -> usize {
        self.cfg.max_state_bytes
    }

    pub(super) fn readdirplus_enabled(&self) -> bool {
        match self.readdirplus_mode {
            ReaddirplusMode::Auto => self.cfg.readonly && !self.cfg.stat_virtualization_enabled(),
            ReaddirplusMode::On => true,
            ReaddirplusMode::Off => false,
        }
    }

    /// Validate an external checkpoint without opening any destination host paths.
    pub fn validate_external_state_with_limit(bytes: &[u8], limit: usize) -> io::Result<()> {
        mobility::validate_unavailable(bytes, limit)
    }

    /// Validate external state with the default filesystem budget.
    pub fn validate_external_state(bytes: &[u8]) -> io::Result<()> {
        Self::validate_external_state_with_limit(
            bytes,
            msb_krun::DEFAULT_MAX_FS_BACKEND_STATE_BYTES,
        )
    }

    /// Validate and translate only the isolated facade's selected host basename.
    pub(crate) fn prepare_single_file_state(
        bytes: &[u8],
        source: &CStr,
        destination: &CStr,
        limit: usize,
    ) -> io::Result<(Vec<u8>, super::ExternalSingleFileIndex)> {
        mobility::prepare_single_file_state(bytes, source, destination, limit)
    }

    /// Charge the quota for growing from `old_len` to `new_end` bytes and hold the
    /// reservation until the caller's host mutation completes.
    pub(super) fn quota_charge_growth(
        &self,
        old_len: u64,
        new_end: u64,
    ) -> io::Result<Option<super::quota::QuotaReservation<'_>>> {
        if let Some(quota) = &self.quota {
            return quota.reserve(new_end.saturating_sub(old_len)).map(Some);
        }
        Ok(None)
    }

    /// Charge the quota for growing an open file to `new_end` bytes and hold the
    /// reservation until the caller's host mutation completes.
    pub(super) fn quota_charge_file_to(
        &self,
        file: &File,
        new_end: u64,
    ) -> io::Result<Option<super::quota::QuotaReservation<'_>>> {
        self.quota_charge_growth(super::quota::file_size(file), new_end)
    }

    /// Capture the quota baseline now if it has not been captured yet.
    ///
    /// The first write-intent operation pays the one-time directory walk so
    /// pre-existing host files become baseline instead of guest growth.
    pub(super) fn quota_ensure_baseline(&self) {
        if let Some(quota) = &self.quota {
            quota.ensure_baseline();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn validate_component(name: &CStr) -> io::Result<&str> {
    let component = name.to_str().map_err(|_| linux_error(LINUX_EINVAL))?;
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.contains('/')
        || component.contains('\\')
        || component.contains(':')
        || is_reserved_name(component)
        || is_windows_device_name(component)
    {
        return Err(linux_error(LINUX_EPERM));
    }

    Ok(component)
}

fn is_windows_device_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or_default().trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    let numbered = upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"))
        .is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        });
    matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || numbered
}

fn is_reserved_name(component: &str) -> bool {
    component.eq_ignore_ascii_case(FALLBACK_METADATA_DIR_NAME)
}

/// Filter out Windows/SMB sentinel file IDs (`0` and `u64::MAX` / `FILE_INVALID_FILE_ID`)
/// so filesystems without stable 64-bit IDs never alias unrelated files into one guest inode.
pub(super) fn valid_file_identity(volume_serial: u32, file_index: u64) -> Option<(u32, u64)> {
    (file_index != 0 && file_index != FILE_INVALID_FILE_ID).then_some((volume_serial, file_index))
}

/// Host file metadata, link count, and volume/file identity collected in a single
/// Win32 handle query or batched directory-enumeration entry.
#[derive(Clone, Copy, Debug)]
pub(super) struct WinFileInfo {
    pub(super) file_attributes: u32,
    pub(super) creation_time: u64,
    pub(super) last_access_time: u64,
    pub(super) last_write_time: u64,
    pub(super) file_size: u64,
    pub(super) nlink: u64,
    pub(super) identity: Option<(u32, u64)>,
}

impl WinFileInfo {
    pub(super) fn from_handle(file: &File) -> io::Result<Self> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };

        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: `file` owns the live handle and `info` has the exact Win32 ABI layout.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(host_error(io::Error::last_os_error()));
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(linux_error(LINUX_ELOOP));
        }

        let filetime = |ft: windows_sys::Win32::Foundation::FILETIME| -> u64 {
            (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime)
        };
        let file_index =
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
        let file_size =
            (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);

        Ok(Self {
            file_attributes: info.dwFileAttributes,
            creation_time: filetime(info.ftCreationTime),
            last_access_time: filetime(info.ftLastAccessTime),
            last_write_time: filetime(info.ftLastWriteTime),
            file_size,
            nlink: u64::from(info.nNumberOfLinks),
            identity: valid_file_identity(info.dwVolumeSerialNumber, file_index),
        })
    }

    pub(super) fn from_dir_entry(
        file_attributes: u32,
        creation_time: i64,
        last_access_time: i64,
        last_write_time: i64,
        end_of_file: i64,
        identity: Option<(u32, u64)>,
    ) -> Self {
        let is_dir = file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        Self {
            file_attributes,
            creation_time: u64::try_from(creation_time).unwrap_or(0),
            last_access_time: u64::try_from(last_access_time).unwrap_or(0),
            last_write_time: u64::try_from(last_write_time).unwrap_or(0),
            file_size: if is_dir {
                0
            } else {
                u64::try_from(end_of_file).unwrap_or(0)
            },
            nlink: 1,
            identity,
        }
    }

    pub(super) fn is_dir(&self) -> bool {
        self.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    pub(super) fn mode(&self) -> u32 {
        let type_bits = if self.is_dir() { S_IFDIR } else { S_IFREG };
        let perms = if self.file_attributes & FILE_ATTRIBUTE_READONLY != 0 {
            0o555
        } else {
            0o777
        };
        type_bits | perms
    }

    pub(super) fn to_host_stat(self, inode: u64) -> stat64 {
        let (atime, atime_nsec) = filetime_to_unix(self.last_access_time);
        let (mtime, mtime_nsec) = filetime_to_unix(self.last_write_time);
        let (ctime, ctime_nsec) = filetime_to_unix(self.creation_time);

        stat64 {
            st_ino: inode,
            st_size: self.file_size as i64,
            st_blocks: blocks_for_size(self.file_size),
            st_atime: atime,
            st_mtime: mtime,
            st_ctime: ctime,
            st_atime_nsec: atime_nsec,
            st_mtime_nsec: mtime_nsec,
            st_ctime_nsec: ctime_nsec,
            st_mode: self.mode(),
            st_nlink: self.nlink,
            st_uid: 0,
            st_gid: 0,
            st_rdev: 0,
            st_blksize: 4096,
        }
    }
}

/// Validate `path` lexically under `root` in memory (no host I/O), returning its normal
/// relative components. Rejects `..`, non-normal components, reserved metadata names, and
/// Windows reserved device names.
fn lexical_relative_under_root<'a>(
    root: &Path,
    path: &'a Path,
) -> io::Result<Vec<&'a std::ffi::OsStr>> {
    ensure_lexically_under_root(root, path)?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| linux_error(LINUX_EACCES))?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                if part
                    .to_str()
                    .is_some_and(|s| is_reserved_name(s) || is_windows_device_name(s))
                {
                    return Err(linux_error(LINUX_EPERM));
                }
                parts.push(part);
            }
            Component::CurDir => {}
            _ => return Err(linux_error(LINUX_EACCES)),
        }
    }
    Ok(parts)
}

/// Query the normalized NT device path (`\Device\...`) of an open handle, with any trailing
/// backslashes stripped so bare volume roots and subdirectories compare uniformly.
/// Loops if a concurrent rename lengthens the path between buffer-sizing attempts.
fn final_nt_path_by_handle(file: &File) -> io::Result<Vec<u16>> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_NT,
    };

    const FLAGS: u32 = VOLUME_NAME_NT | FILE_NAME_NORMALIZED;
    let mut stack = [0u16; 512];
    // SAFETY: `file` owns the handle and `stack` is a valid writable UTF-16 buffer.
    let len = unsafe {
        GetFinalPathNameByHandleW(file.as_raw_handle(), stack.as_mut_ptr(), stack.len() as u32, FLAGS)
    };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out = if (len as usize) < stack.len() {
        stack[..len as usize].to_vec()
    } else {
        let mut capacity = len as usize;
        let mut attempts = 0usize;
        loop {
            attempts += 1;
            if attempts > 8 {
                return Err(io::Error::other("final path kept growing"));
            }
            let mut heap = vec![0u16; capacity];
            // SAFETY: `heap` has room for `capacity` UTF-16 code units.
            let written = unsafe {
                GetFinalPathNameByHandleW(
                    file.as_raw_handle(),
                    heap.as_mut_ptr(),
                    heap.len() as u32,
                    FLAGS,
                )
            };
            if written == 0 {
                return Err(io::Error::last_os_error());
            }
            if (written as usize) < heap.len() {
                heap.truncate(written as usize);
                break heap;
            }
            // Buffer was still too small (path grew concurrently); resize to returned length.
            capacity = written as usize;
        }
    };
    while out.last() == Some(&(b'\\' as u16)) {
        out.pop();
    }
    Ok(out)
}

fn open_root_anchor(root: &Path) -> io::Result<(File, Option<Vec<u16>>)> {
    use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;

    // Prefer pinning `root` without `FILE_SHARE_DELETE` so Windows guarantees `root` and
    // its ancestors cannot be renamed or replaced while mounted. If another host process
    // already holds `DELETE` access, fall back to `FILE_SHARE_ALL` and disable the pathname
    // fast path (`root_nt_path = None`) so every lookup walks directly from `root_handle`.
    let (file, pinned_against_delete) = match StdOpenOptions::new()
        .access_mode(FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE)
        .share_mode(FILE_SHARE_READ_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(root)
    {
        Ok(file) => (file, true),
        Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => {
            let file = StdOpenOptions::new()
                .access_mode(FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE)
                .share_mode(FILE_SHARE_ALL)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
                .open(root)
                .map_err(host_error)?;
            (file, false)
        }
        Err(error) => return Err(host_error(error)),
    };
    let info = WinFileInfo::from_handle(&file)?;
    if !info.is_dir() {
        return Err(linux_error(LINUX_ENOTDIR));
    }
    let root_nt_path = if pinned_against_delete {
        final_nt_path_by_handle(&file).ok()
    } else {
        None
    };
    Ok((file, root_nt_path))
}

/// Query whether the backing volume advertises `FILE_SUPPORTS_HARD_LINKS` via
/// `GetVolumeInformationByHandleW`. Fails closed to `true` if the query fails so unknown
/// filesystems retain the per-child identity probe.
fn volume_supports_hard_links(file: &File) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;
    use windows_sys::Win32::System::SystemServices::FILE_SUPPORTS_HARD_LINKS;

    let mut flags: u32 = 0;
    // SAFETY: `file` owns a live handle; all optional output buffers are null with length 0.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut flags,
            std::ptr::null_mut(),
            0,
        )
    };
    if ok == 0 {
        return true;
    }
    (flags & FILE_SUPPORTS_HARD_LINKS) != 0
}

/// Re-open an existing verified kernel object handle with fresh access/share flags and an
/// independent file pointer, without touching the filesystem namespace.
pub(super) fn reopen_file_handle(
    file: &File,
    desired_access: u32,
    share_access: u32,
    flags: u32,
) -> io::Result<File> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::Storage::FileSystem::ReOpenFile;

    // SAFETY: `file` owns a live handle and `ReOpenFile` returns either `INVALID_HANDLE_VALUE`
    // or a fresh owned handle on the same kernel file object.
    let raw = unsafe { ReOpenFile(file.as_raw_handle(), desired_access, share_access, flags) };
    if raw == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(host_error(io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_handle(raw) })
}

/// Exact UTF-16 prefix check (no case folding, so distinct case-sensitive NTFS sibling
/// directories can never be conflated with `root_nt`).
fn nt_path_under_root(final_path: &[u16], root_nt: &[u16]) -> bool {
    if final_path.len() < root_nt.len() {
        return false;
    }
    if final_path[..root_nt.len()] != *root_nt {
        return false;
    }
    final_path.len() == root_nt.len() || final_path[root_nt.len()] == b'\\' as u16
}

/// Check that `final_path` equals `root_nt + "\" + rel_parts` byte-for-byte in UTF-16 and
/// contains no reserved metadata component (blocking 8.3 short-name aliases because
/// `FILE_NAME_NORMALIZED` expands them back to the long name).
fn nt_path_matches_expected(
    final_path: &[u16],
    root_nt: &[u16],
    rel_parts: &[&std::ffi::OsStr],
) -> bool {
    if !nt_path_under_root(final_path, root_nt) {
        return false;
    }
    let mut cursor = root_nt.len();
    for part in rel_parts {
        if cursor >= final_path.len() || final_path[cursor] != b'\\' as u16 {
            return false;
        }
        cursor += 1;
        let seg_start = cursor;
        for unit in part.encode_wide() {
            if cursor >= final_path.len() || final_path[cursor] != unit {
                return false;
            }
            cursor += 1;
        }
        let seg = OsString::from_wide(&final_path[seg_start..cursor]);
        if seg.to_str().is_some_and(is_reserved_name) {
            return false;
        }
    }
    cursor == final_path.len()
}

/// Reject a handle whose kernel-normalized long filename resolves to the hidden metadata
/// directory or a Windows device name (blocks 8.3 short-name aliases such as `MSB_OV~1` ->
/// `.msb_override_stat`). Fails closed if the kernel cannot report the normalized name.
fn reject_reserved_resolved_name(file: &File) -> io::Result<()> {
    let final_nt = final_nt_path_by_handle(file).map_err(host_error)?;
    let last_start = final_nt
        .iter()
        .rposition(|&unit| unit == b'\\' as u16)
        .map_or(0, |pos| pos + 1);
    let last = OsString::from_wide(&final_nt[last_start..]);
    if last
        .to_str()
        .is_some_and(|name| is_reserved_name(name) || is_windows_device_name(name))
    {
        return Err(linux_error(LINUX_EPERM));
    }
    Ok(())
}

/// Open a single direct child component relative to an already-verified parent directory
/// handle using `NtCreateFile` with `FILE_OPEN_REPARSE_POINT`, guaranteeing no intermediate
/// pathname traversal or symlink/junction follow can occur.
fn nt_open_relative(
    parent_dir: &File,
    component: &std::ffi::OsStr,
    desired_access: u32,
    share_access: u32,
    extra_options: u32,
) -> io::Result<File> {
    nt_create_relative(
        parent_dir,
        component,
        desired_access,
        share_access,
        NT_FILE_OPEN,
        0,
        extra_options,
    )
    .map(|(file, _)| file)
}

/// Open or create a single direct child component relative to an already-verified parent
/// directory handle using `NtCreateFile(RootDirectory, FILE_OPEN_REPARSE_POINT)`.
/// Returns `(file, created_new)` where `created_new` is true only when the kernel created
/// a new file (`FILE_CREATED`).
fn nt_create_relative(
    parent_dir: &File,
    component: &std::ffi::OsStr,
    desired_access: u32,
    share_access: u32,
    create_disposition: u32,
    file_attributes: u32,
    extra_options: u32,
) -> io::Result<(File, bool)> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::Foundation::HANDLE;

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }
    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: HANDLE,
        object_name: *mut UnicodeString,
        attributes: u32,
        security_descriptor: *mut std::ffi::c_void,
        security_quality_of_service: *mut std::ffi::c_void,
    }
    #[repr(C)]
    struct IoStatusBlock {
        status: i32,
        information: usize,
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtCreateFile(
            file_handle: *mut HANDLE,
            desired_access: u32,
            object_attributes: *mut ObjectAttributes,
            io_status_block: *mut IoStatusBlock,
            allocation_size: *mut i64,
            file_attributes: u32,
            share_access: u32,
            create_disposition: u32,
            create_options: u32,
            ea_buffer: *mut std::ffi::c_void,
            ea_length: u32,
        ) -> i32;
        fn RtlNtStatusToDosError(status: i32) -> u32;
    }

    let mut wide: Vec<u16> = component.encode_wide().collect();
    let byte_len = u16::try_from(wide.len().saturating_mul(2))
        .map_err(|_| linux_error(LINUX_EINVAL))?;
    let mut name = UnicodeString {
        length: byte_len,
        maximum_length: byte_len,
        buffer: wide.as_mut_ptr(),
    };
    let mut attrs = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: parent_dir.as_raw_handle(),
        object_name: &mut name,
        attributes: NT_OBJ_CASE_INSENSITIVE,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut iosb = IoStatusBlock {
        status: 0,
        information: 0,
    };
    let mut raw_handle: HANDLE = std::ptr::null_mut();
    let create_options = NT_FILE_OPEN_REPARSE_POINT
        | NT_FILE_OPEN_FOR_BACKUP_INTENT
        | NT_FILE_SYNCHRONOUS_IO_NONALERT
        | extra_options;

    // SAFETY: all pointers (`raw_handle`, `attrs`, `name`, `wide`, `iosb`) are valid and
    // remain alive for the synchronous `NtCreateFile` call.
    let status = unsafe {
        NtCreateFile(
            &mut raw_handle,
            desired_access | NT_SYNCHRONIZE,
            &mut attrs,
            &mut iosb,
            std::ptr::null_mut(),
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            std::ptr::null_mut(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: `RtlNtStatusToDosError` takes any NTSTATUS value and returns a Win32 code.
        let dos = unsafe { RtlNtStatusToDosError(status) };
        return Err(host_error(io::Error::from_raw_os_error(dos as i32)));
    }
    // SAFETY: `NtCreateFile` succeeded (`status >= 0`) and wrote a valid owned handle.
    Ok((
        unsafe { File::from_raw_handle(raw_handle) },
        iosb.information == NT_FILE_CREATED,
    ))
}

fn ensure_lexically_under_root(root: &Path, path: &Path) -> io::Result<()> {
    if path.starts_with(root) {
        Ok(())
    } else {
        Err(linux_error(LINUX_EACCES))
    }
}

/// Resolve the mount root trusting no component of the provided path, returning the
/// resolved path, the live pinned directory handle from the walk, and its normalized NT
/// path (when pinned against delete/rename), so the constructor never reopens `root` by
/// pathname.
fn resolve_root_no_reparse(root_dir: &Path) -> io::Result<(PathBuf, File, Option<Vec<u16>>)> {
    use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;

    // Reject `..` from the RAW path string, not from `Path::components()`.
    //
    // For verbatim (`\\?\`) paths, `components()` collapses `a\..` lexically
    // before we ever see a `ParentDir` or `Normal("..")`, so a `..` would slip
    // through and the filesystem would resolve it out of the subtree. Splitting
    // the raw string on separators catches a `..` segment in any path form.
    // (`..` is pure ASCII, so a lossy conversion can neither hide nor fabricate
    // one.)
    if root_dir
        .as_os_str()
        .to_string_lossy()
        .split(['\\', '/'])
        .any(|segment| segment == "..")
    {
        return Err(linux_error(LINUX_EINVAL));
    }

    // Split into the trusted base and the segments below it. For an absolute
    // path the base is the volume root (prefix + root); for a relative path it
    // is the working directory. Neither is attacker-controllable.
    let mut cursor = PathBuf::new();
    let mut names = Vec::new();
    for component in root_dir.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => cursor.push(component.as_os_str()),
            Component::Normal(part) => names.push(part.to_os_string()),
            Component::CurDir => {}
            Component::ParentDir => return Err(linux_error(LINUX_EINVAL)),
        }
    }
    if cursor.as_os_str().is_empty() {
        cursor.push(".");
    }

    if names.is_empty() {
        let (handle, nt_path) = open_root_anchor(&cursor)?;
        return Ok((cursor, handle, nt_path));
    }

    let mut current = StdOpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | FILE_TRAVERSE)
        .share_mode(FILE_SHARE_ALL)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(&cursor)
        .map_err(host_error)?;
    let base_info = WinFileInfo::from_handle(&current)?;
    if !base_info.is_dir() {
        return Err(linux_error(LINUX_ENOTDIR));
    }

    // Descend one component at a time via `NtCreateFile(RootDirectory, FILE_OPEN_REPARSE_POINT)`;
    // pin the final root directory without `FILE_SHARE_DELETE` so Windows prevents the mount
    // root and its ancestors from being renamed or replaced during `StatStore::new` or later.
    let last_index = names.len() - 1;
    for (idx, name) in names.iter().enumerate() {
        if name.to_str().is_some_and(is_reserved_name) {
            return Err(linux_error(LINUX_EPERM));
        }
        let is_last = idx == last_index;
        let next = if is_last {
            nt_open_relative(
                &current,
                name,
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
                FILE_SHARE_READ_WRITE,
                0,
            )?
        } else {
            nt_open_relative(
                &current,
                name,
                FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
                FILE_SHARE_ALL,
                0,
            )?
        };
        let next_info = WinFileInfo::from_handle(&next)?;
        reject_reserved_resolved_name(&next)?;
        if !next_info.is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }
        cursor.push(name);
        current = next;
    }

    let root_nt_path = final_nt_path_by_handle(&current).ok();
    Ok((cursor, current, root_nt_path))
}

fn safe_metadata_under_root(root: &Path, path: &Path) -> io::Result<std::fs::Metadata> {
    ensure_lexically_under_root(root, path)?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| linux_error(LINUX_EACCES))?;
    let mut cursor = root.to_path_buf();
    reject_reparse_metadata(&std::fs::symlink_metadata(&cursor).map_err(host_error)?)?;

    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                if part.to_str().is_some_and(is_reserved_name) {
                    return Err(linux_error(LINUX_EPERM));
                }
                cursor.push(part);
                let metadata = std::fs::symlink_metadata(&cursor).map_err(host_error)?;
                reject_reparse_metadata(&metadata)?;
            }
            Component::CurDir => {}
            _ => return Err(linux_error(LINUX_EACCES)),
        }
    }

    std::fs::symlink_metadata(path).map_err(host_error)
}

fn reject_reparse_metadata(metadata: &std::fs::Metadata) -> io::Result<()> {
    if metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        Err(linux_error(LINUX_ELOOP))
    } else {
        Ok(())
    }
}

fn open_options_from_flags(flags: u32, create: bool) -> io::Result<StdOpenOptions> {
    let flags = flags as i32;
    if flags & LINUX_O_DIRECT != 0 {
        return Err(linux_error(LINUX_EOPNOTSUPP));
    }
    if !create && flags & (LINUX_O_CREAT | LINUX_O_EXCL) != 0 {
        return Err(linux_error(LINUX_EINVAL));
    }
    if flags & LINUX_O_DIRECTORY != 0 {
        return Err(linux_error(LINUX_EISDIR));
    }

    let accmode = flags & LINUX_O_ACCMODE;
    let mut options = StdOpenOptions::new();
    match accmode {
        0 => {
            options.read(true);
        }
        LINUX_O_WRONLY => {
            options.write(true);
        }
        LINUX_O_RDWR => {
            options.read(true).write(true);
        }
        _ => return Err(linux_error(LINUX_EINVAL)),
    }

    if flags & LINUX_O_APPEND != 0 {
        options.append(true);
    }
    if flags & LINUX_O_TRUNC != 0 {
        if accmode == 0 {
            return Err(linux_error(LINUX_EACCES));
        }
        options.truncate(true);
    }
    if create {
        if flags & LINUX_O_EXCL != 0 {
            options.create_new(true);
        } else {
            options.create(true);
        }
    }
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);

    Ok(options)
}

fn open_flags_readable(flags: u32) -> bool {
    let accmode = flags as i32 & LINUX_O_ACCMODE;
    accmode == 0 || accmode == LINUX_O_RDWR
}

fn open_flags_writable(flags: u32) -> bool {
    let accmode = flags as i32 & LINUX_O_ACCMODE;
    accmode == LINUX_O_WRONLY || accmode == LINUX_O_RDWR || flags as i32 & LINUX_O_APPEND != 0
}

fn open_flags_write(flags: u32) -> bool {
    open_flags_writable(flags) || flags as i32 & (LINUX_O_TRUNC | LINUX_O_CREAT) != 0
}

fn stat_from_metadata(metadata: &std::fs::Metadata, data: &InodeData) -> stat64 {
    let mut st = host_stat_from_metadata(metadata, data.inode);
    let virtual_meta = data.virtual_meta.read().unwrap();
    st.st_uid = virtual_meta.uid;
    st.st_gid = virtual_meta.gid;
    st.st_mode = virtual_meta
        .mode
        .unwrap_or_else(|| mode_from_metadata(metadata));
    st.st_rdev = virtual_meta.rdev;
    st
}

fn host_stat_from_metadata(metadata: &std::fs::Metadata, inode: u64) -> stat64 {
    let (atime, atime_nsec) = filetime_to_unix(metadata.last_access_time());
    let (mtime, mtime_nsec) = filetime_to_unix(metadata.last_write_time());
    let (ctime, ctime_nsec) = filetime_to_unix(metadata.creation_time());

    stat64 {
        st_ino: inode,
        st_size: metadata.file_size() as i64,
        st_blocks: blocks_for_size(metadata.file_size()),
        st_atime: atime,
        st_mtime: mtime,
        st_ctime: ctime,
        st_atime_nsec: atime_nsec,
        st_mtime_nsec: mtime_nsec,
        st_ctime_nsec: ctime_nsec,
        st_mode: mode_from_metadata(metadata),
        st_nlink: 1,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        st_blksize: 4096,
    }
}

fn apply_override_stat(st: &mut stat64, override_stat: OverrideStat) {
    st.st_uid = override_stat.uid;
    st.st_gid = override_stat.gid;
    st.st_mode = override_stat.mode;
    st.st_rdev = u64::from(override_stat.rdev);
}

fn check_access(ctx: Context, st: &stat64, mask: u32) -> io::Result<()> {
    if mask == 0 {
        return Ok(());
    }

    let mode = st.st_mode;
    if ctx.uid == 0 {
        if mask & LINUX_ACCESS_X_OK != 0 && mode & 0o111 == 0 {
            return Err(linux_error(LINUX_EACCES));
        }
        return Ok(());
    }

    let bits = if st.st_uid == ctx.uid {
        (mode >> 6) & 0o7
    } else if st.st_gid == ctx.gid {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    };

    if mask & LINUX_ACCESS_R_OK != 0 && bits & 0o4 == 0 {
        return Err(linux_error(LINUX_EACCES));
    }
    if mask & LINUX_ACCESS_W_OK != 0 && bits & 0o2 == 0 {
        return Err(linux_error(LINUX_EACCES));
    }
    if mask & LINUX_ACCESS_X_OK != 0 && bits & 0o1 == 0 {
        return Err(linux_error(LINUX_EACCES));
    }

    Ok(())
}

fn build_file_times(attr: stat64, valid: SetattrValid) -> io::Result<FileTimes> {
    let mut times = FileTimes::new();
    if valid.contains(SetattrValid::ATIME_NOW) {
        times = times.set_accessed(SystemTime::now());
    } else if valid.contains(SetattrValid::ATIME) {
        times = times.set_accessed(system_time_from_unix(attr.st_atime, attr.st_atime_nsec)?);
    }

    if valid.contains(SetattrValid::MTIME_NOW) {
        times = times.set_modified(SystemTime::now());
    } else if valid.contains(SetattrValid::MTIME) {
        times = times.set_modified(system_time_from_unix(attr.st_mtime, attr.st_mtime_nsec)?);
    }

    Ok(times)
}

fn system_time_from_unix(seconds: i64, nanos: i64) -> io::Result<SystemTime> {
    if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
        return Err(linux_error(LINUX_EINVAL));
    }

    Ok(UNIX_EPOCH + Duration::new(seconds as u64, nanos as u32))
}

fn apply_host_permissions(path: &Path, mode: u32) -> io::Result<()> {
    let mut permissions = std::fs::metadata(path).map_err(host_error)?.permissions();
    permissions.set_readonly(mode & 0o222 == 0);
    std::fs::set_permissions(path, permissions).map_err(host_error)
}

fn mirror_eligible_type(file_type: u32) -> bool {
    file_type == S_IFREG || file_type == S_IFDIR
}

fn read_override_stream(path: &Path) -> io::Result<OverrideStat> {
    let mut file = StdOpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(host_error)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(host_error)?;
    OverrideStat::from_bytes(&bytes)
}

fn write_override_stream(path: &Path, override_stat: OverrideStat) -> io::Result<()> {
    let mut file = StdOpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(host_error)?;
    file.write_all(&override_stat.as_bytes())
        .map_err(host_error)?;
    file.sync_data().map_err(host_error)
}

fn read_override_sidecar_file(path: &Path) -> io::Result<OverrideStat> {
    let bytes = std::fs::read(path).map_err(host_error)?;
    OverrideStat::from_bytes(&bytes)
}

fn write_override_sidecar_file(path: &Path, override_stat: OverrideStat) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
    std::fs::create_dir_all(parent).map_err(host_error)?;

    let mut temp = parent.to_path_buf();
    temp.push(format!("{}.tmp-{}", METADATA_STAT_NAME, unique_suffix()));
    {
        let mut file = StdOpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&temp)
            .map_err(host_error)?;
        file.write_all(&override_stat.as_bytes())
            .map_err(host_error)?;
        file.sync_data().map_err(host_error)?;
    }

    if path.exists() {
        std::fs::remove_file(path).map_err(host_error)?;
    }

    if let Err(error) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(host_error(error));
    }

    Ok(())
}

fn ads_override_path(path: &Path) -> PathBuf {
    ads_stream_path(path, ADS_STREAM_NAME)
}

fn ads_probe_path(path: &Path) -> PathBuf {
    ads_stream_path(path, ADS_PROBE_STREAM_NAME)
}

/// Build an alternate-data-stream path without changing the base path.
///
/// Capability probes must use their own stream name: writing to the real
/// override stream would destroy persisted metadata for the mount root.
fn ads_stream_path(path: &Path, stream_name: &str) -> PathBuf {
    let mut encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    encoded.push(b':' as u16);
    encoded.extend(stream_name.encode_utf16());
    PathBuf::from(OsString::from_wide(&encoded))
}

fn encode_metadata_component(component: &std::ffi::OsStr) -> String {
    let mut encoded = String::new();
    for unit in component.encode_wide() {
        encoded.push(hex_digit(((unit >> 12) & 0xf) as u8));
        encoded.push(hex_digit(((unit >> 8) & 0xf) as u8));
        encoded.push(hex_digit(((unit >> 4) & 0xf) as u8));
        encoded.push(hex_digit((unit & 0xf) as u8));
    }
    encoded
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + value - 10) as char,
    }
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{}-{nanos}", std::process::id())
}

fn init_entry(entry_timeout: Duration, attr_timeout: Duration) -> Entry {
    Entry {
        inode: INIT_INODE,
        generation: 0,
        attr: init_stat(),
        attr_flags: 0,
        attr_timeout,
        entry_timeout,
    }
}

fn init_stat() -> stat64 {
    stat64 {
        st_ino: INIT_INODE,
        st_size: agentd_bytes().len() as i64,
        st_blocks: blocks_for_size(agentd_bytes().len() as u64),
        st_mode: S_IFREG | 0o755,
        st_nlink: 1,
        st_uid: 0,
        st_gid: 0,
        st_blksize: 4096,
        ..Default::default()
    }
}

fn mode_from_metadata(metadata: &std::fs::Metadata) -> u32 {
    let type_bits = if metadata.file_type().is_dir() {
        S_IFDIR
    } else if metadata.file_type().is_file() {
        S_IFREG
    } else {
        0
    };

    // NTFS has no Unix execute bit, so synthesize a default mode for files
    // that have no virtual override yet. Default to executable (matching
    // libkrun's own Windows fs passthrough and WSL DrvFs's no-metadata
    // behavior) so binaries on a bind mount or bind rootfs can run: without
    // this, every host file is exposed as 0o666 and the guest cannot exec
    // anything before it has a chance to chmod it. Precise per-file modes
    // still come from the virtual stat store once the guest sets them.
    let perms = if metadata.file_attributes() & FILE_ATTRIBUTE_READONLY != 0 {
        0o555
    } else {
        0o777
    };
    type_bits | perms
}

fn dirent_type_from_mode(mode: u32) -> u32 {
    match mode & S_IFMT {
        S_IFIFO => DT_FIFO,
        S_IFCHR => DT_CHR,
        S_IFDIR => DT_DIR,
        S_IFBLK => DT_BLK,
        S_IFREG => DT_REG,
        S_IFLNK => DT_LNK,
        S_IFSOCK => DT_SOCK,
        _ => DT_UNKNOWN,
    }
}

fn blocks_for_size(size: u64) -> i64 {
    size.div_ceil(512).try_into().unwrap_or(i64::MAX)
}

fn filetime_to_unix(filetime: u64) -> (i64, i64) {
    let seconds = filetime / WINDOWS_TICKS_PER_SECOND;
    if seconds < WINDOWS_TO_UNIX_EPOCH_SECONDS {
        return (0, 0);
    }

    let unix_seconds = seconds - WINDOWS_TO_UNIX_EPOCH_SECONDS;
    let nanos = (filetime % WINDOWS_TICKS_PER_SECOND) * 100;
    (
        unix_seconds.try_into().unwrap_or(i64::MAX),
        nanos.try_into().unwrap_or(i64::MAX),
    )
}

fn leak_name(name: &[u8]) -> &'static [u8] {
    Box::leak(name.to_vec().into_boxed_slice())
}

fn host_error(error: io::Error) -> io::Error {
    let raw_os_error = error.raw_os_error();
    let errno = match raw_os_error {
        Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => LINUX_ENOENT,
        Some(ERROR_ACCESS_DENIED | ERROR_PRIVILEGE_NOT_HELD) => LINUX_EACCES,
        Some(ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS) => LINUX_EEXIST,
        Some(ERROR_DIR_NOT_EMPTY) => LINUX_ENOTEMPTY,
        Some(ERROR_SHARING_VIOLATION) => LINUX_EBUSY,
        Some(ERROR_INVALID_NAME) => LINUX_EINVAL,
        Some(ERROR_NOT_SAME_DEVICE) => LINUX_EXDEV,
        _ => match error.kind() {
            io::ErrorKind::NotFound => LINUX_ENOENT,
            io::ErrorKind::PermissionDenied => LINUX_EACCES,
            io::ErrorKind::AlreadyExists => LINUX_EEXIST,
            io::ErrorKind::InvalidInput => LINUX_EINVAL,
            io::ErrorKind::Unsupported => LINUX_EOPNOTSUPP,
            _ => LINUX_EIO,
        },
    };

    let kind = error.kind();
    if errno == LINUX_EIO || errno == LINUX_EBUSY {
        log_host_error(raw_os_error, kind, errno);
    }

    linux_error(errno)
}

#[derive(Default)]
struct ErrorRateLimiter {
    buckets: BTreeMap<Option<i32>, (u64, u64)>,
}

impl ErrorRateLimiter {
    const MIN_INTERVAL_MS: u64 = 1_000;
    const MAX_TRACKED_CODES: usize = 64;

    /// Returns `Some(suppressed_count)` when an event for `code` should be logged at `now_ms`,
    /// or `None` when suppressed. Reserves one slot for the overflow bucket (`None`) so total
    /// tracked buckets never exceeds `MAX_TRACKED_CODES`.
    fn record(&mut self, code: Option<i32>, now_ms: u64) -> Option<u64> {
        let has_overflow = self.buckets.contains_key(&None);
        let key = if self.buckets.contains_key(&code)
            || (code.is_some()
                && self.buckets.len() + usize::from(!has_overflow) < Self::MAX_TRACKED_CODES)
            || (code.is_none() && self.buckets.len() < Self::MAX_TRACKED_CODES)
        {
            code
        } else {
            None
        };
        match self.buckets.get_mut(&key) {
            Some((last_ms, suppressed)) => {
                if now_ms.saturating_sub(*last_ms) >= Self::MIN_INTERVAL_MS {
                    let prev_suppressed = std::mem::take(suppressed);
                    *last_ms = now_ms;
                    Some(prev_suppressed)
                } else {
                    *suppressed = suppressed.saturating_add(1);
                    None
                }
            }
            None => {
                self.buckets.insert(key, (now_ms, 0));
                Some(0)
            }
        }
    }
}

fn log_host_error(win32_error: Option<i32>, error_kind: io::ErrorKind, linux_errno: i32) {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    static LIMITER: std::sync::OnceLock<Mutex<ErrorRateLimiter>> = std::sync::OnceLock::new();

    let now_ms = START.get_or_init(std::time::Instant::now).elapsed().as_millis() as u64;
    let suppressed = LIMITER
        .get_or_init(|| Mutex::new(ErrorRateLimiter::default()))
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .record(win32_error, now_ms);

    if let Some(suppressed) = suppressed {
        if let Some(code) = win32_error {
            tracing::warn!(
                win32_error = code,
                linux_errno,
                suppressed,
                "windows passthroughfs host I/O error"
            );
        } else {
            tracing::warn!(
                error_kind = %error_kind,
                linux_errno,
                suppressed,
                "windows passthroughfs host I/O error"
            );
        }
    }
}

fn linux_error(errno: i32) -> io::Error {
    io::Error::from_raw_os_error(errno)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests;
