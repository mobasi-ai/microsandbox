//! Path byte-budget quota for the passthrough filesystem.
//!
//! A passthrough mount shares a host path directly, so without a budget a guest
//! can write unbounded data straight onto the host disk. [`DirQuota`] bounds the
//! *guest-attributable* growth of either one selected file or a directory tree.
//!
//! ## Accounting model
//!
//! `used` is an optimistic running estimate of the subtree's logical size,
//! charged on growth (write / fallocate / truncate-extend / copy). It is
//! deliberately **never decremented** on the unlink / rename / truncate-shrink
//! paths — that would mean fstat-before-remove bookkeeping on every mutation.
//! Instead, when an optimistic charge would cross `limit`, the budget walks the
//! root to recompute the ground-truth size and corrects `used`. The walk is
//! ground truth at the only moment it matters (the limit boundary), so the hot
//! path stays cheap while a churning workload (e.g. a heartbeat file rewritten
//! every second) converges on its true size instead of monotonically draining
//! the budget.
//!
//! Accounting is **logical** (`st_size`, not allocated blocks): a sparse file is
//! charged at its apparent size. That is conservative for a fill-prevention
//! quota — it bounds what the guest could later fill.
//!
//! ## Delta semantics
//!
//! The budget bounds *guest additions beyond what already existed when the
//! guest first writes*, not the absolute subtree size. That baseline — the
//! host-written control-plane files for `/.msb`, or a pre-existing host
//! directory for a bind mount — never counts against the guest. So
//! `quota = 1 GiB` on a directory that already holds 5 GiB means "the guest may
//! add up to 1 GiB," not "instantly full."
//!
//! ## Lazy baseline
//!
//! The baseline is **not** walked at mount — that would put a directory walk on
//! the VM-setup path, costly for a heavy bind mount. It is computed once, on the
//! first guest write-access ([`DirQuota::ensure_baseline`], called from the
//! `open`/`create`/`setattr` handlers). Those ops necessarily precede the first
//! `write`/`fallocate`/truncate-extend, so the baseline always reflects the
//! pre-guest-write state — the snapshot just happens at first touch instead of
//! at boot. A read-only workload never triggers it.

use std::{
    io,
    path::{Path, PathBuf},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use serde::{Deserialize, Serialize};

#[cfg(windows)]
use std::fs::File;
#[cfg(unix)]
use std::os::fd::RawFd;

#[cfg(unix)]
use crate::backends::shared::platform;
use crate::statvfs64;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A delta-charged byte budget for one passthrough mount path.
pub(crate) struct DirQuota {
    /// Hard ceiling in bytes for guest additions. Growth past this returns `ENOSPC`.
    limit: u64,

    /// Host file or directory tree whose growth is bounded.
    root: PathBuf,

    /// Subtree size at first guest write-access. Never counts against the
    /// guest. Computed lazily so a heavy directory is not walked at boot.
    baseline: OnceLock<u64>,

    /// Optimistic running estimate of guest-added bytes beyond the baseline.
    used: AtomicU64,

    /// Bytes currently authorized by in-flight mutations whose host writes have
    /// not finished yet, so a concurrent recount never drops pending growth.
    in_flight: AtomicU64,

    /// Serializes slow-path ground-truth recounts without blocking fast-path charges.
    recount_lock: Mutex<()>,
}

/// Active quota reservation held across the host write/truncate that it authorizes.
#[must_use]
pub(crate) struct QuotaReservation<'a> {
    quota: &'a DirQuota,
    bytes: u64,
}

impl std::fmt::Debug for QuotaReservation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuotaReservation")
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl Drop for QuotaReservation<'_> {
    fn drop(&mut self) {
        if self.bytes != 0 {
            self.quota
                .in_flight
                .fetch_sub(self.bytes, Ordering::Release);
        }
    }
}

/// Durable delta-accounting state for a configured directory quota.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct QuotaState {
    pub baseline: Option<u64>,
    pub used: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DirQuota {
    /// Capture quota accounting without forcing the lazy baseline.
    pub(crate) fn capture_state(&self) -> QuotaState {
        QuotaState {
            baseline: self.baseline.get().copied(),
            used: self.used.load(Ordering::Acquire),
        }
    }

    /// Validate quota state against this destination's configured ceiling.
    pub(crate) fn validate_state(&self, state: &QuotaState) -> io::Result<()> {
        if state.used > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "restored quota usage exceeds configured limit",
            ));
        }
        if let (Some(existing), Some(restored)) = (self.baseline.get(), state.baseline)
            && *existing != restored
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "restored quota baseline conflicts with destination state",
            ));
        }
        Ok(())
    }

    /// Restore validated accounting into a freshly constructed destination quota.
    pub(crate) fn restore_state(&self, state: &QuotaState) -> io::Result<()> {
        self.validate_state(state)?;
        if let Some(baseline) = state.baseline
            && self.baseline.get().is_none()
        {
            self.baseline.set(baseline).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "quota baseline was initialized concurrently",
                )
            })?;
        }
        self.used.store(state.used, Ordering::Release);
        Ok(())
    }

    /// Create a budget of `limit` guest-addable bytes over the path at `root`.
    ///
    /// Does not walk the directory — the baseline is captured lazily on the
    /// first guest write-access (see [`Self::ensure_baseline`]).
    pub(crate) fn new(root: PathBuf, limit: u64) -> Self {
        Self {
            limit,
            root,
            baseline: OnceLock::new(),
            used: AtomicU64::new(0),
            in_flight: AtomicU64::new(0),
            recount_lock: Mutex::new(()),
        }
    }

    /// The configured ceiling in bytes for guest additions.
    pub(crate) fn limit(&self) -> u64 {
        self.limit
    }

    /// Bytes present at the moment the baseline was first captured (never
    /// charged to the guest). Computes the baseline if it has not been yet.
    pub(crate) fn baseline(&self) -> u64 {
        *self.baseline.get_or_init(|| subtree_size(&self.root))
    }

    /// Capture the baseline now if it has not been captured yet.
    ///
    /// Called from the write-gating FUSE handlers (`open` with write intent,
    /// `create`, `setattr`-truncate) so the baseline is snapshotted *before* the
    /// guest's first mutation. Idempotent and cheap after the first call.
    pub(crate) fn ensure_baseline(&self) {
        let _ = self.baseline();
    }

    /// Current best estimate of bytes used, clamped to the ceiling for display.
    pub(crate) fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed).min(self.limit)
    }

    /// Reserve `growth` bytes of pending subtree growth and keep them tracked in
    /// `in_flight` until the returned guard drops after the host write finishes.
    ///
    /// Returns `ENOSPC` if the growth would exceed the limit even after a
    /// ground-truth recount that accounts for all other in-flight reservations.
    pub(crate) fn reserve(&self, growth: u64) -> io::Result<QuotaReservation<'_>> {
        if growth == 0 {
            return Ok(QuotaReservation {
                quota: self,
                bytes: 0,
            });
        }

        // Track our pending growth in `in_flight` before charging `used` so any
        // concurrent recount observes this reservation until the write completes.
        self.in_flight.fetch_add(growth, Ordering::AcqRel);
        let guard = QuotaReservation {
            quota: self,
            bytes: growth,
        };

        if try_fast_charge(&self.used, self.limit, growth) {
            return Ok(guard);
        }

        // The optimistic estimate crossed the ceiling. Serialize recounts so
        // concurrent over-limit callers do not race, while preserving both
        // already-authorized in-flight reservations and any fast-path charges
        // authorized while the walk is running.
        let _recount = self.recount_lock.lock().unwrap_or_else(|p| p.into_inner());
        if try_fast_charge(&self.used, self.limit, growth) {
            return Ok(guard);
        }

        // Sample `before` BEFORE `in_flight` (opposite of `reserve`'s `in_flight` -> `used`
        // order): any reservation whose `used` update landed before `before` is guaranteed
        // to be visible in `in_flight` (or already written to disk before the walk), and any
        // reservation whose `used` update lands after `before` is captured in `concurrent_delta`.
        let before = self.used.load(Ordering::Acquire);
        let other_in_flight = self
            .in_flight
            .load(Ordering::Acquire)
            .saturating_sub(growth);
        // Fail closed if the recount cannot establish every live file's size via
        // handle metadata so a transient host/SMB error can never undercount.
        let Ok(live_total) = subtree_size_recount(&self.root) else {
            return Err(enospc());
        };
        let real = live_total
            .saturating_sub(self.baseline())
            .saturating_add(other_in_flight);

        loop {
            let current = self.used.load(Ordering::Acquire);
            let concurrent_delta = current.saturating_sub(before);
            let adjusted = real.saturating_add(concurrent_delta);
            let next = if adjusted.saturating_add(growth) <= self.limit {
                adjusted.saturating_add(growth)
            } else {
                adjusted
            };
            if self
                .used
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return if adjusted.saturating_add(growth) <= self.limit {
                    Ok(guard)
                } else {
                    Err(enospc())
                };
            }
        }
    }

    /// Charge `growth` bytes without holding an active reservation guard.
    #[cfg(test)]
    pub(crate) fn charge(&self, growth: u64) -> io::Result<()> {
        self.reserve(growth).map(drop)
    }
}

/// Lock-free optimistic charge when `used + growth <= limit`. Never leaves `used`
/// transiently above `limit` on rejection.
fn try_fast_charge(used: &AtomicU64, limit: u64, growth: u64) -> bool {
    let mut current = used.load(Ordering::Acquire);
    loop {
        let Some(next) = current.checked_add(growth) else {
            return false;
        };
        if next > limit {
            return false;
        }
        match used.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Logical size of an open file by fd, or 0 if it cannot be stat'd.
#[cfg(unix)]
pub(crate) fn fd_size(fd: RawFd) -> u64 {
    platform::fstat(fd)
        .map(|st| st.st_size.max(0) as u64)
        .unwrap_or(0)
}

/// Logical size of an open file handle, or 0 if it cannot be stat'd.
#[cfg(windows)]
pub(crate) fn file_size(file: &File) -> u64 {
    file.metadata().map(|metadata| metadata.len()).unwrap_or(0)
}

/// Linux `ENOSPC` error for the guest FUSE ABI.
fn enospc() -> io::Error {
    #[cfg(unix)]
    {
        platform::enospc()
    }
    #[cfg(windows)]
    {
        io::Error::from_raw_os_error(28)
    }
}

/// Return a file's logical size, or sum every regular file beneath a directory.
///
/// Best-effort: unreadable directories and entries are skipped. Symlinks are
/// not followed, so the walk stays within the mount subtree.
fn subtree_size(root: &Path) -> u64 {
    let Ok(root_metadata) = std::fs::symlink_metadata(root) else {
        return 0;
    };
    if root_metadata.file_type().is_file() {
        return root_metadata.len();
    }
    if !root_metadata.file_type().is_dir() {
        return 0;
    }

    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if file_type.is_file() {
                let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                total = total.saturating_add(len);
            }
        }
    }
    total
}

/// Query the live logical size of a non-reparse regular file on Windows using an explicit
/// `FILE_READ_ATTRIBUTES` handle and `GetFileInformationByHandle`. Unlike `std::fs::symlink_metadata`,
/// this never silently falls back to stale `FindFirstFileW` directory-index data on sharing or
/// access errors.
#[cfg(windows)]
fn windows_live_file_size(path: &Path) -> io::Result<Option<u64>> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
    };

    let file = match OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` owns the live handle and `info` has the exact Win32 ABI layout.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
        return Ok(None);
    }
    let size = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
    Ok(Some(size))
}

/// Ground-truth subtree recount used only when an optimistic quota charge crosses
/// `limit`. On Windows NTFS, `DirEntry::metadata()` and `symlink_metadata()`'s fallback
/// path can return stale `WIN32_FIND_DATA` from the parent directory index, so query live
/// handle metadata directly and fail closed on non-`NotFound` I/O errors.
fn subtree_size_recount(root: &Path) -> io::Result<u64> {
    let root_metadata = match std::fs::symlink_metadata(root) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    if root_metadata.file_type().is_file() {
        #[cfg(windows)]
        return Ok(windows_live_file_size(root)?.unwrap_or(0));
        #[cfg(not(windows))]
        return Ok(root_metadata.len());
    }
    if !root_metadata.file_type().is_dir() {
        return Ok(0);
    }

    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if file_type.is_file() {
                #[cfg(windows)]
                let len = windows_live_file_size(&entry.path())?.unwrap_or(0);
                #[cfg(not(windows))]
                let len = match entry.metadata() {
                    Ok(m) => m.len(),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
                    Err(e) => return Err(e),
                };
                total = total.saturating_add(len);
            }
        }
    }
    Ok(total)
}

/// Build a `statvfs64` reply that reports the quota as the filesystem size.
///
/// Makes guest `df` reflect the mount's real constraint instead of the host
/// filesystem's much larger figures. Includes the baseline so that `df`'s
/// derived *used* (total − free) tracks what `du` reports, while *available*
/// stays the remaining guest budget:
///
/// - total     = `baseline + limit`
/// - available = `limit - used`
/// - used (df) = total − available = `baseline + used`
pub(crate) fn quota_statvfs(baseline: u64, limit: u64, used: u64) -> statvfs64 {
    let bsize = 4096u64;
    let total = baseline.saturating_add(limit);
    let free = limit.saturating_sub(used);
    let mut st: statvfs64 = unsafe { std::mem::zeroed() };

    #[cfg(target_os = "linux")]
    {
        st.f_bsize = bsize;
        st.f_frsize = bsize;
        st.f_blocks = total / bsize;
        st.f_bfree = free / bsize;
        st.f_bavail = free / bsize;
        st.f_namemax = 255;
    }

    #[cfg(target_os = "macos")]
    {
        st.f_bsize = bsize;
        st.f_frsize = bsize;
        st.f_blocks = (total / bsize) as _;
        st.f_bfree = (free / bsize) as _;
        st.f_bavail = (free / bsize) as _;
        st.f_namemax = 255;
    }

    #[cfg(windows)]
    {
        st.f_bsize = bsize;
        st.f_frsize = bsize;
        st.f_blocks = total / bsize;
        st.f_bfree = free / bsize;
        st.f_bavail = free / bsize;
        st.f_namemax = 255;
    }

    st
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charge_allows_up_to_limit() {
        let dir = tempfile::tempdir().unwrap();
        let q = DirQuota::new(dir.path().to_path_buf(), 1024);
        assert!(q.charge(512).is_ok());
        assert!(q.charge(512).is_ok());
        assert_eq!(q.used(), 1024);
    }

    #[test]
    fn charge_past_limit_is_enospc_when_real_growth_exceeds_limit() {
        let dir = tempfile::tempdir().unwrap();
        let q = DirQuota::new(dir.path().to_path_buf(), 1024);
        // The handlers force the baseline before the first guest write; mirror
        // that here so the about-to-be-written file is charged, not baselined.
        q.ensure_baseline();
        // Guest writes a real 1 KiB file (charge succeeds, then the write lands).
        assert!(q.charge(1024).is_ok());
        std::fs::write(dir.path().join("a"), vec![0u8; 1024]).unwrap();
        // A second 1 KiB write crosses the ceiling; the recount finds the real
        // 1 KiB already on disk and refuses the new growth.
        let err = q.charge(1024).unwrap_err();
        assert_eq!(err.raw_os_error(), enospc().raw_os_error());
    }

    #[test]
    fn baseline_files_are_not_charged() {
        let dir = tempfile::tempdir().unwrap();
        // A pre-existing 4 KiB file forms the baseline.
        std::fs::write(dir.path().join("preexisting"), vec![0u8; 4096]).unwrap();
        let q = DirQuota::new(dir.path().to_path_buf(), 1024);
        q.ensure_baseline();
        assert_eq!(q.baseline(), 4096);
        // The guest may still add up to the full quota beyond the baseline.
        assert!(q.charge(1024).is_ok());
    }

    #[test]
    fn baseline_is_captured_lazily_not_at_construction() {
        let dir = tempfile::tempdir().unwrap();
        let q = DirQuota::new(dir.path().to_path_buf(), 1024);
        // A file appearing after construction but before first access (e.g. a
        // host-written control file) counts as baseline, not guest usage.
        std::fs::write(dir.path().join("late"), vec![0u8; 800]).unwrap();
        q.ensure_baseline();
        assert_eq!(q.baseline(), 800);
    }

    #[test]
    fn durable_state_preserves_remaining_allowance() {
        let source_dir = tempfile::tempdir().unwrap();
        let source = DirQuota::new(source_dir.path().to_path_buf(), 1024);
        source.ensure_baseline();
        source.charge(640).unwrap();
        std::fs::write(source_dir.path().join("guest"), vec![0u8; 640]).unwrap();
        let state = source.capture_state();

        let destination_dir = tempfile::tempdir().unwrap();
        std::fs::write(destination_dir.path().join("guest"), vec![0u8; 640]).unwrap();
        let destination = DirQuota::new(destination_dir.path().to_path_buf(), 1024);
        destination.restore_state(&state).unwrap();
        assert_eq!(destination.capture_state(), state);
        assert!(destination.charge(384).is_ok());
        std::fs::write(destination_dir.path().join("guest"), vec![0u8; 1024]).unwrap();
        assert_eq!(destination.used(), 1024);
        assert_eq!(
            destination.charge(1).unwrap_err().raw_os_error(),
            enospc().raw_os_error()
        );
    }

    #[test]
    fn file_scope_ignores_siblings_in_the_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let selected = dir.path().join("selected");
        std::fs::write(&selected, b"base").unwrap();
        std::fs::write(dir.path().join("sibling"), vec![0u8; 8192]).unwrap();

        let q = DirQuota::new(selected, 1024);
        q.ensure_baseline();

        assert_eq!(q.baseline(), 4);
        assert!(q.charge(1024).is_ok());
    }

    #[test]
    fn recount_reclaims_drift_from_untracked_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let q = DirQuota::new(dir.path().to_path_buf(), 1024);
        // Simulate a churning writer: the optimistic counter drifts up to the
        // ceiling even though nothing is actually on disk.
        assert!(q.charge(1024).is_ok());
        // Next charge crosses the ceiling, triggers a recount, finds an empty
        // subtree, and succeeds — the budget did not get permanently stuck.
        assert!(q.charge(512).is_ok());
        assert_eq!(q.used(), 512);
    }

    #[test]
    fn zero_growth_is_free() {
        let dir = tempfile::tempdir().unwrap();
        let q = DirQuota::new(dir.path().to_path_buf(), 0);
        assert!(q.charge(0).is_ok());
    }

    #[test]
    fn recount_preserves_in_flight_reservations_before_write_lands() {
        let dir = tempfile::tempdir().unwrap();
        let q = DirQuota::new(dir.path().to_path_buf(), 1024);
        q.ensure_baseline();

        // Writer A reserves 800 bytes and has not written them to disk yet.
        let res_a = q.reserve(800).unwrap();
        // Writer B requests 500 bytes, triggering a recount while the directory is still empty.
        // Because Writer A's 800-byte reservation is in flight, 800 + 500 > 1024 must be rejected.
        let err = q.reserve(500).unwrap_err();
        assert_eq!(err.raw_os_error(), enospc().raw_os_error());
        // Writer B requesting 224 bytes (800 + 224 == 1024) still succeeds.
        let res_b = q.reserve(224).unwrap();
        drop(res_b);
        drop(res_a);
        // Once both reservations drop without writing, a recount reclaims the space.
        assert!(q.reserve(1024).is_ok());

        // Concurrent fast-path reservations racing with over-limit recounts never
        // grant combined active reservations past `limit`.
        let q = std::sync::Arc::new(DirQuota::new(dir.path().to_path_buf(), 1024));
        q.ensure_baseline();
        let active = std::sync::Arc::new(AtomicU64::new(0));
        let max_seen = std::sync::Arc::new(AtomicU64::new(0));
        let mut threads = Vec::new();
        for _ in 0..4 {
            let q = std::sync::Arc::clone(&q);
            let active = std::sync::Arc::clone(&active);
            let max_seen = std::sync::Arc::clone(&max_seen);
            threads.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    if let Ok(guard) = q.reserve(400) {
                        let now = active.fetch_add(400, Ordering::AcqRel) + 400;
                        max_seen.fetch_max(now, Ordering::AcqRel);
                        std::thread::yield_now();
                        active.fetch_sub(400, Ordering::AcqRel);
                        drop(guard);
                    }
                }
            }));
        }
        for t in threads {
            t.join().unwrap();
        }
        assert!(max_seen.load(Ordering::Acquire) <= 1024);
    }
}
