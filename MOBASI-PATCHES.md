# Mobasi patches

This branch is upstream `superradcompany/microsandbox` tag `v0.8.1`
(`e5934249a375f89d50f67c63b4393e4a6905c495`) plus the Windows `virtio-fs`
performance and resilience patches below. Version numbers do not change:
`msb --version` prints `0.8.1`.

The workflow `.github/workflows/mobasi-runtime.yml` builds the Windows
runtime archive `microsandbox-windows-x86_64.zip` from this branch and
publishes it as a release asset with its SHA-256 and `provenance.json`.

## Carried patches

### 1. libkrun: positional Win32 ReadFile/WriteFile with OVERLAPPED

- Source: `mobasi-ai/libkrun` branch `mobasi/win-positional-io`, rev
  `4eb6bff4c10e3af736e2af6f3123756a31f57b77` (based on upstream
  `77cad8a1b7d3c519fe12fd1e1e8dc6b2c5d383a3`).
- How: `[patch.crates-io]` in `Cargo.toml` points `msb_krun` and
  `msb_krun_utils` to that git rev. In `Cargo.lock`, only the 11
  `msb_krun*` crate source URLs change.
- Why: Upstream `libkrun` on Windows implements `virtio-fs` reads and
  writes with `File::try_clone()` + `seek()` + per-descriptor heap copy
  (~32 syscalls per 128 KiB request). Replacing that path with positional
  Win32 `ReadFile`/`WriteFile` using `OVERLAPPED` (with per-thread
  manual-reset completion event and thread-local staging for scattered
  slices) reduces I/O overhead to one Win32 call per FUSE request.
- Drop when: an upstream `microsandbox` release pins an `msb_krun`
  version containing this change.

### 2. microsandbox: eliminate Box::leak and snapshot cloning in streaming readdir and DualFS

- Branch: `mobasi/win-dir-leak-and-snapshot`
  (`fcde4383ccd2b8875c431aecd68c650192273391`).
- Why: Upstream `windows/ops.rs` leaks every directory entry name via
  `Box::leak` and clones the entire snapshot `Vec` on every paginated
  `readdir_for_each` chunk (O(N^2) memory and leak on directory walks).
  Uses `Arc<Vec<DirSnapshotEntry>>` + `partition_point` + borrowed
  slices in streaming callbacks and updates DualFS helpers to stream and
  always call `releasedir`.
- Drop when: merged upstream.

### 3. microsandbox: track dirty bit on open handles and flush DAX views safely

- Branch: `mobasi/win-dirty-flush`
  (`1a7c8f3bd2812e8958b85e2607b5b17031d46b25`).
- Why: Upstream calls `FlushFileBuffers` (`sync_data`) on every
  writable-handle `FUSE_FLUSH` even when no write or truncate occurred.
  Tracks per-handle `dirty: AtomicBool`, flushes writable DAX views via
  `FlushViewOfFile` before `FlushFileBuffers` and before unmap, and skips
  redundant `FlushFileBuffers` on clean handles.
- Drop when: merged upstream.

### 4. microsandbox: rate-limited numeric Win32 error logging on EIO/EBUSY

- Branch: `mobasi/win-host-error-logs`
  (`aa50937da1c75eeac1008f3d37b141e2303ab6d3`).
- Why: Upstream collapses unknown Win32 errors to Linux `EIO` without
  logging the host Win32 code. Adds a bounded, per-code, monotonic
  rate-limited warning log with the integer `win32_error` code on
  `LINUX_EIO` and `LINUX_EBUSY`.
- Drop when: merged upstream.

### 5. microsandbox: anchored single-handle verification, batched directory enumeration, and O(1) write length

- Branch: `mobasi/win-handle-lookup-and-readdir`
  (`44b56c342eaee09120c2f878731d76936c43224a`).
- Why: Upstream calls `safe_metadata` (O(depth) `CreateFileW` ancestor
  walk) on every `lookup`, `getattr`, `open`, `write`, and child during
  `readdir`. Replaces hot paths with mount-pinned `root_handle`, single
  `CreateFileW` + `GetFinalPathNameByHandleW` exact UTF-16 verification
  with anchored `NtCreateFile` fallback, 64 KiB batched
  `FileIdBothDirectoryInfo` enumeration (with `FileFullDirectoryInfo`
  fallback on the same handle), live handle-based `DirQuota` recounts
  with in-flight reservations, and open-handle `old_len` in `write`.
- Drop when: merged upstream.
