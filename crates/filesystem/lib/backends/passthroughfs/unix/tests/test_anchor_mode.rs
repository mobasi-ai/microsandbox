#![cfg(target_os = "macos")]

use super::*;

//--------------------------------------------------------------------------------------------------
// Tests: volfs probe
//--------------------------------------------------------------------------------------------------

/// A temp dir on the developer's APFS volume supports volfs, so a default
/// sandbox must report volfs support and not run in anchor mode.
#[test]
fn test_probe_reports_volfs_on_apfs_tempdir() {
    let sb = TestSandbox::new();
    assert!(!sb.fs.anchor_mode());
}

/// The forced helper flips the share into anchor mode.
#[test]
fn test_with_anchor_mode_forces_anchor_mode() {
    let sb = TestSandbox::with_anchor_mode();
    assert!(sb.fs.anchor_mode());
}

/// The probe itself: a real root fd probes true; a fabricated identity that
/// cannot exist on any mounted volume probes false.
#[test]
fn test_probe_volfs_support_direct() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = std::fs::File::open(tmp.path()).unwrap();
    assert!(probe_volfs_support(dir.as_raw_fd()));
    // dev 0 is never a mounted volume: open("/.vol/0/1") must fail.
    assert!(!probe_volfs_path(0, 1));
}
