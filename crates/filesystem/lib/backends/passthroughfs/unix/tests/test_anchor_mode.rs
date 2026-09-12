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

//--------------------------------------------------------------------------------------------------
// Tests: alias bookkeeping
//--------------------------------------------------------------------------------------------------

/// In anchor mode a lookup records the (parent, name) alias on the inode.
#[test]
fn test_lookup_registers_alias_in_anchor_mode() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_dir("a");
    sb.host_create_file("a/f.txt", b"x");
    let a = sb.lookup_root("a").unwrap();
    let f = sb.lookup(a.inode, "f.txt").unwrap();

    let inodes = sb.fs.inodes.read().unwrap();
    let data = inodes.get(&f.inode).unwrap();
    assert_eq!(
        data.anchor_parent
            .load(std::sync::atomic::Ordering::Acquire),
        a.inode
    );
    assert_eq!(&*data.anchor_name.read().unwrap(), b"f.txt");
    assert_eq!(data.aliases.read().unwrap().len(), 1);
}

/// In volfs mode the alias table stays empty, so APFS behaviour is unchanged.
#[test]
fn test_lookup_records_no_alias_in_volfs_mode() {
    let sb = TestSandbox::new();
    sb.host_create_file("f.txt", b"x");
    let f = sb.lookup_root("f.txt").unwrap();
    let inodes = sb.fs.inodes.read().unwrap();
    let data = inodes.get(&f.inode).unwrap();
    assert_eq!(
        data.anchor_parent
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
    assert!(data.aliases.read().unwrap().is_empty());
}

//--------------------------------------------------------------------------------------------------
// Tests: reopen by anchor
//--------------------------------------------------------------------------------------------------

/// Read a nested file entirely through anchor resolution.
#[test]
fn test_anchor_read_nested_file() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_dir("a/b/c");
    sb.host_create_file("a/b/c/deep.txt", b"deep");
    let a = sb.lookup_root("a").unwrap();
    let b = sb.lookup(a.inode, "b").unwrap();
    let c = sb.lookup(b.inode, "c").unwrap();
    let f = sb.lookup(c.inode, "deep.txt").unwrap();
    let h = sb.fuse_open(f.inode, libc::O_RDONLY as u32).unwrap();
    assert_eq!(&sb.fuse_read(f.inode, h, 64, 0).unwrap()[..], b"deep");
}

/// getattr on a tracked inode reopens through the anchor walk.
#[test]
fn test_anchor_getattr_after_lookup() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_file("g.txt", b"12345");
    let g = sb.lookup_root("g.txt").unwrap();
    let (st, _) = sb.fs.getattr(sb.ctx(), g.inode, None).unwrap();
    assert_eq!(st.st_size, 5);
}

/// opendir + readdir on a nested directory through anchor resolution.
#[test]
fn test_anchor_readdir_nested() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_dir("d");
    sb.host_create_file("d/one", b"1");
    sb.host_create_file("d/two", b"2");
    let d = sb.lookup_root("d").unwrap();
    let h = sb.fuse_opendir(d.inode).unwrap();
    let entries = sb.fs.readdir(sb.ctx(), d.inode, h, 4096, 0).unwrap();
    let mut names: Vec<Vec<u8>> = entries.iter().map(|e| e.name.to_vec()).collect();
    names.sort();
    assert!(names.contains(&b"one".to_vec()));
    assert!(names.contains(&b"two".to_vec()));
}

/// A twelve-level path resolves; this is the deepest layout seen in a real
/// forensic case tree.
#[test]
fn test_anchor_twelve_levels() {
    let sb = TestSandbox::with_anchor_mode();
    let path = "l1/l2/l3/l4/l5/l6/l7/l8/l9/l10/l11";
    sb.host_create_dir(path);
    sb.host_create_file(&format!("{path}/leaf"), b"leaf");
    let mut parent = ROOT_INODE;
    for comp in path.split('/') {
        parent = sb.lookup(parent, comp).unwrap().inode;
    }
    let leaf = sb.lookup(parent, "leaf").unwrap();
    let h = sb.fuse_open(leaf.inode, libc::O_RDONLY as u32).unwrap();
    assert_eq!(&sb.fuse_read(leaf.inode, h, 16, 0).unwrap()[..], b"leaf");
}

/// If the host swaps a different file into the anchored name after lookup, the
/// reopen must fail closed (ENOENT) rather than serve the impostor.
#[test]
fn test_anchor_identity_mismatch_fails_closed() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_file("victim.txt", b"secret");
    let v = sb.lookup_root("victim.txt").unwrap();
    // Replace the directory entry with a different inode.
    std::fs::remove_file(sb.root.join("victim.txt")).unwrap();
    sb.host_create_file("victim.txt", b"impostor");
    let result = sb.fuse_open(v.inode, libc::O_RDONLY as u32);
    TestSandbox::assert_errno(result, LINUX_ENOENT);
}

/// A host-side symlink component in the anchor path is refused.
#[test]
fn test_anchor_refuses_symlink_component() {
    let sb = TestSandbox::with_anchor_mode();
    sb.host_create_dir("real");
    sb.host_create_file("real/f", b"f");
    let real = sb.lookup_root("real").unwrap();
    let f = sb.lookup(real.inode, "f").unwrap();
    // Swap the directory for a symlink to itself-under-another-name.
    std::fs::rename(sb.root.join("real"), sb.root.join("moved")).unwrap();
    std::os::unix::fs::symlink(sb.root.join("moved"), sb.root.join("real")).unwrap();
    let result = sb.fuse_open(f.inode, libc::O_RDONLY as u32);
    TestSandbox::assert_errno(result, LINUX_ENOENT);
}
