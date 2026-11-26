//! Tests for the Windows passthrough backend.

use super::*;
use std::io::{Read, Seek, SeekFrom};
use std::os::windows::fs::FileExt;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct TempDir {
    path: PathBuf,
}

struct CaptureWriter {
    bytes: Vec<u8>,
}

struct SourceReader {
    bytes: Vec<u8>,
    pos: usize,
}

impl TempDir {
    fn new() -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!(
            "msb-windows-fs-test-{}-{unique}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

impl Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ZeroCopyWriter for CaptureWriter {
    fn write_from(&mut self, file: &File, count: usize, offset: u64) -> io::Result<usize> {
        let mut file = file.try_clone()?;
        file.seek(SeekFrom::Start(offset))?;
        let mut take = file.take(count as u64);
        take.read_to_end(&mut self.bytes)
    }
}

impl Read for SourceReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = buf.len().min(self.bytes.len().saturating_sub(self.pos));
        buf[..len].copy_from_slice(&self.bytes[self.pos..self.pos + len]);
        self.pos += len;
        Ok(len)
    }
}

impl ZeroCopyReader for SourceReader {
    fn read_to(&mut self, file: &File, count: usize, offset: u64) -> io::Result<usize> {
        let len = count.min(self.bytes.len().saturating_sub(self.pos));
        if len == 0 {
            return Ok(0);
        }

        let written = file.seek_write(&self.bytes[self.pos..self.pos + len], offset)?;
        self.pos += written;
        Ok(written)
    }
}

fn context() -> Context {
    Context {
        uid: 0,
        gid: 0,
        pid: 0,
    }
}

fn fs_for(path: &Path) -> PassthroughFs {
    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: path.to_path_buf(),
        inject_init: false,
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();
    fs
}

fn external_fs_for(path: &Path, relaxed: bool, remapped: bool) -> PassthroughFs {
    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: path.to_path_buf(),
        inject_init: false,
        stat_virtualization: StatVirtualization::Off,
        external_checkpoint: Some(super::super::ExternalCheckpointOptions {
            relaxed,
            remapped,
            ..Default::default()
        }),
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();
    fs
}

fn assert_ads_store(fs: &PassthroughFs) {
    let store = fs.stat_store.as_ref().expect("stat store enabled");
    assert!(matches!(
        store.backend,
        StatStoreBackend::AlternateDataStream
    ));
}

fn assert_override(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
    expected_rdev: u32,
) {
    let override_stat = read_override_stream(&ads_override_path(path)).unwrap();
    let uid = override_stat.uid;
    let gid = override_stat.gid;
    let mode = override_stat.mode;
    let rdev = override_stat.rdev;
    assert_eq!(uid, expected_uid);
    assert_eq!(gid, expected_gid);
    assert_eq!(mode, expected_mode);
    assert_eq!(rdev, expected_rdev);
}

fn expect_errno<T>(result: io::Result<T>, errno: i32) {
    match result {
        Ok(_) => panic!("expected errno {errno}"),
        Err(error) => assert_eq!(error.raw_os_error(), Some(errno)),
    }
}

#[test]
fn external_checkpoint_changed_file_requires_relaxed_and_retains_stale_ids() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), b"before").unwrap();
    let source = external_fs_for(&temp.path, false, false);
    let entry = source.lookup(context(), ROOT_INODE, c"data").unwrap();
    source.open(context(), entry.inode, false, 0).unwrap();
    let bytes = source.capture_state().unwrap();
    std::fs::write(temp.path.join("data"), b"after!").unwrap();

    let strict = external_fs_for(&temp.path, false, false);
    let untouched = strict.capture_state().unwrap();
    assert!(strict.restore_state(&bytes).is_err());
    assert_eq!(strict.capture_state().unwrap(), untouched);

    let relaxed = external_fs_for(&temp.path, true, false);
    relaxed.restore_state(&bytes).unwrap();
    assert_eq!(relaxed.request_error(entry.inode), Some(116));
    assert_eq!(relaxed.request_error(ROOT_INODE), None);
    assert!(relaxed.handles.read().unwrap().is_empty());
    let current = relaxed.lookup(context(), ROOT_INODE, c"data").unwrap();
    assert_ne!(current.inode, entry.inode);
    assert_eq!(relaxed.request_error(current.inode), None);
    assert_eq!(
        *relaxed
            .cfg
            .external_checkpoint
            .as_ref()
            .unwrap()
            .invalid_inodes
            .lock()
            .unwrap(),
        vec![entry.inode]
    );

    // A later checkpoint must not recycle an inode previously reported as stale.
    let second = relaxed.capture_state().unwrap();
    let next = external_fs_for(&temp.path, true, false);
    next.restore_state(&second).unwrap();
    assert_eq!(next.request_error(entry.inode), Some(116));
    assert_eq!(
        next.lookup(context(), ROOT_INODE, c"data").unwrap().inode,
        current.inode
    );
}

#[test]
fn external_checkpoint_remap_validates_content_and_requires_explicit_policy() {
    let source_dir = TempDir::new();
    let destination_dir = TempDir::new();
    std::fs::write(source_dir.path.join("data"), b"identical").unwrap();
    std::fs::write(destination_dir.path.join("data"), b"identical").unwrap();
    let source = external_fs_for(&source_dir.path, false, false);
    let entry = source.lookup(context(), ROOT_INODE, c"data").unwrap();
    let bytes = source.capture_state().unwrap();
    assert!(
        external_fs_for(&destination_dir.path, false, false)
            .restore_state(&bytes)
            .is_err()
    );
    let remapped = external_fs_for(&destination_dir.path, false, true);
    remapped.restore_state(&bytes).unwrap();
    assert_eq!(
        remapped
            .lookup(context(), ROOT_INODE, c"data")
            .unwrap()
            .inode,
        entry.inode
    );
    std::fs::write(destination_dir.path.join("data"), b"different").unwrap();
    assert!(remapped.restore_state(&bytes).is_err());
}

#[test]
fn external_checkpoint_refuses_replaced_live_file_handle() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), b"same").unwrap();
    let source = external_fs_for(&temp.path, false, false);
    let entry = source.lookup(context(), ROOT_INODE, c"data").unwrap();
    source.open(context(), entry.inode, false, 0).unwrap();
    std::fs::rename(temp.path.join("data"), temp.path.join("old-data")).unwrap();
    std::fs::write(temp.path.join("data"), b"same").unwrap();
    assert!(source.capture_state().is_err());
}

#[test]
fn unavailable_external_checkpoint_validates_bytes_and_always_returns_eio() {
    let temp = TempDir::new();
    let source = external_fs_for(&temp.path, false, false);
    let bytes = source.capture_state().unwrap();
    let unavailable = crate::UnavailableFs::default();
    unavailable.restore_state(&bytes).unwrap();
    assert_eq!(unavailable.request_error(ROOT_INODE), Some(5));
    assert_eq!(unavailable.request_error(123), Some(5));
    let relaxed = external_fs_for(&temp.path, true, false);
    assert!(relaxed.restore_state(&bytes[..bytes.len() - 1]).is_err());
    assert!(unavailable.restore_state(b"invalid").is_err());
    assert!(unavailable.capture_state().is_err());
}

#[test]
fn lists_and_reads_host_file() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("hello.txt"), b"hello from windows").unwrap();
    let fs = fs_for(&temp.path);

    let (handle, _) = fs
        .opendir(context(), ROOT_INODE, LINUX_O_DIRECTORY as u32)
        .unwrap();
    let entries = fs
        .readdirplus(context(), ROOT_INODE, handle.unwrap(), 4096, 0)
        .unwrap();
    assert!(entries.iter().any(|(entry, _)| entry.name == b"hello.txt"));

    let name = c"hello.txt";
    let entry = fs.lookup(context(), ROOT_INODE, name).unwrap();
    let (handle, _) = fs.open(context(), entry.inode, false, 0).unwrap();
    let mut writer = CaptureWriter { bytes: Vec::new() };
    fs.read(
        context(),
        entry.inode,
        handle.unwrap(),
        &mut writer,
        5,
        6,
        None,
        0,
    )
    .unwrap();
    assert_eq!(writer.bytes, b"from ");
}

#[test]
fn directory_listing_skips_host_junctions() {
    let temp = TempDir::new();
    let root = temp.path.join("root");
    let outside = temp.path.join("outside");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(root.join("hello.txt"), b"hello from windows").unwrap();
    std::fs::write(outside.join("secret.txt"), b"outside the mount").unwrap();

    // Junctions exercise the reparse-point guard without needing the symlink
    // privilege or Developer Mode, so this regression always runs in CI.
    let junction = root.join("junction");
    let output = Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&outside)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "mklink failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let fs = fs_for(&root);
    let (handle, _) = fs
        .opendir(context(), ROOT_INODE, LINUX_O_DIRECTORY as u32)
        .unwrap();
    let handle = handle.unwrap();
    let entries = fs
        .readdirplus(context(), ROOT_INODE, handle, 4096, 0)
        .unwrap();
    let names: Vec<_> = entries.iter().map(|(entry, _)| entry.name).collect();
    assert_eq!(names, [b".".as_slice(), b"..", b"hello.txt"]);

    // Filtering must leave usable continuation cookies and ordinary siblings.
    let file = &entries[2];
    assert_eq!(file.0.offset, 3);
    assert!(
        fs.readdirplus(context(), ROOT_INODE, handle, 4096, file.0.offset)
            .unwrap()
            .is_empty()
    );
    let entry = fs.lookup(context(), ROOT_INODE, c"hello.txt").unwrap();
    let (file_handle, _) = fs.open(context(), entry.inode, false, 0).unwrap();
    assert_eq!(
        owned_read(&fs, entry.inode, file_handle.unwrap()),
        b"hello from windows"
    );
    expect_errno(fs.lookup(context(), ROOT_INODE, c"junction"), LINUX_ELOOP);

    // A dangling junction must also be omitted without following its target.
    std::fs::remove_file(outside.join("secret.txt")).unwrap();
    std::fs::remove_dir(&outside).unwrap();
    let (handle, _) = fs
        .opendir(context(), ROOT_INODE, LINUX_O_DIRECTORY as u32)
        .unwrap();
    let entries = fs
        .readdir(context(), ROOT_INODE, handle.unwrap(), 4096, 0)
        .unwrap();
    let names: Vec<_> = entries.iter().map(|entry| entry.name).collect();
    assert_eq!(names, [b".".as_slice(), b"..", b"hello.txt"]);
    expect_errno(fs.lookup(context(), ROOT_INODE, c"junction"), LINUX_ELOOP);
}

#[test]
fn creates_writes_and_reads_file() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let flags = (LINUX_O_CREAT | LINUX_O_RDWR) as u32;
    let (entry, handle, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"created.txt",
            S_IFREG | 0o644,
            false,
            flags,
            0,
            Extensions::default(),
        )
        .unwrap();
    let handle = handle.unwrap();
    let mut reader = SourceReader {
        bytes: b"payload".to_vec(),
        pos: 0,
    };
    fs.write(
        context(),
        entry.inode,
        handle,
        &mut reader,
        7,
        0,
        None,
        false,
        false,
        0,
    )
    .unwrap();

    let mut writer = CaptureWriter { bytes: Vec::new() };
    fs.read(context(), entry.inode, handle, &mut writer, 7, 0, None, 0)
        .unwrap();
    assert_eq!(writer.bytes, b"payload");
}

#[test]
fn quota_rejects_growth_past_limit() {
    let temp = TempDir::new();
    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: temp.path.clone(),
        inject_init: false,
        quota_bytes: Some(4),
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();

    let flags = (LINUX_O_CREAT | LINUX_O_RDWR) as u32;
    let (entry, handle, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"quota.txt",
            S_IFREG | 0o644,
            false,
            flags,
            0,
            Extensions::default(),
        )
        .unwrap();
    let handle = handle.unwrap();

    let mut first = SourceReader {
        bytes: b"abcd".to_vec(),
        pos: 0,
    };
    fs.write(
        context(),
        entry.inode,
        handle,
        &mut first,
        4,
        0,
        None,
        false,
        false,
        0,
    )
    .unwrap();
    assert_eq!(fs.quota.as_ref().unwrap().used(), 4);

    let mut second = SourceReader {
        bytes: b"e".to_vec(),
        pos: 0,
    };
    expect_errno(
        fs.write(
            context(),
            entry.inode,
            handle,
            &mut second,
            1,
            4,
            None,
            false,
            false,
            0,
        ),
        LINUX_ENOSPC,
    );
}

#[test]
fn mobility_preserves_inode_file_handle_and_directory_cookie_state() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("alpha.txt"), b"alpha").unwrap();
    std::fs::write(temp.path.join("beta.txt"), b"beta").unwrap();
    let source = fs_for(&temp.path);

    let alpha = source.lookup(context(), ROOT_INODE, c"alpha.txt").unwrap();
    let beta = source.lookup(context(), ROOT_INODE, c"beta.txt").unwrap();
    let (file_handle, _) = source.open(context(), alpha.inode, false, 0).unwrap();
    let file_handle = file_handle.unwrap();
    let (dir_handle, _) = source
        .opendir(context(), ROOT_INODE, LINUX_O_DIRECTORY as u32)
        .unwrap();
    let dir_handle = dir_handle.unwrap();
    let entries = source
        .readdir(context(), ROOT_INODE, dir_handle, 4096, 0)
        .unwrap();
    let cookie = entries
        .iter()
        .find(|entry| entry.name == b"alpha.txt")
        .unwrap()
        .offset;
    let expected_tail = source
        .readdir(context(), ROOT_INODE, dir_handle, 4096, cookie)
        .unwrap()
        .into_iter()
        .map(|entry| (entry.ino, entry.offset, entry.name.to_vec()))
        .collect::<Vec<_>>();
    let next_inode = source.next_inode.load(Ordering::Acquire);
    let next_handle = source.next_handle.load(Ordering::Acquire);
    let state = source.capture_state().unwrap();

    let destination = fs_for(&temp.path);
    destination.restore_state(&state).unwrap();

    assert_eq!(
        destination
            .lookup(context(), ROOT_INODE, c"alpha.txt")
            .unwrap()
            .inode,
        alpha.inode
    );
    assert_eq!(
        destination
            .lookup(context(), ROOT_INODE, c"beta.txt")
            .unwrap()
            .inode,
        beta.inode
    );
    let mut writer = CaptureWriter { bytes: Vec::new() };
    destination
        .read(
            context(),
            alpha.inode,
            file_handle,
            &mut writer,
            5,
            0,
            None,
            0,
        )
        .unwrap();
    assert_eq!(writer.bytes, b"alpha");
    let restored_tail = destination
        .readdir(context(), ROOT_INODE, dir_handle, 4096, cookie)
        .unwrap()
        .into_iter()
        .map(|entry| (entry.ino, entry.offset, entry.name.to_vec()))
        .collect::<Vec<_>>();
    assert_eq!(restored_tail, expected_tail);
    assert_eq!(destination.next_inode.load(Ordering::Acquire), next_inode);
    assert_eq!(destination.next_handle.load(Ordering::Acquire), next_handle);
}

#[test]
fn mobility_missing_object_rejection_does_not_mutate_destination() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("source.txt"), b"source").unwrap();
    std::fs::write(temp.path.join("destination.txt"), b"destination").unwrap();
    let source = fs_for(&temp.path);
    let source_entry = source.lookup(context(), ROOT_INODE, c"source.txt").unwrap();
    let (source_handle, _) = source
        .open(context(), source_entry.inode, false, 0)
        .unwrap();
    assert!(source_handle.is_some());
    let state = source.capture_state().unwrap();

    let destination = fs_for(&temp.path);
    let destination_entry = destination
        .lookup(context(), ROOT_INODE, c"destination.txt")
        .unwrap();
    let (destination_handle, _) = destination
        .open(context(), destination_entry.inode, false, 0)
        .unwrap();
    assert!(destination_handle.is_some());
    let before = destination.capture_state().unwrap();
    drop(source);
    std::fs::remove_file(temp.path.join("source.txt")).unwrap();

    assert!(destination.restore_state(&state).is_err());

    assert_eq!(destination.capture_state().unwrap(), before);
    let mut writer = CaptureWriter { bytes: Vec::new() };
    destination
        .read(
            context(),
            destination_entry.inode,
            destination_handle.unwrap(),
            &mut writer,
            11,
            0,
            None,
            0,
        )
        .unwrap();
    assert_eq!(writer.bytes, b"destination");
}

#[test]
fn mobility_preserves_quota_accounting_and_open_handle() {
    let temp = TempDir::new();
    let config = PassthroughConfig {
        root_dir: temp.path.clone(),
        inject_init: false,
        quota_bytes: Some(8),
        ..Default::default()
    };
    let source = PassthroughFs::new(config.clone()).unwrap();
    source.init(FsOptions::empty()).unwrap();
    let (entry, handle, _) = source
        .create(
            context(),
            ROOT_INODE,
            c"quota.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let handle = handle.unwrap();
    let mut initial = SourceReader {
        bytes: b"abcd".to_vec(),
        pos: 0,
    };
    source
        .write(
            context(),
            entry.inode,
            handle,
            &mut initial,
            4,
            0,
            None,
            false,
            false,
            0,
        )
        .unwrap();
    let quota_state = source.quota.as_ref().unwrap().capture_state();
    let state = source.capture_state().unwrap();

    let destination = PassthroughFs::new(config).unwrap();
    destination.init(FsOptions::empty()).unwrap();
    destination.restore_state(&state).unwrap();

    assert_eq!(
        destination.quota.as_ref().unwrap().capture_state(),
        quota_state
    );
    let mut remaining = SourceReader {
        bytes: b"efgh".to_vec(),
        pos: 0,
    };
    destination
        .write(
            context(),
            entry.inode,
            handle,
            &mut remaining,
            4,
            4,
            None,
            false,
            false,
            0,
        )
        .unwrap();
    let mut over = SourceReader {
        bytes: b"i".to_vec(),
        pos: 0,
    };
    expect_errno(
        destination.write(
            context(),
            entry.inode,
            handle,
            &mut over,
            1,
            8,
            None,
            false,
            false,
            0,
        ),
        LINUX_ENOSPC,
    );
}

#[test]
fn rejects_malicious_components() {
    for name in [c"..", c".", c"a/b", c"a\\b", c"a:b", c".msb_override_stat"] {
        expect_errno(validate_component(name), LINUX_EPERM);
    }
}

#[test]
fn readonly_rejects_mutation() {
    let temp = TempDir::new();
    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: temp.path.clone(),
        readonly: true,
        inject_init: false,
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();

    expect_errno(
        fs.create(
            context(),
            ROOT_INODE,
            c"created.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        ),
        LINUX_EROFS,
    );
}

#[test]
fn directory_rename_preserves_cached_descendants() {
    for external in [true, false] {
        let temp = TempDir::new();
        std::fs::create_dir_all(temp.path.join("directory/nested")).unwrap();
        std::fs::write(temp.path.join("directory/nested/file"), b"child").unwrap();
        let fs = if external {
            external_fs_for(&temp.path, false, false)
        } else {
            fs_for(&temp.path)
        };
        let directory = fs.lookup(context(), ROOT_INODE, c"directory").unwrap();
        let nested = fs.lookup(context(), directory.inode, c"nested").unwrap();
        let file = fs.lookup(context(), nested.inode, c"file").unwrap();

        fs.rename(context(), ROOT_INODE, c"directory", ROOT_INODE, c"moved", 0)
            .unwrap();

        let (stat, _) = fs.getattr(context(), file.inode, None).unwrap();
        assert_eq!(stat.st_size, 5);
        let (handle, _) = fs.open(context(), file.inode, false, 0).unwrap();
        let handle = handle.unwrap();
        assert_eq!(owned_read(&fs, file.inode, handle), b"child");
        fs.release(context(), file.inode, 0, handle, false, false, None)
            .unwrap();
        let entries = fs.dir_entries(nested.inode).unwrap();
        assert!(entries.iter().any(|entry| entry.name == b"file"));
        assert_eq!(
            fs.lookup(context(), ROOT_INODE, c"moved").unwrap().inode,
            directory.inode
        );
        assert_eq!(
            fs.lookup(context(), directory.inode, c"nested")
                .unwrap()
                .inode,
            nested.inode
        );
        assert_eq!(
            fs.lookup(context(), nested.inode, c"file").unwrap().inode,
            file.inode
        );
        expect_errno(fs.lookup(context(), ROOT_INODE, c"directory"), LINUX_ENOENT);
    }
}

#[test]
fn host_side_rename_keeps_directory_listable() {
    // Renamed by the host (not through FUSE): same file identity, new name.
    let temp = TempDir::new();
    std::fs::create_dir_all(temp.path.join("sub")).unwrap();
    std::fs::write(temp.path.join("sub/a.txt"), b"a").unwrap();
    std::fs::write(temp.path.join("f.txt"), b"f").unwrap();
    let fs = fs_for(&temp.path);
    let sub = fs.lookup(context(), ROOT_INODE, c"sub").unwrap();
    fs.dir_entries(ROOT_INODE).unwrap();
    fs.dir_entries(sub.inode).unwrap();

    // Moved into another directory, then renamed in place.
    std::fs::rename(temp.path.join("f.txt"), temp.path.join("sub/g.txt")).unwrap();
    std::fs::rename(temp.path.join("sub/a.txt"), temp.path.join("sub/b.txt")).unwrap();

    let names: Vec<Vec<u8>> = fs
        .dir_entries(sub.inode)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert!(names.contains(&b"g.txt".to_vec()), "{names:?}");
    assert!(names.contains(&b"b.txt".to_vec()), "{names:?}");
    let g = fs.lookup(context(), sub.inode, c"g.txt").unwrap();
    let (stat, _) = fs.getattr(context(), g.inode, None).unwrap();
    assert_eq!(stat.st_size, 1);
    let (handle, _) = fs.open(context(), g.inode, false, 0).unwrap();
    let handle = handle.unwrap();
    assert_eq!(owned_read(&fs, g.inode, handle), b"f");
    fs.release(context(), g.inode, 0, handle, false, false, None)
        .unwrap();
    expect_errno(fs.lookup(context(), ROOT_INODE, c"f.txt"), LINUX_ENOENT);
}

#[test]
fn host_hard_link_keeps_both_names() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("a.txt"), b"a").unwrap();
    let fs = fs_for(&temp.path);
    let a = fs.lookup(context(), ROOT_INODE, c"a.txt").unwrap();
    std::fs::hard_link(temp.path.join("a.txt"), temp.path.join("b.txt")).unwrap();
    let b = fs.lookup(context(), ROOT_INODE, c"b.txt").unwrap();
    assert_eq!(a.inode, b.inode);
    let names: Vec<Vec<u8>> = fs
        .dir_entries(ROOT_INODE)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert!(names.contains(&b"a.txt".to_vec()) && names.contains(&b"b.txt".to_vec()));
    fs.getattr(context(), a.inode, None).unwrap();
}

#[test]
fn host_rename_of_cached_hard_link_keeps_alias_usable() {
    // Both names cached, then the canonical name is renamed on the host.
    let temp = TempDir::new();
    std::fs::write(temp.path.join("a.txt"), b"a").unwrap();
    std::fs::hard_link(temp.path.join("a.txt"), temp.path.join("b.txt")).unwrap();
    let fs = fs_for(&temp.path);
    let a = fs.lookup(context(), ROOT_INODE, c"a.txt").unwrap();
    let b = fs.lookup(context(), ROOT_INODE, c"b.txt").unwrap();
    assert_eq!(a.inode, b.inode);

    std::fs::rename(temp.path.join("a.txt"), temp.path.join("c.txt")).unwrap();

    // Through the cached alias first, then by listing (b.txt sorts before c.txt).
    let again = fs.lookup(context(), ROOT_INODE, c"b.txt").unwrap();
    assert_eq!(again.inode, a.inode);
    let (stat, _) = fs.getattr(context(), a.inode, None).unwrap();
    assert_eq!(stat.st_size, 1);
    let names: Vec<Vec<u8>> = fs
        .dir_entries(ROOT_INODE)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert!(names.contains(&b"b.txt".to_vec()), "{names:?}");
    assert!(names.contains(&b"c.txt".to_vec()), "{names:?}");
    expect_errno(fs.lookup(context(), ROOT_INODE, c"a.txt"), LINUX_ENOENT);
}

#[test]
fn host_rename_of_cached_hard_link_repairs_during_listing() {
    // Same, but the first access after the rename is a directory listing.
    let temp = TempDir::new();
    std::fs::write(temp.path.join("a.txt"), b"a").unwrap();
    std::fs::hard_link(temp.path.join("a.txt"), temp.path.join("b.txt")).unwrap();
    let fs = fs_for(&temp.path);
    fs.lookup(context(), ROOT_INODE, c"a.txt").unwrap();
    fs.lookup(context(), ROOT_INODE, c"b.txt").unwrap();

    std::fs::rename(temp.path.join("a.txt"), temp.path.join("c.txt")).unwrap();

    let names: Vec<Vec<u8>> = fs
        .dir_entries(ROOT_INODE)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert!(names.contains(&b"b.txt".to_vec()), "{names:?}");
    assert!(names.contains(&b"c.txt".to_vec()), "{names:?}");
}

#[test]
fn host_directory_rename_moves_cached_descendants() {
    // `dir/nested/file.txt` cached, then `dir` renamed on the host.
    let temp = TempDir::new();
    std::fs::create_dir_all(temp.path.join("dir/nested")).unwrap();
    std::fs::write(temp.path.join("dir/nested/file.txt"), b"abc").unwrap();
    let fs = fs_for(&temp.path);
    let dir = fs.lookup(context(), ROOT_INODE, c"dir").unwrap();
    let nested = fs.lookup(context(), dir.inode, c"nested").unwrap();
    let file = fs.lookup(context(), nested.inode, c"file.txt").unwrap();

    std::fs::rename(temp.path.join("dir"), temp.path.join("moved")).unwrap();

    let moved = fs.lookup(context(), ROOT_INODE, c"moved").unwrap();
    assert_eq!(moved.inode, dir.inode);
    // Cached descendants, used directly (no new lookup on them).
    let (stat, _) = fs.getattr(context(), file.inode, None).unwrap();
    assert_eq!(stat.st_size, 3);
    let (handle, _) = fs.open(context(), file.inode, false, 0).unwrap();
    let handle = handle.unwrap();
    assert_eq!(owned_read(&fs, file.inode, handle), b"abc");
    fs.release(context(), file.inode, 0, handle, false, false, None)
        .unwrap();
    let names: Vec<Vec<u8>> = fs
        .dir_entries(nested.inode)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert!(names.contains(&b"file.txt".to_vec()), "{names:?}");
    // Lookups under the new name return the cached inodes.
    let nested_again = fs.lookup(context(), moved.inode, c"nested").unwrap();
    assert_eq!(nested_again.inode, nested.inode);
    let file_again = fs.lookup(context(), nested.inode, c"file.txt").unwrap();
    assert_eq!(file_again.inode, file.inode);
    expect_errno(fs.lookup(context(), ROOT_INODE, c"dir"), LINUX_ENOENT);
}

#[test]
fn host_move_into_recreated_parent_path_repairs_once() {
    // Host: `dir` -> `temp`, new `dir`, `temp` -> `dir/moved`. The new
    // location lies beneath the old path: the repair must not apply twice.
    let temp = TempDir::new();
    std::fs::create_dir_all(temp.path.join("dir/nested")).unwrap();
    std::fs::write(temp.path.join("dir/nested/file.txt"), b"abc").unwrap();
    let fs = fs_for(&temp.path);
    let dir = fs.lookup(context(), ROOT_INODE, c"dir").unwrap();
    let nested = fs.lookup(context(), dir.inode, c"nested").unwrap();
    let file = fs.lookup(context(), nested.inode, c"file.txt").unwrap();

    std::fs::rename(temp.path.join("dir"), temp.path.join("temp")).unwrap();
    std::fs::create_dir(temp.path.join("dir")).unwrap();
    std::fs::rename(temp.path.join("temp"), temp.path.join("dir/moved")).unwrap();

    let moved = fs.lookup(context(), dir.inode, c"moved").unwrap();
    assert_eq!(moved.inode, dir.inode);
    // Repaired once: `…\dir\moved`, not `…\dir\moved\moved`.
    let tail = |inode: u64| {
        let path = fs.inode(inode).unwrap().path();
        let parts: Vec<String> = path
            .components()
            .rev()
            .take(4)
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        parts.into_iter().rev().collect::<Vec<_>>().join("/")
    };
    assert!(
        tail(dir.inode).ends_with("/dir/moved"),
        "{}",
        tail(dir.inode)
    );
    assert_eq!(tail(file.inode), "dir/moved/nested/file.txt");
    let names: Vec<Vec<u8>> = fs
        .dir_entries(moved.inode)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert!(names.contains(&b"nested".to_vec()), "{names:?}");
    let (stat, _) = fs.getattr(context(), file.inode, None).unwrap();
    assert_eq!(stat.st_size, 3);
    fs.getattr(context(), moved.inode, None).unwrap();
}

#[test]
fn host_move_up_to_former_parent_path_moves_children() {
    // Host: `parent/child` -> `temp`; guest removes the empty `parent`;
    // host: `temp` -> `parent`. The new location is an ancestor of the old.
    let temp = TempDir::new();
    std::fs::create_dir_all(temp.path.join("parent/child")).unwrap();
    std::fs::write(temp.path.join("parent/child/file.txt"), b"abc").unwrap();
    let fs = fs_for(&temp.path);
    let parent = fs.lookup(context(), ROOT_INODE, c"parent").unwrap();
    let child = fs.lookup(context(), parent.inode, c"child").unwrap();
    let file = fs.lookup(context(), child.inode, c"file.txt").unwrap();

    std::fs::rename(temp.path.join("parent/child"), temp.path.join("temp")).unwrap();
    fs.rmdir(context(), ROOT_INODE, c"parent").unwrap();
    std::fs::rename(temp.path.join("temp"), temp.path.join("parent")).unwrap();

    let moved = fs.lookup(context(), ROOT_INODE, c"parent").unwrap();
    assert_eq!(moved.inode, child.inode);
    let (stat, _) = fs.getattr(context(), file.inode, None).unwrap();
    assert_eq!(stat.st_size, 3);
    let (handle, _) = fs.open(context(), file.inode, false, 0).unwrap();
    let handle = handle.unwrap();
    assert_eq!(owned_read(&fs, file.inode, handle), b"abc");
    fs.release(context(), file.inode, 0, handle, false, false, None)
        .unwrap();
    let again = fs.lookup(context(), moved.inode, c"file.txt").unwrap();
    assert_eq!(again.inode, file.inode);
}

#[test]
fn host_move_up_keeps_aliases_of_repeated_directory_names() {
    // `p/c/f.txt` and `p/c/c/f.txt` cached; host moves `p/c` up to `p`.
    // `p/c/c/f.txt` lands on the key `p/c/f.txt` still held by the other file.
    let temp = TempDir::new();
    std::fs::create_dir_all(temp.path.join("p/c/c")).unwrap();
    std::fs::write(temp.path.join("p/c/f.txt"), b"outer").unwrap();
    std::fs::write(temp.path.join("p/c/c/f.txt"), b"inner!").unwrap();
    let fs = fs_for(&temp.path);
    let p = fs.lookup(context(), ROOT_INODE, c"p").unwrap();
    let c = fs.lookup(context(), p.inode, c"c").unwrap();
    let outer = fs.lookup(context(), c.inode, c"f.txt").unwrap();
    let cc = fs.lookup(context(), c.inode, c"c").unwrap();
    let inner = fs.lookup(context(), cc.inode, c"f.txt").unwrap();

    std::fs::rename(temp.path.join("p/c"), temp.path.join("temp")).unwrap();
    fs.rmdir(context(), ROOT_INODE, c"p").unwrap();
    std::fs::rename(temp.path.join("temp"), temp.path.join("p")).unwrap();
    let moved = fs.lookup(context(), ROOT_INODE, c"p").unwrap();
    assert_eq!(moved.inode, c.inode);

    // A later guest rename only follows aliases: both files must still have one.
    fs.rename(context(), ROOT_INODE, c"p", ROOT_INODE, c"q", 0)
        .unwrap();
    let (stat, _) = fs.getattr(context(), outer.inode, None).unwrap();
    assert_eq!(stat.st_size, 5);
    let (stat, _) = fs.getattr(context(), inner.inode, None).unwrap();
    assert_eq!(stat.st_size, 6);
    let (handle, _) = fs.open(context(), inner.inode, false, 0).unwrap();
    let handle = handle.unwrap();
    assert_eq!(owned_read(&fs, inner.inode, handle), b"inner!");
    fs.release(context(), inner.inode, 0, handle, false, false, None)
        .unwrap();
}

#[test]
fn host_rename_leaves_entries_of_the_new_occupant_in_place() {
    // Host: `dir` -> `moved`, then a new `dir` with `x.txt`. Before the repair
    // the guest reaches `x.txt` through the stale `dir` inode: that entry
    // belongs to the new `dir` and must not follow the move.
    let temp = TempDir::new();
    std::fs::create_dir(temp.path.join("dir")).unwrap();
    std::fs::write(temp.path.join("dir/a.txt"), b"a").unwrap();
    let fs = fs_for(&temp.path);
    let dir = fs.lookup(context(), ROOT_INODE, c"dir").unwrap();
    let a = fs.lookup(context(), dir.inode, c"a.txt").unwrap();

    std::fs::rename(temp.path.join("dir"), temp.path.join("moved")).unwrap();
    std::fs::create_dir(temp.path.join("dir")).unwrap();
    std::fs::write(temp.path.join("dir/x.txt"), b"xx").unwrap();
    let x = fs.lookup(context(), dir.inode, c"x.txt").unwrap();

    let moved = fs.lookup(context(), ROOT_INODE, c"moved").unwrap();
    assert_eq!(moved.inode, dir.inode);
    let (stat, _) = fs.getattr(context(), a.inode, None).unwrap();
    assert_eq!(stat.st_size, 1);
    let (stat, _) = fs.getattr(context(), x.inode, None).unwrap();
    assert_eq!(stat.st_size, 2);
    let new_dir = fs.lookup(context(), ROOT_INODE, c"dir").unwrap();
    assert_ne!(new_dir.inode, dir.inode);
    let x_again = fs.lookup(context(), new_dir.inode, c"x.txt").unwrap();
    assert_eq!(x_again.inode, x.inode);
}

#[test]
fn heartbeat_style_rename_keeps_source_inode_usable() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("heartbeat.json"), b"old").unwrap();
    std::fs::write(temp.path.join("heartbeat.tmp"), b"new").unwrap();
    let fs = fs_for(&temp.path);

    let source = fs.lookup(context(), ROOT_INODE, c"heartbeat.tmp").unwrap();
    fs.rename(
        context(),
        ROOT_INODE,
        c"heartbeat.tmp",
        ROOT_INODE,
        c"heartbeat.json",
        0,
    )
    .unwrap();

    let (handle, _) = fs.open(context(), source.inode, false, 0).unwrap();
    let mut writer = CaptureWriter { bytes: Vec::new() };
    fs.read(
        context(),
        source.inode,
        handle.unwrap(),
        &mut writer,
        3,
        0,
        None,
        0,
    )
    .unwrap();
    assert_eq!(writer.bytes, b"new");
}

#[test]
fn stat_virtualization_persists_across_backend_restart() {
    let temp = TempDir::new();
    {
        let fs = fs_for(&temp.path);
        assert_ads_store(&fs);
        let ctx = Context {
            uid: 1000,
            gid: 1001,
            pid: 0,
        };
        let (entry, _, _) = fs
            .create(
                ctx,
                ROOT_INODE,
                c"owned.txt",
                S_IFREG | 0o644,
                false,
                (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
                0,
                Extensions::default(),
            )
            .unwrap();
        let attr = stat64 {
            st_uid: 1234,
            st_gid: 5678,
            st_mode: S_IFREG | 0o640,
            ..Default::default()
        };
        fs.setattr(
            ctx,
            entry.inode,
            attr,
            None,
            SetattrValid::UID | SetattrValid::GID | SetattrValid::MODE,
        )
        .unwrap();
    }

    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"owned.txt").unwrap();
    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();
    assert_eq!(st.st_uid, 1234);
    assert_eq!(st.st_gid, 5678);
    assert_eq!(st.st_mode & 0o7777, 0o640);
    assert_eq!(st.st_mode & S_IFMT, S_IFREG);
}

#[test]
fn seeded_virtual_permissions_are_visible_after_backend_start() {
    let temp = TempDir::new();
    let script = temp.path.join("scripts").join("hello");
    std::fs::create_dir_all(script.parent().unwrap()).unwrap();
    std::fs::write(&script, b"#!/bin/sh\necho hello\n").unwrap();

    PassthroughFs::set_path_virtual_permissions(&temp.path, &script, 0, 0, 0o755).unwrap();

    let fs = fs_for(&temp.path);
    let dir = fs.lookup(context(), ROOT_INODE, c"scripts").unwrap();
    let entry = fs.lookup(context(), dir.inode, c"hello").unwrap();
    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();

    assert_eq!(st.st_mode & S_IFMT, S_IFREG);
    assert_eq!(st.st_mode & 0o7777, 0o755);
}

#[test]
fn host_files_without_override_are_executable() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("program"), b"\x7fELFbinary").unwrap();

    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"program").unwrap();
    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();

    // NTFS has no Unix exec bit, but a freshly bound host file must still be
    // runnable (e.g. binaries in a bind rootfs) before the guest chmods it.
    assert_eq!(st.st_mode & S_IFMT, S_IFREG);
    assert_eq!(st.st_mode & 0o7777, 0o777);
    assert_ne!(
        st.st_mode & 0o111,
        0,
        "host file should be executable by default"
    );

    // Root must pass an X_OK access check against the synthesized mode.
    check_access(context(), &st, LINUX_ACCESS_X_OK).unwrap();
}

#[test]
fn readonly_host_files_without_override_are_read_execute_only() {
    let temp = TempDir::new();
    let file = temp.path.join("locked");
    std::fs::write(&file, b"data").unwrap();
    let mut perms = std::fs::metadata(&file).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&file, perms).unwrap();

    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"locked").unwrap();
    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();

    assert_eq!(st.st_mode & S_IFMT, S_IFREG);
    assert_eq!(st.st_mode & 0o7777, 0o555);
}

#[test]
fn strict_uses_ads_and_does_not_create_sidecar() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    assert_ads_store(&fs);

    let ctx = Context {
        uid: 111,
        gid: 222,
        pid: 0,
    };
    let (entry, _, _) = fs
        .create(
            ctx,
            ROOT_INODE,
            c"ads.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let data = fs.inode(entry.inode).unwrap();

    assert!(!temp.path.join(FALLBACK_METADATA_DIR_NAME).exists());
    assert_override(&data.path(), 111, 222, S_IFREG | 0o644, 0);
}

#[test]
fn readonly_probes_do_not_create_metadata() {
    let temp = TempDir::new();
    let override_path = ads_override_path(&temp.path);
    let probe_path = ads_probe_path(&temp.path);

    for policy in [StatVirtualization::Strict, StatVirtualization::Relaxed] {
        let fs = PassthroughFs::new(PassthroughConfig {
            root_dir: temp.path.clone(),
            inject_init: false,
            readonly: true,
            stat_virtualization: policy,
            ..Default::default()
        })
        .unwrap();

        assert_ads_store(&fs);
    }

    for path in [override_path, probe_path] {
        assert_eq!(
            std::fs::metadata(path).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
    assert!(!temp.path.join(FALLBACK_METADATA_DIR_NAME).exists());
}

#[test]
fn readonly_relaxed_probe_preserves_mount_root_override() {
    let temp = TempDir::new();
    write_override_stream(
        &ads_override_path(&temp.path),
        OverrideStat::new(1234, 2345, S_IFDIR | 0o1755, 0),
    )
    .unwrap();

    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: temp.path.clone(),
        inject_init: false,
        readonly: true,
        stat_virtualization: StatVirtualization::Relaxed,
        ..Default::default()
    })
    .unwrap();

    assert_ads_store(&fs);
    assert_override(&temp.path, 1234, 2345, S_IFDIR | 0o1755, 0);
    assert_eq!(
        std::fs::metadata(ads_probe_path(&temp.path))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
    assert!(!temp.path.join(FALLBACK_METADATA_DIR_NAME).exists());
}

#[test]
fn writable_probe_preserves_mount_root_override() {
    let temp = TempDir::new();
    write_override_stream(
        &ads_override_path(&temp.path),
        OverrideStat::new(1234, 2345, S_IFDIR | 0o1755, 0),
    )
    .unwrap();

    let fs = fs_for(&temp.path);
    assert_ads_store(&fs);

    assert_override(&temp.path, 1234, 2345, S_IFDIR | 0o1755, 0);
    assert_eq!(
        std::fs::metadata(ads_probe_path(&temp.path))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn ads_stat_virtualization_persists_for_directories() {
    let temp = TempDir::new();
    {
        let fs = fs_for(&temp.path);
        assert_ads_store(&fs);
        let ctx = Context {
            uid: 321,
            gid: 654,
            pid: 0,
        };
        let entry = fs
            .mkdir(
                ctx,
                ROOT_INODE,
                c"dir",
                S_IFDIR | 0o750,
                0,
                Extensions::default(),
            )
            .unwrap();
        let attr = stat64 {
            st_uid: 333,
            st_gid: 444,
            st_mode: S_IFDIR | 0o710,
            ..Default::default()
        };
        fs.setattr(
            ctx,
            entry.inode,
            attr,
            None,
            SetattrValid::UID | SetattrValid::GID | SetattrValid::MODE,
        )
        .unwrap();
    }

    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"dir").unwrap();
    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();
    assert_eq!(st.st_uid, 333);
    assert_eq!(st.st_gid, 444);
    assert_eq!(st.st_mode & S_IFMT, S_IFDIR);
    assert_eq!(st.st_mode & 0o7777, 0o710);
}

#[test]
fn ads_metadata_follows_rename_without_sidecar_move() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    assert_ads_store(&fs);

    let (entry, _, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"old.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let old_data = fs.inode(entry.inode).unwrap();
    let old_path = old_data.path();
    let attr = stat64 {
        st_uid: 700,
        st_gid: 701,
        st_mode: S_IFREG | 0o600,
        ..Default::default()
    };
    fs.setattr(
        context(),
        entry.inode,
        attr,
        None,
        SetattrValid::UID | SetattrValid::GID | SetattrValid::MODE,
    )
    .unwrap();

    fs.rename(context(), ROOT_INODE, c"old.txt", ROOT_INODE, c"new.txt", 0)
        .unwrap();

    expect_errno(
        read_override_stream(&ads_override_path(&old_path)),
        LINUX_ENOENT,
    );
    let renamed = fs.lookup(context(), ROOT_INODE, c"new.txt").unwrap();
    let data = fs.inode(renamed.inode).unwrap();
    assert_override(&data.path(), 700, 701, S_IFREG | 0o600, 0);
    let (st, _) = fs.getattr(context(), renamed.inode, None).unwrap();
    assert_eq!(st.st_uid, 700);
    assert_eq!(st.st_gid, 701);
    assert_eq!(st.st_mode & 0o7777, 0o600);
}

#[test]
fn metadata_store_is_hidden_from_guest_namespace() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    assert!(!temp.path.join(FALLBACK_METADATA_DIR_NAME).exists());
    std::fs::create_dir(temp.path.join(FALLBACK_METADATA_DIR_NAME)).unwrap();

    let (handle, _) = fs
        .opendir(context(), ROOT_INODE, LINUX_O_DIRECTORY as u32)
        .unwrap();
    let entries = fs
        .readdirplus(context(), ROOT_INODE, handle.unwrap(), 4096, 0)
        .unwrap();
    assert!(
        !entries
            .iter()
            .any(|(entry, _)| entry.name == FALLBACK_METADATA_DIR_NAME.as_bytes())
    );
    expect_errno(
        fs.lookup(context(), ROOT_INODE, c".msb_override_stat"),
        LINUX_EPERM,
    );
}

#[test]
fn corrupt_stat_metadata_fails_closed() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let (entry, _, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"corrupt.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let data = fs.inode(entry.inode).unwrap();
    let override_path = fs
        .stat_store
        .as_ref()
        .unwrap()
        .override_file_path(&data.path())
        .unwrap();
    std::fs::write(override_path, b"bad").unwrap();

    expect_errno(fs.lookup(context(), ROOT_INODE, c"corrupt.txt"), LINUX_EIO);
}

#[test]
fn ads_metadata_does_not_survive_host_delete_and_recreate() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let entry = fs
        .symlink(
            context(),
            c"target.txt",
            ROOT_INODE,
            c"reused",
            Extensions::default(),
        )
        .unwrap();
    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();
    assert_eq!(st.st_mode & S_IFMT, S_IFLNK);

    std::fs::remove_file(temp.path.join("reused")).unwrap();
    std::fs::write(temp.path.join("reused"), b"plain").unwrap();

    let replacement = fs.lookup(context(), ROOT_INODE, c"reused").unwrap();
    let (st, _) = fs.getattr(context(), replacement.inode, None).unwrap();
    assert_eq!(st.st_mode & S_IFMT, S_IFREG);
    expect_errno(fs.readlink(context(), replacement.inode), LINUX_EINVAL);
}

#[test]
fn ads_regular_metadata_does_not_survive_host_delete_and_recreate() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let (entry, _, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"reused.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let attr = stat64 {
        st_uid: 4321,
        st_gid: 8765,
        st_mode: S_IFREG | 0o600,
        ..Default::default()
    };
    fs.setattr(
        context(),
        entry.inode,
        attr,
        None,
        SetattrValid::UID | SetattrValid::GID | SetattrValid::MODE,
    )
    .unwrap();

    std::fs::remove_file(temp.path.join("reused.txt")).unwrap();
    std::fs::write(temp.path.join("reused.txt"), b"replacement").unwrap();

    let replacement = fs.lookup(context(), ROOT_INODE, c"reused.txt").unwrap();
    let (st, _) = fs.getattr(context(), replacement.inode, None).unwrap();
    assert_ne!(st.st_uid, 4321);
    assert_ne!(st.st_gid, 8765);
    assert_ne!(st.st_mode & 0o7777, 0o600);
    assert_eq!(st.st_mode & S_IFMT, S_IFREG);
}

#[test]
fn unlink_removes_ads_metadata_with_file() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let (entry, _, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"gone.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let data = fs.inode(entry.inode).unwrap();
    assert_override(&data.path(), 0, 0, S_IFREG | 0o644, 0);
    let ads_path = ads_override_path(&data.path());

    fs.unlink(context(), ROOT_INODE, c"gone.txt").unwrap();

    expect_errno(read_override_stream(&ads_path), LINUX_ENOENT);
    std::fs::write(temp.path.join("gone.txt"), b"new").unwrap();
    let replacement = fs.lookup(context(), ROOT_INODE, c"gone.txt").unwrap();
    let (st, _) = fs.getattr(context(), replacement.inode, None).unwrap();
    assert_eq!(st.st_mode & S_IFMT, S_IFREG);
    assert_eq!(st.st_uid, 0);
    assert_eq!(st.st_gid, 0);
}

#[test]
fn sidecar_fallback_renames_and_removes_metadata() {
    let temp = TempDir::new();
    let root = std::fs::canonicalize(&temp.path).unwrap();
    std::fs::create_dir(root.join("sub")).unwrap();
    let store = StatStore::sidecar(&root);
    store.probe().unwrap();

    let old_path = root.join("old.txt");
    let new_path = root.join("sub").join("new.txt");
    store.write(&old_path, 12, 34, S_IFREG | 0o640, 0).unwrap();
    store.rename(&old_path, &new_path).unwrap();

    assert!(store.read(&old_path).unwrap().is_none());
    let override_stat = store.read(&new_path).unwrap().unwrap();
    let uid = override_stat.uid;
    let gid = override_stat.gid;
    let mode = override_stat.mode;
    assert_eq!(uid, 12);
    assert_eq!(gid, 34);
    assert_eq!(mode, S_IFREG | 0o640);

    store.remove(&new_path).unwrap();
    assert!(store.read(&new_path).unwrap().is_none());
}

#[test]
fn symlink_is_file_backed_and_readlink_checks_virtual_type() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let ctx = Context {
        uid: 42,
        gid: 43,
        pid: 0,
    };
    let entry = fs
        .symlink(
            ctx,
            c"target.txt",
            ROOT_INODE,
            c"link",
            Extensions::default(),
        )
        .unwrap();
    let target = fs.readlink(context(), entry.inode).unwrap();
    assert_eq!(target, b"target.txt");

    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();
    assert_eq!(st.st_uid, 42);
    assert_eq!(st.st_gid, 43);
    assert_eq!(st.st_mode & S_IFMT, S_IFLNK);
    assert!(std::fs::metadata(temp.path.join("link")).unwrap().is_file());

    let (file_entry, _, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"regular.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    expect_errno(fs.readlink(context(), file_entry.inode), LINUX_EINVAL);
}

#[test]
fn mknod_virtualizes_special_type() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let entry = fs
        .mknod(
            context(),
            ROOT_INODE,
            c"pipe",
            S_IFIFO | 0o600,
            0,
            0,
            Extensions::default(),
        )
        .unwrap();
    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();
    assert_eq!(st.st_mode & S_IFMT, S_IFIFO);
    assert!(std::fs::metadata(temp.path.join("pipe")).unwrap().is_file());

    let (handle, _) = fs
        .opendir(context(), ROOT_INODE, LINUX_O_DIRECTORY as u32)
        .unwrap();
    let entries = fs
        .readdirplus(context(), ROOT_INODE, handle.unwrap(), 4096, 0)
        .unwrap();
    let (dir_entry, _) = entries
        .iter()
        .find(|(dir_entry, _)| dir_entry.name == b"pipe")
        .unwrap();
    assert_eq!(dir_entry.type_, DT_FIFO);
}

#[test]
fn access_uses_virtualized_owner_and_mode() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let owner = Context {
        uid: 1000,
        gid: 1000,
        pid: 0,
    };
    let other = Context {
        uid: 2000,
        gid: 2000,
        pid: 0,
    };
    let (entry, _, _) = fs
        .create(
            owner,
            ROOT_INODE,
            c"private.txt",
            S_IFREG | 0o600,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();

    fs.access(owner, entry.inode, LINUX_ACCESS_R_OK).unwrap();
    expect_errno(
        fs.access(other, entry.inode, LINUX_ACCESS_R_OK),
        LINUX_EACCES,
    );
}

#[test]
fn setattr_updates_mtime() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let (entry, _, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"times.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let attr = stat64 {
        st_atime: 1_700_000_000,
        st_atime_nsec: 123_000_000,
        st_mtime: 1_700_000_123,
        st_mtime_nsec: 456_000_000,
        ..Default::default()
    };
    fs.setattr(
        context(),
        entry.inode,
        attr,
        None,
        SetattrValid::ATIME | SetattrValid::MTIME,
    )
    .unwrap();

    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();
    assert_eq!(st.st_mtime, attr.st_mtime);
}

#[test]
fn write_killpriv_clears_virtual_suid_sgid() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let flags = (LINUX_O_CREAT | LINUX_O_RDWR) as u32;
    let (entry, handle, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"suid.txt",
            S_IFREG | S_ISUID | S_ISGID | 0o755,
            false,
            flags,
            0,
            Extensions::default(),
        )
        .unwrap();

    let mut reader = SourceReader {
        bytes: b"x".to_vec(),
        pos: 0,
    };
    fs.write(
        context(),
        entry.inode,
        handle.unwrap(),
        &mut reader,
        1,
        0,
        None,
        false,
        true,
        0,
    )
    .unwrap();

    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();
    assert_eq!(st.st_mode & (S_ISUID | S_ISGID), 0);
}

//--------------------------------------------------------------------------------------------------
// Tests: mount-root containment (no_symlink_root)
//--------------------------------------------------------------------------------------------------

/// Build a two-tenant layout under a canonical (reparse-free) base:
/// `<base>/vol/tenant-a` and `<base>/vol/tenant-b`, with a secret in tenant-b.
fn two_tenant_layout(temp: &TempDir) -> (PathBuf, PathBuf, PathBuf) {
    // Canonicalize so no redirected system folder trips the no-reparse walk;
    // the control plane owns this step.
    let base = std::fs::canonicalize(&temp.path).unwrap();
    let tenant_a = base.join("vol").join("tenant-a");
    let tenant_b = base.join("vol").join("tenant-b");
    std::fs::create_dir_all(&tenant_a).unwrap();
    std::fs::create_dir_all(&tenant_b).unwrap();
    std::fs::write(tenant_b.join("secret.txt"), b"tenant-b private data").unwrap();
    (base, tenant_a, tenant_b)
}

fn build_no_symlink(root_dir: PathBuf) -> io::Result<PassthroughFs> {
    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir,
        no_symlink_root: true,
        stat_virtualization: StatVirtualization::Off,
        inject_init: false,
        ..Default::default()
    })?;
    fs.init(FsOptions::empty())?;
    Ok(fs)
}

/// Legacy behavior: `canonicalize` follows a junction/symlink root out to the
/// sibling tenant, exposing its files. Documents the escape the flag closes.
#[test]
fn legacy_symlink_root_is_followed() {
    let temp = TempDir::new();
    let (_base, tenant_a, tenant_b) = two_tenant_layout(&temp);

    let evil = tenant_a.join("evil");
    if std::os::windows::fs::symlink_dir(&tenant_b, &evil).is_err() {
        eprintln!("skip: cannot create directory symlink (privilege/Developer Mode)");
        return;
    }

    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: evil,
        no_symlink_root: false,
        stat_virtualization: StatVirtualization::Off,
        inject_init: false,
        ..Default::default()
    })
    .expect("legacy path follows the symlink silently");
    fs.init(FsOptions::empty()).unwrap();

    assert!(
        fs.lookup(context(), ROOT_INODE, c"secret.txt").is_ok(),
        "guest reached tenant-b's secret.txt through the mount (escape)"
    );
}

/// A junction/symlink as the mount root is refused — never followed.
#[test]
fn no_symlink_root_rejects_symlink_root() {
    let temp = TempDir::new();
    let (_base, tenant_a, tenant_b) = two_tenant_layout(&temp);

    let evil = tenant_a.join("evil");
    if std::os::windows::fs::symlink_dir(&tenant_b, &evil).is_err() {
        eprintln!("skip: cannot create directory symlink (privilege/Developer Mode)");
        return;
    }

    let result = build_no_symlink(evil);
    assert!(result.is_err(), "symlink root must be refused");
    assert_eq!(
        result.err().and_then(|e| e.raw_os_error()),
        Some(LINUX_ELOOP)
    );
}

/// A reparse point in a NON-tenant prefix is refused too — nothing is trusted.
#[test]
fn no_symlink_root_rejects_symlinked_prefix() {
    let temp = TempDir::new();
    let (base, _tenant_a, _tenant_b) = two_tenant_layout(&temp);

    let real = base.join("real-mnt");
    std::fs::create_dir_all(real.join("work")).unwrap();
    let linked_prefix = base.join("linked-mnt");
    if std::os::windows::fs::symlink_dir(&real, &linked_prefix).is_err() {
        eprintln!("skip: cannot create directory symlink (privilege/Developer Mode)");
        return;
    }

    let result = build_no_symlink(linked_prefix.join("work"));
    assert!(
        result.is_err(),
        "a symlinked prefix component must be refused"
    );
    assert_eq!(
        result.err().and_then(|e| e.raw_os_error()),
        Some(LINUX_ELOOP)
    );

    // The same real path with no reparse component mounts fine.
    build_no_symlink(real.join("work")).expect("real path should mount");
}

/// A `..` segment is refused even though it crosses no reparse point.
#[test]
fn no_symlink_root_rejects_dotdot() {
    let temp = TempDir::new();
    let (_base, tenant_a, _tenant_b) = two_tenant_layout(&temp);

    // Build the `..` path from a RAW STRING. `PathBuf::join("..")` collapses the
    // `..` at construction on Windows (especially verbatim `\\?\` paths), so it
    // would never reach the resolver; a string preserves the literal segment,
    // which is exactly what a caller that concatenates an untrusted subpath
    // would produce.
    let escaping = PathBuf::from(format!("{}\\..\\tenant-b", tenant_a.display()));
    let result = build_no_symlink(escaping);
    assert_eq!(
        result.err().and_then(|e| e.raw_os_error()),
        Some(LINUX_EINVAL)
    );
}

// Relative paths resolve from the working directory (still no reparse point
// followed), so relative bind mounts keep working under the protective default.
// Covered end-to-end at the app level rather than here to avoid a unit test
// mutating the shared process working directory.

/// A legitimate real subdirectory mounts and the guest sees its own files.
#[test]
fn no_symlink_root_allows_real_subdir() {
    let temp = TempDir::new();
    let (_base, tenant_a, _tenant_b) = two_tenant_layout(&temp);
    let work = tenant_a.join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("hello.txt"), b"tenant-a data").unwrap();

    let fs = build_no_symlink(work).expect("real subdir should mount");
    fs.lookup(context(), ROOT_INODE, c"hello.txt")
        .expect("guest should see its own file");
}

/// A deep chain of real directories is allowed — the resolver rejects reparse
/// points, not depth.
#[test]
fn no_symlink_root_allows_deep_real_path() {
    let temp = TempDir::new();
    let (_base, tenant_a, _tenant_b) = two_tenant_layout(&temp);
    let deep = tenant_a.join("a").join("b").join("c");
    std::fs::create_dir_all(&deep).unwrap();

    build_no_symlink(deep).expect("deep real path should mount");
}

#[test]
fn no_override_falls_back_to_configured_default_owner() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("hostfile.txt"), b"host-created").unwrap();

    // A host-created file has no override stored; with default_owner set it is
    // presented as that owner instead of the raw 0:0.
    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: temp.path.clone(),
        inject_init: false,
        default_owner: Some((1000, 1000)),
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();

    let entry = fs.lookup(context(), ROOT_INODE, c"hostfile.txt").unwrap();
    assert_eq!(entry.attr.st_uid, 1000);
    assert_eq!(entry.attr.st_gid, 1000);

    // Without default_owner the same host file falls back to 0:0.
    let plain = fs_for(&temp.path);
    let entry = plain
        .lookup(context(), ROOT_INODE, c"hostfile.txt")
        .unwrap();
    assert_eq!(entry.attr.st_uid, 0);
    assert_eq!(entry.attr.st_gid, 0);
}

#[test]
fn default_owner_rejected_when_stat_virtualization_is_off() {
    let cfg = PassthroughConfig {
        root_dir: PathBuf::from(r"Z:\this-path-must-not-be-resolved"),
        stat_virtualization: StatVirtualization::Off,
        default_owner: Some((1000, 1000)),
        ..Default::default()
    };

    // EINVAL proves validation happens before root resolution, which would
    // otherwise return a host path-not-found error for this sentinel path.
    let err = match PassthroughFs::new(cfg) {
        Ok(_) => panic!("default owner with stat virtualization off must fail"),
        Err(err) => err,
    };
    assert_eq!(err.raw_os_error(), Some(LINUX_EINVAL));
}

#[test]
fn setattr_preserves_default_owner_for_host_created_file() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("hostfile.txt"), b"host-created").unwrap();

    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: temp.path.clone(),
        inject_init: false,
        default_owner: Some((1000, 1000)),
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();

    let entry = fs.lookup(context(), ROOT_INODE, c"hostfile.txt").unwrap();

    // The guest changes only the mode (chmod, no chown). The mutation baseline
    // must seed the configured default owner rather than 0:0, so the file does
    // not silently become root-owned after the metadata write.
    let attr = stat64 {
        st_mode: S_IFREG | 0o640,
        ..Default::default()
    };
    fs.setattr(context(), entry.inode, attr, None, SetattrValid::MODE)
        .unwrap();

    let (st, _) = fs.getattr(context(), entry.inode, None).unwrap();
    assert_eq!(st.st_uid, 1000);
    assert_eq!(st.st_gid, 1000);
    assert_eq!(st.st_mode & 0o7777, 0o640);
}

fn owned_fs_for(path: &Path, checkpoint: crate::OwnedDirectoryCheckpoint) -> PassthroughFs {
    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: path.into(),
        inject_init: false,
        owned_checkpoint: Some(checkpoint),
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();
    fs
}

fn owned_read(fs: &PassthroughFs, inode: u64, handle: u64) -> Vec<u8> {
    let mut output = CaptureWriter { bytes: Vec::new() };
    fs.read(context(), inode, handle, &mut output, 4096, 0, None, 0)
        .unwrap();
    output.bytes
}

fn owned_write(fs: &PassthroughFs, inode: u64, handle: u64, bytes: &[u8]) {
    let mut input = SourceReader {
        bytes: bytes.to_vec(),
        pos: 0,
    };
    assert_eq!(
        fs.write(
            context(),
            inode,
            handle,
            &mut input,
            bytes.len() as u32,
            0,
            None,
            false,
            false,
            0
        )
        .unwrap(),
        bytes.len()
    );
}

#[test]
fn owned_detached_roundtrip_keeps_handle_metadata_and_private_generations() {
    let temp = TempDir::new();
    let root = temp.path.join("source");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("file"), b"before").unwrap();
    std::fs::write(root.join("never-looked-up"), b"whole namespace").unwrap();
    let checkpoint = crate::OwnedDirectoryCheckpoint::default();
    let source = owned_fs_for(&root, checkpoint.clone());
    let inode = source.lookup(context(), ROOT_INODE, c"file").unwrap().inode;
    let handle = source
        .open(context(), inode, false, LINUX_O_RDWR as u32)
        .unwrap()
        .0
        .unwrap();
    source
        .setattr(
            context(),
            inode,
            stat64 {
                st_uid: 1234,
                st_gid: 2345,
                st_mode: 0o640,
                ..Default::default()
            },
            None,
            SetattrValid::UID | SetattrValid::GID | SetattrValid::MODE,
        )
        .unwrap();
    source.unlink(context(), ROOT_INODE, c"file").unwrap();
    owned_write(&source, inode, handle, b"after!");
    std::fs::write(root.join("file"), b"replacement").unwrap();
    assert_eq!(
        source.getattr(context(), inode, None).unwrap().0.st_uid,
        1234
    );
    let reopened = source.open(context(), inode, false, 0).unwrap().0.unwrap();
    assert_eq!(owned_read(&source, inode, reopened), b"after!");
    let generation = temp.path.join("generation");
    checkpoint.prepare_capture(&generation).unwrap();
    let state = source.capture_state().unwrap();
    let snapshot = checkpoint.finish_capture().unwrap();
    drop(source);
    std::fs::remove_dir_all(&root).unwrap();

    let child = temp.path.join("child");
    snapshot.materialize(&generation, &child).unwrap();
    let restored_checkpoint = crate::OwnedDirectoryCheckpoint::default();
    restored_checkpoint.set_restore(&generation).unwrap();
    let destination = owned_fs_for(&child, restored_checkpoint.clone());
    destination.restore_state(&state).unwrap();
    assert_eq!(owned_read(&destination, inode, handle), b"after!");
    assert_eq!(std::fs::read(child.join("file")).unwrap(), b"replacement");
    assert_eq!(
        std::fs::read(child.join("never-looked-up")).unwrap(),
        b"whole namespace"
    );
    owned_write(&destination, inode, handle, b"child!");
    destination
        .setattr(
            context(),
            inode,
            stat64 {
                st_size: 4,
                st_uid: 3456,
                ..Default::default()
            },
            None,
            SetattrValid::SIZE | SetattrValid::UID,
        )
        .unwrap();
    assert_eq!(owned_read(&destination, inode, handle), b"chil");
    assert_eq!(
        destination
            .getattr(context(), inode, None)
            .unwrap()
            .0
            .st_uid,
        3456
    );

    let sibling = temp.path.join("sibling");
    snapshot.materialize(&generation, &sibling).unwrap();
    let sibling_checkpoint = crate::OwnedDirectoryCheckpoint::default();
    sibling_checkpoint.set_restore(&generation).unwrap();
    let other = owned_fs_for(&sibling, sibling_checkpoint);
    other.restore_state(&state).unwrap();
    assert_eq!(owned_read(&other, inode, handle), b"after!");
    restored_checkpoint
        .prepare_capture(&temp.path.join("second"))
        .unwrap();
    destination.capture_state().unwrap();
    assert!(
        !restored_checkpoint
            .finish_capture()
            .unwrap()
            .payloads()
            .is_empty()
    );
}

#[test]
fn owned_detached_reclaims_only_after_last_lookup_and_open_handle() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("file"), b"data").unwrap();
    let source = owned_fs_for(&temp.path, crate::OwnedDirectoryCheckpoint::default());
    let inode = source.lookup(context(), ROOT_INODE, c"file").unwrap().inode;
    source.lookup(context(), ROOT_INODE, c"file").unwrap();
    let handle = source
        .open(context(), inode, false, LINUX_O_RDWR as u32)
        .unwrap()
        .0
        .unwrap();
    source.unlink(context(), ROOT_INODE, c"file").unwrap();
    source.forget(context(), inode, 1);
    source
        .release(context(), inode, 0, handle, false, false, None)
        .unwrap();
    assert!(source.inode(inode).is_ok());
    source.forget(context(), inode, 1);
    assert!(source.inode(inode).is_err());
}

#[test]
fn owned_retained_hardlink_aliases_share_one_restored_object() {
    for remove_alias in [false, true] {
        let temp = TempDir::new();
        let root = temp.path.join("source");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("file"), b"before").unwrap();
        std::fs::hard_link(root.join("file"), root.join("alias")).unwrap();
        let checkpoint = crate::OwnedDirectoryCheckpoint::default();
        let source = owned_fs_for(&root, checkpoint.clone());
        let inode = source.lookup(context(), ROOT_INODE, c"file").unwrap().inode;
        let handle = source
            .open(context(), inode, false, LINUX_O_RDWR as u32)
            .unwrap()
            .0
            .unwrap();
        let alias = remove_alias.then(|| {
            let inode = source
                .lookup(context(), ROOT_INODE, c"alias")
                .unwrap()
                .inode;
            let handle = source
                .open(context(), inode, false, LINUX_O_RDWR as u32)
                .unwrap()
                .0
                .unwrap();
            (inode, handle)
        });
        source.unlink(context(), ROOT_INODE, c"file").unwrap();
        if remove_alias {
            source.unlink(context(), ROOT_INODE, c"alias").unwrap();
        }
        let generation = temp.path.join("generation");
        checkpoint.prepare_capture(&generation).unwrap();
        let state = source.capture_state().unwrap();
        let snapshot = checkpoint.finish_capture().unwrap();
        drop(source);
        std::fs::remove_dir_all(&root).unwrap();
        let child = temp.path.join("child");
        snapshot.materialize(&generation, &child).unwrap();
        let restored_checkpoint = crate::OwnedDirectoryCheckpoint::default();
        restored_checkpoint.set_restore(&generation).unwrap();
        let restored = owned_fs_for(&child, restored_checkpoint);
        restored.restore_state(&state).unwrap();
        owned_write(&restored, inode, handle, b"shared");
        if let Some((inode, handle)) = alias {
            assert_eq!(owned_read(&restored, inode, handle), b"shared");
        } else {
            assert_eq!(std::fs::read(child.join("alias")).unwrap(), b"shared");
        }
    }
}

#[test]
fn owned_rename_replacement_and_cached_descendants_survive_capture() {
    let temp = TempDir::new();
    let root = temp.path.join("source");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(root.join("directory")).unwrap();
    std::fs::write(root.join("directory/file"), b"child").unwrap();
    std::fs::write(root.join("target"), b"old").unwrap();
    std::fs::write(root.join("new"), b"new").unwrap();
    let checkpoint = crate::OwnedDirectoryCheckpoint::default();
    let source = owned_fs_for(&root, checkpoint.clone());
    let directory = source
        .lookup(context(), ROOT_INODE, c"directory")
        .unwrap()
        .inode;
    let child_inode = source.lookup(context(), directory, c"file").unwrap().inode;
    let old_inode = source
        .lookup(context(), ROOT_INODE, c"target")
        .unwrap()
        .inode;
    let old_handle = source
        .open(context(), old_inode, false, LINUX_O_RDWR as u32)
        .unwrap()
        .0
        .unwrap();
    source
        .rename(context(), ROOT_INODE, c"new", ROOT_INODE, c"target", 0)
        .unwrap();
    source
        .rename(context(), ROOT_INODE, c"directory", ROOT_INODE, c"moved", 0)
        .unwrap();
    assert_eq!(
        source
            .getattr(context(), child_inode, None)
            .unwrap()
            .0
            .st_size,
        5
    );
    assert_eq!(owned_read(&source, old_inode, old_handle), b"old");
    let generation = temp.path.join("generation");
    checkpoint.prepare_capture(&generation).unwrap();
    let state = source.capture_state().unwrap();
    let snapshot = checkpoint.finish_capture().unwrap();
    let child = temp.path.join("child");
    snapshot.materialize(&generation, &child).unwrap();
    let restore = crate::OwnedDirectoryCheckpoint::default();
    restore.set_restore(&generation).unwrap();
    let destination = owned_fs_for(&child, restore);
    destination.restore_state(&state).unwrap();
    assert_eq!(owned_read(&destination, old_inode, old_handle), b"old");
    assert_eq!(std::fs::read(child.join("target")).unwrap(), b"new");
    assert_eq!(
        destination
            .getattr(context(), child_inode, None)
            .unwrap()
            .0
            .st_size,
        5
    );
}

//--------------------------------------------------------------------------------------------------
// DAX
//--------------------------------------------------------------------------------------------------

const DAX_GUEST_BASE: u64 = 0x1000_0000;
const DAX_WINDOW: u64 = 0x2000;
const DAX_FLAG_WRITE: u64 = 0x1;

type DaxSender = crossbeam_channel::Sender<msb_krun_utils::worker_message::WorkerMessage>;
type DaxRecorded = std::sync::Arc<std::sync::Mutex<Vec<(u64, u64, u64, bool)>>>;

/// Spawn a stub VMM worker and return its sender and the mappings it received.
fn dax_worker_stub(accept: impl FnMut() -> bool + Send + 'static) -> (DaxSender, DaxRecorded) {
    dax_worker_stub_with_removals(accept, |_, _| true)
}

fn dax_worker_stub_with_removals(
    mut accept: impl FnMut() -> bool + Send + 'static,
    mut remove: impl FnMut(u64, u64) -> bool + Send + 'static,
) -> (DaxSender, DaxRecorded) {
    use msb_krun_utils::worker_message::WorkerMessage;
    let (sender, receiver) = crossbeam_channel::unbounded();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = seen.clone();
    std::thread::spawn(move || {
        while let Ok(message) = receiver.recv() {
            match message {
                WorkerMessage::DaxAddMapping(reply, host, guest, len, writable) => {
                    let accept = accept();
                    if accept {
                        recorded.lock().unwrap().push((host, guest, len, writable));
                    }
                    let _ = reply.send(accept);
                }
                WorkerMessage::GpuRemoveMapping(reply, guest, len) => {
                    if !remove(guest, len) {
                        let _ = reply.send(false);
                        continue;
                    }
                    let mut mappings = recorded.lock().unwrap();
                    let mut retained = Vec::new();
                    for (host, start, size, writable) in mappings.drain(..) {
                        let end = start + size;
                        if end <= guest || start >= guest + len {
                            retained.push((host, start, size, writable));
                        } else {
                            if start < guest {
                                retained.push((host, start, guest - start, writable));
                            }
                            if guest + len < end {
                                let tail = guest + len;
                                retained.push((host + tail - start, tail, end - tail, writable));
                            }
                        }
                    }
                    *mappings = retained;
                    let _ = reply.send(true);
                }
                _ => {}
            }
        }
    });
    (sender, seen)
}

#[test]
fn dax_setupmapping_readonly_round_trip() {
    let temp = TempDir::new();
    let content: Vec<u8> = (0..0x1000u32).map(|i| i as u8).collect();
    std::fs::write(temp.path.join("data"), &content).unwrap();
    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();

    let (sender, seen) = dax_worker_stub(|| true);
    fs.setupmapping(
        context(),
        entry.inode,
        0,
        0,
        0x1000,
        0,
        0,
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &Some(sender.clone()),
    )
    .unwrap();

    let recorded = seen.lock().unwrap().clone();
    let &(host, guest, len, writable) = recorded.last().expect("mapping sent");
    assert_eq!(guest, DAX_GUEST_BASE);
    assert_eq!(len, 0x1000);
    assert!(!writable);
    // The host view backs the guest window, so reading it exposes the file.
    let mapped = unsafe { std::slice::from_raw_parts(host as *const u8, 0x1000) };
    assert_eq!(mapped, &content[..]);
    drop(recorded);
    assert_eq!(seen.lock().unwrap().len(), 1);

    fs.removemapping(
        context(),
        vec![crate::RemovemappingOne {
            moffset: 0,
            len: 0x1000,
        }],
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &Some(sender),
    )
    .unwrap();
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn dax_setupmapping_writable_round_trip() {
    // Linux requests 2 MiB slots even when the file is smaller than the slot.
    for (file_len, mapping_len) in [
        (1, 0x20_0000),
        (0x1000, 0x1000),
        (0x1000, 0x20_0000),
        (0x10001, 0x20_0000),
    ] {
        let temp = TempDir::new();
        let path = temp.path.join("data");
        std::fs::write(&path, vec![0u8; file_len]).unwrap();
        let fs = fs_for(&temp.path);
        let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();

        let (sender, seen) = dax_worker_stub(|| true);
        fs.setupmapping(
            context(),
            entry.inode,
            u64::MAX,
            0,
            mapping_len,
            DAX_FLAG_WRITE,
            0,
            DAX_GUEST_BASE,
            mapping_len,
            &Some(sender),
        )
        .unwrap();

        let recorded = seen.lock().unwrap();
        let &(host, guest, _, writable) = recorded
            .iter()
            .rev()
            .find(|(_, guest, _, _)| *guest == DAX_GUEST_BASE)
            .expect("file mapping sent");
        assert_eq!(guest, DAX_GUEST_BASE);
        assert!(writable);
        // SAFETY: the acknowledged writable view remains owned by `fs`.
        unsafe { (host as *mut u8).write_volatile(b'x') };
        drop(recorded);

        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), file_len, "mapping must not extend the file");
        assert_eq!(bytes[0], b'x', "DAX writes must reach the backing file");
    }
}

#[test]
fn dax_readonly_mapping_observes_fuse_append() {
    for initial_len in [1, 0x1000, 0x10001] {
        let temp = TempDir::new();
        let path = temp.path.join("data");
        std::fs::write(&path, vec![b'a'; initial_len]).unwrap();
        let fs = fs_for(&temp.path);
        let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();
        let (handle, _) = fs
            .open(context(), entry.inode, false, LINUX_O_RDWR as u32)
            .unwrap();
        let (sender, seen) = dax_worker_stub(|| true);
        fs.setupmapping(
            context(),
            entry.inode,
            u64::MAX,
            0,
            0x20_0000,
            0,
            0,
            DAX_GUEST_BASE,
            0x20_0000,
            &Some(sender),
        )
        .unwrap();

        // Extending writes use FUSE_WRITE even when the guest uses DAX for reads.
        let mut reader = SourceReader {
            bytes: b"appended".to_vec(),
            pos: 0,
        };
        assert_eq!(
            fs.write(
                context(),
                entry.inode,
                handle.unwrap(),
                &mut reader,
                8,
                initial_len as u64,
                None,
                false,
                false,
                0,
            )
            .unwrap(),
            8,
        );
        assert_eq!(&std::fs::read(&path).unwrap()[initial_len..], b"appended");

        let recorded = seen.lock().unwrap();
        let address = DAX_GUEST_BASE + initial_len as u64;
        let &(host, guest, _, _) = recorded
            .iter()
            .rev()
            .find(|(_, guest, len, _)| *guest <= address && address + 8 <= *guest + *len)
            .expect("appended range remains mapped");
        // SAFETY: the current acknowledged mapping covers these eight bytes and
        // remains owned by `fs`; all filesystem operations above have completed.
        let bytes = unsafe { std::slice::from_raw_parts((host + address - guest) as *const u8, 8) };
        assert_eq!(
            bytes, b"appended",
            "guest reads must see the completed write"
        );
    }
}

#[test]
fn dax_mapping_survives_truncate_and_regrowth() {
    let temp = TempDir::new();
    let path = temp.path.join("data");
    std::fs::write(&path, vec![b'a'; 4096]).unwrap();
    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();
    let (handle, _) = fs
        .open(context(), entry.inode, false, LINUX_O_RDWR as u32)
        .unwrap();
    let (sender, seen) = dax_worker_stub(|| true);
    fs.setupmapping(
        context(),
        entry.inode,
        u64::MAX,
        0,
        0x20_0000,
        0,
        0,
        DAX_GUEST_BASE,
        0x20_0000,
        &Some(sender),
    )
    .unwrap();

    for size in [0, 4104] {
        fs.setattr(
            context(),
            entry.inode,
            stat64 {
                st_size: size,
                ..Default::default()
            },
            handle,
            SetattrValid::SIZE,
        )
        .unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), size as u64);
        if size == 0 {
            assert!(
                seen.lock().unwrap().is_empty(),
                "empty file has no mapped pages"
            );
        }
    }
    let mut reader = SourceReader {
        bytes: b"regrown!".to_vec(),
        pos: 0,
    };
    fs.write(
        context(),
        entry.inode,
        handle.unwrap(),
        &mut reader,
        8,
        4096,
        None,
        false,
        false,
        0,
    )
    .unwrap();
    let recorded = seen.lock().unwrap();
    let &(host, _, len, _) = recorded.last().unwrap();
    assert!(len >= 4104);
    // SAFETY: the stub worker's live mapping is retained by the filesystem.
    assert_eq!(
        unsafe { std::slice::from_raw_parts((host + 4096) as *const u8, 8) },
        b"regrown!"
    );
    drop(recorded);

    fs.open(
        context(),
        entry.inode,
        false,
        (LINUX_O_RDWR | LINUX_O_TRUNC) as u32,
    )
    .unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn dax_write_to_another_inode_completes_while_a_write_is_paused() {
    struct PausedReader {
        source: SourceReader,
        entered: crossbeam_channel::Sender<()>,
        resume: crossbeam_channel::Receiver<()>,
    }

    impl Read for PausedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.source.read(buf)
        }
    }

    impl ZeroCopyReader for PausedReader {
        fn read_to(&mut self, file: &File, count: usize, offset: u64) -> io::Result<usize> {
            self.entered.send(()).unwrap();
            self.resume.recv().unwrap();
            self.source.read_to(file, count, offset)
        }
    }

    let temp = TempDir::new();
    std::fs::write(temp.path.join("first"), b"a").unwrap();
    std::fs::write(temp.path.join("second"), b"b").unwrap();
    let fs = fs_for(&temp.path);
    let first = fs.lookup(context(), ROOT_INODE, c"first").unwrap().inode;
    let second = fs.lookup(context(), ROOT_INODE, c"second").unwrap().inode;
    let open = |inode| {
        fs.open(context(), inode, false, LINUX_O_RDWR as u32)
            .unwrap()
            .0
            .unwrap()
    };
    let first_handle = open(first);
    let second_handle = open(second);
    let (sender, seen) = dax_worker_stub(|| true);
    for (inode, moffset) in [(first, 0), (second, 0x1000)] {
        fs.setupmapping(
            context(),
            inode,
            0,
            0,
            0x1000,
            0,
            moffset,
            DAX_GUEST_BASE,
            DAX_WINDOW,
            &Some(sender.clone()),
        )
        .unwrap();
    }

    let (entered_tx, entered_rx) = crossbeam_channel::bounded(1);
    let (resume_tx, resume_rx) = crossbeam_channel::bounded(1);
    let (done_tx, done_rx) = crossbeam_channel::bounded(1);
    let write = |inode, handle, reader: &mut dyn ZeroCopyReader| {
        fs.write(
            context(),
            inode,
            handle,
            reader,
            1,
            1,
            None,
            false,
            false,
            0,
        )
    };
    let completed = std::thread::scope(|scope| {
        scope.spawn(|| {
            let mut reader = PausedReader {
                source: SourceReader {
                    bytes: b"x".to_vec(),
                    pos: 0,
                },
                entered: entered_tx,
                resume: resume_rx,
            };
            write(first, first_handle, &mut reader).unwrap();
        });
        entered_rx.recv().unwrap();
        scope.spawn(|| {
            let mut reader = SourceReader {
                bytes: b"y".to_vec(),
                pos: 0,
            };
            done_tx
                .send(write(second, second_handle, &mut reader))
                .unwrap();
        });
        // The timeout is a hang watchdog. The second write must finish before
        // the first is released; always release it so a regression can exit.
        let completed = done_rx.recv_timeout(std::time::Duration::from_secs(5));
        resume_tx.send(()).unwrap();
        completed
    });
    assert_eq!(
        completed
            .expect("unrelated write blocked behind paused file I/O")
            .unwrap(),
        1
    );
    assert_eq!(std::fs::read(temp.path.join("first")).unwrap(), b"ax");
    assert_eq!(std::fs::read(temp.path.join("second")).unwrap(), b"by");
    let recorded = seen.lock().unwrap();
    for (guest, expected) in [(DAX_GUEST_BASE, b"ax"), (DAX_GUEST_BASE + 0x1000, b"by")] {
        let &(host, _, _, _) = recorded
            .iter()
            .find(|(_, addr, _, _)| *addr == guest)
            .unwrap();
        // SAFETY: the filesystem retains both live views and writes have joined.
        assert_eq!(
            unsafe { std::slice::from_raw_parts(host as *const u8, 2) },
            expected
        );
    }
}

#[test]
fn dax_resize_preserves_concurrent_slot_removal_and_replacement() {
    let temp = TempDir::new();
    let first_path = temp.path.join("first");
    std::fs::write(&first_path, vec![b'a'; 8192]).unwrap();
    std::fs::write(temp.path.join("second"), b"replacement").unwrap();
    let fs = fs_for(&temp.path);
    let first = fs.lookup(context(), ROOT_INODE, c"first").unwrap().inode;
    let second = fs.lookup(context(), ROOT_INODE, c"second").unwrap().inode;
    let (sender, seen) = dax_worker_stub(|| true);
    let sender = Some(sender);
    fs.setupmapping(
        context(),
        first,
        0,
        0,
        8192,
        0,
        0,
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &sender,
    )
    .unwrap();
    let (entered_tx, entered_rx) = crossbeam_channel::bounded(1);
    let (resume_tx, resume_rx) = crossbeam_channel::bounded(1);
    let (done_tx, done_rx) = crossbeam_channel::bounded(1);

    let completed = std::thread::scope(|scope| {
        scope.spawn(|| {
            fs.resize_inode(first, || {
                entered_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
                StdOpenOptions::new()
                    .write(true)
                    .open(&first_path)?
                    .set_len(16384)
            })
            .unwrap();
        });
        entered_rx.recv().unwrap();
        scope.spawn(|| {
            let result = fs
                .removemapping(
                    context(),
                    vec![crate::RemovemappingOne {
                        moffset: 0,
                        len: 4096,
                    }],
                    DAX_GUEST_BASE,
                    DAX_WINDOW,
                    &sender,
                )
                .and_then(|()| {
                    fs.setupmapping(
                        context(),
                        second,
                        0,
                        0,
                        4096,
                        0,
                        4096,
                        DAX_GUEST_BASE,
                        DAX_WINDOW,
                        &sender,
                    )
                });
            done_tx.send(result).unwrap();
        });
        // Always release the resize before asserting so a lock regression exits.
        let completed = done_rx.recv_timeout(std::time::Duration::from_secs(5));
        resume_tx.send(()).unwrap();
        completed
    });
    completed
        .expect("unrelated mapping changes blocked during file resize")
        .unwrap();
    assert_eq!(std::fs::metadata(first_path).unwrap().len(), 16384);
    let recorded = seen.lock().unwrap();
    assert_eq!(recorded.len(), 1, "resize must not resurrect removed slots");
    let (host, guest, len, _) = recorded[0];
    assert_eq!((guest, len), (DAX_GUEST_BASE + 4096, 4096));
    // SAFETY: the surviving replacement is retained by the filesystem.
    assert_eq!(
        unsafe { std::slice::from_raw_parts(host as *const u8, 11) },
        b"replacement"
    );
}

#[test]
fn dax_setupmapping_honors_readonly() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), b"x").unwrap();
    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: temp.path.clone(),
        inject_init: false,
        readonly: true,
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();
    let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();

    let (sender, _) = dax_worker_stub(|| true);
    expect_errno(
        fs.setupmapping(
            context(),
            entry.inode,
            0,
            0,
            0x1000,
            DAX_FLAG_WRITE,
            0,
            DAX_GUEST_BASE,
            DAX_WINDOW,
            &Some(sender),
        ),
        LINUX_EROFS,
    );
}

#[test]
fn dax_setupmapping_propagates_worker_rejection() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), vec![0u8; 0x1000]).unwrap();
    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();

    let (sender, _) = dax_worker_stub(|| false);
    expect_errno(
        fs.setupmapping(
            context(),
            entry.inode,
            0,
            0,
            0x1000,
            0,
            0,
            DAX_GUEST_BASE,
            DAX_WINDOW,
            &Some(sender),
        ),
        LINUX_EINVAL,
    );
}

#[test]
fn dax_removemapping_keeps_the_unremoved_tail() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), vec![0u8; 0x2000]).unwrap();
    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();

    let (sender, seen) = dax_worker_stub(|| true);
    fs.setupmapping(
        context(),
        entry.inode,
        0,
        0,
        0x20_0000,
        0,
        0,
        DAX_GUEST_BASE,
        0x20_0000,
        &Some(sender.clone()),
    )
    .unwrap();
    let host = seen.lock().unwrap().last().unwrap().0;

    fs.removemapping(
        context(),
        vec![crate::RemovemappingOne {
            moffset: 0,
            len: 0x1000,
        }],
        DAX_GUEST_BASE,
        0x20_0000,
        &Some(sender.clone()),
    )
    .unwrap();

    let recorded = seen.lock().unwrap();
    assert_eq!(
        recorded.as_slice(),
        &[(host + 0x1000, DAX_GUEST_BASE + 0x1000, 0x1000, false)]
    );
    // SAFETY: the worker's remaining mapping must retain its backing.
    assert_eq!(unsafe { ((host + 0x1000) as *const u8).read_volatile() }, 0);
    drop(recorded);

    let (handle, _) = fs
        .open(context(), entry.inode, false, LINUX_O_RDWR as u32)
        .unwrap();
    let mut reader = SourceReader {
        bytes: b"appended".to_vec(),
        pos: 0,
    };
    fs.write(
        context(),
        entry.inode,
        handle.unwrap(),
        &mut reader,
        8,
        0x2000,
        None,
        false,
        false,
        0,
    )
    .unwrap();
    let recorded = seen.lock().unwrap();
    assert!(
        recorded
            .iter()
            .all(|(_, guest, _, _)| *guest >= DAX_GUEST_BASE + 0x1000),
        "growth must not reinstall the removed prefix"
    );
    let &(host, guest, len, _) = recorded.last().unwrap();
    let address = DAX_GUEST_BASE + 0x2000;
    assert!(guest <= address && address + 8 <= guest + len);
    // SAFETY: the live worker mapping covers the appended bytes.
    assert_eq!(
        unsafe { std::slice::from_raw_parts((host + address - guest) as *const u8, 8) },
        b"appended"
    );
}

#[test]
fn dax_setupmapping_upgrades_existing_window() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), vec![0u8; 0x1000]).unwrap();
    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();

    // Read-only mapping first.
    let (sender, _) = dax_worker_stub(|| true);
    fs.setupmapping(
        context(),
        entry.inode,
        0,
        0,
        0x1000,
        0,
        0,
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &Some(sender),
    )
    .unwrap();

    // The guest re-sends `FUSE_SETUPMAPPING` for the same range with WRITE to
    // upgrade the mapping; it must replace the window, not fail.
    let (sender, seen) = dax_worker_stub(|| true);
    fs.setupmapping(
        context(),
        entry.inode,
        0,
        0,
        0x1000,
        DAX_FLAG_WRITE,
        0,
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &Some(sender),
    )
    .unwrap();

    let &(_, guest, _, writable) = seen.lock().unwrap().last().unwrap();
    assert_eq!(guest, DAX_GUEST_BASE);
    assert!(writable);
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[test]
fn dax_failed_upgrade_restores_previous_mapping() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), vec![b'a'; 4096]).unwrap();
    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();
    let mut requests = 0;
    let (sender, seen) = dax_worker_stub(move || {
        requests += 1;
        requests != 2
    });
    fs.setupmapping(
        context(),
        entry.inode,
        u64::MAX,
        0,
        0x20_0000,
        0,
        0,
        DAX_GUEST_BASE,
        0x20_0000,
        &Some(sender.clone()),
    )
    .unwrap();
    let original_host = seen.lock().unwrap()[0].0;
    expect_errno(
        fs.setupmapping(
            context(),
            entry.inode,
            u64::MAX,
            0,
            0x20_0000,
            DAX_FLAG_WRITE,
            0,
            DAX_GUEST_BASE,
            0x20_0000,
            &Some(sender),
        ),
        LINUX_EINVAL,
    );
    let recorded = seen.lock().unwrap();
    assert_eq!(
        recorded.as_slice(),
        &[(original_host, DAX_GUEST_BASE, 4096, false)]
    );
    // SAFETY: the restored view remains owned by the filesystem.
    assert_eq!(
        unsafe { (original_host as *const u8).read_volatile() },
        b'a'
    );
}

#[test]
fn setattr_size_uses_existing_handle_after_file_becomes_readonly() {
    for mapped in [false, true] {
        let temp = TempDir::new();
        let path = temp.path.join("data");
        std::fs::write(&path, vec![b'a'; 4096]).unwrap();
        let fs = fs_for(&temp.path);
        let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();
        let handle = fs
            .open(context(), entry.inode, false, LINUX_O_RDWR as u32)
            .unwrap()
            .0;
        let (sender, seen) = dax_worker_stub(|| true);
        if mapped {
            fs.setupmapping(
                context(),
                entry.inode,
                0,
                0,
                DAX_WINDOW,
                0,
                0,
                DAX_GUEST_BASE,
                DAX_WINDOW,
                &Some(sender),
            )
            .unwrap();
        }
        let permissions = std::fs::metadata(&path).unwrap().permissions();
        let mut readonly = permissions.clone();
        readonly.set_readonly(true);
        std::fs::set_permissions(&path, readonly).unwrap();
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());

        let result = fs.setattr(
            context(),
            entry.inode,
            stat64 {
                st_size: 0,
                ..Default::default()
            },
            handle,
            SetattrValid::SIZE,
        );
        std::fs::set_permissions(&path, permissions).unwrap();
        result.expect("an existing writable handle retains permission to truncate");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        assert!(seen.lock().unwrap().is_empty());
    }
}

#[test]
fn dax_hardlink_write_and_truncate_update_existing_mapping() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), vec![b'a'; 4096]).unwrap();
    std::fs::hard_link(temp.path.join("data"), temp.path.join("alias")).unwrap();
    let fs = fs_for(&temp.path);
    let data = fs.lookup(context(), ROOT_INODE, c"data").unwrap();
    let alias = fs.lookup(context(), ROOT_INODE, c"alias").unwrap();
    assert_eq!(
        data.inode, alias.inode,
        "the guest must share one size and page cache across hardlinks"
    );
    let handle = fs
        .open(context(), alias.inode, false, LINUX_O_RDWR as u32)
        .unwrap()
        .0
        .unwrap();
    let (sender, seen) = dax_worker_stub(|| true);
    fs.setupmapping(
        context(),
        data.inode,
        0,
        0,
        8192,
        0,
        0,
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &Some(sender),
    )
    .unwrap();
    let mut reader = SourceReader {
        bytes: b"x".to_vec(),
        pos: 0,
    };
    fs.write(
        context(),
        alias.inode,
        handle,
        &mut reader,
        1,
        4096,
        None,
        false,
        false,
        0,
    )
    .unwrap();
    {
        let recorded = seen.lock().unwrap();
        let &(host, _, len, _) = recorded.last().unwrap();
        assert_eq!(
            len, 8192,
            "growth through an alias must refresh the mapped file"
        );
        // SAFETY: this acknowledged mapping is retained by the filesystem.
        assert_eq!(
            unsafe { ((host + 4096) as *const u8).read_volatile() },
            b'x'
        );
    }
    fs.setattr(
        context(),
        alias.inode,
        stat64 {
            st_size: 0,
            ..Default::default()
        },
        Some(handle),
        SetattrValid::SIZE,
    )
    .unwrap();
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(std::fs::metadata(temp.path.join("data")).unwrap().len(), 0);

    // Renaming one hardlink over another must leave both names intact.
    fs.rename(context(), ROOT_INODE, c"data", ROOT_INODE, c"alias", 0)
        .unwrap();
    assert!(temp.path.join("data").exists());
    assert!(temp.path.join("alias").exists());
    assert_eq!(
        fs.getattr(context(), data.inode, None).unwrap().0.st_nlink,
        2
    );

    // Removing the canonical name must keep the surviving alias usable through
    // the inode the guest already cached, without requiring another lookup.
    fs.unlink(context(), ROOT_INODE, c"data").unwrap();
    let stat = fs.getattr(context(), alias.inode, None).unwrap().0;
    assert_eq!(stat.st_nlink, 1);
    assert_eq!(stat.st_size, 0);
}

#[test]
fn dax_failed_refresh_still_clears_privilege_bits() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), vec![b'a'; 4096]).unwrap();
    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();
    let handle = fs
        .open(context(), entry.inode, false, LINUX_O_RDWR as u32)
        .unwrap()
        .0
        .unwrap();
    fs.setattr(
        context(),
        entry.inode,
        stat64 {
            st_mode: S_IFREG | 0o6755,
            ..Default::default()
        },
        Some(handle),
        SetattrValid::MODE,
    )
    .unwrap();
    assert_eq!(
        fs.getattr(context(), entry.inode, Some(handle))
            .unwrap()
            .0
            .st_mode
            & 0o6000,
        0o6000
    );
    let mut calls = 0;
    let (sender, _) = dax_worker_stub(move || {
        calls += 1;
        calls == 1
    });
    fs.setupmapping(
        context(),
        entry.inode,
        0,
        0,
        8192,
        0,
        0,
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &Some(sender),
    )
    .unwrap();
    let mut reader = SourceReader {
        bytes: b"x".to_vec(),
        pos: 0,
    };
    assert!(
        fs.write(
            context(),
            entry.inode,
            handle,
            &mut reader,
            1,
            4096,
            None,
            false,
            true,
            0
        )
        .is_err()
    );
    assert_eq!(
        std::fs::metadata(temp.path.join("data")).unwrap().len(),
        4097
    );
    assert_eq!(
        fs.getattr(context(), entry.inode, Some(handle))
            .unwrap()
            .0
            .st_mode
            & 0o6000,
        0,
        "modified file must lose privilege bits even if refresh fails"
    );
}

#[test]
fn dax_failed_rollback_is_repaired_by_a_later_write() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), vec![b'a'; 4096]).unwrap();
    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"data").unwrap();
    let handle = fs
        .open(context(), entry.inode, false, LINUX_O_RDWR as u32)
        .unwrap()
        .0
        .unwrap();
    let mut calls = 0;
    let (sender, seen) = dax_worker_stub(move || {
        calls += 1;
        calls != 2 && calls != 3
    });
    fs.setupmapping(
        context(),
        entry.inode,
        0,
        0,
        4096,
        0,
        0,
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &Some(sender.clone()),
    )
    .unwrap();
    assert!(
        fs.setupmapping(
            context(),
            entry.inode,
            0,
            0,
            4096,
            DAX_FLAG_WRITE,
            0,
            DAX_GUEST_BASE,
            DAX_WINDOW,
            &Some(sender)
        )
        .is_err()
    );
    assert!(seen.lock().unwrap().is_empty());
    let mut reader = SourceReader {
        bytes: b"x".to_vec(),
        pos: 0,
    };
    fs.write(
        context(),
        entry.inode,
        handle,
        &mut reader,
        1,
        0,
        None,
        false,
        false,
        0,
    )
    .unwrap();
    let recorded = seen.lock().unwrap();
    assert_eq!(
        recorded.len(),
        1,
        "a failed rollback must not be treated as installed"
    );
    let (host, guest, len, writable) = recorded[0];
    assert_eq!((guest, len, writable), (DAX_GUEST_BASE, 4096, false));
    // SAFETY: the recovered live mapping is retained by the filesystem.
    assert_eq!(unsafe { (host as *const u8).read_volatile() }, b'x');
}

#[test]
fn dax_unmapped_file_write_does_not_wait_for_worker() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("mapped"), b"a").unwrap();
    std::fs::write(temp.path.join("plain"), b"b").unwrap();
    let fs = fs_for(&temp.path);
    let mapped = fs.lookup(context(), ROOT_INODE, c"mapped").unwrap().inode;
    let plain = fs.lookup(context(), ROOT_INODE, c"plain").unwrap().inode;
    let handle = fs
        .open(context(), plain, false, LINUX_O_RDWR as u32)
        .unwrap()
        .0
        .unwrap();
    let (entered_tx, entered_rx) = crossbeam_channel::bounded(1);
    let (resume_tx, resume_rx) = crossbeam_channel::bounded(1);
    let (done_tx, done_rx) = crossbeam_channel::bounded(1);
    let (sender, _) = dax_worker_stub(move || {
        entered_tx.send(()).unwrap();
        resume_rx.recv().unwrap();
        true
    });
    let completed = std::thread::scope(|scope| {
        scope.spawn(|| {
            fs.setupmapping(
                context(),
                mapped,
                0,
                0,
                4096,
                0,
                0,
                DAX_GUEST_BASE,
                DAX_WINDOW,
                &Some(sender),
            )
            .unwrap()
        });
        entered_rx.recv().unwrap();
        scope.spawn(|| {
            let mut reader = SourceReader {
                bytes: b"x".to_vec(),
                pos: 0,
            };
            done_tx
                .send(fs.write(
                    context(),
                    plain,
                    handle,
                    &mut reader,
                    1,
                    0,
                    None,
                    false,
                    false,
                    0,
                ))
                .unwrap();
        });
        let completed = done_rx.recv_timeout(std::time::Duration::from_secs(5));
        resume_tx.send(()).unwrap();
        completed
    });
    assert_eq!(
        completed
            .expect("unmapped file waited for the VMM worker")
            .unwrap(),
        1
    );
    assert_eq!(std::fs::read(temp.path.join("plain")).unwrap(), b"x");
}

#[test]
fn dax_unmapping_skips_holes_and_retries_only_unacknowledged_ranges() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), vec![b'a'; 8192]).unwrap();
    let fs = fs_for(&temp.path);
    let inode = fs.lookup(context(), ROOT_INODE, c"data").unwrap().inode;
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    let (sender, seen) = dax_worker_stub_with_removals(
        || true,
        move |guest, len| {
            let mut requests = recorded.lock().unwrap();
            requests.push((guest, len));
            requests.len() != 2
        },
    );
    let sender = Some(sender);
    for offset in [0, 4096] {
        fs.setupmapping(
            context(),
            inode,
            0,
            offset,
            4096,
            0,
            offset,
            DAX_GUEST_BASE,
            DAX_WINDOW,
            &sender,
        )
        .unwrap();
    }
    assert!(
        requests.lock().unwrap().is_empty(),
        "setup must not remove unmapped pages"
    );
    let remove = || {
        fs.removemapping(
            context(),
            vec![crate::RemovemappingOne {
                moffset: 0,
                len: 8192,
            }],
            DAX_GUEST_BASE,
            DAX_WINDOW,
            &sender,
        )
    };
    assert!(remove().is_err());
    {
        let live = seen.lock().unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!((live[0].1, live[0].2), (DAX_GUEST_BASE + 4096, 4096));
        // SAFETY: a rejected removal must retain this live host backing.
        assert_eq!(unsafe { (live[0].0 as *const u8).read_volatile() }, b'a');
    }
    remove().unwrap();
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(
        *requests.lock().unwrap(),
        vec![
            (DAX_GUEST_BASE, 4096),
            (DAX_GUEST_BASE + 4096, 4096),
            (DAX_GUEST_BASE + 4096, 4096),
        ]
    );
    remove().unwrap();
    assert_eq!(
        requests.lock().unwrap().len(),
        3,
        "empty ranges need no worker request"
    );
}

#[test]
fn dax_mapping_survives_unlink() {
    for fail_refresh in [false, true] {
        dax_namespace_change_keeps_mapping(false, fail_refresh);
    }
}

#[test]
fn dax_mapping_survives_rename_over() {
    for fail_refresh in [false, true] {
        dax_namespace_change_keeps_mapping(true, fail_refresh);
    }
}

fn dax_namespace_change_keeps_mapping(replace: bool, fail_refresh: bool) {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("data"), b"old contents").unwrap();
    std::fs::write(temp.path.join("replacement"), b"new contents").unwrap();
    let fs = fs_for(&temp.path);
    let inode = fs.lookup(context(), ROOT_INODE, c"data").unwrap().inode;
    let replacement = fs.lookup(context(), ROOT_INODE, c"replacement").unwrap();
    let mut calls = 0;
    let (sender, seen) = dax_worker_stub(move || {
        calls += 1;
        !fail_refresh || calls == 1
    });
    fs.setupmapping(
        context(),
        inode,
        0,
        0,
        8192,
        0,
        0,
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &Some(sender.clone()),
    )
    .unwrap();
    if replace {
        let result = fs.rename(
            context(),
            ROOT_INODE,
            c"replacement",
            ROOT_INODE,
            c"data",
            0,
        );
        assert_eq!(result.is_err(), fail_refresh);
        assert_eq!(
            fs.getattr(context(), replacement.inode, None)
                .unwrap()
                .0
                .st_size,
            12
        );
        assert_eq!(
            fs.lookup(context(), ROOT_INODE, c"data").unwrap().inode,
            replacement.inode
        );
        assert_eq!(
            std::fs::read(temp.path.join("data")).unwrap(),
            b"new contents"
        );
    } else {
        let result = fs.unlink(context(), ROOT_INODE, c"data");
        assert_eq!(result.is_err(), fail_refresh);
        assert!(!temp.path.join("data").exists());
        std::fs::write(temp.path.join("data"), b"fresh").unwrap();
        assert_ne!(
            fs.lookup(context(), ROOT_INODE, c"data").unwrap().inode,
            inode
        );
    }
    if fail_refresh {
        assert!(seen.lock().unwrap().is_empty());
    } else {
        let live = seen.lock().unwrap();
        let host = live[0].0;
        // SAFETY: removing a name must retain the acknowledged mapped object.
        assert_eq!(
            unsafe { std::slice::from_raw_parts(host as *const u8, 12) },
            b"old contents"
        );
    }
    fs.removemapping(
        context(),
        vec![crate::RemovemappingOne {
            moffset: 0,
            len: 8192,
        }],
        DAX_GUEST_BASE,
        DAX_WINDOW,
        &Some(sender),
    )
    .unwrap();
    assert!(seen.lock().unwrap().is_empty());
}

fn create_junction(link: &Path, target: &Path) {
    let output = Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "mklink /J failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn nested_dotdot_matches_actual_parent_inode() {
    let temp = TempDir::new();
    std::fs::create_dir_all(temp.path.join("parent").join("child")).unwrap();
    let fs = fs_for(&temp.path);
    let parent = fs.lookup(context(), ROOT_INODE, c"parent").unwrap();
    let child = fs.lookup(context(), parent.inode, c"child").unwrap();

    let (dh, _) = fs
        .opendir(context(), child.inode, LINUX_O_DIRECTORY as u32)
        .unwrap();
    let dh = dh.unwrap();
    let mut dotdot = None;
    fs.readdirplus_for_each(
        context(),
        child.inode,
        dh,
        4096,
        0,
        &mut |dir_entry, full| {
            if dir_entry.name == b".." {
                dotdot = Some((dir_entry.ino, full.inode));
            }
            Ok(dir_entry.name.len() + 128)
        },
    )
    .unwrap();
    assert_eq!(dotdot, Some((parent.inode, parent.inode)));
    assert_ne!(parent.inode, ROOT_INODE);
    fs.releasedir(context(), child.inode, 0, dh).unwrap();
}

#[test]
fn truncating_open_through_swapped_junction_never_modifies_outside_canary() {
    let temp = TempDir::new();
    let root = temp.path.join("root");
    let outside = temp.path.join("outside");
    std::fs::create_dir_all(root.join("dir")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(root.join("dir").join("target.txt"), b"inside-data").unwrap();
    std::fs::write(outside.join("target.txt"), b"OUTSIDE-MUST-SURVIVE").unwrap();

    let fs = fs_for(&root);
    let dir = fs.lookup(context(), ROOT_INODE, c"dir").unwrap();
    let target = fs.lookup(context(), dir.inode, c"target.txt").unwrap();

    // Swap `root/dir` for a junction to `outside`, then attempt O_RDWR | O_TRUNC.
    std::fs::remove_dir_all(root.join("dir")).unwrap();
    create_junction(&root.join("dir"), &outside);
    expect_errno(
        fs.open(
            context(),
            target.inode,
            false,
            (LINUX_O_RDWR | LINUX_O_TRUNC) as u32,
        ),
        LINUX_ELOOP,
    );
    // The outside canary file must remain completely untouched.
    assert_eq!(
        std::fs::read(outside.join("target.txt")).unwrap(),
        b"OUTSIDE-MUST-SURVIVE"
    );
}

#[test]
fn host_file_replacement_assigns_fresh_inode_and_stales_old_inode() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("item.txt"), b"first").unwrap();
    let fs = fs_for(&temp.path);
    let first = fs.lookup(context(), ROOT_INODE, c"item.txt").unwrap();

    // Replace on the host with a distinct file object (different FileId).
    std::fs::remove_file(temp.path.join("item.txt")).unwrap();
    std::fs::write(temp.path.join("other.txt"), b"occupy").unwrap();
    std::fs::write(temp.path.join("item.txt"), b"second").unwrap();

    // Old inode reference must fail with ESTALE rather than silently opening the replacement.
    expect_errno(fs.getattr(context(), first.inode, None), LINUX_ESTALE);
    expect_errno(fs.open(context(), first.inode, false, 0), LINUX_ESTALE);

    // Fresh lookup must drop the stale path alias and assign a new guest inode.
    let second = fs.lookup(context(), ROOT_INODE, c"item.txt").unwrap();
    assert_ne!(second.inode, first.inode);
    assert_eq!(second.attr.st_size, 6);
}

#[test]
fn rejects_windows_reserved_device_names_and_handles_case_mismatch_via_fallback() {
    for reserved in [c"CON", c"nul.txt", c"COM1", c"lpt9.log", c"CONIN$", c"AUX"] {
        expect_errno(validate_component(reserved), LINUX_EPERM);
    }

    let temp = TempDir::new();
    std::fs::create_dir_all(temp.path.join("SubDir")).unwrap();
    std::fs::write(temp.path.join("SubDir").join("MixedCase.txt"), b"hello").unwrap();
    let fs = fs_for(&temp.path);
    // Lookup with different ASCII case forces exact-match miss -> anchored NtCreateFile fallback.
    let sub = fs.lookup(context(), ROOT_INODE, c"subdir").unwrap();
    let file = fs.lookup(context(), sub.inode, c"mixedcase.txt").unwrap();
    assert_eq!(file.attr.st_size, 5);
    let (fh, _) = fs.open(context(), file.inode, false, 0).unwrap();
    assert_eq!(owned_read(&fs, file.inode, fh.unwrap()), b"hello");
}

#[test]
fn batched_readdirplus_matches_lookup_identity_and_skips_junctions() {
    let temp = TempDir::new();
    let root = temp.path.join("root");
    let outside = temp.path.join("outside");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("secret.txt"), b"outside").unwrap();
    create_junction(&root.join("escape"), &outside);

    // Populate 120 files + a subdirectory so FileIdBothDirectoryInfo exercises multi-entry
    // batching and identity matching against GetFileInformationByHandle.
    std::fs::create_dir(root.join("sub")).unwrap();
    for index in 0..120 {
        std::fs::write(
            root.join(format!("item-{index:03}.txt")),
            format!("payload-{index:03}"),
        )
        .unwrap();
    }

    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: root.clone(),
        inject_init: false,
        stat_virtualization: StatVirtualization::Off,
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::DO_READDIRPLUS | FsOptions::READDIRPLUS_AUTO)
        .unwrap();

    let (handle, _) = fs
        .opendir(context(), ROOT_INODE, LINUX_O_DIRECTORY as u32)
        .unwrap();
    let handle = handle.unwrap();

    let mut listed = std::collections::BTreeMap::new();
    let mut offset = 0u64;
    loop {
        let mut batch = 0usize;
        let mut last_offset = offset;
        fs.readdirplus_for_each(
            context(),
            ROOT_INODE,
            handle,
            4096,
            offset,
            &mut |dir_entry, entry| {
                if batch >= 11 {
                    return Ok(0);
                }
                assert_eq!(dir_entry.ino, entry.inode);
                let name = String::from_utf8(dir_entry.name.to_vec()).unwrap();
                listed.insert(name, entry);
                last_offset = dir_entry.offset;
                batch += 1;
                Ok(dir_entry.name.len() + 128)
            },
        )
        .unwrap();
        if batch == 0 {
            break;
        }
        offset = last_offset;
    }
    fs.releasedir(context(), ROOT_INODE, 0, handle).unwrap();

    assert!(!listed.contains_key("escape"), "junction must be skipped");
    assert_eq!(listed.len(), 123); // "." + ".." + "sub" + 120 files

    // Every FileIdBothDirectoryInfo inode must match subsequent single-handle lookup.
    for index in [0usize, 59, 119] {
        let name = format!("item-{index:03}.txt");
        let c_name = std::ffi::CString::new(name.as_str()).unwrap();
        let from_readdir = listed.get(&name).unwrap();
        let from_lookup = fs.lookup(context(), ROOT_INODE, &c_name).unwrap();
        assert_eq!(from_readdir.inode, from_lookup.inode);
        assert_eq!(from_readdir.attr.st_size, from_lookup.attr.st_size);
        assert_eq!(from_readdir.attr.st_mode, from_lookup.attr.st_mode);
    }
    let sub_from_readdir = listed.get("sub").unwrap();
    let sub_from_lookup = fs.lookup(context(), ROOT_INODE, c"sub").unwrap();
    assert_eq!(sub_from_readdir.inode, sub_from_lookup.inode);
    assert_eq!(sub_from_readdir.attr.st_mode & S_IFMT, S_IFDIR);
}

#[test]
fn single_handle_lookup_rejects_intermediate_junctions_outside_and_inside_root() {
    let temp = TempDir::new();
    let root = temp.path.join("root");
    let outside = temp.path.join("outside");
    std::fs::create_dir_all(root.join("dir").join("sub")).unwrap();
    std::fs::create_dir_all(root.join("other").join("sub")).unwrap();
    std::fs::create_dir_all(outside.join("sub")).unwrap();
    std::fs::write(root.join("dir").join("sub").join("file.txt"), b"inside").unwrap();
    std::fs::write(root.join("other").join("sub").join("file.txt"), b"sibling").unwrap();
    std::fs::write(outside.join("sub").join("file.txt"), b"secret").unwrap();

    let fs = fs_for(&root);
    let dir = fs.lookup(context(), ROOT_INODE, c"dir").unwrap();
    let sub = fs.lookup(context(), dir.inode, c"sub").unwrap();
    let file = fs.lookup(context(), sub.inode, c"file.txt").unwrap();

    // Swap cached intermediate directory `root/dir` for a junction pointing OUTSIDE root.
    std::fs::remove_dir_all(root.join("dir")).unwrap();
    create_junction(&root.join("dir"), &outside);
    expect_errno(fs.lookup(context(), sub.inode, c"file.txt"), LINUX_ELOOP);
    expect_errno(fs.getattr(context(), file.inode, None), LINUX_ELOOP);
    expect_errno(fs.open(context(), file.inode, false, 0), LINUX_ELOOP);
    expect_errno(
        fs.opendir(context(), sub.inode, LINUX_O_DIRECTORY as u32),
        LINUX_ELOOP,
    );

    // Swap `root/dir` for a junction pointing to ANOTHER directory INSIDE root (`root/other`).
    std::fs::remove_dir(root.join("dir")).unwrap();
    create_junction(&root.join("dir"), &root.join("other"));
    expect_errno(fs.lookup(context(), sub.inode, c"file.txt"), LINUX_ELOOP);
    expect_errno(fs.getattr(context(), file.inode, None), LINUX_ELOOP);
    expect_errno(fs.open(context(), file.inode, false, 0), LINUX_ELOOP);
}

#[test]
fn concurrent_host_mutator_never_escapes_root_during_lookup_and_readdir() {
    let temp = TempDir::new();
    let root = temp.path.join("root");
    let outside = temp.path.join("outside");
    std::fs::create_dir_all(root.join("slot")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(root.join("slot").join("safe.txt"), b"safe-content").unwrap();
    std::fs::write(outside.join("canary.txt"), b"OUTSIDE-CANARY-SECRET").unwrap();
    std::fs::write(outside.join("safe.txt"), b"OUTSIDE-CANARY-SECRET").unwrap();

    let fs = Arc::new(
        PassthroughFs::new(PassthroughConfig {
            root_dir: root.clone(),
            inject_init: false,
            stat_virtualization: StatVirtualization::Off,
            ..Default::default()
        })
        .unwrap(),
    );
    fs.init(FsOptions::DO_READDIRPLUS | FsOptions::READDIRPLUS_AUTO)
        .unwrap();
    let slot = fs.lookup(context(), ROOT_INODE, c"slot").unwrap();

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mutator_stop = Arc::clone(&stop);
    let mutator_root = root.clone();
    let mutator_outside = outside.clone();
    let mutator = std::thread::spawn(move || {
        let slot_path = mutator_root.join("slot");
        let backup_path = mutator_root.join("slot_backup");
        while !mutator_stop.load(Ordering::Relaxed) {
            if std::fs::rename(&slot_path, &backup_path).is_ok() {
                let _ = Command::new("cmd.exe")
                    .args(["/d", "/c", "mklink", "/J"])
                    .arg(&slot_path)
                    .arg(&mutator_outside)
                    .output();
                std::thread::yield_now();
                let _ = std::fs::remove_dir(&slot_path);
                let _ = std::fs::rename(&backup_path, &slot_path);
            }
            std::thread::yield_now();
        }
    });

    for _ in 0..200 {
        // Never allow lookup of the outside-only canary file.
        if let Ok(entry) = fs.lookup(context(), slot.inode, c"canary.txt") {
            panic!("escaped root: looked up outside canary inode {}", entry.inode);
        }
        // If `safe.txt` is opened, its bytes must never come from `outside/safe.txt`.
        if let Ok(entry) = fs.lookup(context(), slot.inode, c"safe.txt")
            && let Ok((Some(fh), _)) = fs.open(context(), entry.inode, false, 0)
        {
            let mut writer = CaptureWriter { bytes: Vec::new() };
            if fs
                .read(context(), entry.inode, fh, &mut writer, 64, 0, None, 0)
                .is_ok()
            {
                assert_ne!(
                    writer.bytes, b"OUTSIDE-CANARY-SECRET",
                    "escaped root: read outside canary bytes"
                );
            }
            let _ = fs.release(context(), entry.inode, 0, fh, false, false, None);
        }
        // Directory listing of `slot` must never expose `canary.txt`.
        if let Ok((Some(dh), _)) = fs.opendir(context(), slot.inode, LINUX_O_DIRECTORY as u32) {
            let _ = fs.readdirplus_for_each(
                context(),
                slot.inode,
                dh,
                4096,
                0,
                &mut |dir_entry, _| {
                    assert_ne!(
                        dir_entry.name, b"canary.txt",
                        "escaped root: readdirplus exposed outside canary"
                    );
                    Ok(dir_entry.name.len() + 128)
                },
            );
            let _ = fs.releasedir(context(), slot.inode, 0, dh);
        }
    }

    stop.store(true, Ordering::Relaxed);
    mutator.join().unwrap();
}

#[test]
fn readdirplus_sees_live_size_of_open_unclosed_writable_file() {
    let temp = TempDir::new();
    let fs = fs_for(&temp.path);
    let (created, fh, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"live.bin",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let fh = fh.unwrap();
    let mut reader = SourceReader {
        bytes: vec![0xAB; 4096],
        pos: 0,
    };
    fs.write(
        context(),
        created.inode,
        fh,
        &mut reader,
        4096,
        0,
        None,
        false,
        false,
        0,
    )
    .unwrap();

    // Without closing `fh`, readdirplus must still report the live 4096-byte size.
    let (dh, _) = fs
        .opendir(context(), ROOT_INODE, LINUX_O_DIRECTORY as u32)
        .unwrap();
    let dh = dh.unwrap();
    let mut found_size = None;
    fs.readdirplus_for_each(
        context(),
        ROOT_INODE,
        dh,
        4096,
        0,
        &mut |dir_entry, entry| {
            if dir_entry.name == b"live.bin" {
                found_size = Some(entry.attr.st_size);
            }
            Ok(dir_entry.name.len() + 128)
        },
    )
    .unwrap();
    assert_eq!(found_size, Some(4096));
    fs.releasedir(context(), ROOT_INODE, 0, dh).unwrap();
    fs.release(context(), created.inode, 0, fh, false, false, None)
        .unwrap();
}

#[test]
fn setattr_without_handle_rejects_stale_replaced_inode_before_mutation() {
    let temp = TempDir::new();
    let target = temp.path.join("file.txt");
    std::fs::write(&target, b"original-contents").unwrap();

    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"file.txt").unwrap();

    // Replace `file.txt` on the host with a brand new file (different file identity).
    let replacement = temp.path.join("replacement.tmp");
    std::fs::write(&replacement, b"keep-me-intact-12345").unwrap();
    std::fs::remove_file(&target).unwrap();
    std::fs::rename(&replacement, &target).unwrap();
    let before_meta = std::fs::metadata(&target).unwrap();
    let before_mtime = before_meta.modified().unwrap();

    // Handle-less truncate on the stale inode must fail with ESTALE without mutating replacement.
    let attr = stat64 {
        st_size: 0,
        ..Default::default()
    };
    expect_errno(
        fs.setattr(context(), entry.inode, attr, None, SetattrValid::SIZE),
        LINUX_ESTALE,
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"keep-me-intact-12345");

    // Handle-less timestamp update on the stale inode must also fail with ESTALE without mutating.
    let time_attr = stat64 {
        st_mtime: 1_600_000_000,
        ..Default::default()
    };
    expect_errno(
        fs.setattr(context(), entry.inode, time_attr, None, SetattrValid::MTIME),
        LINUX_ESTALE,
    );
    assert_eq!(std::fs::metadata(&target).unwrap().modified().unwrap(), before_mtime);
}

#[test]
fn create_with_o_trunc_rejects_junction_without_truncating_outside_target() {
    let temp = TempDir::new();
    let root = temp.path.join("root");
    let outside = temp.path.join("outside");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let secret = outside.join("victim.txt");
    std::fs::write(&secret, b"do-not-truncate").unwrap();

    let fs = fs_for(&root);
    let sub = fs.lookup(context(), ROOT_INODE, c"sub").unwrap();

    // Replace `root/sub` with a junction to `outside`.
    std::fs::remove_dir(root.join("sub")).unwrap();
    create_junction(&root.join("sub"), &outside);

    expect_errno(
        fs.create(
            context(),
            sub.inode,
            c"victim.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_WRONLY | LINUX_O_TRUNC) as u32,
            0,
            Extensions::default(),
        ),
        LINUX_ELOOP,
    );
    assert_eq!(std::fs::read(&secret).unwrap(), b"do-not-truncate");
}

#[test]
fn invalid_input_offset_error_maps_to_linux_einval() {
    let err = host_error(io::Error::new(
        io::ErrorKind::InvalidInput,
        "file offset out of range",
    ));
    assert_eq!(err.raw_os_error(), Some(LINUX_EINVAL));
    assert_eq!(valid_file_identity(1, 0), None);
    assert_eq!(valid_file_identity(1, u64::MAX), None);
    assert_eq!(valid_file_identity(1, 42), Some((1, 42)));
}

#[test]
fn readdir_for_each_and_readdirplus_for_each_resume_across_chunks() {
    let temp = TempDir::new();
    for index in 0..25 {
        std::fs::write(temp.path.join(format!("file-{index:02}.txt")), b"data").unwrap();
    }
    let fs = fs_for(&temp.path);
    let (handle, _) = fs
        .opendir(context(), ROOT_INODE, LINUX_O_DIRECTORY as u32)
        .unwrap();
    let handle = handle.unwrap();

    // First call populates the snapshot; subsequent calls must reuse the same Arc.
    let snap1 = fs.dir_snapshot(ROOT_INODE, handle).unwrap();
    let snap2 = fs.dir_snapshot(ROOT_INODE, handle).unwrap();
    assert!(Arc::ptr_eq(&snap1, &snap2));

    // Stream via readdir_for_each accepting at most 4 entries per call.
    let mut seen_readdir = Vec::new();
    let mut offset = 0u64;
    loop {
        let mut batch = 0usize;
        let mut last_offset = offset;
        fs.readdir_for_each(
            context(),
            ROOT_INODE,
            handle,
            4096,
            offset,
            &mut |entry| {
                if batch >= 4 {
                    return Ok(0);
                }
                seen_readdir.push(String::from_utf8(entry.name.to_vec()).unwrap());
                last_offset = entry.offset;
                batch += 1;
                Ok(entry.name.len() + 24)
            },
        )
        .unwrap();
        if batch == 0 {
            break;
        }
        offset = last_offset;
    }

    // Stream via readdirplus_for_each accepting at most 3 entries per call.
    let mut seen_plus = Vec::new();
    let mut offset = 0u64;
    loop {
        let mut batch = 0usize;
        let mut last_offset = offset;
        fs.readdirplus_for_each(
            context(),
            ROOT_INODE,
            handle,
            4096,
            offset,
            &mut |entry, full| {
                if batch >= 3 {
                    return Ok(0);
                }
                assert_eq!(entry.ino, full.inode);
                seen_plus.push(String::from_utf8(entry.name.to_vec()).unwrap());
                last_offset = entry.offset;
                batch += 1;
                Ok(entry.name.len() + 128)
            },
        )
        .unwrap();
        if batch == 0 {
            break;
        }
        offset = last_offset;
    }

    assert_eq!(seen_readdir.len(), 27); // "." + ".." + 25 files
    assert_eq!(seen_readdir, seen_plus);
    let unique: std::collections::BTreeSet<_> = seen_readdir.iter().cloned().collect();
    assert_eq!(unique.len(), 27);
    assert!(unique.contains("."));
    assert!(unique.contains(".."));
    for index in 0..25 {
        assert!(unique.contains(&format!("file-{index:02}.txt")));
    }

    fs.releasedir(context(), ROOT_INODE, 0, handle).unwrap();
}

#[test]
fn dirty_flag_tracks_writes_truncates_and_fsync() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("sample.txt"), b"initial").unwrap();
    let fs = fs_for(&temp.path);
    let entry = fs.lookup(context(), ROOT_INODE, c"sample.txt").unwrap();

    // Opening O_RDWR without O_TRUNC starts clean; flush is a no-op.
    let (fh, _) = fs
        .open(context(), entry.inode, false, LINUX_O_RDWR as u32)
        .unwrap();
    let fh = fh.unwrap();
    assert!(
        !fs.handle(entry.inode, fh)
            .unwrap()
            .dirty
            .load(Ordering::Acquire)
    );
    fs.flush(context(), entry.inode, fh, 0).unwrap();
    assert!(
        !fs.handle(entry.inode, fh)
            .unwrap()
            .dirty
            .load(Ordering::Acquire)
    );

    // Writing marks the handle dirty; flush clears it and persists bytes.
    let mut reader = SourceReader {
        bytes: b"updated!".to_vec(),
        pos: 0,
    };
    let written = fs
        .write(
            context(),
            entry.inode,
            fh,
            &mut reader,
            8,
            0,
            None,
            false,
            false,
            0,
        )
        .unwrap();
    assert_eq!(written, 8);
    assert!(
        fs.handle(entry.inode, fh)
            .unwrap()
            .dirty
            .load(Ordering::Acquire)
    );
    fs.flush(context(), entry.inode, fh, 0).unwrap();
    assert!(
        !fs.handle(entry.inode, fh)
            .unwrap()
            .dirty
            .load(Ordering::Acquire)
    );
    assert_eq!(std::fs::read(temp.path.join("sample.txt")).unwrap(), b"updated!");

    // Writing then fsync also clears dirty.
    let mut reader2 = SourceReader {
        bytes: b"fsynced!".to_vec(),
        pos: 0,
    };
    fs.write(
        context(),
        entry.inode,
        fh,
        &mut reader2,
        8,
        0,
        None,
        false,
        false,
        0,
    )
    .unwrap();
    assert!(
        fs.handle(entry.inode, fh)
            .unwrap()
            .dirty
            .load(Ordering::Acquire)
    );
    fs.fsync(context(), entry.inode, true, fh).unwrap();
    assert!(
        !fs.handle(entry.inode, fh)
            .unwrap()
            .dirty
            .load(Ordering::Acquire)
    );

    // setattr(SIZE) with handle marks the handle dirty; flush clears it.
    fs.setattr(
        context(),
        entry.inode,
        stat64 {
            st_size: 4,
            ..Default::default()
        },
        Some(fh),
        SetattrValid::SIZE,
    )
    .unwrap();
    assert!(
        fs.handle(entry.inode, fh)
            .unwrap()
            .dirty
            .load(Ordering::Acquire)
    );
    fs.flush(context(), entry.inode, fh, 0).unwrap();
    assert!(
        !fs.handle(entry.inode, fh)
            .unwrap()
            .dirty
            .load(Ordering::Acquire)
    );

    // Handle-based set_times marks the handle dirty; flush clears it.
    fs.setattr(
        context(),
        entry.inode,
        stat64::default(),
        Some(fh),
        SetattrValid::MTIME_NOW,
    )
    .unwrap();
    assert!(
        fs.handle(entry.inode, fh)
            .unwrap()
            .dirty
            .load(Ordering::Acquire)
    );
    fs.flush(context(), entry.inode, fh, 0).unwrap();
    assert!(
        !fs.handle(entry.inode, fh)
            .unwrap()
            .dirty
            .load(Ordering::Acquire)
    );
    fs.release(context(), entry.inode, 0, fh, false, false, None)
        .unwrap();

    // Opening with O_TRUNC starts dirty.
    let (trunc_fh, _) = fs
        .open(
            context(),
            entry.inode,
            false,
            (LINUX_O_RDWR | LINUX_O_TRUNC) as u32,
        )
        .unwrap();
    let trunc_fh = trunc_fh.unwrap();
    assert!(
        fs.handle(entry.inode, trunc_fh)
            .unwrap()
            .dirty
            .load(Ordering::Acquire)
    );
    fs.flush(context(), entry.inode, trunc_fh, 0).unwrap();
    assert!(
        !fs.handle(entry.inode, trunc_fh)
            .unwrap()
            .dirty
            .load(Ordering::Acquire)
    );
    fs.release(context(), entry.inode, 0, trunc_fh, false, false, None)
        .unwrap();

    // Creating a new file starts dirty.
    let (created, created_fh, _) = fs
        .create(
            context(),
            ROOT_INODE,
            c"new.txt",
            S_IFREG | 0o644,
            false,
            (LINUX_O_CREAT | LINUX_O_RDWR) as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let created_fh = created_fh.unwrap();
    assert!(
        fs.handle(created.inode, created_fh)
            .unwrap()
            .dirty
            .load(Ordering::Acquire)
    );
    fs.flush(context(), created.inode, created_fh, 0).unwrap();
    assert!(
        !fs.handle(created.inode, created_fh)
            .unwrap()
            .dirty
            .load(Ordering::Acquire)
    );
    fs.release(context(), created.inode, 0, created_fh, false, false, None)
        .unwrap();
}

#[test]
fn host_error_maps_win32_codes_and_rate_limits_eio_and_ebusy() {
    assert_eq!(
        host_error(io::Error::from_raw_os_error(ERROR_FILE_NOT_FOUND)).raw_os_error(),
        Some(LINUX_ENOENT)
    );
    assert_eq!(
        host_error(io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION)).raw_os_error(),
        Some(LINUX_EBUSY)
    );
    assert_eq!(
        host_error(io::Error::from_raw_os_error(1392)).raw_os_error(),
        Some(LINUX_EIO)
    );

    // Deterministic per-code rate limiter check (monotonic timestamps).
    let mut limiter = ErrorRateLimiter::default();
    assert_eq!(limiter.record(Some(1392), 100), Some(0));
    assert_eq!(limiter.record(Some(1392), 200), None);
    assert_eq!(limiter.record(Some(1392), 900), None);
    // A distinct Win32 error code within the same second is NOT hidden by 1392.
    assert_eq!(limiter.record(Some(ERROR_SHARING_VIOLATION), 250), Some(0));
    assert_eq!(limiter.record(Some(ERROR_SHARING_VIOLATION), 500), None);
    // After 1000 ms, 1392 logs again and reports 2 suppressed events.
    assert_eq!(limiter.record(Some(1392), 1_100), Some(2));
    // ErrorKind-only (no raw Win32 code) uses the `None` bucket independently.
    assert_eq!(limiter.record(None, 300), Some(0));
    assert_eq!(limiter.record(None, 400), None);

    // Distinct numeric codes never grow the map beyond MAX_TRACKED_CODES (64).
    let mut bounded = ErrorRateLimiter::default();
    for code in 1..=100 {
        let _ = bounded.record(Some(code), 100);
    }
    assert_eq!(bounded.buckets.len(), ErrorRateLimiter::MAX_TRACKED_CODES);
}

#[test]
fn volume_without_hard_links_skips_per_child_identity_probe_on_missing_file_id() {
    use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;

    let temp = TempDir::new();
    std::fs::write(temp.path.join("real.txt"), b"hello").unwrap();

    let mut fs = PassthroughFs::new(PassthroughConfig {
        root_dir: temp.path.clone(),
        inject_init: false,
        stat_virtualization: StatVirtualization::Off,
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::empty()).unwrap();
    assert!(
        fs.supports_hard_links,
        "local NTFS temp volume should advertise FILE_SUPPORTS_HARD_LINKS"
    );

    let (dir_file, _) = fs
        .open_verified_handle(
            &fs.root,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_SHARE_ALL,
            NT_FILE_DIRECTORY_FILE,
        )
        .unwrap();

    // With hard-link support enabled, an absent FileId probes via `nt_open_relative`, so a
    // synthetic name that is absent on disk returns ENOENT and is skipped.
    let synthetic_info = WinFileInfo::from_dir_entry(FILE_ATTRIBUTE_NORMAL, 0, 0, 0, 0, None);
    let mut probed = Vec::new();
    fs.push_enumerated_child(
        &dir_file,
        &fs.root,
        std::ffi::OsStr::new("ghost-when-probed.txt"),
        synthetic_info,
        &mut probed,
    )
    .unwrap();
    assert!(probed.is_empty());

    // Simulate a NAS/FAT volume whose volume flags lack FILE_SUPPORTS_HARD_LINKS.
    fs.supports_hard_links = false;

    // A missing FileId must NOT invoke `nt_open_relative`, so the synthetic entry is interned
    // directly with a path-keyed inode (`identity: None`).
    let mut unprobed = Vec::new();
    fs.push_enumerated_child(
        &dir_file,
        &fs.root,
        std::ffi::OsStr::new("no-probe-needed.txt"),
        synthetic_info,
        &mut unprobed,
    )
    .unwrap();
    assert_eq!(unprobed.len(), 1);
    assert_eq!(unprobed[0].name, b"no-probe-needed.txt");
    let interned = fs.inode(unprobed[0].inode).unwrap();
    assert_eq!(interned.identity, None);

    // Fallback `FileFullDirectoryInfo` enumeration on the real directory still returns `real.txt`
    // cleanly without per-child probes.
    let (dir_file_full, _) = fs
        .open_verified_handle(
            &fs.root,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_SHARE_ALL,
            NT_FILE_DIRECTORY_FILE,
        )
        .unwrap();
    let mut full_entries = Vec::new();
    fs.read_dir_entries_full_info(&dir_file_full, &fs.root, &mut full_entries)
        .unwrap();
    assert_eq!(full_entries.len(), 1);
    assert_eq!(full_entries[0].name, b"real.txt");
}

#[test]
fn long_paths_over_max_path_resolve_enumerate_and_read() {
    let temp = TempDir::new();
    let canonical_root = std::fs::canonicalize(&temp.path).unwrap();

    // Build a nested directory path exceeding the 260-char Win32 MAX_PATH boundary (~310 chars).
    let seg = "nested_directory_segment_for_long_path_testing_0123456789";
    let mut deep = canonical_root.clone();
    for depth in 0..5 {
        deep.push(format!("{seg}_{depth}"));
    }
    std::fs::create_dir_all(&deep).unwrap();
    let file_path = deep.join("deep_evidence_artifact_over_max_path.txt");
    assert!(
        file_path.as_os_str().len() > 290,
        "expected >290-char path, got {}",
        file_path.as_os_str().len()
    );
    std::fs::write(&file_path, b"long-path-payload").unwrap();

    for no_symlink_root in [false, true] {
        // Test with non-verbatim root path when `no_symlink_root` is true to exercise
        // the `ERROR_FILENAME_EXCED_RANGE` / handle-relative fallback too.
        let root_input = if no_symlink_root {
            temp.path.clone()
        } else {
            canonical_root.clone()
        };
        let fs = PassthroughFs::new(PassthroughConfig {
            root_dir: root_input,
            no_symlink_root,
            inject_init: false,
            readonly: true,
            stat_virtualization: StatVirtualization::Off,
            ..Default::default()
        })
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();

        let mut parent = ROOT_INODE;
        for depth in 0..5 {
            let name = std::ffi::CString::new(format!("{seg}_{depth}")).unwrap();
            parent = fs.lookup(context(), parent, &name).unwrap().inode;
        }
        let (dir_fh, _) = fs
            .opendir(context(), parent, LINUX_O_DIRECTORY as u32)
            .unwrap();
        let dir_entries = fs
            .readdir(context(), parent, dir_fh.unwrap(), 4096, 0)
            .unwrap();
        assert!(
            dir_entries
                .iter()
                .any(|e| e.name == b"deep_evidence_artifact_over_max_path.txt")
        );
        fs.releasedir(context(), parent, 0, dir_fh.unwrap()).unwrap();

        let file_entry = fs
            .lookup(context(), parent, c"deep_evidence_artifact_over_max_path.txt")
            .unwrap();
        let (fh, _) = fs.open(context(), file_entry.inode, false, 0).unwrap();
        let mut writer = CaptureWriter { bytes: Vec::new() };
        fs.read(
            context(),
            file_entry.inode,
            fh.unwrap(),
            &mut writer,
            64,
            0,
            None,
            0,
        )
        .unwrap();
        assert_eq!(writer.bytes, b"long-path-payload");
        fs.release(context(), file_entry.inode, 0, fh.unwrap(), false, false, None)
            .unwrap();
    }
}

#[test]
fn init_negotiates_readdirplus_only_when_allowed_by_mode_and_config() {
    let temp = TempDir::new();
    let caps = FsOptions::DO_READDIRPLUS | FsOptions::READDIRPLUS_AUTO;

    assert_eq!(ReaddirplusMode::parse("on"), ReaddirplusMode::On);
    assert_eq!(ReaddirplusMode::parse("1"), ReaddirplusMode::On);
    assert_eq!(ReaddirplusMode::parse("TRUE"), ReaddirplusMode::On);
    assert_eq!(ReaddirplusMode::parse("off"), ReaddirplusMode::Off);
    assert_eq!(ReaddirplusMode::parse("0"), ReaddirplusMode::Off);
    assert_eq!(ReaddirplusMode::parse("false"), ReaddirplusMode::Off);
    assert_eq!(ReaddirplusMode::parse("auto"), ReaddirplusMode::Auto);
    assert_eq!(ReaddirplusMode::parse("unknown"), ReaddirplusMode::Auto);

    // Auto + readonly + stat_virtualization Off => DO_READDIRPLUS enabled (without READDIRPLUS_AUTO).
    let mut ro_off = PassthroughFs::new(PassthroughConfig {
        root_dir: temp.path.clone(),
        inject_init: false,
        readonly: true,
        stat_virtualization: StatVirtualization::Off,
        ..Default::default()
    })
    .unwrap();
    ro_off.readdirplus_mode = ReaddirplusMode::Auto;
    let opts = ro_off.init(caps).unwrap();
    assert!(opts.contains(FsOptions::DO_READDIRPLUS));
    assert!(!opts.contains(FsOptions::READDIRPLUS_AUTO));
    assert_eq!(ro_off.init(FsOptions::empty()).unwrap(), FsOptions::empty());

    // Auto + Off kill-switch => disabled.
    ro_off.readdirplus_mode = ReaddirplusMode::Off;
    assert!(!ro_off.init(caps).unwrap().contains(FsOptions::DO_READDIRPLUS));

    // Auto + writable => disabled; explicit On => enabled.
    let mut rw_off = PassthroughFs::new(PassthroughConfig {
        root_dir: temp.path.clone(),
        inject_init: false,
        readonly: false,
        stat_virtualization: StatVirtualization::Off,
        ..Default::default()
    })
    .unwrap();
    rw_off.readdirplus_mode = ReaddirplusMode::Auto;
    assert!(!rw_off.init(caps).unwrap().contains(FsOptions::DO_READDIRPLUS));
    rw_off.readdirplus_mode = ReaddirplusMode::On;
    assert!(rw_off.init(caps).unwrap().contains(FsOptions::DO_READDIRPLUS));

    // Auto + readonly + Strict stat virtualization => disabled.
    let mut ro_strict = PassthroughFs::new(PassthroughConfig {
        root_dir: temp.path.clone(),
        inject_init: false,
        readonly: true,
        stat_virtualization: StatVirtualization::Strict,
        ..Default::default()
    })
    .unwrap();
    ro_strict.readdirplus_mode = ReaddirplusMode::Auto;
    assert!(!ro_strict.init(caps).unwrap().contains(FsOptions::DO_READDIRPLUS));
}

#[test]
fn readdirplus_uses_cached_dir_entry_info_and_detects_stale_size_on_open() {
    let temp = TempDir::new();
    let growing = temp.path.join("growing.bin");
    let steady = temp.path.join("steady.bin");
    std::fs::write(&growing, b"initial-10").unwrap();
    std::fs::write(&steady, b"unchanged").unwrap();

    // Keep an open host write handle on `growing.bin` while appending so NTFS directory
    // metadata can lag behind the live MFT file size.
    let mut host_writer = StdOpenOptions::new()
        .write(true)
        .append(true)
        .open(&growing)
        .unwrap();

    let fs = PassthroughFs::new(PassthroughConfig {
        root_dir: temp.path.clone(),
        inject_init: false,
        readonly: true,
        stat_virtualization: StatVirtualization::Off,
        ..Default::default()
    })
    .unwrap();
    fs.init(FsOptions::DO_READDIRPLUS).unwrap();

    // Enumerate via readdirplus before the host append.
    let (dh, _) = fs
        .opendir(context(), ROOT_INODE, LINUX_O_DIRECTORY as u32)
        .unwrap();
    let entries = fs
        .readdirplus(context(), ROOT_INODE, dh.unwrap(), 4096, 0)
        .unwrap();
    fs.releasedir(context(), ROOT_INODE, 0, dh.unwrap()).unwrap();

    let (_, steady_entry) = entries
        .iter()
        .find(|(de, _)| de.name == b"steady.bin")
        .unwrap();
    let (_, growing_entry) = entries
        .iter()
        .find(|(de, _)| de.name == b"growing.bin")
        .unwrap();
    assert_eq!(steady_entry.attr.st_size, 9);
    assert_eq!(growing_entry.attr.st_size, 10);

    // Unchanged file opens with normal page-cache options (not DIRECT_IO).
    let (steady_fh, steady_opts) = fs.open(context(), steady_entry.inode, false, 0).unwrap();
    assert!(!steady_opts.contains(OpenOptions::DIRECT_IO));
    fs.release(
        context(),
        steady_entry.inode,
        0,
        steady_fh.unwrap(),
        false,
        false,
        None,
    )
    .unwrap();

    // Append bytes via the still-open host writer, then open the file via FUSE.
    host_writer.write_all(b"-plus-more-bytes").unwrap();
    host_writer.flush().unwrap();

    let (growing_fh, growing_opts) = fs.open(context(), growing_entry.inode, false, 0).unwrap();
    assert!(
        growing_opts.contains(OpenOptions::DIRECT_IO),
        "stale directory-entry size must trigger FOPEN_DIRECT_IO so Linux FUSE does not truncate"
    );
    let mut writer = CaptureWriter { bytes: Vec::new() };
    fs.read(
        context(),
        growing_entry.inode,
        growing_fh.unwrap(),
        &mut writer,
        64,
        0,
        None,
        0,
    )
    .unwrap();
    assert_eq!(writer.bytes, b"initial-10-plus-more-bytes");
    fs.release(
        context(),
        growing_entry.inode,
        0,
        growing_fh.unwrap(),
        false,
        false,
        None,
    )
    .unwrap();

    // After open/getattr refreshes the inode, a subsequent open returns normal cached options.
    let (live_stat, _) = fs.getattr(context(), growing_entry.inode, None).unwrap();
    assert_eq!(live_stat.st_size, 26);
    let (fh2, opts2) = fs.open(context(), growing_entry.inode, false, 0).unwrap();
    assert!(!opts2.contains(OpenOptions::DIRECT_IO));
    fs.release(
        context(),
        growing_entry.inode,
        0,
        fh2.unwrap(),
        false,
        false,
        None,
    )
    .unwrap();
}
