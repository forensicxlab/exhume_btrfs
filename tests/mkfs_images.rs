#![cfg(unix)]

//! Comparison of the reader against images produced by `mkfs.btrfs --rootdir`.
//!
//! These tests need `mkfs.btrfs` (btrfs-progs >= 6.x with `--compress` and
//! `--subvol`) and are `#[ignore]`d by default:
//!
//! ```sh
//! cargo test --test mkfs_images -- --ignored
//! # or against a prebuilt sample set (manifest.tsv: image<TAB>srcdir<TAB>options)
//! EXHUME_BTRFS_SAMPLES=/path/to/images cargo test --test mkfs_images -- --ignored
//! ```

use exhume_btrfs::BtrfsFS;
use exhume_btrfs::dir::FT_DIR;
use exhume_btrfs::inode::Inode;
use exhume_btrfs::key::FS_TREE_OBJECTID;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

fn mkfs_available() -> bool {
    Command::new("mkfs.btrfs")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Deterministic pseudo-random bytes.
fn prng(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn write(path: &Path, data: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, data).unwrap();
}

/// Build the source tree the images are filled from.
fn build_source_tree(src: &Path) {
    write(&src.join("empty.txt"), b"");
    write(&src.join("tiny.txt"), b"hello btrfs\n");
    write(&src.join("inline_2k.bin"), &prng(1, 2000));
    write(&src.join("sector_4096.bin"), &prng(2, 4096));
    write(&src.join("sector_4097.bin"), &prng(3, 4097));
    let text: Vec<u8> = b"the quick brown fox jumps over the lazy dog \n"
        .iter()
        .cycle()
        .take(200_000)
        .copied()
        .collect();
    write(&src.join("docs/compressible.txt"), &text);
    let mut zeros = vec![0u8; 300_000];
    zeros.extend_from_slice(b"end");
    write(&src.join("docs/repeated_zeros.bin"), &zeros);
    write(&src.join("data/random_1m.bin"), &prng(4, 1_000_003));
    let mut mixed = text[..150_000].to_vec();
    mixed.extend(prng(5, 150_000));
    mixed.extend_from_slice(&text[..70_000]);
    write(&src.join("data/mixed.bin"), &mixed);
    {
        fs::create_dir_all(src.join("data")).unwrap();
        let mut f = File::create(src.join("data/sparse.bin")).unwrap();
        f.write_all(&b"head".repeat(1024)).unwrap();
        f.seek(SeekFrom::Start(3 * 1024 * 1024 + 4096)).unwrap();
        f.write_all(&b"tail".repeat(1024)).unwrap();
    }
    for i in 0..600 {
        write(
            &src.join(format!("many/f{i:04}.txt")),
            &format!("file {i}\n").repeat(1 + i % 5).into_bytes(),
        );
    }
    for d in 0..20 {
        for j in 0..5 {
            write(
                &src.join(format!("tree/d{d:02}/sub/leaf{j}.dat")),
                &[d as u8, j as u8].repeat(10 + d),
            );
        }
    }
    let deep: PathBuf = (0..30).fold(src.join("deep"), |p, i| p.join(format!("l{i}")));
    write(&deep.join("bottom.txt"), b"bottom\n");
    write(&src.join("names/été.txt"), b"accent\n");
    write(&src.join("names/日本語.txt"), b"japanese\n");
    write(&src.join("names/with space and 'quote'.txt"), b"space\n");
    write(
        &src.join(format!("names/{}", "x".repeat(255))),
        b"longname\n",
    );
    write(&src.join("perm/exec.sh"), b"#!/bin/sh\necho hi\n");
    fs::set_permissions(src.join("perm/exec.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    write(&src.join("perm/setuid.bin"), b"\x7fELF");
    fs::set_permissions(
        src.join("perm/setuid.bin"),
        fs::Permissions::from_mode(0o4755),
    )
    .unwrap();
    fs::create_dir_all(src.join("links")).unwrap();
    std::os::unix::fs::symlink("../tiny.txt", src.join("links/rel_link")).unwrap();
    std::os::unix::fs::symlink("/etc/hostname", src.join("links/abs_link")).unwrap();
    std::os::unix::fs::symlink("nowhere", src.join("links/dangling")).unwrap();
    fs::hard_link(src.join("tiny.txt"), src.join("links/hard_tiny")).unwrap();
    fs::hard_link(
        src.join("data/random_1m.bin"),
        src.join("links/hard_random"),
    )
    .unwrap();
    write(&src.join("subvols/data/project/readme.md"), b"# project\n");
    write(&src.join("subvols/data/project/big.bin"), &prng(6, 300_000));
    write(
        &src.join("subvols/data/nested/inner/file.txt"),
        b"nested subvolume file\n",
    );
    write(
        &src.join("subvols/ro_snapshotlike/config.ini"),
        b"[a]\nb=c\n",
    );
    write(
        &src.join("subvols/default_root/hello.txt"),
        b"from the default subvolume\n",
    );
}

const SUBVOL_ARGS: &[&str] = &[
    "--subvol",
    "rw:subvols/data",
    "--subvol",
    "rw:subvols/data/nested",
    "--subvol",
    "ro:subvols/ro_snapshotlike",
    "--subvol",
    "default:subvols/default_root",
];

fn mkfs(image: &Path, src: &Path, size: &str, extra: &[&str]) {
    let f = File::create(image).unwrap();
    let bytes: u64 = match size.strip_suffix('M') {
        Some(m) => m.parse::<u64>().unwrap() << 20,
        None => size.parse().unwrap(),
    };
    f.set_len(bytes).unwrap();
    let out = Command::new("mkfs.btrfs")
        .args(["-q", "-f", "-r"])
        .arg(src)
        .args(extra)
        .arg(image)
        .output()
        .expect("mkfs.btrfs");
    assert!(
        out.status.success(),
        "mkfs.btrfs {:?} failed: {}",
        extra,
        String::from_utf8_lossy(&out.stderr)
    );
}

fn open(image: &Path) -> BtrfsFS<File> {
    BtrfsFS::new(File::open(image).unwrap())
        .unwrap_or_else(|e| panic!("open {}: {e}", image.display()))
}

/// Compare every entry of `src` with the filesystem, recursively.
fn compare_tree(
    fs: &mut BtrfsFS<File>,
    src_root: &Path,
    dir: &Path,
    fs_dir: &Inode,
    stats: &mut BTreeMap<&'static str, usize>,
) {
    let mut entries: BTreeMap<String, fs::DirEntry> = BTreeMap::new();
    for e in fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        entries.insert(e.file_name().to_string_lossy().into_owned(), e);
    }
    let listed = fs.list_dir(fs_dir).unwrap();
    let listed_names: BTreeMap<String, _> = listed.iter().map(|e| (e.name.clone(), e)).collect();
    assert_eq!(
        listed_names.keys().collect::<Vec<_>>(),
        entries.keys().collect::<Vec<_>>(),
        "directory listing mismatch in {}",
        dir.display()
    );
    for (name, entry) in &entries {
        let meta = fs::symlink_metadata(entry.path()).unwrap();
        let de = listed_names[name];
        let inode = fs.resolve_entry(de).unwrap();
        // Path-based lookup must agree with the listing.
        let rel = entry
            .path()
            .strip_prefix(src_root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let by_path = fs.resolve_path(&format!("/{rel}")).unwrap();
        assert_eq!(
            (by_path.tree_id, by_path.ino),
            (inode.tree_id, inode.ino),
            "path lookup of /{rel}"
        );
        let path_back = fs.inode_path(inode.tree_id, inode.ino).unwrap();
        if meta.nlink() == 1 || meta.is_dir() {
            assert_eq!(
                path_back,
                format!("/{rel}"),
                "path reconstruction of /{rel}"
            );
        }
        // Mode bits.
        assert_eq!(inode.mode() & 0o7777, meta.mode() & 0o7777, "mode of {rel}");
        if meta.file_type().is_symlink() {
            assert!(inode.is_symlink(), "{rel} should be a symlink");
            let target = fs::read_link(entry.path()).unwrap();
            assert_eq!(
                fs.read_symlink(&inode).unwrap(),
                target.to_string_lossy(),
                "symlink target of {rel}"
            );
            *stats.entry("symlinks").or_default() += 1;
        } else if meta.is_dir() {
            assert!(inode.is_dir(), "{rel} should be a directory");
            if de.is_subvolume() {
                assert_eq!(de.file_type, FT_DIR);
                assert_ne!(
                    inode.tree_id, fs_dir.tree_id,
                    "subvolume {rel} must switch tree"
                );
                *stats.entry("subvolumes").or_default() += 1;
            }
            compare_tree(fs, src_root, &entry.path(), &inode, stats);
            *stats.entry("dirs").or_default() += 1;
        } else if meta.is_file() {
            assert!(inode.is_regular_file(), "{rel} should be a regular file");
            assert_eq!(inode.size(), meta.len(), "size of {rel}");
            if meta.len() > 64 << 20 {
                // Large (sparse) file: compare by 4 MiB windows instead of one read.
                use std::io::Read;
                let mut src_file = File::open(entry.path()).unwrap();
                let mut buf = vec![0u8; 4 << 20];
                let mut off = 0u64;
                while off < meta.len() {
                    let want = ((meta.len() - off) as usize).min(buf.len());
                    src_file.seek(SeekFrom::Start(off)).unwrap();
                    src_file.read_exact(&mut buf[..want]).unwrap();
                    let got = fs.read_inode_slice(&inode, off, want).unwrap();
                    assert!(
                        got == buf[..want],
                        "content of {rel} differs at offset {off}"
                    );
                    off += want as u64;
                }
                assert!(
                    fs.read_inode(&inode).is_err() || meta.len() <= exhume_btrfs::MAX_READ_BYTES
                );
                *stats.entry("files").or_default() += 1;
                *stats.entry("large_files").or_default() += 1;
                continue;
            }
            let expected = fs::read(entry.path()).unwrap();
            let got = fs.read_inode(&inode).unwrap();
            assert!(
                got == expected,
                "content of {rel} differs ({} vs {} bytes)",
                got.len(),
                expected.len()
            );
            // Slice reads: a window in the middle and a window across the end.
            if expected.len() > 10 {
                let off = expected.len() as u64 / 3;
                let len = (expected.len() / 2).max(1);
                let slice = fs.read_inode_slice(&inode, off, len).unwrap();
                assert_eq!(
                    slice,
                    &expected[off as usize..(off as usize + len).min(expected.len())],
                    "slice of {rel}"
                );
                let tail = fs
                    .read_inode_slice(&inode, expected.len() as u64 - 5, 100)
                    .unwrap();
                assert_eq!(tail, &expected[expected.len() - 5..], "tail slice of {rel}");
                assert!(
                    fs.read_inode_slice(&inode, expected.len() as u64 + 1, 10)
                        .unwrap()
                        .is_empty()
                );
            }
            assert_eq!(
                fs.read_inode_prefix(&inode, 7).unwrap(),
                &expected[..expected.len().min(7)]
            );
            if meta.nlink() > 1 {
                assert_eq!(inode.nlink() as u64, meta.nlink(), "nlink of {rel}");
                assert_eq!(
                    fs.inode_refs(&inode).unwrap().len() as u64,
                    meta.nlink(),
                    "inode refs of {rel}"
                );
                *stats.entry("hardlinks").or_default() += 1;
            }
            *stats.entry("files").or_default() += 1;
            *stats.entry("bytes").or_default() += expected.len();
        } else {
            assert!(inode.is_special(), "{rel} should be a special file");
            *stats.entry("special").or_default() += 1;
        }
    }
}

fn check_image(image: &Path, src: &Path, has_subvols: bool) -> BTreeMap<&'static str, usize> {
    let mut fs = open(image);
    let root = fs.get_root().unwrap();
    assert_eq!((root.tree_id, root.ino), (FS_TREE_OBJECTID, 256));
    let mut stats = BTreeMap::new();
    compare_tree(&mut fs, src, src, &root, &mut stats);
    if has_subvols {
        let subs = fs.subvolumes();
        let by_path: BTreeMap<&str, _> = subs.iter().map(|s| (s.path.as_str(), s)).collect();
        assert!(
            by_path.contains_key("/subvols/data"),
            "subvolume list: {:?}",
            by_path.keys()
        );
        assert!(by_path.contains_key("/subvols/data/nested"));
        assert!(by_path["/subvols/ro_snapshotlike"].readonly);
        assert!(!by_path["/subvols/data"].readonly);
        assert!(by_path["/subvols/default_root"].is_default);
        assert_eq!(fs.default_subvolume(), by_path["/subvols/default_root"].id);
        assert_eq!(
            by_path["/subvols/data/nested"].parent_id,
            Some(by_path["/subvols/data"].id)
        );
        assert!(subs.iter().all(|s| s.readable));
        // Every subvolume must be reachable through a packed identifier.
        let subs_owned = subs.to_vec();
        for s in subs_owned {
            let slot = fs.subvolume_slot(s.id).unwrap();
            let inode = fs
                .get_inode_packed(exhume_btrfs::pack_id(slot, s.root_dirid).unwrap())
                .unwrap();
            assert_eq!(inode.tree_id, s.id);
        }
    }
    // The metadata rendering must not panic.
    let _ = fs.metadata_pretty();
    let _ = fs.metadata_json();
    stats
}

#[test]
#[ignore]
fn mkfs_variants_match_source_tree() {
    if !mkfs_available() {
        eprintln!("mkfs.btrfs not found, skipping");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    build_source_tree(&src);
    let variants: Vec<(&str, &str, Vec<&str>)> = vec![
        ("plain", "64M", vec![]),
        ("zstd", "64M", vec!["--compress", "zstd:3"]),
        ("lzo", "64M", vec!["--compress", "lzo"]),
        ("zlib", "64M", vec!["--compress", "zlib:6"]),
        ("dup", "96M", vec!["-m", "dup", "-d", "dup"]),
        ("xxhash", "64M", vec!["--csum", "xxhash"]),
        ("sha256", "64M", vec!["--csum", "sha256"]),
        ("blake2", "64M", vec!["--csum", "blake2"]),
        ("node4k", "64M", vec!["-n", "4096", "--compress", "zstd:1"]),
        ("node64k", "64M", vec!["-n", "65536"]),
        ("holes", "64M", vec!["-O", "^no-holes"]),
        ("mixedbg", "64M", vec!["-M"]),
        ("shrink", "64M", vec!["--shrink"]),
    ];
    for (name, size, extra) in variants {
        let image = tmp.path().join(format!("{name}.img"));
        let mut args: Vec<&str> = SUBVOL_ARGS.to_vec();
        args.extend(extra.iter());
        mkfs(&image, &src, size, &args);
        let stats = check_image(&image, &src, true);
        eprintln!("{name}: {stats:?}");
        assert!(stats["files"] > 700 && stats["subvolumes"] == 4 && stats["symlinks"] == 3);
    }
}

#[test]
#[ignore]
fn prebuilt_samples_match_their_source_trees() {
    let Ok(dir) = std::env::var("EXHUME_BTRFS_SAMPLES") else {
        eprintln!("EXHUME_BTRFS_SAMPLES not set, skipping");
        return;
    };
    let manifest = fs::read_to_string(Path::new(&dir).join("manifest.tsv")).expect("manifest.tsv");
    let mut checked = 0;
    for line in manifest.lines().filter(|l| !l.trim().is_empty()) {
        let mut cols = line.split('\t');
        let image = Path::new(&dir).join(cols.next().unwrap());
        let src = PathBuf::from(cols.next().unwrap());
        let options = cols.next().unwrap_or("");
        let has_subvols = options.contains("--subvol");
        let stats = check_image(&image, &src, has_subvols);
        eprintln!("{}: {stats:?}", image.display());
        checked += 1;
    }
    assert!(checked > 0);
}

#[test]
#[ignore]
fn corrupted_mkfs_images_never_panic() {
    if !mkfs_available() {
        eprintln!("mkfs.btrfs not found, skipping");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    build_source_tree(&src);
    let image = tmp.path().join("fuzz.img");
    let mut args: Vec<&str> = SUBVOL_ARGS.to_vec();
    args.extend(["--compress", "zstd:1", "-n", "4096"]);
    mkfs(&image, &src, "64M", &args);
    let pristine = fs::read(&image).unwrap();
    // Metadata lives in the chunks listed by the pristine filesystem: corrupt
    // bytes there (and in the superblock) rather than in unused space.
    let mut ranges: Vec<(u64, u64)> = vec![(0x10000, 4096)];
    {
        let fs = open(&image);
        for c in fs.chunks().chunks() {
            for s in &c.stripes {
                ranges.push((s.offset, c.length.min(8 << 20)));
            }
        }
    }
    let mut seed = 0x1234_5678_9ABC_DEF0u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut opened = 0;
    for round in 0..400 {
        let mut data = pristine.clone();
        let flips = 1 + (next() % 16) as usize;
        for _ in 0..flips {
            let (start, len) = ranges[(next() % ranges.len() as u64) as usize];
            let pos = (start + next() % len) as usize;
            if pos < data.len() {
                data[pos] ^= (1u8 << (next() % 8)).max(1);
            }
        }
        if round % 3 == 0 {
            // Also truncate the image at a random point.
            let cut = (next() % data.len() as u64) as usize;
            data.truncate(cut.max(0x11000));
        }
        let cursor = std::io::Cursor::new(data);
        let tolerate = round % 2 == 1;
        if let Ok(mut fs) = BtrfsFS::open(cursor, tolerate) {
            {
                opened += 1;
                let _ = fs.metadata_json();
                if let Ok(root) = fs.get_root()
                    && let Ok(entries) = fs.list_dir(&root)
                {
                    for e in entries.iter().take(40) {
                        if let Ok(inode) = fs.resolve_entry(e) {
                            if inode.is_dir() {
                                let _ = fs.list_dir(&inode);
                            } else {
                                let _ = fs.read_inode_prefix(&inode, 70000);
                                let _ = fs.extents(&inode);
                            }
                            let _ = fs.inode_path(inode.tree_id, inode.ino);
                            let _ = fs.xattrs(&inode);
                        }
                    }
                }
                let _ = fs.resolve_path("/data/random_1m.bin");
                let _ = fs.resolve_path("/subvols/data/project/big.bin");
            }
        }
    }
    eprintln!("{opened}/400 corrupted images still opened");
}
