//! Self-contained tests on hand-built Btrfs images: every structure (super-
//! block, chunk tree, root tree, file trees, checksums) is written by the
//! test itself, so these run without btrfs-progs and can exercise error
//! paths that no tool will produce (loops, bad pointers, unknown features).

use exhume_btrfs::checksum::{self, CSUM_TYPE_CRC32C};
use exhume_btrfs::chunk::{BLOCK_GROUP_DATA, BLOCK_GROUP_METADATA, BLOCK_GROUP_SYSTEM};
use exhume_btrfs::dir::{FT_DIR, FT_REG_FILE, FT_SYMLINK};
use exhume_btrfs::extent::{
    COMPRESS_NONE, COMPRESS_ZLIB, COMPRESS_ZSTD, FILE_EXTENT_INLINE, FILE_EXTENT_PREALLOC,
    FILE_EXTENT_REG,
};
use exhume_btrfs::inode::{S_IFDIR, S_IFLNK, S_IFREG};
use exhume_btrfs::key::*;
use exhume_btrfs::superblock::{
    FEATURE_INCOMPAT_NO_HOLES, FEATURE_INCOMPAT_ZONED, SUPERBLOCK_MAGIC,
};
use exhume_btrfs::{BtrfsFS, pack_id};
use std::collections::BTreeMap;
use std::io::{Cursor, Write};

const SECTOR: u32 = 4096;
const NODESIZE: u32 = 4096;
const HEADER: usize = 101;
/// Logical address space starts here and maps 1:1 onto the image.
const BASE: u64 = 1 << 20;
const FSID: [u8; 16] = [0x11; 16];

// ---------------------------------------------------------------------------
// Encoders
// ---------------------------------------------------------------------------

fn timespec(sec: u64, nsec: u32) -> Vec<u8> {
    let mut v = sec.to_le_bytes().to_vec();
    v.extend_from_slice(&nsec.to_le_bytes());
    v
}

fn inode_item(mode: u32, size: u64, nlink: u32, flags: u64) -> Vec<u8> {
    let mut d = vec![0u8; 160];
    d[0..8].copy_from_slice(&1u64.to_le_bytes()); // generation
    d[8..16].copy_from_slice(&1u64.to_le_bytes()); // transid
    d[16..24].copy_from_slice(&size.to_le_bytes());
    d[24..32].copy_from_slice(&size.to_le_bytes()); // nbytes
    d[40..44].copy_from_slice(&nlink.to_le_bytes());
    d[44..48].copy_from_slice(&1000u32.to_le_bytes()); // uid
    d[48..52].copy_from_slice(&1001u32.to_le_bytes()); // gid
    d[52..56].copy_from_slice(&mode.to_le_bytes());
    d[64..72].copy_from_slice(&flags.to_le_bytes());
    d[0x70..0x7C].copy_from_slice(&timespec(1_600_000_000, 1));
    d[0x7C..0x88].copy_from_slice(&timespec(1_600_000_001, 2));
    d[0x88..0x94].copy_from_slice(&timespec(1_600_000_002, 3));
    d[0x94..0xA0].copy_from_slice(&timespec(1_500_000_000, 4));
    d
}

fn dir_item(location: Key, ty: u8, name: &[u8], data: &[u8]) -> Vec<u8> {
    let mut d = location.to_bytes().to_vec();
    d.extend_from_slice(&1u64.to_le_bytes());
    d.extend_from_slice(&(data.len() as u16).to_le_bytes());
    d.extend_from_slice(&(name.len() as u16).to_le_bytes());
    d.push(ty);
    d.extend_from_slice(name);
    d.extend_from_slice(data);
    d
}

fn inode_ref(index: u64, name: &[u8]) -> Vec<u8> {
    let mut d = index.to_le_bytes().to_vec();
    d.extend_from_slice(&(name.len() as u16).to_le_bytes());
    d.extend_from_slice(name);
    d
}

fn extent_inline(compression: u8, ram_bytes: u64, data: &[u8]) -> Vec<u8> {
    let mut d = vec![0u8; 21];
    d[0..8].copy_from_slice(&1u64.to_le_bytes());
    d[8..16].copy_from_slice(&ram_bytes.to_le_bytes());
    d[16] = compression;
    d[20] = FILE_EXTENT_INLINE;
    d.extend_from_slice(data);
    d
}

fn extent_regular(
    ty: u8,
    compression: u8,
    ram_bytes: u64,
    disk_bytenr: u64,
    disk_num_bytes: u64,
    offset: u64,
    num_bytes: u64,
) -> Vec<u8> {
    let mut d = vec![0u8; 53];
    d[0..8].copy_from_slice(&1u64.to_le_bytes());
    d[8..16].copy_from_slice(&ram_bytes.to_le_bytes());
    d[16] = compression;
    d[20] = ty;
    d[21..29].copy_from_slice(&disk_bytenr.to_le_bytes());
    d[29..37].copy_from_slice(&disk_num_bytes.to_le_bytes());
    d[37..45].copy_from_slice(&offset.to_le_bytes());
    d[45..53].copy_from_slice(&num_bytes.to_le_bytes());
    d
}

fn root_item(bytenr: u64, level: u8, flags: u64, uuid: u8, parent_uuid: u8) -> Vec<u8> {
    let mut d = vec![0u8; 439];
    d[..160].copy_from_slice(&inode_item(S_IFDIR | 0o755, 3, 1, 0));
    d[0xA0..0xA8].copy_from_slice(&1u64.to_le_bytes());
    d[0xEF..0xF7].copy_from_slice(&1u64.to_le_bytes()); // generation_v2 == generation
    d[0xA8..0xB0].copy_from_slice(&256u64.to_le_bytes()); // root_dirid
    d[0xB0..0xB8].copy_from_slice(&bytenr.to_le_bytes());
    d[0xD0..0xD8].copy_from_slice(&flags.to_le_bytes());
    d[0xD8..0xDC].copy_from_slice(&1u32.to_le_bytes());
    d[0xEE] = level;
    d[0xF7..0x107].copy_from_slice(&[uuid; 16]);
    d[0x107..0x117].copy_from_slice(&[parent_uuid; 16]);
    d[0x153..0x15F].copy_from_slice(&timespec(1_650_000_000, 0));
    d
}

fn root_ref(dirid: u64, sequence: u64, name: &[u8]) -> Vec<u8> {
    let mut d = dirid.to_le_bytes().to_vec();
    d.extend_from_slice(&sequence.to_le_bytes());
    d.extend_from_slice(&(name.len() as u16).to_le_bytes());
    d.extend_from_slice(name);
    d
}

fn chunk_item(length: u64, ty: u64, stripes: &[(u64, u64)]) -> Vec<u8> {
    let mut d = vec![0u8; 48];
    d[0..8].copy_from_slice(&length.to_le_bytes());
    d[8..16].copy_from_slice(&2u64.to_le_bytes());
    d[16..24].copy_from_slice(&65536u64.to_le_bytes());
    d[24..32].copy_from_slice(&ty.to_le_bytes());
    d[32..36].copy_from_slice(&SECTOR.to_le_bytes());
    d[36..40].copy_from_slice(&SECTOR.to_le_bytes());
    d[40..44].copy_from_slice(&SECTOR.to_le_bytes());
    d[44..46].copy_from_slice(&(stripes.len() as u16).to_le_bytes());
    for (devid, offset) in stripes {
        d.extend_from_slice(&devid.to_le_bytes());
        d.extend_from_slice(&offset.to_le_bytes());
        d.extend_from_slice(&[0x22; 16]);
    }
    d
}

fn dev_item(devid: u64, total: u64) -> Vec<u8> {
    let mut d = vec![0u8; 98];
    d[0..8].copy_from_slice(&devid.to_le_bytes());
    d[8..16].copy_from_slice(&total.to_le_bytes());
    d[0x20..0x24].copy_from_slice(&SECTOR.to_le_bytes());
    d[0x42..0x52].copy_from_slice(&[0x22; 16]);
    d[0x52..0x62].copy_from_slice(&FSID);
    d
}

// ---------------------------------------------------------------------------
// Image builder
// ---------------------------------------------------------------------------

struct Image {
    data: Vec<u8>,
    next: u64,
    csum_type: u16,
}

impl Image {
    fn new(size: usize) -> Self {
        Image {
            data: vec![0u8; size],
            next: BASE,
            csum_type: CSUM_TYPE_CRC32C,
        }
    }

    fn alloc(&mut self, len: u64) -> u64 {
        let at = self.next;
        self.next += len.div_ceil(NODESIZE as u64) * NODESIZE as u64;
        assert!(
            self.next as usize <= self.data.len(),
            "synthetic image too small"
        );
        at
    }

    fn write_data(&mut self, bytes: &[u8]) -> u64 {
        let at = self.alloc(bytes.len().max(1) as u64);
        self.data[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
        at
    }

    fn header(node: &mut [u8], bytenr: u64, owner: u64, nritems: u32, level: u8) {
        node[0x20..0x30].copy_from_slice(&FSID);
        node[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
        node[0x38..0x40].copy_from_slice(&1u64.to_le_bytes());
        node[0x40..0x50].copy_from_slice(&[0x33; 16]);
        node[0x50..0x58].copy_from_slice(&1u64.to_le_bytes());
        node[0x58..0x60].copy_from_slice(&owner.to_le_bytes());
        node[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
        node[0x64] = level;
    }

    fn seal(&mut self, bytenr: u64, mut node: Vec<u8>) -> u64 {
        let sum = checksum::compute(self.csum_type, &node[32..]).unwrap();
        node[..32].copy_from_slice(&sum);
        self.data[bytenr as usize..bytenr as usize + node.len()].copy_from_slice(&node);
        bytenr
    }

    fn write_leaf_at(&mut self, bytenr: u64, owner: u64, items: &[(Key, Vec<u8>)]) -> u64 {
        let mut node = vec![0u8; NODESIZE as usize];
        Self::header(&mut node, bytenr, owner, items.len() as u32, 0);
        let mut data_end = NODESIZE as usize - HEADER;
        for (i, (key, data)) in items.iter().enumerate() {
            data_end -= data.len();
            let base = HEADER + i * 25;
            node[base..base + 17].copy_from_slice(&key.to_bytes());
            node[base + 17..base + 21].copy_from_slice(&(data_end as u32).to_le_bytes());
            node[base + 21..base + 25].copy_from_slice(&(data.len() as u32).to_le_bytes());
            node[HEADER + data_end..HEADER + data_end + data.len()].copy_from_slice(data);
        }
        self.seal(bytenr, node)
    }

    fn write_leaf(&mut self, owner: u64, items: &[(Key, Vec<u8>)]) -> u64 {
        let at = self.alloc(NODESIZE as u64);
        self.write_leaf_at(at, owner, items)
    }

    fn write_internal_at(
        &mut self,
        bytenr: u64,
        owner: u64,
        level: u8,
        ptrs: &[(Key, u64)],
    ) -> u64 {
        let mut node = vec![0u8; NODESIZE as usize];
        Self::header(&mut node, bytenr, owner, ptrs.len() as u32, level);
        for (i, (key, blockptr)) in ptrs.iter().enumerate() {
            let base = HEADER + i * 33;
            node[base..base + 17].copy_from_slice(&key.to_bytes());
            node[base + 17..base + 25].copy_from_slice(&blockptr.to_le_bytes());
            node[base + 25..base + 33].copy_from_slice(&1u64.to_le_bytes());
        }
        self.seal(bytenr, node)
    }

    fn write_internal(&mut self, owner: u64, level: u8, ptrs: &[(Key, u64)]) -> u64 {
        let at = self.alloc(NODESIZE as u64);
        self.write_internal_at(at, owner, level, ptrs)
    }

    /// Write a whole tree from sorted items, `per_node` entries per node.
    fn write_tree(
        &mut self,
        owner: u64,
        items: &BTreeMap<Key, Vec<u8>>,
        per_node: usize,
    ) -> (u64, u8) {
        let items: Vec<(Key, Vec<u8>)> = items.iter().map(|(k, v)| (*k, v.clone())).collect();
        let mut ptrs: Vec<(Key, u64)> = items
            .chunks(per_node.max(1))
            .map(|chunk| (chunk[0].0, self.write_leaf(owner, chunk)))
            .collect();
        if ptrs.is_empty() {
            return (self.write_leaf(owner, &[]), 0);
        }
        let mut level = 0u8;
        while ptrs.len() > 1 {
            level += 1;
            ptrs = ptrs
                .chunks(per_node.max(2))
                .map(|chunk| (chunk[0].0, self.write_internal(owner, level, chunk)))
                .collect();
        }
        (ptrs[0].1, level)
    }

    /// Superblock at 64 KiB (and at 64 MiB when the image is large enough).
    fn write_superblock(
        &mut self,
        root: (u64, u8),
        chunk_root: (u64, u8),
        sys_chunk: &[u8],
        incompat: u64,
        tweak: &dyn Fn(&mut [u8]),
    ) {
        let mut sb = vec![0u8; 4096];
        sb[0x20..0x30].copy_from_slice(&FSID);
        sb[0x40..0x48].copy_from_slice(&SUPERBLOCK_MAGIC.to_le_bytes());
        sb[0x48..0x50].copy_from_slice(&1u64.to_le_bytes());
        sb[0x50..0x58].copy_from_slice(&root.0.to_le_bytes());
        sb[0x58..0x60].copy_from_slice(&chunk_root.0.to_le_bytes());
        sb[0x70..0x78].copy_from_slice(&(self.data.len() as u64).to_le_bytes());
        sb[0x80..0x88].copy_from_slice(&6u64.to_le_bytes());
        sb[0x88..0x90].copy_from_slice(&1u64.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&SECTOR.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&NODESIZE.to_le_bytes());
        sb[0x98..0x9C].copy_from_slice(&NODESIZE.to_le_bytes());
        sb[0x9C..0xA0].copy_from_slice(&4096u32.to_le_bytes());
        sb[0xA0..0xA4].copy_from_slice(&(sys_chunk.len() as u32).to_le_bytes());
        sb[0xA4..0xAC].copy_from_slice(&1u64.to_le_bytes());
        sb[0xBC..0xC4].copy_from_slice(&incompat.to_le_bytes());
        sb[0xC4..0xC6].copy_from_slice(&self.csum_type.to_le_bytes());
        sb[0xC6] = root.1;
        sb[0xC7] = chunk_root.1;
        sb[0xC9..0xC9 + 98].copy_from_slice(&dev_item(1, self.data.len() as u64));
        sb[0x12B..0x12B + 9].copy_from_slice(b"synthetic");
        sb[0x32B..0x32B + sys_chunk.len()].copy_from_slice(sys_chunk);
        tweak(&mut sb);
        for &offset in &[0x1_0000usize, 0x400_0000] {
            if offset + 4096 <= self.data.len() {
                sb[0x30..0x38].copy_from_slice(&(offset as u64).to_le_bytes());
                let sum = checksum::compute(self.csum_type, &sb[32..]).unwrap();
                sb[..32].copy_from_slice(&sum);
                self.data[offset..offset + 4096].copy_from_slice(&sb);
            }
        }
    }
}

/// Declarative file tree: items keyed for one subvolume.
#[derive(Default)]
struct FsTree {
    items: BTreeMap<Key, Vec<u8>>,
    dir_index: BTreeMap<u64, u64>,
}

impl FsTree {
    fn add_inode(&mut self, ino: u64, mode: u32, size: u64, nlink: u32, flags: u64) {
        self.items.insert(
            Key::new(ino, INODE_ITEM_KEY, 0),
            inode_item(mode, size, nlink, flags),
        );
    }

    fn add_entry(&mut self, parent: u64, name: &[u8], location: Key, ty: u8) {
        let index = self.dir_index.entry(parent).or_insert(2);
        *index += 1;
        let idx = *index;
        self.items.insert(
            Key::new(parent, DIR_INDEX_KEY, idx),
            dir_item(location, ty, name, &[]),
        );
        let hash = checksum::name_hash(name);
        let packed = dir_item(location, ty, name, &[]);
        self.items
            .entry(Key::new(parent, DIR_ITEM_KEY, hash))
            .and_modify(|existing| existing.extend_from_slice(&packed))
            .or_insert(packed);
        if location.ty == INODE_ITEM_KEY {
            let r = inode_ref(idx, name);
            self.items
                .entry(Key::new(location.objectid, INODE_REF_KEY, parent))
                .and_modify(|existing| existing.extend_from_slice(&r))
                .or_insert(r);
        }
    }

    fn add_dir(&mut self, ino: u64, parent: Option<u64>, name: &[u8]) {
        self.add_inode(ino, S_IFDIR | 0o755, 0, 1, 0);
        match parent {
            Some(p) => self.add_entry(p, name, Key::new(ino, INODE_ITEM_KEY, 0), FT_DIR),
            None => {
                // Subvolume root: "..": INODE_REF to itself.
                self.items
                    .insert(Key::new(ino, INODE_REF_KEY, ino), inode_ref(0, b".."));
            }
        }
    }

    fn add_file(
        &mut self,
        ino: u64,
        parent: u64,
        name: &[u8],
        size: u64,
        extents: Vec<(u64, Vec<u8>)>,
    ) {
        self.add_inode(ino, S_IFREG | 0o644, size, 1, 0);
        self.add_entry(parent, name, Key::new(ino, INODE_ITEM_KEY, 0), FT_REG_FILE);
        for (off, e) in extents {
            self.items.insert(Key::new(ino, EXTENT_DATA_KEY, off), e);
        }
    }

    fn add_symlink(&mut self, ino: u64, parent: u64, name: &[u8], target: &[u8]) {
        self.add_inode(ino, S_IFLNK | 0o777, target.len() as u64, 1, 0);
        self.add_entry(parent, name, Key::new(ino, INODE_ITEM_KEY, 0), FT_SYMLINK);
        self.items.insert(
            Key::new(ino, EXTENT_DATA_KEY, 0),
            extent_inline(COMPRESS_NONE, target.len() as u64, target),
        );
    }

    fn add_xattr(&mut self, ino: u64, name: &[u8], value: &[u8]) {
        self.items.insert(
            Key::new(ino, XATTR_ITEM_KEY, checksum::name_hash(name)),
            dir_item(Key::new(0, 0, 0), 8, name, value),
        );
    }
}

/// Non-zero byte used to fill a tree's UUID.
fn uuid_byte(id: u64) -> u8 {
    (id % 251 + 1) as u8
}

struct Built {
    image: Image,
    root_items: BTreeMap<Key, Vec<u8>>,
    chunk_root: (u64, u8),
    sys_chunk: Vec<u8>,
}

/// Lay out the chunk tree, then let the caller add file trees.
fn start(size: usize) -> Built {
    let mut image = Image::new(size);
    let chunk = chunk_item(
        size as u64 - BASE,
        BLOCK_GROUP_SYSTEM | BLOCK_GROUP_METADATA | BLOCK_GROUP_DATA,
        &[(1, BASE)],
    );
    let mut sys_chunk = Key::new(FIRST_CHUNK_TREE_OBJECTID, CHUNK_ITEM_KEY, BASE)
        .to_bytes()
        .to_vec();
    sys_chunk.extend_from_slice(&chunk);
    let mut chunk_items = BTreeMap::new();
    chunk_items.insert(
        Key::new(DEV_ITEMS_OBJECTID, DEV_ITEM_KEY, 1),
        dev_item(1, size as u64),
    );
    chunk_items.insert(
        Key::new(FIRST_CHUNK_TREE_OBJECTID, CHUNK_ITEM_KEY, BASE),
        chunk,
    );
    let chunk_root = image.write_tree(CHUNK_TREE_OBJECTID, &chunk_items, 16);
    Built {
        image,
        root_items: BTreeMap::new(),
        chunk_root,
        sys_chunk,
    }
}

impl Built {
    fn add_tree(&mut self, id: u64, tree: &FsTree, per_node: usize, flags: u64, parent_uuid: u8) {
        let (bytenr, level) = self.image.write_tree(id, &tree.items, per_node);
        self.root_items.insert(
            Key::new(id, ROOT_ITEM_KEY, 0),
            root_item(bytenr, level, flags, uuid_byte(id), parent_uuid),
        );
    }

    fn add_subvol_ref(&mut self, parent: u64, dirid: u64, child: u64, name: &[u8]) {
        self.root_items.insert(
            Key::new(parent, ROOT_REF_KEY, child),
            root_ref(dirid, 3, name),
        );
        self.root_items.insert(
            Key::new(child, ROOT_BACKREF_KEY, parent),
            root_ref(dirid, 3, name),
        );
    }

    fn set_default(&mut self, subvol: u64) {
        self.root_items.insert(
            Key::new(
                ROOT_TREE_DIR_OBJECTID,
                DIR_ITEM_KEY,
                checksum::name_hash(b"default"),
            ),
            dir_item(
                Key::new(subvol, ROOT_ITEM_KEY, u64::MAX),
                FT_DIR,
                b"default",
                &[],
            ),
        );
    }

    fn finish_with(mut self, incompat: u64, tweak: &dyn Fn(&mut [u8])) -> Vec<u8> {
        let root = self
            .image
            .write_tree(ROOT_TREE_OBJECTID, &self.root_items, 16);
        let chunk_root = self.chunk_root;
        let sys = self.sys_chunk.clone();
        self.image
            .write_superblock(root, chunk_root, &sys, incompat, tweak);
        self.image.data
    }

    fn finish(self) -> Vec<u8> {
        self.finish_with(FEATURE_INCOMPAT_NO_HOLES, &|_| {})
    }
}

fn open(data: Vec<u8>) -> BtrfsFS<Cursor<Vec<u8>>> {
    BtrfsFS::new(Cursor::new(data)).expect("open synthetic image")
}

/// Error message of a failed open.
fn open_err(data: Vec<u8>) -> String {
    match BtrfsFS::new(Cursor::new(data)) {
        Ok(_) => panic!("the image opened but an error was expected"),
        Err(e) => e.to_string(),
    }
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// A top-level tree with the usual suspects. Returns the built image (before
/// `finish`) and the expected contents by path.
fn standard_tree(built: &mut Built) -> BTreeMap<&'static str, Vec<u8>> {
    let mut expected = BTreeMap::new();
    let mut t = FsTree::default();
    t.add_dir(256, None, b"");
    t.add_dir(257, Some(256), b"dir");
    // Inline file.
    t.add_file(
        258,
        256,
        b"inline.txt",
        11,
        vec![(0, extent_inline(COMPRESS_NONE, 11, b"hello world"))],
    );
    expected.insert("/inline.txt", b"hello world".to_vec());
    // Regular uncompressed, two extents, second one with an extent offset.
    let a: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    let a_at = built.image.write_data(&a);
    let b: Vec<u8> = (0..8192u32).map(|i| (i % 13) as u8).collect();
    let b_at = built.image.write_data(&b);
    t.add_file(
        259,
        256,
        b"plain.bin",
        8192 + 4096,
        vec![
            (
                0,
                extent_regular(FILE_EXTENT_REG, COMPRESS_NONE, 8192, a_at, 8192, 0, 8192),
            ),
            (
                8192,
                extent_regular(FILE_EXTENT_REG, COMPRESS_NONE, 8192, b_at, 8192, 4096, 4096),
            ),
        ],
    );
    let mut plain = a.clone();
    plain.extend_from_slice(&b[4096..]);
    expected.insert("/plain.bin", plain);
    // zlib compressed extent, then a hole (no_holes gap), then a zstd extent
    // read with an offset inside the decompressed data, then prealloc.
    let text: Vec<u8> = b"compressible text "
        .iter()
        .cycle()
        .take(20000)
        .copied()
        .collect();
    let z = zlib(&text);
    let z_at = built.image.write_data(&z);
    let zs =
        ruzstd::encoding::compress_to_vec(&text[..], ruzstd::encoding::CompressionLevel::Fastest);
    let zs_at = built.image.write_data(&zs);
    t.add_file(
        260,
        257,
        b"compressed.bin",
        20000 + 4096 + 10000 + 4096,
        vec![
            (
                0,
                extent_regular(
                    FILE_EXTENT_REG,
                    COMPRESS_ZLIB,
                    20000,
                    z_at,
                    z.len() as u64,
                    0,
                    20000,
                ),
            ),
            (
                24096,
                extent_regular(
                    FILE_EXTENT_REG,
                    COMPRESS_ZSTD,
                    20000,
                    zs_at,
                    zs.len() as u64,
                    5000,
                    10000,
                ),
            ),
            (
                34096,
                extent_regular(FILE_EXTENT_PREALLOC, COMPRESS_NONE, 4096, 0, 4096, 0, 4096),
            ),
        ],
    );
    let mut comp = text.clone();
    comp.extend_from_slice(&[0u8; 4096]);
    comp.extend_from_slice(&text[5000..15000]);
    comp.extend_from_slice(&[0u8; 4096]);
    expected.insert("/dir/compressed.bin", comp);
    // Explicit hole extent + compressed inline.
    let inline_z = zlib(b"inline compressed payload");
    t.add_file(
        261,
        257,
        b"holes.bin",
        4096 + 25,
        vec![
            (
                0,
                extent_regular(FILE_EXTENT_REG, COMPRESS_NONE, 4096, 0, 0, 0, 4096),
            ),
            (4096, extent_inline(COMPRESS_ZLIB, 25, &inline_z)),
        ],
    );
    let mut holes = vec![0u8; 4096];
    holes.extend_from_slice(b"inline compressed payload");
    expected.insert("/dir/holes.bin", holes);
    // Hard link to inline.txt from dir/.
    t.add_entry(
        257,
        b"hardlink.txt",
        Key::new(258, INODE_ITEM_KEY, 0),
        FT_REG_FILE,
    );
    t.items.insert(
        Key::new(258, INODE_ITEM_KEY, 0),
        inode_item(S_IFREG | 0o644, 11, 2, 0),
    );
    expected.insert("/dir/hardlink.txt", b"hello world".to_vec());
    // Symlink and xattr.
    t.add_symlink(262, 256, b"link", b"dir/compressed.bin");
    t.add_xattr(258, b"user.comment", b"synthetic");
    t.add_xattr(258, b"security.selinux", b"unconfined_u:object_r:t:s0\0");
    built.add_tree(FS_TREE_OBJECTID, &t, 64, 0, 0);
    expected
}

fn read_path(fs: &mut BtrfsFS<Cursor<Vec<u8>>>, path: &str) -> Vec<u8> {
    let inode = fs
        .resolve_path(path)
        .unwrap_or_else(|e| panic!("{path}: {e}"));
    fs.read_inode(&inode)
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn reads_files_of_every_extent_kind() {
    let mut built = start(8 << 20);
    let expected = standard_tree(&mut built);
    let mut fs = open(built.finish());
    assert_eq!(fs.superblock.label, "synthetic");
    assert_eq!(fs.subvolumes().len(), 1);
    for (path, content) in &expected {
        assert_eq!(&read_path(&mut fs, path), content, "{path}");
        let inode = fs.resolve_path(path).unwrap();
        assert_eq!(inode.size(), content.len() as u64);
        // Slices across extent boundaries.
        if content.len() > 9000 {
            assert_eq!(
                fs.read_inode_slice(&inode, 8000, 2000).unwrap(),
                &content[8000..10000],
                "{path} slice"
            );
            assert_eq!(
                fs.read_inode_slice(&inode, content.len() as u64 - 3, 50)
                    .unwrap(),
                &content[content.len() - 3..]
            );
        }
        assert_eq!(
            fs.inode_path(inode.tree_id, inode.ino).unwrap(),
            if *path == "/dir/hardlink.txt" {
                "/inline.txt"
            } else {
                *path
            }
        );
    }
    let root = fs.get_root().unwrap();
    let names: Vec<String> = fs
        .list_dir(&root)
        .unwrap()
        .iter()
        .map(|e| e.name.clone())
        .collect();
    assert_eq!(names, vec!["dir", "inline.txt", "plain.bin", "link"]);
    let link = fs.resolve_path("/link").unwrap();
    assert!(link.is_symlink());
    assert_eq!(fs.read_symlink(&link).unwrap(), "dir/compressed.bin");
    let inline = fs.resolve_path("/inline.txt").unwrap();
    assert_eq!(inline.nlink(), 2);
    assert_eq!(fs.inode_refs(&inline).unwrap().len(), 2);
    let xattrs = fs.xattrs(&inline).unwrap();
    assert_eq!(xattrs.len(), 2);
    assert!(
        xattrs
            .iter()
            .any(|x| x.name == "user.comment" && x.value == b"synthetic")
    );
    assert_eq!(inline.uid(), 1000);
    assert_eq!(inline.item.otime.sec, 1_500_000_000);
    assert!(fs.lookup_name(&root, b"missing").unwrap().is_none());
    assert!(fs.resolve_path("/dir/nope").is_err());
    assert!(fs.resolve_path("/inline.txt/x").is_err());
    assert!(fs.list_dir(&inline).is_err());
    let dir = fs.resolve_path("/dir").unwrap();
    assert_eq!(fs.parent_of(&dir).unwrap().ino, 256);
    assert_eq!(fs.resolve_path("/dir/../dir/./holes.bin").unwrap().ino, 261);
    let compressed = fs.resolve_path("/dir/compressed.bin").unwrap();
    let extents = fs.extents(&compressed).unwrap();
    assert_eq!(extents.len(), 3);
    assert_eq!(extents[0].compression, COMPRESS_ZLIB);
    let _ = fs.metadata_pretty();
    assert_eq!(fs.metadata_json()["default_subvolume"], 5);
}

#[test]
fn multi_level_trees_and_hash_collisions() {
    let mut built = start(16 << 20);
    let mut t = FsTree::default();
    t.add_dir(256, None, b"");
    // Find two names with the same directory hash.
    let mut seen: BTreeMap<u64, String> = BTreeMap::new();
    let mut collision: Option<(String, String)> = None;
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    for _ in 0..3_000_000u32 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let name = format!("{x:016x}");
        let h = checksum::name_hash(name.as_bytes());
        if let Some(prev) = seen.insert(h, name.clone()) {
            collision = Some((prev, name));
            break;
        }
    }
    let (first, second) = collision.expect("no CRC collision found");
    t.add_file(
        257,
        256,
        first.as_bytes(),
        1,
        vec![(0, extent_inline(COMPRESS_NONE, 1, b"1"))],
    );
    t.add_file(
        258,
        256,
        second.as_bytes(),
        1,
        vec![(0, extent_inline(COMPRESS_NONE, 1, b"2"))],
    );
    for i in 0..300u64 {
        let ino = 300 + i;
        let content = format!("content {i}");
        t.add_file(
            ino,
            256,
            format!("file{i:03}").as_bytes(),
            content.len() as u64,
            vec![(
                0,
                extent_inline(COMPRESS_NONE, content.len() as u64, content.as_bytes()),
            )],
        );
    }
    // 4 items per node forces at least three levels.
    built.add_tree(FS_TREE_OBJECTID, &t, 4, 0, 0);
    let mut fs = open(built.finish());
    assert!(fs.tree_root(FS_TREE_OBJECTID).unwrap().level >= 2);
    assert_eq!(read_path(&mut fs, &format!("/{first}")), b"1");
    assert_eq!(read_path(&mut fs, &format!("/{second}")), b"2");
    for i in [0u64, 1, 150, 299] {
        assert_eq!(
            read_path(&mut fs, &format!("/file{i:03}")),
            format!("content {i}").as_bytes()
        );
    }
    let root = fs.get_root().unwrap();
    assert_eq!(fs.list_dir(&root).unwrap().len(), 302);
    assert!(fs.get_inode(FS_TREE_OBJECTID, 9999).is_err());
}

#[test]
fn subvolumes_snapshots_and_default() {
    let mut built = start(8 << 20);
    let _ = standard_tree(&mut built);
    // Subvolume 256 "vol" at /vol, snapshot 257 "snap" at /vol/snap (read-only,
    // parent_uuid = vol's uuid).
    let mut vol = FsTree::default();
    vol.add_dir(256, None, b"");
    vol.add_file(
        257,
        256,
        b"in_vol.txt",
        6,
        vec![(0, extent_inline(COMPRESS_NONE, 6, b"in vol"))],
    );
    vol.add_dir(258, Some(256), b"snapshots");
    vol.add_entry(258, b"snap", Key::new(257, ROOT_ITEM_KEY, u64::MAX), FT_DIR);
    let mut snap = FsTree::default();
    snap.add_dir(256, None, b"");
    // A snapshot keeps the parent's DIR_ITEM for a nested subvolume, but no
    // root ref backs it from the snapshot: the kernel shows an empty dir.
    snap.add_entry(
        256,
        b"stale_vol",
        Key::new(256, ROOT_ITEM_KEY, u64::MAX),
        FT_DIR,
    );
    snap.add_file(
        257,
        256,
        b"in_vol.txt",
        7,
        vec![(0, extent_inline(COMPRESS_NONE, 7, b"in snap"))],
    );
    // Entry of the subvolume in the top level: a DIR_INDEX under 256 pointing
    // to the ROOT_ITEM. Rebuild the top-level tree with it.
    let mut top = FsTree::default();
    top.add_dir(256, None, b"");
    top.add_entry(256, b"vol", Key::new(256, ROOT_ITEM_KEY, u64::MAX), FT_DIR);
    built.add_tree(FS_TREE_OBJECTID, &top, 64, 0, 0);
    built.add_tree(256, &vol, 64, 0, 0);
    built.add_tree(
        257,
        &snap,
        64,
        exhume_btrfs::root::ROOT_SUBVOL_RDONLY,
        uuid_byte(256),
    );
    built.add_subvol_ref(FS_TREE_OBJECTID, 256, 256, b"vol");
    built.add_subvol_ref(256, 258, 257, b"snap");
    built.set_default(256);
    let mut fs = open(built.finish());

    let subs = fs.subvolumes();
    assert_eq!(
        subs.iter().map(|s| s.id).collect::<Vec<_>>(),
        vec![5, 256, 257]
    );
    assert_eq!(subs[1].path, "/vol");
    assert_eq!(subs[2].path, "/vol/snapshots/snap");
    assert!(subs[2].is_snapshot && subs[2].readonly && !subs[1].is_snapshot);
    assert!(subs[1].is_default);
    assert_eq!(subs[2].kind_name(), "snapshot");
    assert_eq!(fs.default_subvolume(), 256);

    assert_eq!(read_path(&mut fs, "/vol/in_vol.txt"), b"in vol");
    assert_eq!(
        read_path(&mut fs, "/vol/snapshots/snap/in_vol.txt"),
        b"in snap"
    );
    let snap_file = fs.resolve_path("/vol/snapshots/snap/in_vol.txt").unwrap();
    assert_eq!((snap_file.tree_id, snap_file.ino), (257, 257));
    assert_eq!(
        fs.inode_path(257, 257).unwrap(),
        "/vol/snapshots/snap/in_vol.txt"
    );
    // Crossing back out with "..".
    let snap_root = fs.resolve_path("/vol/snapshots/snap").unwrap();
    assert_eq!(snap_root.entered_from, Some((256, 258)));
    assert_eq!(fs.parent_of(&snap_root).unwrap().ino, 258);
    assert_eq!(
        fs.resolve_path("/vol/snapshots/snap/../../in_vol.txt")
            .unwrap()
            .tree_id,
        256
    );
    // Directory entry of a subvolume.
    let root = fs.get_root().unwrap();
    let entries = fs.list_dir(&root).unwrap();
    let vol_entry = entries.iter().find(|e| e.name == "vol").unwrap();
    assert!(vol_entry.is_subvolume());
    assert_eq!(vol_entry.target(), Some((256, 256)));
    let vol_root = fs.resolve_entry(vol_entry).unwrap();
    assert_eq!(vol_root.tree_id, 256);
    // The stale subvolume entry inside the snapshot is listed but not crossable.
    let snap_entries = fs.list_dir(&snap_root).unwrap();
    let stale = snap_entries.iter().find(|e| e.name == "stale_vol").unwrap();
    assert!(stale.is_subvolume() && !stale.reachable && stale.target().is_none());
    let e = fs.resolve_entry(stale).unwrap_err().to_string();
    assert!(e.contains("stale"), "{e}");
    assert!(
        fs.resolve_path("/vol/snapshots/snap/stale_vol/in_vol.txt")
            .is_err()
    );
    assert!(format!("{stale}").contains("not reachable"));
    // Packed identifiers.
    let slot = fs.subvolume_slot(257).unwrap();
    let packed = pack_id(slot, 257).unwrap();
    assert_eq!(fs.get_inode_packed(packed).unwrap().tree_id, 257);
    assert_eq!(fs.packed_id(&snap_file), Some(packed));
    assert!(fs.get_inode_packed(pack_id(7, 256).unwrap()).is_err());
}

#[test]
fn checksum_and_superblock_fallbacks() {
    let mut built = start(8 << 20);
    let _ = standard_tree(&mut built);
    let good = built.finish();
    let mut fs = open(good.clone());
    let inline = fs.resolve_path("/inline.txt").unwrap();
    // Corrupt a byte inside the fs tree leaf: find it through the root item.
    let root = fs.tree_root(FS_TREE_OBJECTID).unwrap();
    let mut bad = good.clone();
    bad[root.bytenr as usize + 200] ^= 0xFF;
    let err = BtrfsFS::new(Cursor::new(bad.clone()));
    // Opening succeeds (fs tree is read lazily) but the inode lookup fails.
    let mut fs_bad = err.expect("open");
    let e = fs_bad
        .get_inode(FS_TREE_OBJECTID, inline.ino)
        .unwrap_err()
        .to_string();
    assert!(e.contains("crc32c mismatch"), "{e}");
    // Salvage mode keeps going when the structure still parses.
    let mut tolerant = BtrfsFS::open(Cursor::new(bad), true).unwrap();
    let _ = tolerant.get_inode(FS_TREE_OBJECTID, inline.ino);

    // Bad primary superblock checksum: no mirror in an 8 MiB image -> error.
    let mut bad_sb = good.clone();
    bad_sb[0x1_0000 + 0x50] ^= 1;
    let e = open_err(bad_sb);
    assert!(e.contains("bad checksum"), "{e}");
    // Bad magic.
    let mut bad_magic = good.clone();
    bad_magic[0x1_0000 + 0x40] = 0;
    assert!(open_err(bad_magic).contains("magic"));
    // Not Btrfs at all.
    assert!(BtrfsFS::new(Cursor::new(vec![0u8; 1 << 20])).is_err());
    assert!(BtrfsFS::new(Cursor::new(vec![0u8; 100])).is_err());

    // With a 65 MiB image the mirror at 64 MiB saves the day.
    let mut built = start(65 << 20);
    let expected = standard_tree(&mut built);
    let mut big = built.finish();
    big[0x1_0000 + 0x50] ^= 1;
    let mut fs = open(big);
    assert_eq!(fs.superblock.read_from, 0x400_0000);
    assert_eq!(&read_path(&mut fs, "/inline.txt"), &expected["/inline.txt"]);
}

#[test]
fn structural_errors_are_reported_not_panics() {
    // Unsupported incompat feature.
    let mut built = start(8 << 20);
    let _ = standard_tree(&mut built);
    let zoned = built.finish_with(FEATURE_INCOMPAT_NO_HOLES | FEATURE_INCOMPAT_ZONED, &|_| {});
    let e = open_err(zoned);
    assert!(e.contains("zoned"), "{e}");

    // Unknown checksum type.
    let mut built = start(8 << 20);
    let _ = standard_tree(&mut built);
    let img = built.finish_with(0, &|sb| sb[0xC4] = 9);
    assert!(BtrfsFS::new(Cursor::new(img)).is_err());

    // Invalid nodesize.
    let mut built = start(8 << 20);
    let _ = standard_tree(&mut built);
    let img = built.finish_with(0, &|sb| {
        sb[0x94..0x98].copy_from_slice(&3000u32.to_le_bytes())
    });
    assert!(open_err(img).contains("nodesize"));

    // Root tree pointing outside any chunk.
    let mut built = start(8 << 20);
    let _ = standard_tree(&mut built);
    let img = built.finish_with(0, &|sb| {
        sb[0x50..0x58].copy_from_slice(&(1u64 << 40).to_le_bytes())
    });
    let e = open_err(img);
    assert!(e.contains("not mapped"), "{e}");

    // Tree loop: an internal node that points to itself.
    let mut built = start(8 << 20);
    let _ = standard_tree(&mut built);
    let loop_at = built.image.alloc(NODESIZE as u64);
    built
        .image
        .write_internal_at(loop_at, FS_TREE_OBJECTID, 1, &[(Key::MIN, loop_at)]);
    built.root_items.insert(
        Key::new(FS_TREE_OBJECTID, ROOT_ITEM_KEY, 0),
        root_item(loop_at, 1, 0, 5, 0),
    );
    let mut fs = open(built.finish());
    let e = fs.get_root().unwrap_err().to_string();
    assert!(e.contains("level") || e.contains("loop"), "{e}");

    // Internal node whose child claims the wrong level, and a child whose
    // header bytenr does not match the pointer.
    let mut built = start(8 << 20);
    let _ = standard_tree(&mut built);
    let leaf_at = built.image.alloc(NODESIZE as u64);
    built.image.write_leaf_at(
        leaf_at,
        FS_TREE_OBJECTID,
        &[(
            Key::new(256, INODE_ITEM_KEY, 0),
            inode_item(S_IFDIR | 0o755, 0, 1, 0),
        )],
    );
    let wrong_level = built.image.alloc(NODESIZE as u64);
    built
        .image
        .write_internal_at(wrong_level, FS_TREE_OBJECTID, 2, &[(Key::MIN, leaf_at)]);
    built.root_items.insert(
        Key::new(FS_TREE_OBJECTID, ROOT_ITEM_KEY, 0),
        root_item(wrong_level, 2, 0, 5, 0),
    );
    let mut fs = open(built.finish());
    assert!(fs.get_root().unwrap_err().to_string().contains("level"));

    let mut built = start(8 << 20);
    let _ = standard_tree(&mut built);
    let leaf_at = built.image.alloc(NODESIZE as u64);
    built.image.write_leaf_at(
        leaf_at,
        FS_TREE_OBJECTID,
        &[(
            Key::new(256, INODE_ITEM_KEY, 0),
            inode_item(S_IFDIR | 0o755, 0, 1, 0),
        )],
    );
    let parent = built.image.alloc(NODESIZE as u64);
    built.image.write_internal_at(
        parent,
        FS_TREE_OBJECTID,
        1,
        &[(Key::MIN, leaf_at + NODESIZE as u64)],
    );
    built.root_items.insert(
        Key::new(FS_TREE_OBJECTID, ROOT_ITEM_KEY, 0),
        root_item(parent, 1, 0, 5, 0),
    );
    let mut fs = open(built.finish());
    assert!(fs.get_root().is_err());

    // Extent on another device, encrypted extent, extent past the chunk.
    let mut built = start(8 << 20);
    let mut t = FsTree::default();
    t.add_dir(256, None, b"");
    t.add_file(
        257,
        256,
        b"far.bin",
        4096,
        vec![(
            0,
            extent_regular(FILE_EXTENT_REG, COMPRESS_NONE, 4096, 1 << 40, 4096, 0, 4096),
        )],
    );
    let mut enc = extent_regular(FILE_EXTENT_REG, COMPRESS_NONE, 4096, BASE, 4096, 0, 4096);
    enc[17] = 1;
    t.add_file(258, 256, b"encrypted.bin", 4096, vec![(0, enc)]);
    t.add_file(
        259,
        256,
        b"badcomp.bin",
        4096,
        vec![(
            0,
            extent_regular(FILE_EXTENT_REG, 7, 4096, BASE, 4096, 0, 4096),
        )],
    );
    t.add_file(
        260,
        256,
        b"garbage_zlib.bin",
        4096,
        vec![(
            0,
            extent_regular(FILE_EXTENT_REG, COMPRESS_ZLIB, 4096, BASE, 4096, 0, 4096),
        )],
    );
    t.add_file(
        261,
        256,
        b"short_inline.bin",
        100,
        vec![(0, extent_inline(COMPRESS_NONE, 100, b"only 10 b."))],
    );
    t.add_file(262, 256, b"no_extents.bin", 4096, vec![]);
    built.add_tree(FS_TREE_OBJECTID, &t, 64, 0, 0);
    let mut fs = open(built.finish());
    for name in [
        "far.bin",
        "encrypted.bin",
        "badcomp.bin",
        "garbage_zlib.bin",
    ] {
        let inode = fs.resolve_path(&format!("/{name}")).unwrap();
        assert!(fs.read_inode(&inode).is_err(), "{name} should fail");
    }
    // Short inline data and a file without extents read as zero-padded / zeroes.
    let short = fs.resolve_path("/short_inline.bin").unwrap();
    let data = fs.read_inode(&short).unwrap();
    assert_eq!(data.len(), 100);
    assert_eq!(&data[..10], b"only 10 b.");
    assert!(data[10..].iter().all(|&b| b == 0));
    let none = fs.resolve_path("/no_extents.bin").unwrap();
    assert_eq!(fs.read_inode(&none).unwrap(), vec![0u8; 4096]);
}

#[test]
fn multi_device_stripes_and_log_tree_warning() {
    // A chunk whose only stripe is on device 2: metadata inside it is unreadable.
    let mut built = start(8 << 20);
    let _ = standard_tree(&mut built);
    let other = chunk_item(1 << 20, BLOCK_GROUP_DATA, &[(2, 0)]);
    let mut t = FsTree::default();
    t.add_dir(256, None, b"");
    t.add_file(
        257,
        256,
        b"remote.bin",
        4096,
        vec![(
            0,
            extent_regular(FILE_EXTENT_REG, COMPRESS_NONE, 4096, 1 << 30, 4096, 0, 4096),
        )],
    );
    built.add_tree(FS_TREE_OBJECTID, &t, 64, 0, 0);
    // Add the remote chunk to the chunk tree by rebuilding it.
    let mut chunk_items = BTreeMap::new();
    chunk_items.insert(
        Key::new(DEV_ITEMS_OBJECTID, DEV_ITEM_KEY, 1),
        dev_item(1, 8 << 20),
    );
    chunk_items.insert(
        Key::new(FIRST_CHUNK_TREE_OBJECTID, CHUNK_ITEM_KEY, BASE),
        chunk_item(
            (8 << 20) - BASE,
            BLOCK_GROUP_SYSTEM | BLOCK_GROUP_METADATA | BLOCK_GROUP_DATA,
            &[(1, BASE)],
        ),
    );
    chunk_items.insert(
        Key::new(FIRST_CHUNK_TREE_OBJECTID, CHUNK_ITEM_KEY, 1 << 30),
        other,
    );
    built.chunk_root = built
        .image
        .write_tree(CHUNK_TREE_OBJECTID, &chunk_items, 16);
    let img = built.finish_with(FEATURE_INCOMPAT_NO_HOLES, &|sb| {
        sb[0x60..0x68].copy_from_slice(&BASE.to_le_bytes()); // log_root != 0
        sb[0x88..0x90].copy_from_slice(&2u64.to_le_bytes()); // num_devices
    });
    let mut fs = open(img);
    assert_eq!(fs.superblock.log_root, BASE);
    assert_eq!(fs.chunks().len(), 2);
    let inode = fs.resolve_path("/remote.bin").unwrap();
    let e = fs.read_inode(&inode).unwrap_err().to_string();
    assert!(e.contains("device(s) 2"), "{e}");
    assert!(fs.metadata_json()["log_tree_unreplayed"].as_bool().unwrap());
}
