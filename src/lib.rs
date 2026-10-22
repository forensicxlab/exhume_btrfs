//! Read-only access to Btrfs filesystems for the Exhume toolkit.
//!
//! The reader opens a single device image (or the partition slice of one),
//! walks the chunk and root trees, exposes every subvolume and snapshot, and
//! reads files through their extents with zlib / LZO / zstd decompression.
//! It never writes and never replays the log tree: an unreplayed log is
//! reported so the investigator knows the view may miss the last fsync.
//!
//! On-disk format reference:
//! <https://btrfs.readthedocs.io/en/latest/dev/On-disk-format.html>

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::io::{Read, Seek, SeekFrom};

pub mod checksum;
pub mod chunk;
pub mod compression;
pub mod dir;
pub mod extent;
pub mod inode;
pub mod key;
pub mod root;
pub mod superblock;
pub mod tree;

use chunk::ChunkMap;
use dir::{DirEntry, DirItem, InodeRef, Xattr};
use extent::{ExtentStorage, FileExtent};
use inode::{Inode, InodeItem};
use key::*;
use log::{debug, info, warn};
use root::{RootItem, RootRef, Subvolume};
use serde_json::{Value, json};
use superblock::{SUPERBLOCK_OFFSETS, SUPERBLOCK_SIZE, Superblock};
use tree::Node;

/// Number of tree nodes kept in memory.
const NODE_CACHE_LIMIT: usize = 512;
/// Upper bound on a whole-file read into memory.
pub const MAX_READ_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Materialised items: `(key, item data)` pairs in key order.
pub type Items = Vec<(Key, Vec<u8>)>;

/// Root of a tree: logical address of its root node and its level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeRoot {
    pub bytenr: u64,
    pub level: u8,
    /// Generation the root node must carry (root item / superblock value).
    pub generation: u64,
}

/// What a parent pointer or root item promises about a child node.
#[derive(Debug, Clone, Copy, Default)]
pub struct NodeExpectation {
    pub level: Option<u8>,
    pub generation: Option<u64>,
    pub first_key: Option<Key>,
}

/// A Btrfs filesystem opened on any `Read + Seek` source.
pub struct BtrfsFS<T: Read + Seek> {
    body: T,
    pub superblock: Superblock,
    chunks: ChunkMap,
    /// Root tree root.
    root_tree: TreeRoot,
    /// Tree roots discovered from the root tree, by tree id.
    tree_roots: HashMap<u64, TreeRoot>,
    subvolumes: Vec<Subvolume>,
    default_subvolume: u64,
    node_cache: HashMap<u64, std::rc::Rc<Node>>,
    /// Bad metadata blocks seen so far (reported once each).
    reported_bad_nodes: HashSet<u64>,
    /// Allow nodes whose checksum does not match (forensic salvage).
    pub tolerate_bad_checksums: bool,
}

impl<T: Read + Seek> BtrfsFS<T> {
    /// Open a Btrfs filesystem. The primary superblock is used when its
    /// checksum is valid, otherwise the mirrors are tried in order.
    pub fn new(body: T) -> Result<Self, Box<dyn Error>> {
        Self::open(body, false)
    }

    /// Open with the option to continue past metadata checksum mismatches.
    pub fn open(mut body: T, tolerate_bad_checksums: bool) -> Result<Self, Box<dyn Error>> {
        let superblock = read_best_superblock(&mut body)?;
        superblock.validate()?;
        let unsupported = superblock.unsupported_incompat();
        if !unsupported.is_empty() {
            return Err(format!(
                "filesystem uses features this reader does not support: {}",
                unsupported.join(", ")
            )
            .into());
        }
        if superblock.flags & superblock::SUPER_FLAG_ERROR != 0 {
            warn!(
                "superblock carries the ERROR flag: the filesystem was in error when last written"
            );
        }
        if superblock.flags & superblock::SUPER_FLAG_SEEDING != 0 {
            info!("seeding filesystem (read-only seed device)");
        }
        if superblock.log_root != 0 {
            warn!(
                "the filesystem has an unreplayed log tree at {} (unclean shutdown): the last fsync'd changes may be missing from the tree view",
                superblock.log_root
            );
        }
        if superblock.num_devices > 1 {
            warn!(
                "filesystem spans {} devices; this image is device {}, data on the other devices is unreadable",
                superblock.num_devices, superblock.dev_item.devid
            );
        }
        let chunks = ChunkMap::from_sys_chunk_array(
            superblock.dev_item.devid,
            superblock.sectorsize,
            &superblock.sys_chunk_array,
        )?;
        let root_tree = TreeRoot {
            bytenr: superblock.root,
            level: superblock.root_level,
            generation: superblock.generation,
        };
        let mut fs = BtrfsFS {
            body,
            superblock,
            chunks,
            root_tree,
            tree_roots: HashMap::new(),
            subvolumes: Vec::new(),
            default_subvolume: FS_TREE_OBJECTID,
            node_cache: HashMap::new(),
            reported_bad_nodes: HashSet::new(),
            tolerate_bad_checksums,
        };
        fs.load_chunk_tree()?;
        fs.load_root_tree()?;
        fs.load_subvolumes()?;
        Ok(fs)
    }

    // ----------------------------------------------------------------------
    // Low-level I/O
    // ----------------------------------------------------------------------

    fn read_physical(&mut self, physical: u64, buf: &mut [u8]) -> Result<(), Box<dyn Error>> {
        self.body.seek(SeekFrom::Start(physical))?;
        self.body.read_exact(buf).map_err(|e| {
            format!(
                "read of {} bytes at physical offset {physical} failed: {e}",
                buf.len()
            )
        })?;
        Ok(())
    }

    /// Read a logical byte range, following the chunk mapping.
    pub fn read_logical(&mut self, logical: u64, length: u64) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut out = vec![0u8; length as usize];
        let mut pos = 0usize;
        for segment in self.chunks.map_range(logical, length)? {
            let len = segment.length as usize;
            self.read_physical(segment.physical, &mut out[pos..pos + len])?;
            pos += len;
        }
        Ok(out)
    }

    /// Read and validate a tree node at `logical`. `expected` carries what the
    /// parent pointer (or the root item) says about the node: level,
    /// generation and first key. A stale block left at a reused address by
    /// copy-on-write has a valid checksum but a different generation, so the
    /// generation check is what keeps trees of different transactions apart.
    pub fn read_node(
        &mut self,
        logical: u64,
        expected: NodeExpectation,
    ) -> Result<std::rc::Rc<Node>, Box<dyn Error>> {
        if let Some(node) = self.node_cache.get(&logical) {
            let node = node.clone();
            self.check_expectation(logical, &node, &expected)?;
            return Ok(node);
        }
        let nodesize = self.superblock.nodesize as u64;
        // sectorsize is a validated power of two.
        if logical & (self.superblock.sectorsize as u64 - 1) != 0 {
            return Err(format!("node address {logical} is not sector aligned").into());
        }
        let physical = self.chunks.map_contiguous(logical, nodesize)?;
        let mut data = vec![0u8; nodesize as usize];
        self.read_physical(physical, &mut data)?;
        if let Err(e) = checksum::verify_block(self.superblock.csum_type, &data) {
            if self.tolerate_bad_checksums {
                if self.reported_bad_nodes.insert(logical) {
                    warn!(
                        "metadata block at {logical}: {e} (continuing, --tolerate-bad-checksums)"
                    );
                }
            } else {
                return Err(format!("metadata block at {logical}: {e}").into());
            }
        }
        let node = Node::parse(data, logical, expected.level)?;
        if node.header.fsid != self.superblock.effective_metadata_uuid() {
            let msg = format!(
                "metadata block at {logical}: fsid {} differs from the filesystem's {}",
                node.header.fsid,
                self.superblock.effective_metadata_uuid()
            );
            if self.tolerate_bad_checksums {
                if self.reported_bad_nodes.insert(logical) {
                    warn!("{msg} (continuing, --tolerate-bad-checksums)");
                }
            } else {
                return Err(msg.into());
            }
        }
        self.check_expectation(logical, &node, &expected)?;
        if self.node_cache.len() >= NODE_CACHE_LIMIT {
            self.node_cache.clear();
        }
        let node = std::rc::Rc::new(node);
        self.node_cache.insert(logical, node.clone());
        Ok(node)
    }

    /// Generation and first-key checks against the parent pointer (the kernel's
    /// "parent transid verify failed" and `btrfs_verify_level_key`).
    fn check_expectation(
        &mut self,
        logical: u64,
        node: &Node,
        expected: &NodeExpectation,
    ) -> Result<(), Box<dyn Error>> {
        if let Some(level) = expected.level
            && node.header.level != level
        {
            return Err(format!(
                "node at {logical}: level {} but parent expects {level}",
                node.header.level
            )
            .into());
        }
        let mut problems = Vec::new();
        if let Some(generation) = expected.generation
            && node.header.generation != generation
        {
            problems.push(format!(
                "generation {} but parent expects {generation} (stale block)",
                node.header.generation
            ));
        }
        if let Some(first_key) = expected.first_key
            && node.nritems() > 0
        {
            let actual = if node.is_leaf() {
                node.item(0).key
            } else {
                node.key_ptr(0).key
            };
            if actual != first_key {
                problems.push(format!(
                    "first key {actual} but parent pointer says {first_key}"
                ));
            }
        }
        if problems.is_empty() {
            return Ok(());
        }
        let msg = format!("metadata block at {logical}: {}", problems.join("; "));
        if self.tolerate_bad_checksums {
            if self.reported_bad_nodes.insert(logical) {
                warn!("{msg} (continuing, --tolerate-bad-checksums)");
            }
            Ok(())
        } else {
            Err(msg.into())
        }
    }

    // ----------------------------------------------------------------------
    // Tree search
    // ----------------------------------------------------------------------

    /// Collect every item of `tree` whose key is in `[lo, hi]`, in key order.
    /// Stops early when `cb` returns `false`.
    pub fn walk_range(
        &mut self,
        tree: TreeRoot,
        lo: Key,
        hi: Key,
        cb: &mut dyn FnMut(Key, &[u8]) -> bool,
    ) -> Result<(), Box<dyn Error>> {
        let mut visited: HashSet<u64> = HashSet::new();
        let expected = NodeExpectation {
            level: Some(tree.level),
            generation: Some(tree.generation),
            first_key: None,
        };
        self.walk_node(tree.bytenr, expected, &lo, &hi, cb, &mut visited, 0)
            .map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_node(
        &mut self,
        bytenr: u64,
        expected: NodeExpectation,
        lo: &Key,
        hi: &Key,
        cb: &mut dyn FnMut(Key, &[u8]) -> bool,
        visited: &mut HashSet<u64>,
        depth: u8,
    ) -> Result<bool, Box<dyn Error>> {
        if depth >= tree::MAX_LEVEL {
            return Err("tree deeper than the maximum level".into());
        }
        if !visited.insert(bytenr) {
            return Err(format!("tree node {bytenr} is referenced twice (loop)").into());
        }
        let node = self.read_node(bytenr, expected)?;
        if node.is_leaf() {
            let start = node.leaf_lower_bound(lo);
            for i in start..node.nritems() {
                let item = node.item(i);
                if item.key > *hi {
                    return Ok(false);
                }
                if !cb(item.key, node.item_data(i)) {
                    return Ok(false);
                }
            }
            Ok(true)
        } else {
            let first = node.child_for(lo);
            let child_level = node.header.level - 1;
            for i in first..node.nritems() {
                let ptr = node.key_ptr(i);
                if ptr.key > *hi {
                    return Ok(false);
                }
                let child = NodeExpectation {
                    level: Some(child_level),
                    generation: Some(ptr.generation),
                    first_key: Some(ptr.key),
                };
                let more = self.walk_node(ptr.blockptr, child, lo, hi, cb, visited, depth + 1)?;
                if !more {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }

    /// All items in `[lo, hi]` of `tree`, materialised.
    pub fn items_in_range(
        &mut self,
        tree: TreeRoot,
        lo: Key,
        hi: Key,
    ) -> Result<Items, Box<dyn Error>> {
        let mut out = Vec::new();
        self.walk_range(tree, lo, hi, &mut |k, d| {
            out.push((k, d.to_vec()));
            true
        })?;
        Ok(out)
    }

    /// Exact key lookup.
    pub fn lookup(&mut self, tree: TreeRoot, key: Key) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        let mut found = None;
        self.walk_range(tree, key, key, &mut |_, d| {
            found = Some(d.to_vec());
            false
        })?;
        Ok(found)
    }

    // ----------------------------------------------------------------------
    // Bootstrap: chunk tree, root tree, subvolumes
    // ----------------------------------------------------------------------

    fn load_chunk_tree(&mut self) -> Result<(), Box<dyn Error>> {
        let root = TreeRoot {
            bytenr: self.superblock.chunk_root,
            level: self.superblock.chunk_root_level,
            generation: self.superblock.chunk_root_generation,
        };
        let items = self
            .items_in_range(
                root,
                Key::first(FIRST_CHUNK_TREE_OBJECTID, CHUNK_ITEM_KEY),
                Key::last(FIRST_CHUNK_TREE_OBJECTID, CHUNK_ITEM_KEY),
            )
            .map_err(|e| format!("chunk tree: {e}"))?;
        for (key, data) in items {
            let (chunk, _) = chunk::Chunk::from_bytes(key.offset, &data)
                .map_err(|e| format!("chunk tree: {e}"))?;
            self.chunks
                .insert(chunk)
                .map_err(|e| format!("chunk tree: {e}"))?;
        }
        debug!("{} chunks mapped", self.chunks.len());
        Ok(())
    }

    fn load_root_tree(&mut self) -> Result<(), Box<dyn Error>> {
        let root = self.root_tree;
        let items = self
            .items_in_range(root, Key::MIN, Key::MAX)
            .map_err(|e| format!("root tree: {e}"))?;
        let mut roots: HashMap<u64, (u64, TreeRoot)> = HashMap::new();
        for (key, data) in &items {
            if key.ty == ROOT_ITEM_KEY {
                match RootItem::from_bytes(data) {
                    Ok(item) => {
                        // Several ROOT_ITEMs for one tree id: keep the highest offset.
                        let root = TreeRoot {
                            bytenr: item.bytenr,
                            level: item.level,
                            generation: item.generation,
                        };
                        let entry = roots.entry(key.objectid).or_insert((key.offset, root));
                        if key.offset >= entry.0 {
                            *entry = (key.offset, root);
                        }
                    }
                    Err(e) => warn!("root tree: ignoring malformed ROOT_ITEM {key}: {e}"),
                }
            }
        }
        self.tree_roots = roots.into_iter().map(|(id, (_, r))| (id, r)).collect();
        if !self.tree_roots.contains_key(&FS_TREE_OBJECTID) {
            return Err("root tree has no FS_TREE (5) root item".into());
        }
        // Default subvolume: DIR_ITEM "default" under the root tree directory.
        let default_key = superblock::default_subvol_dir_key(self.superblock.root_dir_objectid);
        if let Some(data) = self.lookup(root, default_key)? {
            match DirItem::parse_all(&data) {
                Ok(items) => {
                    if let Some(item) = items.iter().find(|i| i.name == b"default")
                        && item.location.ty == ROOT_ITEM_KEY
                    {
                        self.default_subvolume = item.location.objectid;
                    }
                }
                Err(e) => warn!("root tree: malformed default subvolume entry: {e}"),
            }
        }
        Ok(())
    }

    fn load_subvolumes(&mut self) -> Result<(), Box<dyn Error>> {
        let root = self.root_tree;
        let items = self.items_in_range(root, Key::MIN, Key::MAX)?;
        let mut subvols: Vec<Subvolume> = Vec::new();
        let mut backrefs: HashMap<u64, (u64, RootRef)> = HashMap::new();
        for (key, data) in &items {
            match key.ty {
                ROOT_ITEM_KEY
                    if key.objectid == FS_TREE_OBJECTID
                        || (FIRST_FREE_OBJECTID..=LAST_FREE_OBJECTID).contains(&key.objectid) =>
                {
                    if let Ok(item) = RootItem::from_bytes(data) {
                        if let Some(existing) = subvols.iter_mut().find(|s| s.id == key.objectid) {
                            *existing = Subvolume::from_root_item(key.objectid, &item);
                        } else {
                            subvols.push(Subvolume::from_root_item(key.objectid, &item));
                        }
                    }
                }
                ROOT_BACKREF_KEY => match RootRef::from_bytes(data) {
                    Ok(r) => {
                        backrefs.insert(key.objectid, (key.offset, r));
                    }
                    Err(e) => warn!("root tree: malformed ROOT_BACKREF {key}: {e}"),
                },
                _ => {}
            }
        }
        // Names, parents and paths.
        for s in subvols.iter_mut() {
            if let Some((parent, r)) = backrefs.get(&s.id) {
                s.name = r.name.clone();
                s.parent_id = Some(*parent);
                s.parent_dirid = Some(r.dirid);
            }
            s.is_default = s.id == self.default_subvolume;
            s.readable = self.tree_roots.contains_key(&s.id);
        }
        // Sort: top-level first, then by id, so the slot of tree 5 is 0.
        subvols.sort_by_key(|s| if s.id == FS_TREE_OBJECTID { 0 } else { s.id });
        self.subvolumes = subvols;
        // Paths need the directory names of parents; resolve lazily by walking
        // INODE_REFs. Done after the table is in place.
        let ids: Vec<u64> = self.subvolumes.iter().map(|s| s.id).collect();
        for id in ids {
            let path = self.subvolume_path(id).unwrap_or_else(|e| {
                debug!("subvolume {id}: path unresolved: {e}");
                String::new()
            });
            if let Some(s) = self.subvolumes.iter_mut().find(|s| s.id == id) {
                s.path = path;
            }
        }
        info!(
            "{} subvolume(s) incl. top-level, default subvolume {}",
            self.subvolumes.len(),
            self.default_subvolume
        );
        Ok(())
    }

    /// Path of a subvolume from the top level, e.g. `/home/snapshots/2024`.
    fn subvolume_path(&mut self, id: u64) -> Result<String, Box<dyn Error>> {
        if id == FS_TREE_OBJECTID {
            return Ok("/".to_string());
        }
        let (parent_id, parent_dirid, name) = {
            let s = self
                .subvolumes
                .iter()
                .find(|s| s.id == id)
                .ok_or_else(|| format!("subvolume {id} unknown"))?;
            match (s.parent_id, s.parent_dirid) {
                (Some(p), Some(d)) => (p, d, s.name.clone()),
                _ => return Err(format!("subvolume {id} has no parent reference").into()),
            }
        };
        // `inode_path` already crosses subvolume boundaries up to the top level.
        let dir_path = self.inode_path(parent_id, parent_dirid)?;
        Ok(if dir_path == "/" {
            format!("/{name}")
        } else {
            format!("{dir_path}/{name}")
        })
    }

    // ----------------------------------------------------------------------
    // Public accessors
    // ----------------------------------------------------------------------

    pub fn subvolumes(&self) -> &[Subvolume] {
        &self.subvolumes
    }

    pub fn subvolume(&self, id: u64) -> Option<&Subvolume> {
        self.subvolumes.iter().find(|s| s.id == id)
    }

    pub fn default_subvolume(&self) -> u64 {
        self.default_subvolume
    }

    pub fn chunks(&self) -> &ChunkMap {
        &self.chunks
    }

    pub fn tree_root(&self, tree_id: u64) -> Option<TreeRoot> {
        self.tree_roots.get(&tree_id).copied()
    }

    /// Ids of the trees listed in the root tree (internal trees included).
    pub fn tree_ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self.tree_roots.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    pub fn block_size(&self) -> u64 {
        self.superblock.sectorsize as u64
    }

    fn fs_tree(&self, tree_id: u64) -> Result<TreeRoot, Box<dyn Error>> {
        if !(tree_id == FS_TREE_OBJECTID
            || (FIRST_FREE_OBJECTID..=LAST_FREE_OBJECTID).contains(&tree_id))
        {
            return Err(format!("tree {tree_id} is not a file tree").into());
        }
        self.tree_roots
            .get(&tree_id)
            .copied()
            .ok_or_else(|| format!("subvolume {tree_id} has no root item").into())
    }

    // ----------------------------------------------------------------------
    // Inodes and directories
    // ----------------------------------------------------------------------

    /// Fetch an inode by `(subvolume, inode number)`.
    pub fn get_inode(&mut self, tree_id: u64, ino: u64) -> Result<Inode, Box<dyn Error>> {
        let tree = self.fs_tree(tree_id)?;
        let data = self
            .lookup(tree, Key::new(ino, INODE_ITEM_KEY, 0))?
            .ok_or_else(|| format!("inode {ino} not found in subvolume {tree_id}"))?;
        let item = InodeItem::from_bytes(&data)?;
        Ok(Inode::new(tree_id, ino, item))
    }

    /// Root directory of a subvolume.
    pub fn get_subvolume_root(&mut self, tree_id: u64) -> Result<Inode, Box<dyn Error>> {
        let dirid = self
            .subvolume(tree_id)
            .map(|s| s.root_dirid)
            .unwrap_or(FIRST_FREE_OBJECTID);
        self.get_inode(tree_id, dirid)
    }

    /// Root directory of the top-level subvolume (tree 5, inode 256).
    pub fn get_root(&mut self) -> Result<Inode, Box<dyn Error>> {
        self.get_subvolume_root(FS_TREE_OBJECTID)
    }

    /// List a directory from its `DIR_INDEX` items (one per entry, ordered by
    /// insertion sequence). Subvolume entries are returned with their
    /// `ROOT_ITEM` location so callers can cross into the child tree.
    pub fn list_dir(&mut self, dir: &Inode) -> Result<Vec<DirEntry>, Box<dyn Error>> {
        if !dir.is_dir() {
            return Err(format!(
                "inode {} of subvolume {} is not a directory",
                dir.ino, dir.tree_id
            )
            .into());
        }
        let tree = self.fs_tree(dir.tree_id)?;
        let items = self.items_in_range(
            tree,
            Key::first(dir.ino, DIR_INDEX_KEY),
            Key::last(dir.ino, DIR_INDEX_KEY),
        )?;
        let mut entries = Vec::with_capacity(items.len());
        for (key, data) in items {
            match DirItem::parse_all(&data) {
                Ok(dir_items) => {
                    for item in dir_items {
                        entries.push(self.make_entry(dir, key.offset, item));
                    }
                }
                Err(e) => warn!(
                    "subvolume {} inode {}: skipping malformed DIR_INDEX {}: {e}",
                    dir.tree_id, dir.ino, key.offset
                ),
            }
        }
        Ok(entries)
    }

    /// Resolve a directory entry to its inode, crossing into subvolumes.
    pub fn resolve_entry(&mut self, entry: &DirEntry) -> Result<Inode, Box<dyn Error>> {
        if entry.is_subvolume() && !entry.reachable {
            return Err(format!(
                "directory entry {} points to subvolume {} but no root reference backs it from this directory (stale copy inside a snapshot, shown as an empty directory by the kernel)",
                entry.name, entry.location.objectid
            )
            .into());
        }
        let (tree_id, ino) = entry.target().ok_or_else(|| {
            format!(
                "directory entry {} has an unexpected location {}",
                entry.name, entry.location
            )
        })?;
        let mut inode = if entry.is_subvolume() {
            self.get_subvolume_root(tree_id)?
        } else {
            self.get_inode(tree_id, ino)?
        };
        if entry.is_subvolume() {
            inode.entered_from = Some((entry.parent_tree, entry.parent_ino));
        }
        Ok(inode)
    }

    /// Look a name up in a directory through its hashed `DIR_ITEM`.
    pub fn lookup_name(
        &mut self,
        dir: &Inode,
        name: &[u8],
    ) -> Result<Option<DirEntry>, Box<dyn Error>> {
        let tree = self.fs_tree(dir.tree_id)?;
        let key = Key::new(dir.ino, DIR_ITEM_KEY, checksum::name_hash(name));
        let Some(data) = self.lookup(tree, key)? else {
            return Ok(None);
        };
        for item in DirItem::parse_all(&data)? {
            if item.name == name {
                return Ok(Some(self.make_entry(dir, 0, item)));
            }
        }
        Ok(None)
    }

    /// Build a directory entry. An entry pointing to a subvolume is only
    /// crossable when a root reference backs it from this very directory:
    /// a snapshot copies the parent's `DIR_ITEM`s unchanged, and the kernel
    /// (`fixup_tree_root_location`) shows such stale entries as empty
    /// directories instead of descending into the live child subvolume.
    fn make_entry(&self, dir: &Inode, index: u64, item: DirItem) -> DirEntry {
        let reachable = if item.location.ty == ROOT_ITEM_KEY {
            self.subvolume(item.location.objectid)
                .map(|s| {
                    s.parent_id == Some(dir.tree_id)
                        && s.parent_dirid == Some(dir.ino)
                        && s.name.as_bytes() == item.name.as_slice()
                })
                .unwrap_or(false)
        } else {
            true
        };
        DirEntry {
            parent_tree: dir.tree_id,
            parent_ino: dir.ino,
            index,
            name: item.name_lossy(),
            raw_name: item.name,
            file_type: item.ty,
            transid: item.transid,
            location: item.location,
            reachable,
        }
    }

    /// Resolve an absolute path from the top-level subvolume, crossing
    /// subvolume boundaries like a mounted filesystem would.
    pub fn resolve_path(&mut self, path: &str) -> Result<Inode, Box<dyn Error>> {
        let mut current = self.get_root()?;
        for component in path.split('/').filter(|c| !c.is_empty() && *c != ".") {
            if component == ".." {
                current = self.parent_of(&current)?;
                continue;
            }
            if !current.is_dir() {
                return Err(format!("{component}: not a directory").into());
            }
            let entry = self
                .lookup_name(&current, component.as_bytes())?
                .ok_or_else(|| format!("path component not found: {component:?}"))?;
            current = self.resolve_entry(&entry)?;
        }
        Ok(current)
    }

    /// Parent directory of an inode (first `INODE_REF`), crossing back out of
    /// a subvolume root.
    pub fn parent_of(&mut self, inode: &Inode) -> Result<Inode, Box<dyn Error>> {
        if inode.tree_id == FS_TREE_OBJECTID && inode.ino == FIRST_FREE_OBJECTID {
            return self.get_root();
        }
        if let Some((tree, ino)) = inode.entered_from {
            return self.get_inode(tree, ino);
        }
        let refs = self.inode_refs(inode)?;
        if let Some(r) = refs.first() {
            if r.parent_ino == inode.ino
                && inode.ino
                    == self
                        .subvolume(inode.tree_id)
                        .map(|s| s.root_dirid)
                        .unwrap_or(FIRST_FREE_OBJECTID)
            {
                // Subvolume root refers to itself ("..") : go to the parent subvolume.
                return self.subvolume_parent_dir(inode.tree_id);
            }
            return self.get_inode(inode.tree_id, r.parent_ino);
        }
        self.subvolume_parent_dir(inode.tree_id)
    }

    fn subvolume_parent_dir(&mut self, tree_id: u64) -> Result<Inode, Box<dyn Error>> {
        let s = self
            .subvolume(tree_id)
            .ok_or_else(|| format!("subvolume {tree_id} unknown"))?;
        match (s.parent_id, s.parent_dirid) {
            (Some(p), Some(d)) => self.get_inode(p, d),
            _ => Err(format!("subvolume {tree_id} has no parent").into()),
        }
    }

    /// Names of an inode (hard links included).
    pub fn inode_refs(&mut self, inode: &Inode) -> Result<Vec<InodeRef>, Box<dyn Error>> {
        let tree = self.fs_tree(inode.tree_id)?;
        let mut refs = Vec::new();
        for (key, data) in self.items_in_range(
            tree,
            Key::first(inode.ino, INODE_REF_KEY),
            Key::last(inode.ino, INODE_REF_KEY),
        )? {
            refs.extend(InodeRef::parse_all(key.offset, &data)?);
        }
        for (_, data) in self.items_in_range(
            tree,
            Key::first(inode.ino, INODE_EXTREF_KEY),
            Key::last(inode.ino, INODE_EXTREF_KEY),
        )? {
            refs.extend(InodeRef::parse_all_ext(&data)?);
        }
        Ok(refs)
    }

    /// Absolute path of an inode inside the whole filesystem (first name of
    /// each ancestor), crossing subvolume boundaries.
    pub fn inode_path(&mut self, tree_id: u64, ino: u64) -> Result<String, Box<dyn Error>> {
        let mut parts: Vec<String> = Vec::new();
        let mut cur_tree = tree_id;
        let mut cur_ino = ino;
        let mut guard = 0;
        loop {
            guard += 1;
            if guard > 4096 {
                return Err("path deeper than 4096 components".into());
            }
            let root_dirid = self
                .subvolume(cur_tree)
                .map(|s| s.root_dirid)
                .unwrap_or(FIRST_FREE_OBJECTID);
            if cur_ino == root_dirid {
                if cur_tree == FS_TREE_OBJECTID {
                    break;
                }
                let s = self
                    .subvolume(cur_tree)
                    .ok_or_else(|| format!("subvolume {cur_tree} unknown"))?;
                match (s.parent_id, s.parent_dirid) {
                    (Some(p), Some(d)) => {
                        parts.push(s.name.clone());
                        cur_tree = p;
                        cur_ino = d;
                        continue;
                    }
                    _ => return Err(format!("subvolume {cur_tree} has no parent").into()),
                }
            }
            let inode = self.get_inode(cur_tree, cur_ino)?;
            let refs = self.inode_refs(&inode)?;
            let r = refs
                .first()
                .ok_or_else(|| format!("inode {cur_ino} of subvolume {cur_tree} has no name"))?;
            parts.push(r.name.clone());
            cur_ino = r.parent_ino;
        }
        parts.reverse();
        Ok(format!("/{}", parts.join("/")))
    }

    /// Extended attributes of an inode.
    pub fn xattrs(&mut self, inode: &Inode) -> Result<Vec<Xattr>, Box<dyn Error>> {
        let tree = self.fs_tree(inode.tree_id)?;
        let mut out = Vec::new();
        for (_, data) in self.items_in_range(
            tree,
            Key::first(inode.ino, XATTR_ITEM_KEY),
            Key::last(inode.ino, XATTR_ITEM_KEY),
        )? {
            for item in DirItem::parse_all(&data)? {
                out.push(Xattr {
                    name: item.name_lossy(),
                    value: item.data,
                });
            }
        }
        Ok(out)
    }

    // ----------------------------------------------------------------------
    // File data
    // ----------------------------------------------------------------------

    /// File extents of an inode, in file offset order.
    pub fn extents(&mut self, inode: &Inode) -> Result<Vec<FileExtent>, Box<dyn Error>> {
        let tree = self.fs_tree(inode.tree_id)?;
        let items = self.items_in_range(
            tree,
            Key::first(inode.ino, EXTENT_DATA_KEY),
            Key::last(inode.ino, EXTENT_DATA_KEY),
        )?;
        let mut extents = Vec::with_capacity(items.len());
        for (key, data) in items {
            match FileExtent::from_bytes(key.offset, &data) {
                Ok(extent) => extents.push(extent),
                Err(e) => warn!(
                    "subvolume {} inode {}: skipping malformed EXTENT_DATA at file offset {}: {e} (range reads as zeroes)",
                    inode.tree_id, inode.ino, key.offset
                ),
            }
        }
        Ok(extents)
    }

    /// Bytes of one extent's file range `[from, to)` relative to the extent's
    /// file offset.
    fn read_extent_part(
        &mut self,
        extent: &FileExtent,
        from: u64,
        to: u64,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let len = (to - from) as usize;
        if extent.encryption != 0 {
            return Err(format!(
                "extent at file offset {} is encrypted (type {}), not supported",
                extent.file_offset, extent.encryption
            )
            .into());
        }
        if extent.other_encoding != 0 {
            return Err(format!(
                "extent at file offset {} uses an unknown encoding {}",
                extent.file_offset, extent.other_encoding
            )
            .into());
        }
        let sectorsize = self.superblock.sectorsize;
        match &extent.storage {
            ExtentStorage::Inline { data } => {
                let plain = if extent.compression == extent::COMPRESS_NONE {
                    data.clone()
                } else {
                    compression::decompress(extent.compression, data, extent.ram_bytes, sectorsize)?
                };
                let mut out = vec![0u8; len];
                let avail = plain.len() as u64;
                if from < avail {
                    let end = to.min(avail);
                    out[..(end - from) as usize]
                        .copy_from_slice(&plain[from as usize..end as usize]);
                }
                Ok(out)
            }
            ExtentStorage::Prealloc { .. } => Ok(vec![0u8; len]),
            ExtentStorage::Regular {
                disk_bytenr,
                disk_num_bytes,
                offset,
                num_bytes,
            } => {
                if *disk_bytenr == 0 {
                    return Ok(vec![0u8; len]);
                }
                if extent.compression == extent::COMPRESS_NONE {
                    let start = disk_bytenr
                        .checked_add(*offset)
                        .and_then(|s| s.checked_add(from))
                        .ok_or("extent offset overflow")?;
                    if offset
                        .checked_add(*num_bytes)
                        .is_none_or(|end| end > *disk_num_bytes)
                    {
                        return Err(format!(
                            "extent at file offset {} reads past its disk extent",
                            extent.file_offset
                        )
                        .into());
                    }
                    self.read_logical(start, len as u64)
                } else {
                    if *disk_num_bytes > compression::MAX_DECOMPRESSED_EXTENT {
                        return Err(format!(
                            "compressed extent at file offset {} is {} bytes on disk, refusing",
                            extent.file_offset, disk_num_bytes
                        )
                        .into());
                    }
                    let raw = self.read_logical(*disk_bytenr, *disk_num_bytes)?;
                    let plain = compression::decompress(
                        extent.compression,
                        &raw,
                        extent.ram_bytes,
                        sectorsize,
                    )?;
                    let start = offset.checked_add(from).ok_or("extent offset overflow")?;
                    let end = offset.checked_add(to).ok_or("extent offset overflow")?;
                    let mut out = vec![0u8; len];
                    if start < plain.len() as u64 {
                        let (start, end) = (start as usize, end as usize);
                        let e = end.min(plain.len());
                        out[..e - start].copy_from_slice(&plain[start..e]);
                    } else {
                        warn!(
                            "extent at file offset {}: decompressed {} bytes, shorter than expected (reading zeroes)",
                            extent.file_offset,
                            plain.len()
                        );
                    }
                    Ok(out)
                }
            }
        }
    }

    /// Read `[offset, offset+length)` of a file. Ranges without an extent
    /// (holes, `no_holes` gaps) read as zeroes; reads past `size` are cut.
    pub fn read_inode_slice(
        &mut self,
        inode: &Inode,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let size = inode.size();
        if offset >= size {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(length as u64).min(size);
        let mut out = vec![0u8; (end - offset) as usize];
        if inode.is_dir() {
            return Err("cannot read a directory as a file".into());
        }
        let extents = self.extents(inode)?;
        let mut last_end = 0u64;
        for extent in &extents {
            let e_start = extent.file_offset;
            let e_end = e_start.saturating_add(extent.num_bytes());
            if e_start < last_end {
                warn!(
                    "subvolume {} inode {}: overlapping extents at file offset {e_start}",
                    inode.tree_id, inode.ino
                );
            }
            last_end = e_end;
            if e_end <= offset || e_start >= end {
                continue;
            }
            let from = offset.max(e_start);
            let to = end.min(e_end);
            let part = self.read_extent_part(extent, from - e_start, to - e_start)?;
            let dst = (from - offset) as usize;
            out[dst..dst + part.len()].copy_from_slice(&part);
        }
        Ok(out)
    }

    pub fn read_inode_prefix(
        &mut self,
        inode: &Inode,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.read_inode_slice(inode, 0, length)
    }

    /// Read a whole file (bounded by [`MAX_READ_BYTES`]).
    pub fn read_inode(&mut self, inode: &Inode) -> Result<Vec<u8>, Box<dyn Error>> {
        if inode.size() > MAX_READ_BYTES {
            return Err(format!(
                "file is {} bytes, larger than the {} byte in-memory limit; use slices",
                inode.size(),
                MAX_READ_BYTES
            )
            .into());
        }
        self.read_inode_slice(inode, 0, inode.size() as usize)
    }

    /// Target of a symbolic link.
    pub fn read_symlink(&mut self, inode: &Inode) -> Result<String, Box<dyn Error>> {
        if !inode.is_symlink() {
            return Err("not a symbolic link".into());
        }
        let data = self.read_inode(inode)?;
        Ok(String::from_utf8_lossy(&data).into_owned())
    }

    // ----------------------------------------------------------------------
    // Metadata
    // ----------------------------------------------------------------------

    pub fn metadata_json(&self) -> Value {
        json!({
            "filesystem": "btrfs",
            "superblock": self.superblock.to_json(),
            "default_subvolume": self.default_subvolume,
            "subvolumes": self.subvolumes.iter().map(|s| s.to_json()).collect::<Vec<_>>(),
            "chunks": self.chunks.chunks().map(|c| c.to_json()).collect::<Vec<_>>(),
            "trees": self.tree_ids(),
            "log_tree_unreplayed": self.superblock.log_root != 0,
        })
    }

    pub fn metadata_pretty(&self) -> String {
        use prettytable::{Cell, Row, Table};
        let mut out = format!("{}\n", self.superblock);
        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("ID"),
            Cell::new("Kind"),
            Cell::new("Path"),
            Cell::new("RO"),
            Cell::new("Default"),
            Cell::new("Created"),
            Cell::new("UUID"),
            Cell::new("Parent UUID"),
        ]));
        for s in &self.subvolumes {
            table.add_row(Row::new(vec![
                Cell::new(&s.id.to_string()),
                Cell::new(s.kind_name()),
                Cell::new(&s.path),
                Cell::new(if s.readonly { "yes" } else { "no" }),
                Cell::new(if s.is_default { "yes" } else { "" }),
                Cell::new(&s.otime_h),
                Cell::new(&s.uuid),
                Cell::new(&s.parent_uuid),
            ]));
        }
        out.push_str(&format!("{table}"));
        let mut chunks = Table::new();
        chunks.add_row(Row::new(vec![
            Cell::new("Logical"),
            Cell::new("Length"),
            Cell::new("Kind"),
            Cell::new("Profile"),
            Cell::new("Stripes (devid:offset)"),
        ]));
        for c in self.chunks.chunks() {
            let stripes: Vec<String> = c
                .stripes
                .iter()
                .map(|s| format!("{}:{}", s.devid, s.offset))
                .collect();
            chunks.add_row(Row::new(vec![
                Cell::new(&c.logical.to_string()),
                Cell::new(&c.length.to_string()),
                Cell::new(&c.kind_name()),
                Cell::new(c.profile_name()),
                Cell::new(&stripes.join(" ")),
            ]));
        }
        out.push_str(&format!("{chunks}"));
        out
    }
}

/// Whether the source carries a Btrfs superblock magic at the primary
/// location. Cheap probe for filesystem detection: a positive answer followed
/// by an open failure means a damaged or unsupported Btrfs filesystem, not
/// another filesystem.
pub fn has_btrfs_magic<T: Read + Seek>(body: &mut T) -> bool {
    let mut magic = [0u8; 8];
    body.seek(SeekFrom::Start(SUPERBLOCK_OFFSETS[0] + 0x40))
        .is_ok()
        && body.read_exact(&mut magic).is_ok()
        && u64::from_le_bytes(magic) == superblock::SUPERBLOCK_MAGIC
}

/// Read the superblock copies and return the best one: the first copy with a
/// valid checksum, preferring the highest generation among valid copies.
fn read_best_superblock<T: Read + Seek>(body: &mut T) -> Result<Superblock, Box<dyn Error>> {
    let mut best: Option<Superblock> = None;
    let mut first_error: Option<String> = None;
    for &offset in &SUPERBLOCK_OFFSETS {
        if body.seek(SeekFrom::Start(offset)).is_err() {
            continue;
        }
        let mut buf = vec![0u8; SUPERBLOCK_SIZE];
        if body.read_exact(&mut buf).is_err() {
            continue;
        }
        match Superblock::from_bytes(&buf, offset) {
            Ok(sb) => {
                if checksum::csum_len(sb.csum_type).is_none() {
                    if first_error.is_none() {
                        first_error = Some(format!(
                            "superblock at 0x{offset:x} uses an unsupported checksum type {}",
                            sb.csum_type
                        ));
                    }
                    continue;
                }
                if sb.bytenr != offset {
                    warn!(
                        "superblock copy at 0x{offset:x} claims bytenr {}, skipping it",
                        sb.bytenr
                    );
                    if first_error.is_none() {
                        first_error = Some(format!(
                            "superblock at 0x{offset:x} has a wrong bytenr {}",
                            sb.bytenr
                        ));
                    }
                    continue;
                }
                if !sb.csum_valid {
                    warn!("superblock copy at 0x{offset:x} has a bad checksum, skipping it");
                    if first_error.is_none() {
                        first_error =
                            Some(format!("superblock at 0x{offset:x} has a bad checksum"));
                    }
                    continue;
                }
                match &best {
                    Some(b) if b.generation >= sb.generation => {}
                    _ => best = Some(sb),
                }
            }
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
    }
    match best {
        Some(sb) => {
            if sb.read_from != SUPERBLOCK_OFFSETS[0] {
                warn!("using the superblock mirror at 0x{:x}", sb.read_from);
            }
            Ok(sb)
        }
        None => Err(first_error
            .unwrap_or_else(|| "no Btrfs superblock found".to_string())
            .into()),
    }
}

/// Pack `(subvolume slot, inode)` into one `u64` identifier for consumers
/// that need a single number per file (the `exhume_filesystem` abstraction).
/// The slot is the position in [`BtrfsFS::subvolumes`] (0 = top level), the
/// inode number is limited to 48 bits.
pub const PACKED_INO_BITS: u32 = 48;
pub const PACKED_INO_MASK: u64 = (1 << PACKED_INO_BITS) - 1;

pub fn pack_id(slot: usize, ino: u64) -> Option<u64> {
    if slot >= (1 << (64 - PACKED_INO_BITS)) || ino > PACKED_INO_MASK {
        return None;
    }
    Some(((slot as u64) << PACKED_INO_BITS) | ino)
}

pub fn unpack_id(id: u64) -> (usize, u64) {
    ((id >> PACKED_INO_BITS) as usize, id & PACKED_INO_MASK)
}

impl<T: Read + Seek> BtrfsFS<T> {
    /// Slot of a subvolume in the sorted subvolume table.
    pub fn subvolume_slot(&self, tree_id: u64) -> Option<usize> {
        self.subvolumes.iter().position(|s| s.id == tree_id)
    }

    pub fn subvolume_at_slot(&self, slot: usize) -> Option<&Subvolume> {
        self.subvolumes.get(slot)
    }

    /// Packed identifier of an inode, see [`pack_id`].
    pub fn packed_id(&self, inode: &Inode) -> Option<u64> {
        pack_id(self.subvolume_slot(inode.tree_id)?, inode.ino)
    }

    /// Fetch an inode from a packed identifier.
    pub fn get_inode_packed(&mut self, id: u64) -> Result<Inode, Box<dyn Error>> {
        let (slot, ino) = unpack_id(id);
        let tree_id = self
            .subvolume_at_slot(slot)
            .map(|s| s.id)
            .ok_or_else(|| format!("identifier {id}: no subvolume at slot {slot}"))?;
        self.get_inode(tree_id, ino)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_ids() {
        assert_eq!(pack_id(0, 256), Some(256));
        assert_eq!(unpack_id(pack_id(3, 1000).unwrap()), (3, 1000));
        assert!(pack_id(70000, 1).is_none());
        assert!(pack_id(0, 1 << 50).is_none());
    }
}
