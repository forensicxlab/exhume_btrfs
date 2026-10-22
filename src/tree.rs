//! B-tree node parsing (`btrfs_header`, `btrfs_item`, `btrfs_key_ptr`).
//!
//! A node is exactly `nodesize` bytes. It starts with a 101-byte header; a
//! leaf (level 0) then holds an array of 25-byte items whose data is stored
//! from the end of the node backwards, an internal node holds 33-byte key
//! pointers to child nodes.

use crate::key::{KEY_SIZE, Key};
use crate::superblock::{format_uuid, le_u32, le_u64};
use serde::{Deserialize, Serialize};

pub const HEADER_SIZE: usize = 101;
pub const ITEM_SIZE: usize = 25;
pub const KEY_PTR_SIZE: usize = 33;
pub const MAX_LEVEL: u8 = 8;

pub const HEADER_FLAG_WRITTEN: u64 = 1 << 0;
pub const HEADER_FLAG_RELOC: u64 = 1 << 1;
pub const HEADER_FLAG_MIXED_BACKREF: u64 = 1 << 56;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHeader {
    pub csum: Vec<u8>,
    pub fsid: String,
    pub bytenr: u64,
    pub flags: u64,
    pub chunk_tree_uuid: String,
    pub generation: u64,
    pub owner: u64,
    pub nritems: u32,
    pub level: u8,
}

impl NodeHeader {
    pub fn from_bytes(d: &[u8]) -> Option<Self> {
        if d.len() < HEADER_SIZE {
            return None;
        }
        Some(NodeHeader {
            csum: d[0..32].to_vec(),
            fsid: format_uuid(&d[0x20..0x30]),
            bytenr: le_u64(d, 0x30),
            flags: le_u64(d, 0x38),
            chunk_tree_uuid: format_uuid(&d[0x40..0x50]),
            generation: le_u64(d, 0x50),
            owner: le_u64(d, 0x58),
            nritems: le_u32(d, 0x60),
            level: d[0x64],
        })
    }
}

/// Leaf item descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Item {
    pub key: Key,
    /// Offset of the item data relative to the end of the header.
    pub offset: u32,
    pub size: u32,
}

/// Internal node child pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPtr {
    pub key: Key,
    pub blockptr: u64,
    pub generation: u64,
}

/// A validated tree node.
#[derive(Debug, Clone)]
pub struct Node {
    pub header: NodeHeader,
    data: Vec<u8>,
}

impl Node {
    /// Parse and structurally validate a node. `expected_bytenr` is the
    /// logical address it was read from; `expected_level`, when known, must
    /// match the header. The checksum is verified by the caller (it needs the
    /// superblock checksum type).
    pub fn parse(
        data: Vec<u8>,
        expected_bytenr: u64,
        expected_level: Option<u8>,
    ) -> Result<Self, String> {
        let header = NodeHeader::from_bytes(&data)
            .ok_or_else(|| format!("node at {expected_bytenr}: shorter than a header"))?;
        if header.bytenr != expected_bytenr {
            return Err(format!(
                "node at {expected_bytenr}: header bytenr is {} (block pointer mismatch)",
                header.bytenr
            ));
        }
        if header.level >= MAX_LEVEL {
            return Err(format!(
                "node at {expected_bytenr}: level {} out of range",
                header.level
            ));
        }
        if let Some(level) = expected_level
            && header.level != level
        {
            return Err(format!(
                "node at {expected_bytenr}: level {} but parent expects {level}",
                header.level
            ));
        }
        let nritems = header.nritems as usize;
        let avail = data.len() - HEADER_SIZE;
        if header.level == 0 {
            if nritems * ITEM_SIZE > avail {
                return Err(format!(
                    "leaf at {expected_bytenr}: {nritems} items do not fit in the node"
                ));
            }
            let node = Node { header, data };
            let mut prev_key: Option<Key> = None;
            let mut data_start = avail;
            for i in 0..nritems {
                let item = node.item(i);
                let start = item.offset as usize;
                let end = start
                    .checked_add(item.size as usize)
                    .ok_or_else(|| format!("leaf at {expected_bytenr}: item {i} overflows"))?;
                if end > avail || start < nritems * ITEM_SIZE {
                    return Err(format!(
                        "leaf at {expected_bytenr}: item {i} data [{start}, {end}) is outside the node"
                    ));
                }
                // Items are laid out from the end of the leaf backwards.
                if end > data_start {
                    return Err(format!(
                        "leaf at {expected_bytenr}: item {i} overlaps the previous item"
                    ));
                }
                data_start = start;
                if let Some(prev) = prev_key
                    && item.key <= prev
                {
                    return Err(format!(
                        "leaf at {expected_bytenr}: keys out of order at item {i} ({} after {prev})",
                        item.key
                    ));
                }
                prev_key = Some(item.key);
            }
            Ok(node)
        } else {
            if nritems * KEY_PTR_SIZE > avail {
                return Err(format!(
                    "node at {expected_bytenr}: {nritems} key pointers do not fit in the node"
                ));
            }
            if nritems == 0 {
                return Err(format!(
                    "internal node at {expected_bytenr} has no children"
                ));
            }
            let node = Node { header, data };
            let mut prev_key: Option<Key> = None;
            for i in 0..nritems {
                let ptr = node.key_ptr(i);
                if let Some(prev) = prev_key
                    && ptr.key <= prev
                {
                    return Err(format!(
                        "node at {expected_bytenr}: keys out of order at pointer {i}"
                    ));
                }
                prev_key = Some(ptr.key);
            }
            Ok(node)
        }
    }

    pub fn raw(&self) -> &[u8] {
        &self.data
    }

    pub fn is_leaf(&self) -> bool {
        self.header.level == 0
    }

    pub fn nritems(&self) -> usize {
        self.header.nritems as usize
    }

    /// Leaf item descriptor `i` (caller guarantees `i < nritems`, leaf).
    pub fn item(&self, i: usize) -> Item {
        let base = HEADER_SIZE + i * ITEM_SIZE;
        let d = &self.data[base..base + ITEM_SIZE];
        Item {
            key: Key::from_bytes(d).unwrap(),
            offset: le_u32(d, KEY_SIZE),
            size: le_u32(d, KEY_SIZE + 4),
        }
    }

    /// Data of leaf item `i`.
    pub fn item_data(&self, i: usize) -> &[u8] {
        let item = self.item(i);
        let start = HEADER_SIZE + item.offset as usize;
        &self.data[start..start + item.size as usize]
    }

    /// Internal node key pointer `i`.
    pub fn key_ptr(&self, i: usize) -> KeyPtr {
        let base = HEADER_SIZE + i * KEY_PTR_SIZE;
        let d = &self.data[base..base + KEY_PTR_SIZE];
        KeyPtr {
            key: Key::from_bytes(d).unwrap(),
            blockptr: le_u64(d, KEY_SIZE),
            generation: le_u64(d, KEY_SIZE + 8),
        }
    }

    pub fn items(&self) -> impl Iterator<Item = (Item, &[u8])> + '_ {
        (0..self.nritems()).map(move |i| (self.item(i), self.item_data(i)))
    }

    pub fn key_ptrs(&self) -> impl Iterator<Item = KeyPtr> + '_ {
        (0..self.nritems()).map(move |i| self.key_ptr(i))
    }

    /// Index of the first leaf item whose key is `>= key`.
    pub fn leaf_lower_bound(&self, key: &Key) -> usize {
        let (mut lo, mut hi) = (0, self.nritems());
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.item(mid).key < *key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }

    /// Index of the child that may contain `key`: the last pointer whose key
    /// is `<= key`, or 0 when all pointers are greater.
    pub fn child_for(&self, key: &Key) -> usize {
        let (mut lo, mut hi) = (0, self.nritems());
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.key_ptr(mid).key <= *key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo.saturating_sub(1)
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Minimal node builder used by the unit tests.
    use super::*;

    pub fn leaf(nodesize: usize, bytenr: u64, owner: u64, items: &[(Key, Vec<u8>)]) -> Vec<u8> {
        let mut node = vec![0u8; nodesize];
        node[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
        node[0x38..0x40].copy_from_slice(&HEADER_FLAG_WRITTEN.to_le_bytes());
        node[0x50..0x58].copy_from_slice(&1u64.to_le_bytes());
        node[0x58..0x60].copy_from_slice(&owner.to_le_bytes());
        node[0x60..0x64].copy_from_slice(&(items.len() as u32).to_le_bytes());
        node[0x64] = 0;
        let mut data_end = nodesize - HEADER_SIZE;
        for (i, (key, data)) in items.iter().enumerate() {
            data_end -= data.len();
            let base = HEADER_SIZE + i * ITEM_SIZE;
            node[base..base + KEY_SIZE].copy_from_slice(&key.to_bytes());
            node[base + KEY_SIZE..base + KEY_SIZE + 4]
                .copy_from_slice(&(data_end as u32).to_le_bytes());
            node[base + KEY_SIZE + 4..base + ITEM_SIZE]
                .copy_from_slice(&(data.len() as u32).to_le_bytes());
            node[HEADER_SIZE + data_end..HEADER_SIZE + data_end + data.len()].copy_from_slice(data);
        }
        node
    }

    pub fn internal(
        nodesize: usize,
        bytenr: u64,
        owner: u64,
        level: u8,
        ptrs: &[(Key, u64)],
    ) -> Vec<u8> {
        let mut node = vec![0u8; nodesize];
        node[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
        node[0x50..0x58].copy_from_slice(&1u64.to_le_bytes());
        node[0x58..0x60].copy_from_slice(&owner.to_le_bytes());
        node[0x60..0x64].copy_from_slice(&(ptrs.len() as u32).to_le_bytes());
        node[0x64] = level;
        for (i, (key, blockptr)) in ptrs.iter().enumerate() {
            let base = HEADER_SIZE + i * KEY_PTR_SIZE;
            node[base..base + KEY_SIZE].copy_from_slice(&key.to_bytes());
            node[base + KEY_SIZE..base + KEY_SIZE + 8].copy_from_slice(&blockptr.to_le_bytes());
            node[base + KEY_SIZE + 8..base + KEY_PTR_SIZE].copy_from_slice(&1u64.to_le_bytes());
        }
        node
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use crate::key::{DIR_INDEX_KEY, INODE_ITEM_KEY};

    #[test]
    fn leaf_items_are_parsed_and_searched() {
        let items = vec![
            (Key::new(256, INODE_ITEM_KEY, 0), vec![1u8; 160]),
            (Key::new(256, DIR_INDEX_KEY, 2), vec![2u8; 40]),
            (Key::new(257, INODE_ITEM_KEY, 0), vec![3u8; 160]),
        ];
        let node = Node::parse(leaf(4096, 0x1000, 5, &items), 0x1000, Some(0)).unwrap();
        assert_eq!(node.nritems(), 3);
        assert_eq!(node.item_data(1), &[2u8; 40]);
        assert_eq!(node.leaf_lower_bound(&Key::new(256, DIR_INDEX_KEY, 0)), 1);
        assert_eq!(node.leaf_lower_bound(&Key::new(300, 0, 0)), 3);
        assert!(Node::parse(leaf(4096, 0x1000, 5, &items), 0x2000, None).is_err());
        assert!(Node::parse(leaf(4096, 0x1000, 5, &items), 0x1000, Some(1)).is_err());
    }

    #[test]
    fn leaf_rejects_out_of_order_and_overlapping_items() {
        let items = vec![
            (Key::new(257, INODE_ITEM_KEY, 0), vec![1u8; 16]),
            (Key::new(256, INODE_ITEM_KEY, 0), vec![2u8; 16]),
        ];
        assert!(Node::parse(leaf(4096, 0, 5, &items), 0, None).is_err());
        let ok = vec![(Key::new(256, INODE_ITEM_KEY, 0), vec![1u8; 16])];
        let mut raw = leaf(4096, 0, 5, &ok);
        // Make the item claim a size running past the node.
        raw[HEADER_SIZE + KEY_SIZE + 4..HEADER_SIZE + ITEM_SIZE]
            .copy_from_slice(&5000u32.to_le_bytes());
        assert!(Node::parse(raw, 0, None).is_err());
        let mut raw = leaf(4096, 0, 5, &ok);
        raw[0x60..0x64].copy_from_slice(&1000u32.to_le_bytes());
        assert!(Node::parse(raw, 0, None).is_err());
    }

    #[test]
    fn internal_child_selection() {
        let ptrs = vec![
            (Key::new(256, INODE_ITEM_KEY, 0), 0x10000),
            (Key::new(300, INODE_ITEM_KEY, 0), 0x20000),
            (Key::new(400, INODE_ITEM_KEY, 0), 0x30000),
        ];
        let node = Node::parse(internal(4096, 0x4000, 5, 1, &ptrs), 0x4000, None).unwrap();
        assert!(!node.is_leaf());
        assert_eq!(node.child_for(&Key::new(1, 0, 0)), 0);
        assert_eq!(node.child_for(&Key::new(256, INODE_ITEM_KEY, 0)), 0);
        assert_eq!(node.child_for(&Key::new(350, 0, 0)), 1);
        assert_eq!(node.child_for(&Key::new(400, INODE_ITEM_KEY, 0)), 2);
        assert_eq!(node.child_for(&Key::MAX), 2);
        assert!(Node::parse(internal(4096, 0, 5, 1, &[]), 0, None).is_err());
    }
}
