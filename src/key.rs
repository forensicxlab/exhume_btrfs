//! Btrfs keys, item types and well-known object identifiers.
//!
//! Reference: <https://btrfs.readthedocs.io/en/latest/dev/On-disk-format.html>
//! and `include/uapi/linux/btrfs_tree.h` in the Linux kernel.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;

/// Size of an on-disk key (`btrfs_disk_key`).
pub const KEY_SIZE: usize = 17;

// Well-known tree / object identifiers.
pub const ROOT_TREE_OBJECTID: u64 = 1;
pub const EXTENT_TREE_OBJECTID: u64 = 2;
pub const CHUNK_TREE_OBJECTID: u64 = 3;
pub const DEV_TREE_OBJECTID: u64 = 4;
pub const FS_TREE_OBJECTID: u64 = 5;
pub const ROOT_TREE_DIR_OBJECTID: u64 = 6;
pub const CSUM_TREE_OBJECTID: u64 = 7;
pub const QUOTA_TREE_OBJECTID: u64 = 8;
pub const UUID_TREE_OBJECTID: u64 = 9;
pub const FREE_SPACE_TREE_OBJECTID: u64 = 10;
pub const BLOCK_GROUP_TREE_OBJECTID: u64 = 11;
pub const RAID_STRIPE_TREE_OBJECTID: u64 = 12;
pub const DEV_ITEMS_OBJECTID: u64 = 1;
pub const FIRST_CHUNK_TREE_OBJECTID: u64 = 256;
pub const FIRST_FREE_OBJECTID: u64 = 256;
pub const LAST_FREE_OBJECTID: u64 = u64::MAX - 256;
pub const TREE_LOG_OBJECTID: u64 = u64::MAX - 6;
pub const TREE_RELOC_OBJECTID: u64 = u64::MAX - 7;
pub const DATA_RELOC_TREE_OBJECTID: u64 = u64::MAX - 8;
pub const FREE_INO_OBJECTID: u64 = u64::MAX - 11;
pub const ORPHAN_OBJECTID: u64 = u64::MAX - 4;

// Item types.
pub const INODE_ITEM_KEY: u8 = 1;
pub const INODE_REF_KEY: u8 = 12;
pub const INODE_EXTREF_KEY: u8 = 13;
pub const XATTR_ITEM_KEY: u8 = 24;
pub const VERITY_DESC_ITEM_KEY: u8 = 36;
pub const VERITY_MERKLE_ITEM_KEY: u8 = 37;
pub const ORPHAN_ITEM_KEY: u8 = 48;
pub const DIR_LOG_ITEM_KEY: u8 = 60;
pub const DIR_LOG_INDEX_KEY: u8 = 72;
pub const DIR_ITEM_KEY: u8 = 84;
pub const DIR_INDEX_KEY: u8 = 96;
pub const EXTENT_DATA_KEY: u8 = 108;
pub const EXTENT_CSUM_KEY: u8 = 128;
pub const ROOT_ITEM_KEY: u8 = 132;
pub const ROOT_BACKREF_KEY: u8 = 144;
pub const ROOT_REF_KEY: u8 = 156;
pub const EXTENT_ITEM_KEY: u8 = 168;
pub const METADATA_ITEM_KEY: u8 = 169;
pub const TREE_BLOCK_REF_KEY: u8 = 176;
pub const EXTENT_DATA_REF_KEY: u8 = 178;
pub const SHARED_BLOCK_REF_KEY: u8 = 182;
pub const SHARED_DATA_REF_KEY: u8 = 184;
pub const BLOCK_GROUP_ITEM_KEY: u8 = 192;
pub const FREE_SPACE_INFO_KEY: u8 = 198;
pub const FREE_SPACE_EXTENT_KEY: u8 = 199;
pub const FREE_SPACE_BITMAP_KEY: u8 = 200;
pub const DEV_EXTENT_KEY: u8 = 204;
pub const DEV_ITEM_KEY: u8 = 216;
pub const CHUNK_ITEM_KEY: u8 = 228;
pub const RAID_STRIPE_KEY: u8 = 230;
pub const QGROUP_STATUS_KEY: u8 = 240;
pub const QGROUP_INFO_KEY: u8 = 242;
pub const QGROUP_LIMIT_KEY: u8 = 244;
pub const QGROUP_RELATION_KEY: u8 = 246;
pub const TEMPORARY_ITEM_KEY: u8 = 248;
pub const PERSISTENT_ITEM_KEY: u8 = 249;
pub const DEV_REPLACE_KEY: u8 = 250;
pub const UUID_KEY_SUBVOL: u8 = 251;
pub const UUID_KEY_RECEIVED_SUBVOL: u8 = 252;
pub const STRING_ITEM_KEY: u8 = 253;

pub fn item_type_name(ty: u8) -> &'static str {
    match ty {
        INODE_ITEM_KEY => "INODE_ITEM",
        INODE_REF_KEY => "INODE_REF",
        INODE_EXTREF_KEY => "INODE_EXTREF",
        XATTR_ITEM_KEY => "XATTR_ITEM",
        VERITY_DESC_ITEM_KEY => "VERITY_DESC_ITEM",
        VERITY_MERKLE_ITEM_KEY => "VERITY_MERKLE_ITEM",
        ORPHAN_ITEM_KEY => "ORPHAN_ITEM",
        DIR_LOG_ITEM_KEY => "DIR_LOG_ITEM",
        DIR_LOG_INDEX_KEY => "DIR_LOG_INDEX",
        DIR_ITEM_KEY => "DIR_ITEM",
        DIR_INDEX_KEY => "DIR_INDEX",
        EXTENT_DATA_KEY => "EXTENT_DATA",
        EXTENT_CSUM_KEY => "EXTENT_CSUM",
        ROOT_ITEM_KEY => "ROOT_ITEM",
        ROOT_BACKREF_KEY => "ROOT_BACKREF",
        ROOT_REF_KEY => "ROOT_REF",
        EXTENT_ITEM_KEY => "EXTENT_ITEM",
        METADATA_ITEM_KEY => "METADATA_ITEM",
        TREE_BLOCK_REF_KEY => "TREE_BLOCK_REF",
        EXTENT_DATA_REF_KEY => "EXTENT_DATA_REF",
        SHARED_BLOCK_REF_KEY => "SHARED_BLOCK_REF",
        SHARED_DATA_REF_KEY => "SHARED_DATA_REF",
        BLOCK_GROUP_ITEM_KEY => "BLOCK_GROUP_ITEM",
        FREE_SPACE_INFO_KEY => "FREE_SPACE_INFO",
        FREE_SPACE_EXTENT_KEY => "FREE_SPACE_EXTENT",
        FREE_SPACE_BITMAP_KEY => "FREE_SPACE_BITMAP",
        DEV_EXTENT_KEY => "DEV_EXTENT",
        DEV_ITEM_KEY => "DEV_ITEM",
        CHUNK_ITEM_KEY => "CHUNK_ITEM",
        RAID_STRIPE_KEY => "RAID_STRIPE",
        QGROUP_STATUS_KEY => "QGROUP_STATUS",
        QGROUP_INFO_KEY => "QGROUP_INFO",
        QGROUP_LIMIT_KEY => "QGROUP_LIMIT",
        QGROUP_RELATION_KEY => "QGROUP_RELATION",
        TEMPORARY_ITEM_KEY => "TEMPORARY_ITEM",
        PERSISTENT_ITEM_KEY => "PERSISTENT_ITEM",
        DEV_REPLACE_KEY => "DEV_REPLACE",
        UUID_KEY_SUBVOL => "UUID_KEY_SUBVOL",
        UUID_KEY_RECEIVED_SUBVOL => "UUID_KEY_RECEIVED_SUBVOL",
        STRING_ITEM_KEY => "STRING_ITEM",
        _ => "UNKNOWN",
    }
}

/// A Btrfs key: `(objectid, type, offset)`, ordered lexicographically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Key {
    pub objectid: u64,
    pub ty: u8,
    pub offset: u64,
}

impl Key {
    pub const MIN: Key = Key {
        objectid: 0,
        ty: 0,
        offset: 0,
    };
    pub const MAX: Key = Key {
        objectid: u64::MAX,
        ty: u8::MAX,
        offset: u64::MAX,
    };

    pub const fn new(objectid: u64, ty: u8, offset: u64) -> Self {
        Key {
            objectid,
            ty,
            offset,
        }
    }

    /// Parse a `btrfs_disk_key` from 17 little-endian bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < KEY_SIZE {
            return None;
        }
        Some(Key {
            objectid: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            ty: data[8],
            offset: u64::from_le_bytes(data[9..17].try_into().unwrap()),
        })
    }

    pub fn to_bytes(&self) -> [u8; KEY_SIZE] {
        let mut out = [0u8; KEY_SIZE];
        out[0..8].copy_from_slice(&self.objectid.to_le_bytes());
        out[8] = self.ty;
        out[9..17].copy_from_slice(&self.offset.to_le_bytes());
        out
    }

    /// First possible key for `(objectid, ty)`.
    pub const fn first(objectid: u64, ty: u8) -> Self {
        Key::new(objectid, ty, 0)
    }

    /// Last possible key for `(objectid, ty)`.
    pub const fn last(objectid: u64, ty: u8) -> Self {
        Key::new(objectid, ty, u64::MAX)
    }

    pub fn type_name(&self) -> &'static str {
        item_type_name(self.ty)
    }
}

impl PartialOrd for Key {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Key {
    fn cmp(&self, other: &Self) -> Ordering {
        self.objectid
            .cmp(&other.objectid)
            .then(self.ty.cmp(&other.ty))
            .then(self.offset.cmp(&other.offset))
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let offset = if self.offset == u64::MAX {
            "-1".to_string()
        } else {
            self.offset.to_string()
        };
        write!(f, "({} {} {})", self.objectid, self.type_name(), offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_roundtrip_and_order() {
        let k = Key::new(256, DIR_INDEX_KEY, 7);
        assert_eq!(Key::from_bytes(&k.to_bytes()), Some(k));
        assert!(Key::new(256, INODE_ITEM_KEY, 0) < Key::new(256, DIR_INDEX_KEY, 0));
        assert!(Key::new(256, DIR_INDEX_KEY, 1) < Key::new(257, INODE_ITEM_KEY, 0));
        assert!(Key::from_bytes(&[0u8; 16]).is_none());
        assert_eq!(
            format!("{}", Key::new(5, ROOT_ITEM_KEY, u64::MAX)),
            "(5 ROOT_ITEM -1)"
        );
    }
}
