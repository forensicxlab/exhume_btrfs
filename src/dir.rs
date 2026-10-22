//! Directory items (`btrfs_dir_item`), directory entries and inode references.

use crate::key::{INODE_ITEM_KEY, Key, ROOT_ITEM_KEY};
use crate::superblock::{le_u16, le_u64};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;

pub const DIR_ITEM_HEADER_SIZE: usize = 30;

pub const FT_UNKNOWN: u8 = 0;
pub const FT_REG_FILE: u8 = 1;
pub const FT_DIR: u8 = 2;
pub const FT_CHRDEV: u8 = 3;
pub const FT_BLKDEV: u8 = 4;
pub const FT_FIFO: u8 = 5;
pub const FT_SOCK: u8 = 6;
pub const FT_SYMLINK: u8 = 7;
pub const FT_XATTR: u8 = 8;

pub fn file_type_name(ty: u8) -> &'static str {
    match ty {
        FT_UNKNOWN => "unknown",
        FT_REG_FILE => "file",
        FT_DIR => "dir",
        FT_CHRDEV => "chardev",
        FT_BLKDEV => "blockdev",
        FT_FIFO => "fifo",
        FT_SOCK => "socket",
        FT_SYMLINK => "symlink",
        FT_XATTR => "xattr",
        _ => "invalid",
    }
}

/// One decoded `btrfs_dir_item` (an item may pack several when names collide).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirItem {
    pub location: Key,
    pub transid: u64,
    pub ty: u8,
    pub name: Vec<u8>,
    pub data: Vec<u8>,
}

impl DirItem {
    /// Decode every dir item packed in an item body.
    pub fn parse_all(d: &[u8]) -> Result<Vec<DirItem>, String> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < d.len() {
            let rest = &d[pos..];
            if rest.len() < DIR_ITEM_HEADER_SIZE {
                return Err("truncated dir item header".to_string());
            }
            let location = Key::from_bytes(rest).unwrap();
            let transid = le_u64(rest, 17);
            let data_len = le_u16(rest, 25) as usize;
            let name_len = le_u16(rest, 27) as usize;
            let ty = rest[29];
            let total = DIR_ITEM_HEADER_SIZE + name_len + data_len;
            if rest.len() < total {
                return Err(format!(
                    "dir item claims {name_len} name bytes and {data_len} data bytes but only {} remain",
                    rest.len() - DIR_ITEM_HEADER_SIZE
                ));
            }
            let name = rest[DIR_ITEM_HEADER_SIZE..DIR_ITEM_HEADER_SIZE + name_len].to_vec();
            let data = rest[DIR_ITEM_HEADER_SIZE + name_len..total].to_vec();
            out.push(DirItem {
                location,
                transid,
                ty,
                name,
                data,
            });
            pos += total;
        }
        Ok(out)
    }

    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
}

/// A directory entry as exposed to callers: the name, the entry type, the
/// position in the directory (`DIR_INDEX` key offset) and the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    /// Tree that holds the directory.
    pub parent_tree: u64,
    /// Directory inode number.
    pub parent_ino: u64,
    /// `DIR_INDEX` sequence number.
    pub index: u64,
    pub name: String,
    #[serde(skip)]
    pub raw_name: Vec<u8>,
    pub file_type: u8,
    pub transid: u64,
    /// Raw location key: `(ino, INODE_ITEM, 0)` or `(subvol, ROOT_ITEM, -1)`.
    pub location: Key,
    /// False for a subvolume entry that no root reference backs from this
    /// directory (a stale copy inside a snapshot): the kernel shows it as an
    /// empty directory and this reader does not descend into it.
    pub reachable: bool,
}

impl DirEntry {
    /// `(tree_id, ino)` of the target. A subvolume entry points at the root
    /// directory (inode 256) of its own tree.
    pub fn target(&self) -> Option<(u64, u64)> {
        match self.location.ty {
            INODE_ITEM_KEY => Some((self.parent_tree, self.location.objectid)),
            ROOT_ITEM_KEY if self.reachable => {
                Some((self.location.objectid, crate::key::FIRST_FREE_OBJECTID))
            }
            _ => None,
        }
    }

    pub fn is_subvolume(&self) -> bool {
        self.location.ty == ROOT_ITEM_KEY
    }

    pub fn file_type_name(&self) -> &'static str {
        file_type_name(self.file_type)
    }

    pub fn to_json(&self) -> Value {
        let mut value = serde_json::to_value(self).unwrap_or_else(|_| json!({}));
        if let Value::Object(map) = &mut value {
            map.insert("file_type_name".into(), json!(self.file_type_name()));
            map.insert("is_subvolume".into(), json!(self.is_subvolume()));
            map.insert("reachable".into(), json!(self.reachable));
            if let Some((tree, ino)) = self.target() {
                map.insert("target_tree".into(), json!(tree));
                map.insert("target_ino".into(), json!(ino));
            }
        }
        value
    }
}

impl fmt::Display for DirEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_subvolume() && !self.reachable {
            return write!(
                f,
                "[subvol {} - stale entry, not reachable from here] {} ({})",
                self.location.objectid,
                self.name,
                self.file_type_name()
            );
        }
        match self.target() {
            Some((tree, ino)) if self.is_subvolume() => {
                write!(
                    f,
                    "[subvol {tree}:{ino}] {} ({})",
                    self.name,
                    self.file_type_name()
                )
            }
            Some((_, ino)) => write!(f, "[{ino}] {} ({})", self.name, self.file_type_name()),
            None => write!(
                f,
                "[{}] {} ({})",
                self.location,
                self.name,
                self.file_type_name()
            ),
        }
    }
}

/// `btrfs_inode_ref`: a name under a parent directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InodeRef {
    pub parent_ino: u64,
    pub index: u64,
    pub name: String,
}

impl InodeRef {
    /// Decode the `INODE_REF` item body (several refs when hard-linked under
    /// the same parent). `parent_ino` is the key offset.
    pub fn parse_all(parent_ino: u64, d: &[u8]) -> Result<Vec<InodeRef>, String> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < d.len() {
            let rest = &d[pos..];
            if rest.len() < 10 {
                return Err("truncated inode ref".to_string());
            }
            let index = le_u64(rest, 0);
            let name_len = le_u16(rest, 8) as usize;
            if rest.len() < 10 + name_len {
                return Err("truncated inode ref name".to_string());
            }
            out.push(InodeRef {
                parent_ino,
                index,
                name: String::from_utf8_lossy(&rest[10..10 + name_len]).into_owned(),
            });
            pos += 10 + name_len;
        }
        Ok(out)
    }

    /// Decode an `INODE_EXTREF` item body (extended refs, keyed by hash).
    pub fn parse_all_ext(d: &[u8]) -> Result<Vec<InodeRef>, String> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < d.len() {
            let rest = &d[pos..];
            if rest.len() < 18 {
                return Err("truncated inode extref".to_string());
            }
            let parent_ino = le_u64(rest, 0);
            let index = le_u64(rest, 8);
            let name_len = le_u16(rest, 16) as usize;
            if rest.len() < 18 + name_len {
                return Err("truncated inode extref name".to_string());
            }
            out.push(InodeRef {
                parent_ino,
                index,
                name: String::from_utf8_lossy(&rest[18..18 + name_len]).into_owned(),
            });
            pos += 18 + name_len;
        }
        Ok(out)
    }
}

/// An extended attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Xattr {
    pub name: String,
    pub value: Vec<u8>,
}

impl Xattr {
    pub fn to_json(&self) -> Value {
        let printable = self.value.iter().all(|b| (0x20..0x7f).contains(b));
        json!({
            "name": self.name,
            "size": self.value.len(),
            "value": if printable { Value::String(String::from_utf8_lossy(&self.value).into_owned()) } else { Value::Null },
            "value_hex": crate::checksum::hex(&self.value),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn encode_dir_item(
        location: Key,
        transid: u64,
        ty: u8,
        name: &[u8],
        data: &[u8],
    ) -> Vec<u8> {
        let mut out = location.to_bytes().to_vec();
        out.extend_from_slice(&transid.to_le_bytes());
        out.extend_from_slice(&(data.len() as u16).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.push(ty);
        out.extend_from_slice(name);
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn dir_items_decode_packed_entries() {
        let mut body = encode_dir_item(
            Key::new(257, INODE_ITEM_KEY, 0),
            7,
            FT_REG_FILE,
            b"a.txt",
            &[],
        );
        body.extend(encode_dir_item(
            Key::new(258, INODE_ITEM_KEY, 0),
            8,
            FT_DIR,
            b"dir",
            &[],
        ));
        let items = DirItem::parse_all(&body).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].name_lossy(), "a.txt");
        assert_eq!(items[1].location.objectid, 258);
        assert!(DirItem::parse_all(&body[..body.len() - 1]).is_err());
        assert!(DirItem::parse_all(&body[..10]).is_err());

        let entry = DirEntry {
            parent_tree: 5,
            parent_ino: 256,
            index: 3,
            name: "snap".into(),
            raw_name: b"snap".to_vec(),
            file_type: FT_DIR,
            transid: 9,
            location: Key::new(260, ROOT_ITEM_KEY, u64::MAX),
            reachable: true,
        };
        assert_eq!(entry.target(), Some((260, 256)));
        assert!(entry.is_subvolume());
        assert_eq!(format!("{entry}"), "[subvol 260:256] snap (dir)");
    }

    #[test]
    fn inode_refs_decode() {
        let mut body = 5u64.to_le_bytes().to_vec();
        body.extend_from_slice(&4u16.to_le_bytes());
        body.extend_from_slice(b"name");
        let refs = InodeRef::parse_all(256, &body).unwrap();
        assert_eq!(refs[0].name, "name");
        assert_eq!(refs[0].index, 5);
        assert!(InodeRef::parse_all(256, &body[..12]).is_err());
        let mut ext = 300u64.to_le_bytes().to_vec();
        ext.extend_from_slice(&2u64.to_le_bytes());
        ext.extend_from_slice(&1u16.to_le_bytes());
        ext.push(b'x');
        let refs = InodeRef::parse_all_ext(&ext).unwrap();
        assert_eq!(
            (refs[0].parent_ino, refs[0].index, refs[0].name.as_str()),
            (300, 2, "x")
        );
    }
}
