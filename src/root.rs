//! Root items (`btrfs_root_item`), root references and the subvolume list.

use crate::inode::{InodeItem, Timespec};
use crate::key::Key;
use crate::superblock::{format_uuid, le_u16, le_u32, le_u64};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const ROOT_ITEM_V0_SIZE: usize = 239;
pub const ROOT_ITEM_SIZE: usize = 439;

pub const ROOT_SUBVOL_RDONLY: u64 = 1 << 0;

const ZERO_UUID: &str = "00000000-0000-0000-0000-000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootItem {
    pub inode: InodeItem,
    pub generation: u64,
    pub root_dirid: u64,
    pub bytenr: u64,
    pub byte_limit: u64,
    pub bytes_used: u64,
    pub last_snapshot: u64,
    pub flags: u64,
    pub refs: u32,
    pub drop_progress: Key,
    pub drop_level: u8,
    pub level: u8,
    pub generation_v2: u64,
    pub uuid: String,
    pub parent_uuid: String,
    pub received_uuid: String,
    pub ctransid: u64,
    pub otransid: u64,
    pub stransid: u64,
    pub rtransid: u64,
    pub ctime: Timespec,
    pub otime: Timespec,
    pub stime: Timespec,
    pub rtime: Timespec,
}

impl RootItem {
    pub fn from_bytes(d: &[u8]) -> Result<Self, String> {
        if d.len() < ROOT_ITEM_V0_SIZE {
            return Err(format!(
                "root item is {} bytes, expected at least {ROOT_ITEM_V0_SIZE}",
                d.len()
            ));
        }
        let inode = InodeItem::from_bytes(d)?;
        // The v2 fields are only meaningful when generation_v2 matches the
        // generation (btrfs_read_root_item): older kernels left them stale.
        let v2 = d.len() >= ROOT_ITEM_SIZE && le_u64(d, 0xEF) == le_u64(d, 0xA0);
        let item = RootItem {
            inode,
            generation: le_u64(d, 0xA0),
            root_dirid: le_u64(d, 0xA8),
            bytenr: le_u64(d, 0xB0),
            byte_limit: le_u64(d, 0xB8),
            bytes_used: le_u64(d, 0xC0),
            last_snapshot: le_u64(d, 0xC8),
            flags: le_u64(d, 0xD0),
            refs: le_u32(d, 0xD8),
            drop_progress: Key::from_bytes(&d[0xDC..]).unwrap(),
            drop_level: d[0xED],
            level: d[0xEE],
            generation_v2: if v2 { le_u64(d, 0xEF) } else { 0 },
            uuid: if v2 {
                format_uuid(&d[0xF7..0x107])
            } else {
                ZERO_UUID.into()
            },
            parent_uuid: if v2 {
                format_uuid(&d[0x107..0x117])
            } else {
                ZERO_UUID.into()
            },
            received_uuid: if v2 {
                format_uuid(&d[0x117..0x127])
            } else {
                ZERO_UUID.into()
            },
            ctransid: if v2 { le_u64(d, 0x127) } else { 0 },
            otransid: if v2 { le_u64(d, 0x12F) } else { 0 },
            stransid: if v2 { le_u64(d, 0x137) } else { 0 },
            rtransid: if v2 { le_u64(d, 0x13F) } else { 0 },
            ctime: if v2 {
                Timespec::from_bytes(&d[0x147..])
            } else {
                Timespec::default()
            },
            otime: if v2 {
                Timespec::from_bytes(&d[0x153..])
            } else {
                Timespec::default()
            },
            stime: if v2 {
                Timespec::from_bytes(&d[0x15F..])
            } else {
                Timespec::default()
            },
            rtime: if v2 {
                Timespec::from_bytes(&d[0x16B..])
            } else {
                Timespec::default()
            },
        };
        if item.level >= crate::tree::MAX_LEVEL {
            return Err(format!("root item level {} out of range", item.level));
        }
        Ok(item)
    }

    pub fn is_readonly(&self) -> bool {
        self.flags & ROOT_SUBVOL_RDONLY != 0
    }

    pub fn has_parent_uuid(&self) -> bool {
        self.parent_uuid != ZERO_UUID
    }

    pub fn has_received_uuid(&self) -> bool {
        self.received_uuid != ZERO_UUID
    }
}

/// `btrfs_root_ref`: names a subvolume inside its parent subvolume.
/// `ROOT_REF` keys are `(parent, ROOT_REF, child)`, `ROOT_BACKREF` keys are
/// `(child, ROOT_BACKREF, parent)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootRef {
    pub dirid: u64,
    pub sequence: u64,
    pub name: String,
}

impl RootRef {
    pub fn from_bytes(d: &[u8]) -> Result<Self, String> {
        if d.len() < 18 {
            return Err("truncated root ref".to_string());
        }
        let name_len = le_u16(d, 16) as usize;
        if d.len() < 18 + name_len {
            return Err("truncated root ref name".to_string());
        }
        Ok(RootRef {
            dirid: le_u64(d, 0),
            sequence: le_u64(d, 8),
            name: String::from_utf8_lossy(&d[18..18 + name_len]).into_owned(),
        })
    }
}

/// A subvolume or snapshot, as listed from the root tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subvolume {
    /// Tree object id (5 for the top-level subvolume).
    pub id: u64,
    /// Name inside the parent directory (empty for the top-level subvolume).
    pub name: String,
    /// Full path from the top-level subvolume, `/` for the top level.
    pub path: String,
    /// Parent subvolume id and the directory inode holding the entry.
    pub parent_id: Option<u64>,
    pub parent_dirid: Option<u64>,
    pub uuid: String,
    pub parent_uuid: String,
    pub received_uuid: String,
    pub generation: u64,
    pub ctransid: u64,
    pub otransid: u64,
    pub stransid: u64,
    pub rtransid: u64,
    pub ctime_h: String,
    pub otime_h: String,
    pub stime_h: String,
    pub rtime_h: String,
    pub flags: u64,
    pub readonly: bool,
    /// A snapshot is a subvolume created from another one (`parent_uuid` set).
    pub is_snapshot: bool,
    pub is_received: bool,
    pub is_default: bool,
    pub root_dirid: u64,
    pub bytenr: u64,
    pub level: u8,
    pub last_snapshot: u64,
    pub bytes_used: u64,
    /// Whether the tree root could be read.
    pub readable: bool,
}

impl Subvolume {
    pub fn from_root_item(id: u64, item: &RootItem) -> Self {
        Subvolume {
            id,
            name: String::new(),
            path: String::new(),
            parent_id: None,
            parent_dirid: None,
            uuid: item.uuid.clone(),
            parent_uuid: item.parent_uuid.clone(),
            received_uuid: item.received_uuid.clone(),
            generation: item.generation,
            ctransid: item.ctransid,
            otransid: item.otransid,
            stransid: item.stransid,
            rtransid: item.rtransid,
            ctime_h: item.ctime.to_rfc3339(),
            otime_h: item.otime.to_rfc3339(),
            stime_h: item.stime.to_rfc3339(),
            rtime_h: item.rtime.to_rfc3339(),
            flags: item.flags,
            readonly: item.is_readonly(),
            is_snapshot: item.has_parent_uuid(),
            is_received: item.has_received_uuid(),
            is_default: false,
            root_dirid: item.root_dirid,
            bytenr: item.bytenr,
            level: item.level,
            last_snapshot: item.last_snapshot,
            bytes_used: item.bytes_used,
            readable: true,
        }
    }

    pub fn kind_name(&self) -> &'static str {
        if self.id == crate::key::FS_TREE_OBJECTID {
            "top-level"
        } else if self.is_snapshot {
            "snapshot"
        } else {
            "subvolume"
        }
    }

    pub fn to_json(&self) -> Value {
        let mut value = serde_json::to_value(self).unwrap_or_else(|_| json!({}));
        if let Value::Object(map) = &mut value {
            map.insert("kind".into(), json!(self.kind_name()));
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_item_v0_and_v2() {
        let mut d = vec![0u8; ROOT_ITEM_SIZE];
        d[0xA8..0xB0].copy_from_slice(&256u64.to_le_bytes());
        d[0xB0..0xB8].copy_from_slice(&(30u64 << 20).to_le_bytes());
        d[0xD0..0xD8].copy_from_slice(&ROOT_SUBVOL_RDONLY.to_le_bytes());
        d[0xEE] = 1;
        d[0xA0..0xA8].copy_from_slice(&7u64.to_le_bytes());
        d[0xEF..0xF7].copy_from_slice(&7u64.to_le_bytes());
        d[0x107] = 0xAA;
        d[0x153..0x15B].copy_from_slice(&1_700_000_000u64.to_le_bytes());
        let item = RootItem::from_bytes(&d).unwrap();
        assert_eq!(item.root_dirid, 256);
        assert_eq!(item.bytenr, 30 << 20);
        assert!(item.is_readonly());
        assert!(item.has_parent_uuid());
        assert_eq!(item.level, 1);
        let sub = Subvolume::from_root_item(260, &item);
        assert!(sub.is_snapshot && sub.readonly);
        assert_eq!(sub.kind_name(), "snapshot");
        assert_eq!(sub.otime_h, "2023-11-14T22:13:20.000000000Z");
        let v0 = RootItem::from_bytes(&d[..ROOT_ITEM_V0_SIZE]).unwrap();
        assert!(!v0.has_parent_uuid());
        // Stale v2 block (generation_v2 != generation) is ignored.
        let mut stale = d.clone();
        stale[0xEF..0xF7].copy_from_slice(&3u64.to_le_bytes());
        assert!(!RootItem::from_bytes(&stale).unwrap().has_parent_uuid());
        assert!(RootItem::from_bytes(&d[..100]).is_err());
        d[0xEE] = 9;
        assert!(RootItem::from_bytes(&d).is_err());
    }

    #[test]
    fn root_ref_decoding() {
        let mut d = 256u64.to_le_bytes().to_vec();
        d.extend_from_slice(&3u64.to_le_bytes());
        d.extend_from_slice(&4u16.to_le_bytes());
        d.extend_from_slice(b"snap");
        let r = RootRef::from_bytes(&d).unwrap();
        assert_eq!((r.dirid, r.sequence, r.name.as_str()), (256, 3, "snap"));
        assert!(RootRef::from_bytes(&d[..20]).is_err());
    }
}
