//! The Btrfs superblock (`btrfs_super_block`).
//!
//! The primary copy lives at byte offset 64 KiB of the device; mirrors follow
//! at 64 MiB and 256 GiB when the device is large enough. All fields are
//! little-endian. Reference: `include/uapi/linux/btrfs_tree.h`.

use crate::checksum::{self, CSUM_SIZE};
use crate::key::Key;
use prettytable::{Cell, Row, Table};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;

pub const SUPERBLOCK_SIZE: usize = 4096;
pub const SUPERBLOCK_MAGIC: u64 = 0x4D5F_5366_5248_425F; // "_BHRfS_M"
/// Physical offsets of the superblock copies.
pub const SUPERBLOCK_OFFSETS: [u64; 3] = [0x1_0000, 0x400_0000, 0x40_0000_0000];
pub const SYS_CHUNK_ARRAY_SIZE: usize = 2048;
pub const LABEL_SIZE: usize = 256;
pub const NUM_BACKUP_ROOTS: usize = 4;
pub const DEV_ITEM_SIZE: usize = 98;
pub const ROOT_BACKUP_SIZE: usize = 168;

// Incompat feature flags.
pub const FEATURE_INCOMPAT_MIXED_BACKREF: u64 = 1 << 0;
pub const FEATURE_INCOMPAT_DEFAULT_SUBVOL: u64 = 1 << 1;
pub const FEATURE_INCOMPAT_MIXED_GROUPS: u64 = 1 << 2;
pub const FEATURE_INCOMPAT_COMPRESS_LZO: u64 = 1 << 3;
pub const FEATURE_INCOMPAT_COMPRESS_ZSTD: u64 = 1 << 4;
pub const FEATURE_INCOMPAT_BIG_METADATA: u64 = 1 << 5;
pub const FEATURE_INCOMPAT_EXTENDED_IREF: u64 = 1 << 6;
pub const FEATURE_INCOMPAT_RAID56: u64 = 1 << 7;
pub const FEATURE_INCOMPAT_SKINNY_METADATA: u64 = 1 << 8;
pub const FEATURE_INCOMPAT_NO_HOLES: u64 = 1 << 9;
pub const FEATURE_INCOMPAT_METADATA_UUID: u64 = 1 << 10;
pub const FEATURE_INCOMPAT_RAID1C34: u64 = 1 << 11;
pub const FEATURE_INCOMPAT_ZONED: u64 = 1 << 12;
pub const FEATURE_INCOMPAT_EXTENT_TREE_V2: u64 = 1 << 13;
pub const FEATURE_INCOMPAT_RAID_STRIPE_TREE: u64 = 1 << 14;
pub const FEATURE_INCOMPAT_SIMPLE_QUOTA: u64 = 1 << 16;

// Compat-RO feature flags.
pub const FEATURE_COMPAT_RO_FREE_SPACE_TREE: u64 = 1 << 0;
pub const FEATURE_COMPAT_RO_FREE_SPACE_TREE_VALID: u64 = 1 << 1;
pub const FEATURE_COMPAT_RO_VERITY: u64 = 1 << 2;
pub const FEATURE_COMPAT_RO_BLOCK_GROUP_TREE: u64 = 1 << 3;

// Superblock flags.
pub const SUPER_FLAG_ERROR: u64 = 1 << 2;
pub const SUPER_FLAG_SEEDING: u64 = 1 << 32;
pub const SUPER_FLAG_METADUMP: u64 = 1 << 33;
pub const SUPER_FLAG_METADUMP_V2: u64 = 1 << 34;
pub const SUPER_FLAG_CHANGING_FSID: u64 = 1 << 35;
pub const SUPER_FLAG_CHANGING_FSID_V2: u64 = 1 << 36;

const INCOMPAT_NAMES: [(u64, &str); 16] = [
    (FEATURE_INCOMPAT_MIXED_BACKREF, "mixed_backref"),
    (FEATURE_INCOMPAT_DEFAULT_SUBVOL, "default_subvol"),
    (FEATURE_INCOMPAT_MIXED_GROUPS, "mixed_groups"),
    (FEATURE_INCOMPAT_COMPRESS_LZO, "compress_lzo"),
    (FEATURE_INCOMPAT_COMPRESS_ZSTD, "compress_zstd"),
    (FEATURE_INCOMPAT_BIG_METADATA, "big_metadata"),
    (FEATURE_INCOMPAT_EXTENDED_IREF, "extended_iref"),
    (FEATURE_INCOMPAT_RAID56, "raid56"),
    (FEATURE_INCOMPAT_SKINNY_METADATA, "skinny_metadata"),
    (FEATURE_INCOMPAT_NO_HOLES, "no_holes"),
    (FEATURE_INCOMPAT_METADATA_UUID, "metadata_uuid"),
    (FEATURE_INCOMPAT_RAID1C34, "raid1c34"),
    (FEATURE_INCOMPAT_ZONED, "zoned"),
    (FEATURE_INCOMPAT_EXTENT_TREE_V2, "extent_tree_v2"),
    (FEATURE_INCOMPAT_RAID_STRIPE_TREE, "raid_stripe_tree"),
    (FEATURE_INCOMPAT_SIMPLE_QUOTA, "simple_quota"),
];

const COMPAT_RO_NAMES: [(u64, &str); 4] = [
    (FEATURE_COMPAT_RO_FREE_SPACE_TREE, "free_space_tree"),
    (
        FEATURE_COMPAT_RO_FREE_SPACE_TREE_VALID,
        "free_space_tree_valid",
    ),
    (FEATURE_COMPAT_RO_VERITY, "verity"),
    (FEATURE_COMPAT_RO_BLOCK_GROUP_TREE, "block_group_tree"),
];

/// `btrfs_dev_item`: description of one device of the filesystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevItem {
    pub devid: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub io_align: u32,
    pub io_width: u32,
    pub sector_size: u32,
    pub ty: u64,
    pub generation: u64,
    pub start_offset: u64,
    pub dev_group: u32,
    pub seek_speed: u8,
    pub bandwidth: u8,
    pub uuid: String,
    pub fsid: String,
}

impl DevItem {
    pub fn from_bytes(d: &[u8]) -> Option<Self> {
        if d.len() < DEV_ITEM_SIZE {
            return None;
        }
        Some(DevItem {
            devid: le_u64(d, 0x00),
            total_bytes: le_u64(d, 0x08),
            bytes_used: le_u64(d, 0x10),
            io_align: le_u32(d, 0x18),
            io_width: le_u32(d, 0x1C),
            sector_size: le_u32(d, 0x20),
            ty: le_u64(d, 0x24),
            generation: le_u64(d, 0x2C),
            start_offset: le_u64(d, 0x34),
            dev_group: le_u32(d, 0x3C),
            seek_speed: d[0x40],
            bandwidth: d[0x41],
            uuid: format_uuid(&d[0x42..0x52]),
            fsid: format_uuid(&d[0x52..0x62]),
        })
    }
}

/// `btrfs_root_backup`: one of the four backup root slots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootBackup {
    pub tree_root: u64,
    pub tree_root_gen: u64,
    pub chunk_root: u64,
    pub chunk_root_gen: u64,
    pub extent_root: u64,
    pub extent_root_gen: u64,
    pub fs_root: u64,
    pub fs_root_gen: u64,
    pub dev_root: u64,
    pub dev_root_gen: u64,
    pub csum_root: u64,
    pub csum_root_gen: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub num_devices: u64,
    pub tree_root_level: u8,
    pub chunk_root_level: u8,
    pub extent_root_level: u8,
    pub fs_root_level: u8,
    pub dev_root_level: u8,
    pub csum_root_level: u8,
}

impl RootBackup {
    fn from_bytes(d: &[u8]) -> Self {
        RootBackup {
            tree_root: le_u64(d, 0x00),
            tree_root_gen: le_u64(d, 0x08),
            chunk_root: le_u64(d, 0x10),
            chunk_root_gen: le_u64(d, 0x18),
            extent_root: le_u64(d, 0x20),
            extent_root_gen: le_u64(d, 0x28),
            fs_root: le_u64(d, 0x30),
            fs_root_gen: le_u64(d, 0x38),
            dev_root: le_u64(d, 0x40),
            dev_root_gen: le_u64(d, 0x48),
            csum_root: le_u64(d, 0x50),
            csum_root_gen: le_u64(d, 0x58),
            total_bytes: le_u64(d, 0x60),
            bytes_used: le_u64(d, 0x68),
            num_devices: le_u64(d, 0x70),
            tree_root_level: d[0x98],
            chunk_root_level: d[0x99],
            extent_root_level: d[0x9A],
            fs_root_level: d[0x9B],
            dev_root_level: d[0x9C],
            csum_root_level: d[0x9D],
        }
    }
}

/// Parsed superblock. Raw byte arrays that are only consumed by the chunk
/// mapping (`sys_chunk_array`) are kept as bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Superblock {
    /// Physical offset the copy was read from.
    pub read_from: u64,
    pub csum: String,
    pub fsid: String,
    pub bytenr: u64,
    pub flags: u64,
    pub magic: u64,
    pub generation: u64,
    pub root: u64,
    pub chunk_root: u64,
    pub log_root: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub root_dir_objectid: u64,
    pub num_devices: u64,
    pub sectorsize: u32,
    pub nodesize: u32,
    pub stripesize: u32,
    pub sys_chunk_array_size: u32,
    pub chunk_root_generation: u64,
    pub compat_flags: u64,
    pub compat_ro_flags: u64,
    pub incompat_flags: u64,
    pub csum_type: u16,
    pub root_level: u8,
    pub chunk_root_level: u8,
    pub log_root_level: u8,
    pub dev_item: DevItem,
    pub label: String,
    pub cache_generation: u64,
    pub uuid_tree_generation: u64,
    pub metadata_uuid: String,
    pub nr_global_roots: u64,
    #[serde(skip)]
    pub sys_chunk_array: Vec<u8>,
    pub root_backups: Vec<RootBackup>,
    /// Whether the stored checksum matched the computed one.
    pub csum_valid: bool,
}

impl Superblock {
    /// Parse one 4096-byte superblock copy. `read_from` is only recorded.
    pub fn from_bytes(data: &[u8], read_from: u64) -> Result<Self, String> {
        if data.len() < SUPERBLOCK_SIZE {
            return Err(format!(
                "superblock buffer is {} bytes, expected {}",
                data.len(),
                SUPERBLOCK_SIZE
            ));
        }
        let d = &data[..SUPERBLOCK_SIZE];
        let magic = le_u64(d, 0x40);
        if magic != SUPERBLOCK_MAGIC {
            return Err(format!(
                "bad superblock magic 0x{magic:016x} (expected \"_BHRfS_M\")"
            ));
        }
        let csum_type = le_u16(d, 0xC4);
        let csum_valid = checksum::verify_block(csum_type, d).is_ok();
        let sys_chunk_array_size = le_u32(d, 0xA0);
        if sys_chunk_array_size as usize > SYS_CHUNK_ARRAY_SIZE {
            return Err(format!(
                "sys_chunk_array_size {sys_chunk_array_size} exceeds {SYS_CHUNK_ARRAY_SIZE}"
            ));
        }
        let label_raw = &d[0x12B..0x12B + LABEL_SIZE];
        let label_len = label_raw.iter().position(|&b| b == 0).unwrap_or(LABEL_SIZE);
        let label = String::from_utf8_lossy(&label_raw[..label_len]).into_owned();
        let dev_item = DevItem::from_bytes(&d[0xC9..0xC9 + DEV_ITEM_SIZE])
            .ok_or_else(|| "truncated dev_item".to_string())?;
        let sys_chunk_array = d[0x32B..0x32B + sys_chunk_array_size as usize].to_vec();
        let root_backups = (0..NUM_BACKUP_ROOTS)
            .map(|i| {
                let start = 0xB2B + i * ROOT_BACKUP_SIZE;
                RootBackup::from_bytes(&d[start..start + ROOT_BACKUP_SIZE])
            })
            .collect();
        Ok(Superblock {
            read_from,
            csum: checksum::hex(&d[..checksum::csum_len(csum_type).unwrap_or(CSUM_SIZE)]),
            fsid: format_uuid(&d[0x20..0x30]),
            bytenr: le_u64(d, 0x30),
            flags: le_u64(d, 0x38),
            magic,
            generation: le_u64(d, 0x48),
            root: le_u64(d, 0x50),
            chunk_root: le_u64(d, 0x58),
            log_root: le_u64(d, 0x60),
            total_bytes: le_u64(d, 0x70),
            bytes_used: le_u64(d, 0x78),
            root_dir_objectid: le_u64(d, 0x80),
            num_devices: le_u64(d, 0x88),
            sectorsize: le_u32(d, 0x90),
            nodesize: le_u32(d, 0x94),
            stripesize: le_u32(d, 0x9C),
            sys_chunk_array_size,
            chunk_root_generation: le_u64(d, 0xA4),
            compat_flags: le_u64(d, 0xAC),
            compat_ro_flags: le_u64(d, 0xB4),
            incompat_flags: le_u64(d, 0xBC),
            csum_type,
            root_level: d[0xC6],
            chunk_root_level: d[0xC7],
            log_root_level: d[0xC8],
            dev_item,
            label,
            cache_generation: le_u64(d, 0x22B),
            uuid_tree_generation: le_u64(d, 0x233),
            metadata_uuid: format_uuid(&d[0x23B..0x24B]),
            nr_global_roots: le_u64(d, 0x24B),
            sys_chunk_array,
            root_backups,
            csum_valid,
        })
    }

    /// Structural sanity checks a reader relies on.
    pub fn validate(&self) -> Result<(), String> {
        if checksum::csum_len(self.csum_type).is_none() {
            return Err(format!("unsupported checksum type {}", self.csum_type));
        }
        if !self.csum_valid {
            return Err(format!(
                "superblock checksum ({}) does not match",
                checksum::csum_type_name(self.csum_type)
            ));
        }
        let ss = self.sectorsize;
        if !(ss.is_power_of_two() && (4096..=65536).contains(&ss)) {
            return Err(format!("invalid sectorsize {ss}"));
        }
        let ns = self.nodesize;
        if !(ns.is_power_of_two() && ns >= ss && (4096..=65536).contains(&ns)) {
            return Err(format!("invalid nodesize {ns} (sectorsize {ss})"));
        }
        if self.root_level >= 8 || self.chunk_root_level >= 8 || self.log_root_level >= 8 {
            return Err("tree level out of range".to_string());
        }
        if self.sys_chunk_array_size == 0 {
            return Err("empty sys_chunk_array".to_string());
        }
        if self.num_devices == 0 {
            return Err("num_devices is 0".to_string());
        }
        Ok(())
    }

    /// The UUID that metadata blocks carry in their `fsid` field.
    pub fn effective_metadata_uuid(&self) -> &str {
        if self.incompat_flags & FEATURE_INCOMPAT_METADATA_UUID != 0 {
            &self.metadata_uuid
        } else {
            &self.fsid
        }
    }

    pub fn has_incompat(&self, flag: u64) -> bool {
        self.incompat_flags & flag != 0
    }

    pub fn has_compat_ro(&self, flag: u64) -> bool {
        self.compat_ro_flags & flag != 0
    }

    pub fn incompat_names(&self) -> Vec<String> {
        let mut names: Vec<String> = INCOMPAT_NAMES
            .iter()
            .filter(|(bit, _)| self.incompat_flags & bit != 0)
            .map(|(_, name)| name.to_string())
            .collect();
        let known: u64 = INCOMPAT_NAMES.iter().map(|(bit, _)| bit).sum();
        let unknown = self.incompat_flags & !known;
        if unknown != 0 {
            names.push(format!("unknown(0x{unknown:x})"));
        }
        names
    }

    pub fn compat_ro_names(&self) -> Vec<String> {
        let mut names: Vec<String> = COMPAT_RO_NAMES
            .iter()
            .filter(|(bit, _)| self.compat_ro_flags & bit != 0)
            .map(|(_, name)| name.to_string())
            .collect();
        let known: u64 = COMPAT_RO_NAMES.iter().map(|(bit, _)| bit).sum();
        let unknown = self.compat_ro_flags & !known;
        if unknown != 0 {
            names.push(format!("unknown(0x{unknown:x})"));
        }
        names
    }

    /// Incompat features that this reader cannot handle correctly.
    pub fn unsupported_incompat(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.has_incompat(FEATURE_INCOMPAT_ZONED) {
            out.push("zoned");
        }
        if self.has_incompat(FEATURE_INCOMPAT_RAID_STRIPE_TREE) {
            out.push("raid_stripe_tree");
        }
        if self.has_incompat(FEATURE_INCOMPAT_EXTENT_TREE_V2) {
            out.push("extent_tree_v2");
        }
        let known: u64 = INCOMPAT_NAMES.iter().map(|(bit, _)| bit).sum();
        if self.incompat_flags & !known != 0 {
            out.push("unknown incompat bits");
        }
        out
    }

    pub fn to_json(&self) -> Value {
        let mut value = serde_json::to_value(self).unwrap_or_else(|_| json!({}));
        if let Value::Object(map) = &mut value {
            map.insert("incompat_features".into(), json!(self.incompat_names()));
            map.insert("compat_ro_features".into(), json!(self.compat_ro_names()));
            map.insert(
                "csum_type_name".into(),
                json!(checksum::csum_type_name(self.csum_type)),
            );
            map.insert(
                "sys_chunk_array_hex".into(),
                json!(checksum::hex(&self.sys_chunk_array)),
            );
        }
        value
    }
}

impl fmt::Display for Superblock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut table = Table::new();
        let mut row = |k: &str, v: String| {
            table.add_row(Row::new(vec![Cell::new(k), Cell::new(&v)]));
        };
        row("Read from offset", format!("0x{:x}", self.read_from));
        row("Label", self.label.clone());
        row("FSID", self.fsid.clone());
        row("Metadata UUID", self.effective_metadata_uuid().to_string());
        row("Device UUID", self.dev_item.uuid.clone());
        row("Device ID", self.dev_item.devid.to_string());
        row("Devices", self.num_devices.to_string());
        row("Generation", self.generation.to_string());
        row(
            "Chunk root generation",
            self.chunk_root_generation.to_string(),
        );
        row(
            "Root tree",
            format!("{} (level {})", self.root, self.root_level),
        );
        row(
            "Chunk tree",
            format!("{} (level {})", self.chunk_root, self.chunk_root_level),
        );
        row(
            "Log tree",
            if self.log_root == 0 {
                "none".to_string()
            } else {
                format!(
                    "{} (level {}) - NOT REPLAYED",
                    self.log_root, self.log_root_level
                )
            },
        );
        row("Total bytes", self.total_bytes.to_string());
        row("Bytes used", self.bytes_used.to_string());
        row("Sector size", self.sectorsize.to_string());
        row("Node size", self.nodesize.to_string());
        row("Stripe size", self.stripesize.to_string());
        row(
            "Checksum",
            format!(
                "{} ({}) {}",
                checksum::csum_type_name(self.csum_type),
                self.csum,
                if self.csum_valid { "valid" } else { "INVALID" }
            ),
        );
        row("Flags", format!("0x{:x}", self.flags));
        row("Compat flags", format!("0x{:x}", self.compat_flags));
        row("Compat RO features", self.compat_ro_names().join(", "));
        row("Incompat features", self.incompat_names().join(", "));
        row("Root dir objectid", self.root_dir_objectid.to_string());
        row("Cache generation", self.cache_generation.to_string());
        row(
            "UUID tree generation",
            self.uuid_tree_generation.to_string(),
        );
        write!(f, "{table}")
    }
}

pub(crate) fn le_u16(d: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(d[off..off + 2].try_into().unwrap())
}

pub(crate) fn le_u32(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(d[off..off + 4].try_into().unwrap())
}

pub(crate) fn le_u64(d: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(d[off..off + 8].try_into().unwrap())
}

pub fn format_uuid(b: &[u8]) -> String {
    if b.len() < 16 {
        return String::new();
    }
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

/// Key of the `default` subvolume directory item in the root tree
/// (`root_dir_objectid` is the superblock field, 6 in practice).
pub fn default_subvol_dir_key(root_dir_objectid: u64) -> Key {
    Key::new(
        root_dir_objectid,
        crate::key::DIR_ITEM_KEY,
        checksum::name_hash(b"default"),
    )
}
