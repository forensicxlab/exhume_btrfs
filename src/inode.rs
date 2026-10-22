//! Inode items (`btrfs_inode_item`) and their presentation.

use crate::superblock::{le_u32, le_u64};
use chrono::{TimeZone, Utc};
use prettytable::{Cell, Row, Table};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;

pub const INODE_ITEM_SIZE: usize = 160;
pub const TIMESPEC_SIZE: usize = 12;

// Inode flags.
pub const INODE_NODATASUM: u64 = 1 << 0;
pub const INODE_NODATACOW: u64 = 1 << 1;
pub const INODE_READONLY: u64 = 1 << 2;
pub const INODE_NOCOMPRESS: u64 = 1 << 3;
pub const INODE_PREALLOC: u64 = 1 << 4;
pub const INODE_SYNC: u64 = 1 << 5;
pub const INODE_IMMUTABLE: u64 = 1 << 6;
pub const INODE_APPEND: u64 = 1 << 7;
pub const INODE_NODUMP: u64 = 1 << 8;
pub const INODE_NOATIME: u64 = 1 << 9;
pub const INODE_DIRSYNC: u64 = 1 << 10;
pub const INODE_COMPRESS: u64 = 1 << 11;
pub const INODE_ROOT_ITEM_INIT: u64 = 1 << 31;

const FLAG_NAMES: [(u64, &str); 12] = [
    (INODE_NODATASUM, "nodatasum"),
    (INODE_NODATACOW, "nodatacow"),
    (INODE_READONLY, "readonly"),
    (INODE_NOCOMPRESS, "nocompress"),
    (INODE_PREALLOC, "prealloc"),
    (INODE_SYNC, "sync"),
    (INODE_IMMUTABLE, "immutable"),
    (INODE_APPEND, "append"),
    (INODE_NODUMP, "nodump"),
    (INODE_NOATIME, "noatime"),
    (INODE_DIRSYNC, "dirsync"),
    (INODE_COMPRESS, "compress"),
];

pub const S_IFMT: u32 = 0o170000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFIFO: u32 = 0o010000;

/// `btrfs_timespec`: seconds since the Unix epoch (signed) and nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Timespec {
    pub sec: i64,
    pub nsec: u32,
}

impl Timespec {
    pub fn from_bytes(d: &[u8]) -> Self {
        Timespec {
            sec: le_u64(d, 0) as i64,
            nsec: le_u32(d, 8),
        }
    }

    /// RFC 3339 rendering, empty when the value is not representable.
    pub fn to_rfc3339(&self) -> String {
        Utc.timestamp_opt(self.sec, self.nsec.min(999_999_999))
            .single()
            .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
            .unwrap_or_default()
    }

    /// Seconds clamped to `u64` for the Exhume `File` abstraction.
    pub fn unix_seconds(&self) -> u64 {
        self.sec.max(0) as u64
    }
}

/// On-disk `btrfs_inode_item`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InodeItem {
    pub generation: u64,
    pub transid: u64,
    pub size: u64,
    pub nbytes: u64,
    pub block_group: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub rdev: u64,
    pub flags: u64,
    pub sequence: u64,
    pub atime: Timespec,
    pub ctime: Timespec,
    pub mtime: Timespec,
    pub otime: Timespec,
}

impl InodeItem {
    pub fn from_bytes(d: &[u8]) -> Result<Self, String> {
        if d.len() < INODE_ITEM_SIZE {
            return Err(format!(
                "inode item is {} bytes, expected at least {INODE_ITEM_SIZE}",
                d.len()
            ));
        }
        Ok(InodeItem {
            generation: le_u64(d, 0x00),
            transid: le_u64(d, 0x08),
            size: le_u64(d, 0x10),
            nbytes: le_u64(d, 0x18),
            block_group: le_u64(d, 0x20),
            nlink: le_u32(d, 0x28),
            uid: le_u32(d, 0x2C),
            gid: le_u32(d, 0x30),
            mode: le_u32(d, 0x34),
            rdev: le_u64(d, 0x38),
            flags: le_u64(d, 0x40),
            sequence: le_u64(d, 0x48),
            // 0x50..0x70: reserved[4]
            atime: Timespec::from_bytes(&d[0x70..]),
            ctime: Timespec::from_bytes(&d[0x7C..]),
            mtime: Timespec::from_bytes(&d[0x88..]),
            otime: Timespec::from_bytes(&d[0x94..]),
        })
    }

    pub fn flag_names(&self) -> Vec<String> {
        let mut names: Vec<String> = FLAG_NAMES
            .iter()
            .filter(|(bit, _)| self.flags & bit != 0)
            .map(|(_, n)| n.to_string())
            .collect();
        let known: u64 = FLAG_NAMES.iter().map(|(b, _)| b).sum::<u64>() | INODE_ROOT_ITEM_INIT;
        if self.flags & !known != 0 {
            names.push(format!("unknown(0x{:x})", self.flags & !known));
        }
        names
    }
}

/// An inode together with the identifiers needed to locate it: the tree it
/// belongs to (subvolume) and its inode number inside that tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inode {
    /// Subvolume (file tree) object id.
    pub tree_id: u64,
    /// Inode number inside the tree.
    pub ino: u64,
    pub item: InodeItem,
    pub atime_h: String,
    pub ctime_h: String,
    pub mtime_h: String,
    pub otime_h: String,
    /// Set when the inode is the root directory of a subvolume reached through
    /// a directory entry: the subvolume it was entered from, for `..`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entered_from: Option<(u64, u64)>,
}

impl Inode {
    pub fn new(tree_id: u64, ino: u64, item: InodeItem) -> Self {
        Inode {
            tree_id,
            ino,
            atime_h: item.atime.to_rfc3339(),
            ctime_h: item.ctime.to_rfc3339(),
            mtime_h: item.mtime.to_rfc3339(),
            otime_h: item.otime.to_rfc3339(),
            item,
            entered_from: None,
        }
    }

    pub fn size(&self) -> u64 {
        self.item.size
    }

    pub fn mode(&self) -> u32 {
        self.item.mode
    }

    pub fn uid(&self) -> u32 {
        self.item.uid
    }

    pub fn gid(&self) -> u32 {
        self.item.gid
    }

    pub fn nlink(&self) -> u32 {
        self.item.nlink
    }

    pub fn flags(&self) -> u64 {
        self.item.flags
    }

    pub fn is_dir(&self) -> bool {
        self.item.mode & S_IFMT == S_IFDIR
    }

    pub fn is_regular_file(&self) -> bool {
        self.item.mode & S_IFMT == S_IFREG
    }

    pub fn is_symlink(&self) -> bool {
        self.item.mode & S_IFMT == S_IFLNK
    }

    pub fn is_special(&self) -> bool {
        !(self.is_dir() || self.is_regular_file() || self.is_symlink())
    }

    pub fn kind_name(&self) -> &'static str {
        match self.item.mode & S_IFMT {
            S_IFDIR => "dir",
            S_IFREG => "file",
            S_IFLNK => "symlink",
            S_IFCHR => "chardev",
            S_IFBLK => "blockdev",
            S_IFIFO => "fifo",
            S_IFSOCK => "socket",
            _ => "other",
        }
    }

    pub fn permissions(&self) -> String {
        mode_to_string(self.item.mode)
    }

    pub fn to_json(&self) -> Value {
        let mut value = serde_json::to_value(self).unwrap_or_else(|_| json!({}));
        if let Value::Object(map) = &mut value {
            map.insert("kind".into(), json!(self.kind_name()));
            map.insert("permissions".into(), json!(self.permissions()));
            map.insert("flag_names".into(), json!(self.item.flag_names()));
        }
        value
    }
}

impl fmt::Display for Inode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut table = Table::new();
        let mut row = |k: &str, v: String| {
            table.add_row(Row::new(vec![Cell::new(k), Cell::new(&v)]));
        };
        row("Subvolume (tree)", self.tree_id.to_string());
        row("Inode", self.ino.to_string());
        row("Kind", self.kind_name().to_string());
        row(
            "Mode",
            format!("{} (0{:o})", self.permissions(), self.item.mode & 0o7777),
        );
        row("Size", self.item.size.to_string());
        row("Bytes on disk (nbytes)", self.item.nbytes.to_string());
        row("Links", self.item.nlink.to_string());
        row(
            "UID / GID",
            format!("{} / {}", self.item.uid, self.item.gid),
        );
        row("Generation", self.item.generation.to_string());
        row("Transid", self.item.transid.to_string());
        row("Sequence", self.item.sequence.to_string());
        row("Rdev", self.item.rdev.to_string());
        row(
            "Flags",
            format!(
                "0x{:x} {}",
                self.item.flags,
                self.item.flag_names().join(",")
            ),
        );
        row("Access time", self.atime_h.clone());
        row("Change time", self.ctime_h.clone());
        row("Modification time", self.mtime_h.clone());
        row("Creation time", self.otime_h.clone());
        write!(f, "{table}")
    }
}

/// Convert a mode (with file-type bits) into the `ls -l` 10-character form.
pub fn mode_to_string(mode: u32) -> String {
    const S_ISUID: u32 = 0o4000;
    const S_ISGID: u32 = 0o2000;
    const S_ISVTX: u32 = 0o1000;
    let file_ch = match mode & S_IFMT {
        S_IFSOCK => 's',
        S_IFLNK => 'l',
        S_IFREG => '-',
        S_IFBLK => 'b',
        S_IFDIR => 'd',
        S_IFCHR => 'c',
        S_IFIFO => 'p',
        _ => '?',
    };
    let mut buf = [b'-'; 9];
    let bits = [
        0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001,
    ];
    let chars = [b'r', b'w', b'x', b'r', b'w', b'x', b'r', b'w', b'x'];
    for i in 0..9 {
        if mode & bits[i] != 0 {
            buf[i] = chars[i];
        }
    }
    if mode & S_ISUID != 0 {
        buf[2] = if buf[2] == b'x' { b's' } else { b'S' };
    }
    if mode & S_ISGID != 0 {
        buf[5] = if buf[5] == b'x' { b's' } else { b'S' };
    }
    if mode & S_ISVTX != 0 {
        buf[8] = if buf[8] == b'x' { b't' } else { b'T' };
    }
    let mut s = String::with_capacity(10);
    s.push(file_ch);
    s.push_str(std::str::from_utf8(&buf).unwrap());
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inode_item_layout() {
        let mut d = vec![0u8; INODE_ITEM_SIZE];
        d[0x10..0x18].copy_from_slice(&1234u64.to_le_bytes());
        d[0x28..0x2C].copy_from_slice(&2u32.to_le_bytes());
        d[0x2C..0x30].copy_from_slice(&1000u32.to_le_bytes());
        d[0x34..0x38].copy_from_slice(&(S_IFDIR | 0o755).to_le_bytes());
        d[0x40..0x48].copy_from_slice(&INODE_COMPRESS.to_le_bytes());
        d[0x88..0x90].copy_from_slice(&1_700_000_000u64.to_le_bytes());
        d[0x90..0x94].copy_from_slice(&5u32.to_le_bytes());
        let inode = Inode::new(5, 256, InodeItem::from_bytes(&d).unwrap());
        assert!(inode.is_dir());
        assert_eq!(inode.size(), 1234);
        assert_eq!(inode.uid(), 1000);
        assert_eq!(inode.permissions(), "drwxr-xr-x");
        assert_eq!(inode.mtime_h, "2023-11-14T22:13:20.000000005Z");
        assert_eq!(inode.item.flag_names(), vec!["compress"]);
        assert!(InodeItem::from_bytes(&d[..100]).is_err());
        assert_eq!(mode_to_string(S_IFREG | 0o4755), "-rwsr-xr-x");
        assert_eq!(mode_to_string(S_IFDIR | 0o1777), "drwxrwxrwt");
    }
}
