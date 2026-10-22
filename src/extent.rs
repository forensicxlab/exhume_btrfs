//! File extent items (`btrfs_file_extent_item`).

use crate::superblock::{le_u16, le_u64};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const FILE_EXTENT_HEADER_SIZE: usize = 21;
pub const FILE_EXTENT_REG_SIZE: usize = 53;

pub const FILE_EXTENT_INLINE: u8 = 0;
pub const FILE_EXTENT_REG: u8 = 1;
pub const FILE_EXTENT_PREALLOC: u8 = 2;

pub const COMPRESS_NONE: u8 = 0;
pub const COMPRESS_ZLIB: u8 = 1;
pub const COMPRESS_LZO: u8 = 2;
pub const COMPRESS_ZSTD: u8 = 3;

pub fn compression_name(c: u8) -> &'static str {
    match c {
        COMPRESS_NONE => "none",
        COMPRESS_ZLIB => "zlib",
        COMPRESS_LZO => "lzo",
        COMPRESS_ZSTD => "zstd",
        _ => "unknown",
    }
}

/// Storage of an extent's bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExtentStorage {
    /// Data stored in the item itself (possibly compressed).
    Inline { data: Vec<u8> },
    /// Data stored in a logical extent on disk. `disk_bytenr == 0` means a
    /// hole.
    Regular {
        disk_bytenr: u64,
        disk_num_bytes: u64,
        /// Offset inside the (decompressed) extent where this file range begins.
        offset: u64,
        num_bytes: u64,
    },
    /// Preallocated, never written: reads as zeroes.
    Prealloc {
        disk_bytenr: u64,
        disk_num_bytes: u64,
        offset: u64,
        num_bytes: u64,
    },
}

/// A decoded file extent, positioned at `file_offset` (the key offset).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileExtent {
    pub file_offset: u64,
    pub generation: u64,
    /// Decompressed size of the whole extent (inline: of the inline data).
    pub ram_bytes: u64,
    pub compression: u8,
    pub encryption: u8,
    pub other_encoding: u16,
    pub ty: u8,
    pub storage: ExtentStorage,
}

impl FileExtent {
    pub fn from_bytes(file_offset: u64, d: &[u8]) -> Result<Self, String> {
        if d.len() < FILE_EXTENT_HEADER_SIZE {
            return Err(format!("file extent item is {} bytes, too short", d.len()));
        }
        let generation = le_u64(d, 0);
        let ram_bytes = le_u64(d, 8);
        let compression = d[16];
        let encryption = d[17];
        let other_encoding = le_u16(d, 18);
        let ty = d[20];
        let storage = match ty {
            FILE_EXTENT_INLINE => ExtentStorage::Inline {
                data: d[FILE_EXTENT_HEADER_SIZE..].to_vec(),
            },
            FILE_EXTENT_REG | FILE_EXTENT_PREALLOC => {
                if d.len() < FILE_EXTENT_REG_SIZE {
                    return Err(format!(
                        "regular file extent item is {} bytes, expected {FILE_EXTENT_REG_SIZE}",
                        d.len()
                    ));
                }
                let disk_bytenr = le_u64(d, 21);
                let disk_num_bytes = le_u64(d, 29);
                let offset = le_u64(d, 37);
                let num_bytes = le_u64(d, 45);
                if ty == FILE_EXTENT_REG {
                    ExtentStorage::Regular {
                        disk_bytenr,
                        disk_num_bytes,
                        offset,
                        num_bytes,
                    }
                } else {
                    ExtentStorage::Prealloc {
                        disk_bytenr,
                        disk_num_bytes,
                        offset,
                        num_bytes,
                    }
                }
            }
            other => return Err(format!("unknown file extent type {other}")),
        };
        Ok(FileExtent {
            file_offset,
            generation,
            ram_bytes,
            compression,
            encryption,
            other_encoding,
            ty,
            storage,
        })
    }

    /// Number of file bytes this extent covers.
    pub fn num_bytes(&self) -> u64 {
        match &self.storage {
            ExtentStorage::Inline { data } => {
                if self.compression == COMPRESS_NONE {
                    data.len() as u64
                } else {
                    self.ram_bytes
                }
            }
            ExtentStorage::Regular { num_bytes, .. }
            | ExtentStorage::Prealloc { num_bytes, .. } => *num_bytes,
        }
    }

    pub fn is_hole(&self) -> bool {
        matches!(&self.storage, ExtentStorage::Regular { disk_bytenr: 0, .. })
    }

    pub fn is_inline(&self) -> bool {
        matches!(&self.storage, ExtentStorage::Inline { .. })
    }

    pub fn type_name(&self) -> &'static str {
        match self.ty {
            FILE_EXTENT_INLINE => "inline",
            FILE_EXTENT_REG => "regular",
            FILE_EXTENT_PREALLOC => "prealloc",
            _ => "unknown",
        }
    }

    pub fn to_json(&self) -> Value {
        let mut value = json!({
            "file_offset": self.file_offset,
            "num_bytes": self.num_bytes(),
            "generation": self.generation,
            "ram_bytes": self.ram_bytes,
            "compression": compression_name(self.compression),
            "encryption": self.encryption,
            "type": self.type_name(),
        });
        if let Value::Object(map) = &mut value {
            match &self.storage {
                ExtentStorage::Inline { data } => {
                    map.insert("inline_bytes".into(), json!(data.len()));
                }
                ExtentStorage::Regular {
                    disk_bytenr,
                    disk_num_bytes,
                    offset,
                    ..
                }
                | ExtentStorage::Prealloc {
                    disk_bytenr,
                    disk_num_bytes,
                    offset,
                    ..
                } => {
                    map.insert("disk_bytenr".into(), json!(disk_bytenr));
                    map.insert("disk_num_bytes".into(), json!(disk_num_bytes));
                    map.insert("extent_offset".into(), json!(offset));
                    map.insert("hole".into(), json!(self.is_hole()));
                }
            }
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn encode_regular(
        ty: u8,
        compression: u8,
        ram: u64,
        disk_bytenr: u64,
        disk_num: u64,
        offset: u64,
        num: u64,
    ) -> Vec<u8> {
        let mut d = vec![0u8; FILE_EXTENT_REG_SIZE];
        d[0..8].copy_from_slice(&3u64.to_le_bytes());
        d[8..16].copy_from_slice(&ram.to_le_bytes());
        d[16] = compression;
        d[20] = ty;
        d[21..29].copy_from_slice(&disk_bytenr.to_le_bytes());
        d[29..37].copy_from_slice(&disk_num.to_le_bytes());
        d[37..45].copy_from_slice(&offset.to_le_bytes());
        d[45..53].copy_from_slice(&num.to_le_bytes());
        d
    }

    #[test]
    fn extent_decoding() {
        let reg = FileExtent::from_bytes(
            4096,
            &encode_regular(
                FILE_EXTENT_REG,
                COMPRESS_ZLIB,
                131072,
                1 << 20,
                65536,
                0,
                131072,
            ),
        )
        .unwrap();
        assert_eq!(reg.num_bytes(), 131072);
        assert!(!reg.is_hole());
        assert_eq!(reg.type_name(), "regular");
        let hole =
            FileExtent::from_bytes(0, &encode_regular(FILE_EXTENT_REG, 0, 4096, 0, 0, 0, 4096))
                .unwrap();
        assert!(hole.is_hole());
        let mut inline = vec![0u8; FILE_EXTENT_HEADER_SIZE];
        inline[8..16].copy_from_slice(&5u64.to_le_bytes());
        inline.extend_from_slice(b"hello");
        let inline = FileExtent::from_bytes(0, &inline).unwrap();
        assert!(inline.is_inline());
        assert_eq!(inline.num_bytes(), 5);
        assert!(FileExtent::from_bytes(0, &[0u8; 10]).is_err());
        assert!(FileExtent::from_bytes(0, &encode_regular(9, 0, 0, 0, 0, 0, 0)).is_err());
        assert!(
            FileExtent::from_bytes(0, &encode_regular(FILE_EXTENT_REG, 0, 0, 0, 0, 0, 0)[..30])
                .is_err()
        );
    }
}
