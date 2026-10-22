//! Logical to physical address mapping (`btrfs_chunk` items).
//!
//! Every metadata and data address in Btrfs is a *logical* address inside a
//! 64-bit space. Chunk items (in the superblock `sys_chunk_array` for SYSTEM
//! chunks, then in the chunk tree for the rest) map ranges of that space onto
//! one or more device stripes. A single-device image only ever exposes the
//! stripes of its own `devid`; stripes on other devices are reported as
//! unreadable instead of being silently zero-filled.

use crate::key::{CHUNK_ITEM_KEY, KEY_SIZE, Key};
use crate::superblock::{format_uuid, le_u16, le_u32, le_u64};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const CHUNK_HEADER_SIZE: usize = 48;
pub const STRIPE_SIZE: usize = 32;
/// The only stripe length Btrfs uses (`BTRFS_STRIPE_LEN`).
pub const STRIPE_LEN: u64 = 64 * 1024;

pub const BLOCK_GROUP_DATA: u64 = 1 << 0;
pub const BLOCK_GROUP_SYSTEM: u64 = 1 << 1;
pub const BLOCK_GROUP_METADATA: u64 = 1 << 2;
pub const BLOCK_GROUP_RAID0: u64 = 1 << 3;
pub const BLOCK_GROUP_RAID1: u64 = 1 << 4;
pub const BLOCK_GROUP_DUP: u64 = 1 << 5;
pub const BLOCK_GROUP_RAID10: u64 = 1 << 6;
pub const BLOCK_GROUP_RAID5: u64 = 1 << 7;
pub const BLOCK_GROUP_RAID6: u64 = 1 << 8;
pub const BLOCK_GROUP_RAID1C3: u64 = 1 << 9;
pub const BLOCK_GROUP_RAID1C4: u64 = 1 << 10;
pub const BLOCK_GROUP_PROFILE_MASK: u64 = BLOCK_GROUP_RAID0
    | BLOCK_GROUP_RAID1
    | BLOCK_GROUP_DUP
    | BLOCK_GROUP_RAID10
    | BLOCK_GROUP_RAID5
    | BLOCK_GROUP_RAID6
    | BLOCK_GROUP_RAID1C3
    | BLOCK_GROUP_RAID1C4;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stripe {
    pub devid: u64,
    pub offset: u64,
    pub dev_uuid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    /// Logical start address (the key offset of the chunk item).
    pub logical: u64,
    pub length: u64,
    pub owner: u64,
    pub stripe_len: u64,
    pub ty: u64,
    pub io_align: u32,
    pub io_width: u32,
    pub sector_size: u32,
    pub num_stripes: u16,
    pub sub_stripes: u16,
    pub stripes: Vec<Stripe>,
}

impl Chunk {
    /// Parse a chunk item body. Returns the chunk and the number of bytes
    /// consumed (header plus stripes).
    pub fn from_bytes(logical: u64, d: &[u8]) -> Result<(Self, usize), String> {
        if d.len() < CHUNK_HEADER_SIZE {
            return Err("truncated chunk item".to_string());
        }
        let num_stripes = le_u16(d, 0x2C);
        let total = CHUNK_HEADER_SIZE + num_stripes as usize * STRIPE_SIZE;
        if num_stripes == 0 {
            return Err(format!("chunk at logical {logical} has no stripes"));
        }
        if d.len() < total {
            return Err(format!(
                "chunk at logical {logical} declares {num_stripes} stripes but only {} bytes are present",
                d.len()
            ));
        }
        let stripes = (0..num_stripes as usize)
            .map(|i| {
                let s = &d[CHUNK_HEADER_SIZE + i * STRIPE_SIZE..];
                Stripe {
                    devid: le_u64(s, 0),
                    offset: le_u64(s, 8),
                    dev_uuid: format_uuid(&s[16..32]),
                }
            })
            .collect();
        let chunk = Chunk {
            logical,
            length: le_u64(d, 0x00),
            owner: le_u64(d, 0x08),
            stripe_len: le_u64(d, 0x10),
            ty: le_u64(d, 0x18),
            io_align: le_u32(d, 0x20),
            io_width: le_u32(d, 0x24),
            sector_size: le_u32(d, 0x28),
            num_stripes,
            sub_stripes: le_u16(d, 0x2E),
            stripes,
        };
        chunk.validate()?;
        Ok((chunk, total))
    }

    fn validate(&self) -> Result<(), String> {
        if self.length == 0 {
            return Err(format!("chunk at logical {} has zero length", self.logical));
        }
        if self.logical.checked_add(self.length).is_none() {
            return Err(format!("chunk at logical {} overflows", self.logical));
        }
        if self.stripe_len != STRIPE_LEN {
            return Err(format!(
                "chunk at logical {} has stripe_len {} (expected {STRIPE_LEN})",
                self.logical, self.stripe_len
            ));
        }
        if self.ty & (BLOCK_GROUP_DATA | BLOCK_GROUP_SYSTEM | BLOCK_GROUP_METADATA) == 0 {
            return Err(format!(
                "chunk at logical {} has no data/system/metadata type (0x{:x})",
                self.logical, self.ty
            ));
        }
        let profile = self.ty & BLOCK_GROUP_PROFILE_MASK;
        if profile.count_ones() > 1 {
            return Err(format!(
                "chunk at logical {} has several RAID profiles (0x{:x})",
                self.logical, self.ty
            ));
        }
        let n = self.num_stripes;
        // Same rules as the kernel's btrfs_check_chunk_valid.
        let stripes_ok = match profile {
            0 => n == 1,
            BLOCK_GROUP_DUP | BLOCK_GROUP_RAID1 => n == 2,
            BLOCK_GROUP_RAID1C3 => n == 3,
            BLOCK_GROUP_RAID1C4 => n == 4,
            BLOCK_GROUP_RAID10 => self.sub_stripes == 2 && n >= 2 && n & 1 == 0,
            BLOCK_GROUP_RAID0 => n >= 1,
            BLOCK_GROUP_RAID5 => n >= 2,
            BLOCK_GROUP_RAID6 => n >= 3,
            _ => false,
        };
        if !stripes_ok {
            return Err(format!(
                "chunk at logical {} has {} stripes (sub_stripes {}), invalid for profile {}",
                self.logical,
                n,
                self.sub_stripes,
                self.profile_name()
            ));
        }
        Ok(())
    }

    pub fn profile_name(&self) -> &'static str {
        match self.ty & BLOCK_GROUP_PROFILE_MASK {
            0 => "single",
            BLOCK_GROUP_RAID0 => "raid0",
            BLOCK_GROUP_RAID1 => "raid1",
            BLOCK_GROUP_DUP => "dup",
            BLOCK_GROUP_RAID10 => "raid10",
            BLOCK_GROUP_RAID5 => "raid5",
            BLOCK_GROUP_RAID6 => "raid6",
            BLOCK_GROUP_RAID1C3 => "raid1c3",
            BLOCK_GROUP_RAID1C4 => "raid1c4",
            _ => "invalid",
        }
    }

    pub fn kind_name(&self) -> String {
        let mut parts = Vec::new();
        if self.ty & BLOCK_GROUP_DATA != 0 {
            parts.push("data");
        }
        if self.ty & BLOCK_GROUP_SYSTEM != 0 {
            parts.push("system");
        }
        if self.ty & BLOCK_GROUP_METADATA != 0 {
            parts.push("metadata");
        }
        parts.join("+")
    }

    fn contains(&self, logical: u64) -> bool {
        logical >= self.logical && logical - self.logical < self.length
    }

    /// Map one logical address inside this chunk to a physical offset on
    /// `devid`, together with the number of contiguous bytes available from
    /// that offset before the mapping changes (stripe boundary or chunk end).
    fn map(&self, logical: u64, devid: u64) -> Result<(u64, u64), String> {
        let off = logical - self.logical;
        let remaining_in_chunk = self.length - off;
        let profile = self.ty & BLOCK_GROUP_PROFILE_MASK;
        let on_device = |s: &Stripe| s.devid == devid;
        match profile {
            0 | BLOCK_GROUP_RAID1 | BLOCK_GROUP_DUP | BLOCK_GROUP_RAID1C3 | BLOCK_GROUP_RAID1C4 => {
                let stripe = self
                    .stripes
                    .iter()
                    .find(|s| on_device(s))
                    .ok_or_else(|| self.missing_device(devid))?;
                let physical = stripe
                    .offset
                    .checked_add(off)
                    .ok_or_else(|| self.overflow())?;
                Ok((physical, remaining_in_chunk))
            }
            BLOCK_GROUP_RAID0 => {
                let stripe_nr = off / self.stripe_len;
                let inner = off % self.stripe_len;
                let index = (stripe_nr % self.num_stripes as u64) as usize;
                let stripe = &self.stripes[index];
                if !on_device(stripe) {
                    return Err(self.missing_device(devid));
                }
                let physical = (stripe_nr / self.num_stripes as u64)
                    .checked_mul(self.stripe_len)
                    .and_then(|v| v.checked_add(stripe.offset))
                    .and_then(|v| v.checked_add(inner))
                    .ok_or_else(|| self.overflow())?;
                Ok((physical, (self.stripe_len - inner).min(remaining_in_chunk)))
            }
            BLOCK_GROUP_RAID10 => {
                let groups = (self.num_stripes / self.sub_stripes) as u64;
                let stripe_nr = off / self.stripe_len;
                let inner = off % self.stripe_len;
                let group = (stripe_nr % groups) as usize;
                let base = group * self.sub_stripes as usize;
                let stripe = self.stripes[base..base + self.sub_stripes as usize]
                    .iter()
                    .find(|s| on_device(s))
                    .ok_or_else(|| self.missing_device(devid))?;
                let physical = (stripe_nr / groups)
                    .checked_mul(self.stripe_len)
                    .and_then(|v| v.checked_add(stripe.offset))
                    .and_then(|v| v.checked_add(inner))
                    .ok_or_else(|| self.overflow())?;
                Ok((physical, (self.stripe_len - inner).min(remaining_in_chunk)))
            }
            BLOCK_GROUP_RAID5 | BLOCK_GROUP_RAID6 => {
                let nparity = if profile == BLOCK_GROUP_RAID5 { 1 } else { 2 };
                let data_stripes = self.num_stripes as u64 - nparity;
                let stripe_nr = off / self.stripe_len;
                let inner = off % self.stripe_len;
                let full_stripe = stripe_nr / data_stripes;
                let rot = full_stripe % self.num_stripes as u64;
                let index = ((stripe_nr % data_stripes) + rot) % self.num_stripes as u64;
                let stripe = &self.stripes[index as usize];
                if !on_device(stripe) {
                    return Err(self.missing_device(devid));
                }
                let physical = full_stripe
                    .checked_mul(self.stripe_len)
                    .and_then(|v| v.checked_add(stripe.offset))
                    .and_then(|v| v.checked_add(inner))
                    .ok_or_else(|| self.overflow())?;
                Ok((physical, (self.stripe_len - inner).min(remaining_in_chunk)))
            }
            _ => Err(format!(
                "chunk at logical {} has an unsupported profile 0x{:x}",
                self.logical, self.ty
            )),
        }
    }

    fn overflow(&self) -> String {
        format!(
            "chunk at logical {}: physical address overflows",
            self.logical
        )
    }

    fn missing_device(&self, devid: u64) -> String {
        let others: Vec<String> = self
            .stripes
            .iter()
            .filter(|s| s.devid != devid)
            .map(|s| s.devid.to_string())
            .collect();
        format!(
            "logical range {}..{} ({} {}) is stored on device(s) {} which are not part of this image (this image is device {})",
            self.logical,
            self.logical + self.length,
            self.kind_name(),
            self.profile_name(),
            others.join(", "),
            devid
        )
    }

    pub fn to_json(&self) -> Value {
        let mut value = serde_json::to_value(self).unwrap_or_else(|_| json!({}));
        if let Value::Object(map) = &mut value {
            map.insert("profile".into(), json!(self.profile_name()));
            map.insert("kind".into(), json!(self.kind_name()));
        }
        value
    }
}

/// Physical segment of a logical range on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalSegment {
    pub physical: u64,
    pub length: u64,
}

/// Ordered set of chunks with logical to physical translation.
#[derive(Debug, Clone, Default)]
pub struct ChunkMap {
    chunks: BTreeMap<u64, Chunk>,
    devid: u64,
    sectorsize: u64,
}

impl ChunkMap {
    pub fn new(devid: u64, sectorsize: u32) -> Self {
        ChunkMap {
            chunks: BTreeMap::new(),
            devid,
            sectorsize: if sectorsize.is_power_of_two() {
                sectorsize as u64
            } else {
                4096
            },
        }
    }

    pub fn devid(&self) -> u64 {
        self.devid
    }

    /// Add a chunk; rejects misaligned chunks and overlaps with existing ones
    /// (an identical chunk already present, as the sys_chunk_array copies of
    /// the chunk tree items, is accepted).
    pub fn insert(&mut self, chunk: Chunk) -> Result<(), String> {
        // sectorsize is a power of two (see `new`).
        let mask = self.sectorsize - 1;
        if chunk.logical & mask != 0 || chunk.length & mask != 0 {
            return Err(format!(
                "chunk at logical {} (length {}) is not sector aligned",
                chunk.logical, chunk.length
            ));
        }
        let end = chunk.logical + chunk.length;
        if let Some((_, prev)) = self.chunks.range(..=chunk.logical).next_back()
            && prev.logical + prev.length > chunk.logical
        {
            if prev.logical == chunk.logical && prev.length == chunk.length {
                self.chunks.insert(chunk.logical, chunk);
                return Ok(());
            }
            return Err(format!(
                "chunk at logical {} overlaps the chunk at logical {}",
                chunk.logical, prev.logical
            ));
        }
        if let Some((next_logical, _)) = self.chunks.range(chunk.logical + 1..).next()
            && *next_logical < end
        {
            return Err(format!(
                "chunk at logical {} overlaps the chunk at logical {next_logical}",
                chunk.logical
            ));
        }
        self.chunks.insert(chunk.logical, chunk);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    pub fn chunks(&self) -> impl Iterator<Item = &Chunk> {
        self.chunks.values()
    }

    /// Parse the superblock `sys_chunk_array`: a packed sequence of
    /// `(disk_key, chunk)` pairs describing the SYSTEM chunks.
    pub fn from_sys_chunk_array(devid: u64, sectorsize: u32, array: &[u8]) -> Result<Self, String> {
        let mut map = ChunkMap::new(devid, sectorsize);
        let mut pos = 0;
        while pos < array.len() {
            let key = Key::from_bytes(&array[pos..])
                .ok_or_else(|| "truncated key in sys_chunk_array".to_string())?;
            if key.ty != CHUNK_ITEM_KEY {
                return Err(format!(
                    "unexpected key {key} in sys_chunk_array (expected CHUNK_ITEM)"
                ));
            }
            pos += KEY_SIZE;
            let (chunk, consumed) = Chunk::from_bytes(key.offset, &array[pos..])?;
            if chunk.ty & BLOCK_GROUP_SYSTEM == 0 {
                return Err(format!(
                    "chunk at logical {} in sys_chunk_array is not a SYSTEM chunk",
                    chunk.logical
                ));
            }
            pos += consumed;
            map.insert(chunk)?;
        }
        if map.is_empty() {
            return Err("sys_chunk_array contains no chunk".to_string());
        }
        Ok(map)
    }

    pub fn chunk_for(&self, logical: u64) -> Option<&Chunk> {
        self.chunks
            .range(..=logical)
            .next_back()
            .map(|(_, c)| c)
            .filter(|c| c.contains(logical))
    }

    /// Translate a logical byte range into the list of physical segments on
    /// this device, in logical order. Fails if any part of the range is not
    /// mapped or lives on another device.
    pub fn map_range(&self, logical: u64, length: u64) -> Result<Vec<PhysicalSegment>, String> {
        let mut out = Vec::new();
        let mut cur = logical;
        let end = logical
            .checked_add(length)
            .ok_or_else(|| format!("logical range {logical}+{length} overflows"))?;
        while cur < end {
            let chunk = self
                .chunk_for(cur)
                .ok_or_else(|| format!("logical address {cur} is not mapped by any chunk"))?;
            let (physical, available) = chunk.map(cur, self.devid)?;
            let take = available.min(end - cur);
            match out.last_mut() {
                Some(PhysicalSegment {
                    physical: p,
                    length: l,
                }) if p.checked_add(*l) == Some(physical) => *l += take,
                _ => out.push(PhysicalSegment {
                    physical,
                    length: take,
                }),
            }
            cur += take;
        }
        Ok(out)
    }

    /// Translate a logical address to a physical one, for an access of
    /// `length` bytes that must be contiguous (tree nodes).
    pub fn map_contiguous(&self, logical: u64, length: u64) -> Result<u64, String> {
        let segments = self.map_range(logical, length)?;
        match segments.as_slice() {
            [single] => Ok(single.physical),
            _ => Err(format!(
                "logical range {logical}+{length} is not physically contiguous"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(
        logical: u64,
        length: u64,
        ty: u64,
        stripe_len: u64,
        stripes: &[(u64, u64)],
        sub: u16,
    ) -> Chunk {
        Chunk {
            logical,
            length,
            owner: 2,
            stripe_len,
            ty,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes: stripes.len() as u16,
            sub_stripes: sub,
            stripes: stripes
                .iter()
                .map(|(d, o)| Stripe {
                    devid: *d,
                    offset: *o,
                    dev_uuid: String::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn single_and_dup_map_linearly() {
        let mut map = ChunkMap::new(1, 4096);
        map.insert(chunk(
            1 << 20,
            8 << 20,
            BLOCK_GROUP_METADATA | BLOCK_GROUP_DUP,
            65536,
            &[(1, 1 << 20), (1, 9 << 20)],
            0,
        ))
        .unwrap();
        map.insert(chunk(
            9 << 20,
            8 << 20,
            BLOCK_GROUP_DATA,
            65536,
            &[(1, 17 << 20)],
            0,
        ))
        .unwrap();
        assert_eq!(
            map.map_contiguous((1 << 20) + 4096, 16384).unwrap(),
            (1 << 20) + 4096
        );
        let segs = map.map_range((1 << 20) + 100, (16 << 20) - 100).unwrap();
        assert_eq!(
            segs,
            vec![
                PhysicalSegment {
                    physical: (1 << 20) + 100,
                    length: (8 << 20) - 100
                },
                PhysicalSegment {
                    physical: 17 << 20,
                    length: 8 << 20
                },
            ]
        );
        assert!(map.map_range(0, 10).is_err());
        assert!(map.map_range(17 << 20, 1).is_err());
    }

    #[test]
    fn raid0_rotates_stripes() {
        let mut map = ChunkMap::new(1, 4096);
        map.insert(chunk(
            0,
            1 << 20,
            BLOCK_GROUP_DATA | BLOCK_GROUP_RAID0,
            65536,
            &[(1, 1 << 30), (2, 2 << 30)],
            0,
        ))
        .unwrap();
        // First stripe on device 1, second on device 2, third back on device 1.
        assert_eq!(map.map_contiguous(0, 65536).unwrap(), 1 << 30);
        assert!(
            map.map_contiguous(65536, 10)
                .unwrap_err()
                .contains("device(s) 2")
        );
        assert_eq!(
            map.map_contiguous(2 * 65536 + 16, 16).unwrap(),
            (1 << 30) + 65536 + 16
        );
        assert!(map.map_contiguous(65536 - 8, 16).is_err());
    }

    #[test]
    fn raid10_and_raid5_pick_a_local_copy() {
        let mut map = ChunkMap::new(3, 4096);
        map.insert(chunk(
            0,
            1 << 20,
            BLOCK_GROUP_DATA | BLOCK_GROUP_RAID10,
            65536,
            &[(1, 100), (3, 200), (2, 300), (4, 400)],
            2,
        ))
        .unwrap();
        assert_eq!(map.map_contiguous(0, 100).unwrap(), 200);
        assert!(map.map_contiguous(65536, 1).is_err());
        assert_eq!(
            map.map_contiguous(2 * 65536 + 5, 1).unwrap(),
            200 + 65536 + 5
        );

        let mut raid5 = ChunkMap::new(1, 4096);
        raid5
            .insert(chunk(
                0,
                1 << 20,
                BLOCK_GROUP_DATA | BLOCK_GROUP_RAID5,
                65536,
                &[(1, 1000), (2, 2000), (3, 3000)],
                0,
            ))
            .unwrap();
        // Full stripe 0: data stripes 0,1 on devices 1,2; parity on 3.
        assert_eq!(raid5.map_contiguous(0, 10).unwrap(), 1000);
        assert!(raid5.map_contiguous(65536, 10).is_err());
        // Full stripe 1: rotation by one, data stripes on devices 2,3.
        assert!(raid5.map_contiguous(2 * 65536, 10).is_err());
        // Full stripe 2: rotation by two, data on devices 3,1.
        assert_eq!(
            raid5.map_contiguous(5 * 65536, 10).unwrap(),
            1000 + 2 * 65536
        );
    }

    #[test]
    fn sys_chunk_array_parsing_rejects_garbage() {
        assert!(ChunkMap::from_sys_chunk_array(1, 4096, &[]).is_err());
        assert!(ChunkMap::from_sys_chunk_array(1, 4096, &[0u8; 10]).is_err());
        let mut array = Key::new(256, CHUNK_ITEM_KEY, 1 << 20).to_bytes().to_vec();
        let mut body = vec![0u8; CHUNK_HEADER_SIZE + STRIPE_SIZE];
        body[0..8].copy_from_slice(&(4u64 << 20).to_le_bytes());
        body[0x10..0x18].copy_from_slice(&65536u64.to_le_bytes());
        body[0x18..0x20].copy_from_slice(&BLOCK_GROUP_SYSTEM.to_le_bytes());
        body[0x2C..0x2E].copy_from_slice(&1u16.to_le_bytes());
        body[CHUNK_HEADER_SIZE..CHUNK_HEADER_SIZE + 8].copy_from_slice(&1u64.to_le_bytes());
        body[CHUNK_HEADER_SIZE + 8..CHUNK_HEADER_SIZE + 16]
            .copy_from_slice(&(1u64 << 20).to_le_bytes());
        array.extend_from_slice(&body);
        let map = ChunkMap::from_sys_chunk_array(1, 4096, &array).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.map_contiguous(1 << 20, 4096).unwrap(), 1 << 20);
        // Non-SYSTEM chunk in the array.
        let mut bad = array.clone();
        bad[KEY_SIZE + 0x18] = BLOCK_GROUP_DATA as u8;
        assert!(ChunkMap::from_sys_chunk_array(1, 4096, &bad).is_err());
        // Truncated stripes.
        assert!(ChunkMap::from_sys_chunk_array(1, 4096, &array[..array.len() - 1]).is_err());
    }
}
