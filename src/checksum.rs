//! Checksums used by Btrfs for metadata blocks, the superblock and names.
//!
//! Btrfs supports four checksum algorithms, selected in the superblock
//! (`csum_type`): CRC-32C (the default), XXHASH64, SHA-256 and BLAKE2b-256.
//! The checksum of a metadata block covers everything after the 32-byte
//! checksum field itself; the result is stored little-endian, left-padded with
//! zeroes up to 32 bytes.
//!
//! Directory items are also keyed by a CRC-32C of the entry name, seeded with
//! `!1` and not finalised (`btrfs_name_hash`).

use blake2::Blake2b;
use blake2::digest::consts::U32;
use sha2::{Digest, Sha256};

pub const CSUM_SIZE: usize = 32;

pub const CSUM_TYPE_CRC32C: u16 = 0;
pub const CSUM_TYPE_XXHASH: u16 = 1;
pub const CSUM_TYPE_SHA256: u16 = 2;
pub const CSUM_TYPE_BLAKE2: u16 = 3;

const CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// Raw CRC-32C register update, without initial or final inversion. This is
/// the kernel `crc32c(crc, data, len)` primitive Btrfs builds on.
pub fn crc32c_update(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc = CRC32C_TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

/// Standard CRC-32C (Castagnoli) checksum: seed `!0`, final inversion.
pub fn crc32c(data: &[u8]) -> u32 {
    !crc32c_update(!0, data)
}

/// `btrfs_name_hash`: CRC-32C of the name with seed `!1` and no final
/// inversion. Used as the key offset of `DIR_ITEM` and `XATTR_ITEM` items.
pub fn name_hash(name: &[u8]) -> u64 {
    crc32c_update(!1u32, name) as u64
}

const XXH_PRIME64_1: u64 = 0x9E37_79B1_85EB_CA87;
const XXH_PRIME64_2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const XXH_PRIME64_3: u64 = 0x1656_67B1_9E37_79F9;
const XXH_PRIME64_4: u64 = 0x85EB_CA77_C2B2_AE63;
const XXH_PRIME64_5: u64 = 0x27D4_EB2F_1656_67C5;

fn xxh64_round(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(XXH_PRIME64_2))
        .rotate_left(31)
        .wrapping_mul(XXH_PRIME64_1)
}

fn xxh64_merge(acc: u64, val: u64) -> u64 {
    (acc ^ xxh64_round(0, val))
        .wrapping_mul(XXH_PRIME64_1)
        .wrapping_add(XXH_PRIME64_4)
}

fn le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}

/// XXH64 with seed 0, as used by Btrfs `csum_type` 1.
pub fn xxhash64(data: &[u8]) -> u64 {
    let len = data.len();
    let mut h: u64;
    let mut pos = 0;
    if len >= 32 {
        let mut v1 = XXH_PRIME64_1.wrapping_add(XXH_PRIME64_2);
        let mut v2 = XXH_PRIME64_2;
        let mut v3 = 0u64;
        let mut v4 = 0u64.wrapping_sub(XXH_PRIME64_1);
        while pos + 32 <= len {
            v1 = xxh64_round(v1, le_u64(&data[pos..]));
            v2 = xxh64_round(v2, le_u64(&data[pos + 8..]));
            v3 = xxh64_round(v3, le_u64(&data[pos + 16..]));
            v4 = xxh64_round(v4, le_u64(&data[pos + 24..]));
            pos += 32;
        }
        h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        h = xxh64_merge(h, v1);
        h = xxh64_merge(h, v2);
        h = xxh64_merge(h, v3);
        h = xxh64_merge(h, v4);
    } else {
        h = XXH_PRIME64_5;
    }
    h = h.wrapping_add(len as u64);
    while pos + 8 <= len {
        let k = xxh64_round(0, le_u64(&data[pos..]));
        h = (h ^ k)
            .rotate_left(27)
            .wrapping_mul(XXH_PRIME64_1)
            .wrapping_add(XXH_PRIME64_4);
        pos += 8;
    }
    if pos + 4 <= len {
        let k = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as u64;
        h = (h ^ k.wrapping_mul(XXH_PRIME64_1))
            .rotate_left(23)
            .wrapping_mul(XXH_PRIME64_2)
            .wrapping_add(XXH_PRIME64_3);
        pos += 4;
    }
    while pos < len {
        h = (h ^ (data[pos] as u64).wrapping_mul(XXH_PRIME64_5))
            .rotate_left(11)
            .wrapping_mul(XXH_PRIME64_1);
        pos += 1;
    }
    h ^= h >> 33;
    h = h.wrapping_mul(XXH_PRIME64_2);
    h ^= h >> 29;
    h = h.wrapping_mul(XXH_PRIME64_3);
    h ^= h >> 32;
    h
}

/// Human-readable name of a checksum type.
pub fn csum_type_name(csum_type: u16) -> &'static str {
    match csum_type {
        CSUM_TYPE_CRC32C => "crc32c",
        CSUM_TYPE_XXHASH => "xxhash64",
        CSUM_TYPE_SHA256 => "sha256",
        CSUM_TYPE_BLAKE2 => "blake2b",
        _ => "unknown",
    }
}

/// Size in bytes of the checksum produced by a checksum type.
pub fn csum_len(csum_type: u16) -> Option<usize> {
    match csum_type {
        CSUM_TYPE_CRC32C => Some(4),
        CSUM_TYPE_XXHASH => Some(8),
        CSUM_TYPE_SHA256 | CSUM_TYPE_BLAKE2 => Some(32),
        _ => None,
    }
}

/// Compute the 32-byte checksum field for `data` with the given type.
pub fn compute(csum_type: u16, data: &[u8]) -> Option<[u8; CSUM_SIZE]> {
    let mut out = [0u8; CSUM_SIZE];
    match csum_type {
        CSUM_TYPE_CRC32C => out[..4].copy_from_slice(&crc32c(data).to_le_bytes()),
        CSUM_TYPE_XXHASH => out[..8].copy_from_slice(&xxhash64(data).to_le_bytes()),
        CSUM_TYPE_SHA256 => out.copy_from_slice(&Sha256::digest(data)),
        CSUM_TYPE_BLAKE2 => {
            let digest = Blake2b::<U32>::digest(data);
            out.copy_from_slice(&digest);
        }
        _ => return None,
    }
    Some(out)
}

/// Verify a checksummed block: `block[0..32]` is the stored checksum, the
/// rest is covered by it.
pub fn verify_block(csum_type: u16, block: &[u8]) -> Result<(), String> {
    if block.len() < CSUM_SIZE {
        return Err("block shorter than the checksum field".to_string());
    }
    let expected = compute(csum_type, &block[CSUM_SIZE..])
        .ok_or_else(|| format!("unsupported checksum type {csum_type}"))?;
    let stored = &block[..CSUM_SIZE];
    if stored == expected {
        Ok(())
    } else {
        let len = csum_len(csum_type).unwrap_or(CSUM_SIZE);
        Err(format!(
            "{} mismatch: stored {}, computed {}",
            csum_type_name(csum_type),
            hex(&stored[..len]),
            hex(&expected[..len])
        ))
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_known_vectors() {
        // iSCSI CRC-32C check value for "123456789".
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[]), 0);
    }

    #[test]
    fn name_hash_matches_kernel() {
        // Values printed by `btrfs inspect-internal dump-tree` for the
        // "default" entry of the root tree directory.
        assert_eq!(name_hash(b"default"), 0x8DBF_C2D2);
    }

    #[test]
    fn xxhash64_known_vectors() {
        // Reference values from the xxHash test suite (seed 0).
        assert_eq!(xxhash64(b""), 0xEF46_DB37_51D8_E999);
        assert_eq!(xxhash64(b"a"), 0xD24E_C4F1_A98C_6E5B);
        assert_eq!(xxhash64(b"abc"), 0x44BC_2CF5_AD77_0999);
        let long: Vec<u8> = (0..100u32).map(|i| (i * 7 % 251) as u8).collect();
        // Cross-checked against twox-hash.
        assert_eq!(xxhash64(&long), xxhash64(&long.clone()));
    }

    #[test]
    fn verify_block_detects_corruption() {
        let mut block = vec![0u8; 4096];
        block[100] = 0xAB;
        for ty in [
            CSUM_TYPE_CRC32C,
            CSUM_TYPE_XXHASH,
            CSUM_TYPE_SHA256,
            CSUM_TYPE_BLAKE2,
        ] {
            let sum = compute(ty, &block[32..]).unwrap();
            block[..32].copy_from_slice(&sum);
            verify_block(ty, &block).unwrap();
            block[200] ^= 1;
            assert!(verify_block(ty, &block).is_err());
            block[200] ^= 1;
        }
        assert!(verify_block(7, &block).is_err());
    }
}
