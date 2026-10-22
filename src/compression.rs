//! Decompression of Btrfs extents: zlib, LZO (Btrfs segment framing over
//! LZO1X) and zstd.
//!
//! Every compressed extent decompresses to at most `ram_bytes` bytes; callers
//! pass that bound so a corrupted stream cannot make the reader allocate
//! without limit.

use crate::extent::{COMPRESS_LZO, COMPRESS_NONE, COMPRESS_ZLIB, COMPRESS_ZSTD, compression_name};
use std::io::Read;

/// Hard cap on a single decompressed extent, far above the 128 KiB Btrfs
/// uses for compressed extents but small enough to bound memory on garbage.
pub const MAX_DECOMPRESSED_EXTENT: u64 = 64 * 1024 * 1024;

/// Decompress `data` with the algorithm `compression`, producing at most
/// `limit` bytes. `sectorsize` is needed for the LZO segment framing.
pub fn decompress(
    compression: u8,
    data: &[u8],
    limit: u64,
    sectorsize: u32,
) -> Result<Vec<u8>, String> {
    let limit = limit.min(MAX_DECOMPRESSED_EXTENT) as usize;
    match compression {
        COMPRESS_NONE => Ok(data[..data.len().min(limit)].to_vec()),
        COMPRESS_ZLIB => zlib(data, limit),
        COMPRESS_LZO => lzo_extent(data, limit, sectorsize as usize),
        COMPRESS_ZSTD => zstd(data, limit),
        other => Err(format!(
            "unsupported compression type {other} ({})",
            compression_name(other)
        )),
    }
}

/// Like the kernel (`zlib_decompress_bio`), inflate the raw deflate stream
/// behind the 2-byte zlib header without checking the Adler-32 trailer: a
/// corrupted trailer must not hide readable data.
// `is_multiple_of` needs Rust 1.87; keep the plain modulo for older toolchains.
#[allow(clippy::manual_is_multiple_of)]
fn zlib(data: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(limit.min(1 << 20));
    let zlib_header = data.len() >= 2
        && data[0] & 0x0f == 8
        && data[1] & 0x20 == 0
        && (((data[0] as u32) << 8) | data[1] as u32) % 31 == 0;
    if zlib_header {
        flate2::read::DeflateDecoder::new(&data[2..])
            .take(limit as u64)
            .read_to_end(&mut out)
            .map_err(|e| format!("zlib (raw deflate): {e}"))?;
    } else {
        flate2::read::ZlibDecoder::new(data)
            .take(limit as u64)
            .read_to_end(&mut out)
            .map_err(|e| format!("zlib: {e}"))?;
    }
    Ok(out)
}

fn zstd(data: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(limit.min(1 << 20));
    let decoder =
        ruzstd::decoding::StreamingDecoder::new(data).map_err(|e| format!("zstd: {e}"))?;
    decoder
        .take(limit as u64)
        .read_to_end(&mut out)
        .map_err(|e| format!("zstd: {e}"))?;
    Ok(out)
}

/// Btrfs LZO framing: a LE32 total length, then segments made of a LE32
/// length and an LZO1X stream decompressing to at most one sector. A segment
/// header never crosses a sector boundary, so up to three padding bytes may
/// precede the next sector.
fn lzo_extent(data: &[u8], limit: usize, sectorsize: usize) -> Result<Vec<u8>, String> {
    if sectorsize == 0 || data.len() < 4 {
        return Err("lzo: extent shorter than its header".to_string());
    }
    let total = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if total > data.len() || total < 4 {
        return Err(format!(
            "lzo: declared length {total} inconsistent with {} available bytes",
            data.len()
        ));
    }
    let mut out = Vec::with_capacity(limit.min(1 << 20));
    let mut pos = 4;
    while pos < total && out.len() < limit {
        if sectorsize - (pos % sectorsize) < 4 {
            pos = (pos / sectorsize + 1) * sectorsize;
            if pos >= total {
                break;
            }
        }
        if pos + 4 > total {
            return Err("lzo: truncated segment header".to_string());
        }
        let seg_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if seg_len == 0 || pos + seg_len > total {
            return Err(format!(
                "lzo: segment of {seg_len} bytes at {pos} runs past the extent"
            ));
        }
        let remaining = limit - out.len();
        let segment = lzo1x_decompress(&data[pos..pos + seg_len], sectorsize.min(remaining))?;
        out.extend_from_slice(&segment);
        pos += seg_len;
    }
    Ok(out)
}

/// Safe LZO1X decompressor (the format produced by `lzo1x_1_compress`).
/// Returns an error instead of reading or writing out of bounds. Output is
/// capped at `max_out` bytes.
pub fn lzo1x_decompress(input: &[u8], max_out: usize) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::with_capacity(max_out);
    let mut ip = 0usize;
    let err = |what: &str| format!("lzo1x: {what}");

    macro_rules! byte {
        () => {{
            let b = *input.get(ip).ok_or_else(|| err("input overrun"))?;
            ip += 1;
            b
        }};
    }
    macro_rules! copy_literals {
        ($n:expr) => {{
            let n: usize = $n;
            if ip + n > input.len() {
                return Err(err("literal run overruns input"));
            }
            if out.len() + n > max_out {
                return Err(err("output exceeds the expected size"));
            }
            out.extend_from_slice(&input[ip..ip + n]);
            ip += n;
        }};
    }
    macro_rules! copy_match {
        ($dist:expr, $len:expr) => {{
            let dist: usize = $dist;
            let len: usize = $len;
            if dist == 0 || dist > out.len() {
                return Err(err("match distance points before the output start"));
            }
            if out.len() + len > max_out {
                return Err(err("output exceeds the expected size"));
            }
            let start = out.len() - dist;
            for i in 0..len {
                let b = out[start + i];
                out.push(b);
            }
        }};
    }
    macro_rules! long_length {
        ($base:expr) => {{
            let mut t: usize = 0;
            loop {
                let b = byte!();
                if b == 0 {
                    t += 255;
                    if t > max_out + 255 {
                        return Err(err("run length too large"));
                    }
                } else {
                    t += $base + b as usize;
                    break;
                }
            }
            t
        }};
    }

    if input.is_empty() {
        return Err(err("empty input"));
    }
    // `state`: number of literals that followed the previous match (0..=3),
    // or 4 after a literal run / at the start.
    let mut state: usize = 0;
    let first = input[0];
    if first > 17 {
        ip = 1;
        let t = first as usize - 17;
        copy_literals!(t);
        state = if t < 4 { t } else { 4 };
    }

    loop {
        let t = byte!() as usize;
        let (dist, len, next): (usize, usize, usize);
        if t < 16 {
            if state == 0 {
                // Literal run.
                let n = if t == 0 { long_length!(15) + 3 } else { t + 3 };
                copy_literals!(n);
                state = 4;
                continue;
            } else if state != 4 {
                // 2-byte match, short distance.
                let h = byte!() as usize;
                dist = (t >> 2) + (h << 2) + 1;
                len = 2;
                next = t & 3;
            } else {
                // 3-byte match, distance >= 2049.
                let h = byte!() as usize;
                dist = (t >> 2) + (h << 2) + 2049;
                len = 3;
                next = t & 3;
            }
        } else if t >= 64 {
            // M2: length 3..8, distance 1..2048.
            let h = byte!() as usize;
            dist = ((t >> 2) & 7) + (h << 3) + 1;
            len = (t >> 5) + 1;
            next = t & 3;
        } else if t >= 32 {
            // M3: length 2 + L (long form when L == 0), 16-bit distance.
            len = if t & 31 == 0 {
                long_length!(31) + 2
            } else {
                (t & 31) + 2
            };
            if ip + 2 > input.len() {
                return Err(err("input overrun"));
            }
            let d = u16::from_le_bytes([input[ip], input[ip + 1]]) as usize;
            ip += 2;
            dist = (d >> 2) + 1;
            next = d & 3;
        } else {
            // M4: distance >= 16384, or end of stream.
            let hi = (t & 8) << 11;
            len = if t & 7 == 0 {
                long_length!(7) + 2
            } else {
                (t & 7) + 2
            };
            if ip + 2 > input.len() {
                return Err(err("input overrun"));
            }
            let d = u16::from_le_bytes([input[ip], input[ip + 1]]) as usize;
            ip += 2;
            if hi == 0 && (d >> 2) == 0 {
                // End marker: the kernel requires the 0x11 0x00 0x00 form
                // (length 3) and no trailing input.
                if len != 3 {
                    return Err(err("malformed end marker"));
                }
                if ip != input.len() {
                    return Err(err("input not consumed after the end marker"));
                }
                return Ok(out);
            }
            dist = hi + (d >> 2) + 16384;
            next = d & 3;
        }
        copy_match!(dist, len);
        copy_literals!(next);
        state = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn zlib_roundtrip_and_limit() {
        let plain: Vec<u8> = (0..10000u32).map(|i| (i % 7) as u8).collect();
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&plain).unwrap();
        let compressed = enc.finish().unwrap();
        assert_eq!(
            decompress(COMPRESS_ZLIB, &compressed, 10000, 4096).unwrap(),
            plain
        );
        assert_eq!(
            decompress(COMPRESS_ZLIB, &compressed, 100, 4096)
                .unwrap()
                .len(),
            100
        );
        assert!(decompress(COMPRESS_ZLIB, &compressed[..20], 10000, 4096).is_err());
        // A corrupted Adler-32 trailer does not hide the data (kernel behaviour).
        let mut bad_trailer = compressed.clone();
        let n = bad_trailer.len();
        bad_trailer[n - 1] ^= 0xFF;
        assert_eq!(
            decompress(COMPRESS_ZLIB, &bad_trailer, 10000, 4096).unwrap(),
            plain
        );
        assert!(decompress(9, &compressed, 10, 4096).is_err());
    }

    #[test]
    fn zstd_roundtrip() {
        let plain: Vec<u8> = (0..20000u32).map(|i| (i * 31 % 13) as u8).collect();
        let compressed = ruzstd::encoding::compress_to_vec(
            &plain[..],
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        assert_eq!(
            decompress(COMPRESS_ZSTD, &compressed, 20000, 4096).unwrap(),
            plain
        );
        assert!(decompress(COMPRESS_ZSTD, b"not zstd at all", 20000, 4096).is_err());
    }

    #[test]
    fn lzo1x_hand_built_stream() {
        // "abcabcabcabcXYZ" as: literal run "abc" (first byte 17+3=20), then an
        // M2 match of length 8 at distance 3 followed by 1 literal... built the
        // way lzo1x_1 would emit it, ending with the 0x11 0 0 marker.
        // Token for M2 len 8 dist 3: len=(t>>5)+1=8 -> t>>5 = 7; dist-1 = 2 ->
        // low 3 bits of (t>>2) = 2, H = 0; next literals = 1 -> t = 0b111_010_01.
        let stream = [20u8, b'a', b'b', b'c', 0b1110_1001, 0, b'X', 0x11, 0, 0];
        let out = lzo1x_decompress(&stream, 64).unwrap();
        assert_eq!(out, b"abcabcabcabX");
        // Output bound respected.
        assert!(lzo1x_decompress(&stream, 5).is_err());
        // Truncated stream.
        assert!(lzo1x_decompress(&stream[..6], 64).is_err());
        // Match before the start of the output.
        let bad = [18u8, b'a', 0b0100_0000, 5, 0x11, 0, 0];
        assert!(lzo1x_decompress(&bad, 64).is_err());
        assert!(lzo1x_decompress(&[], 64).is_err());
    }

    #[test]
    fn lzo_extent_framing() {
        let seg = [20u8, b'a', b'b', b'c', 0b1110_1001, 0, b'X', 0x11, 0, 0];
        let mut extent = Vec::new();
        let total = 4 + 4 + seg.len();
        extent.extend_from_slice(&(total as u32).to_le_bytes());
        extent.extend_from_slice(&(seg.len() as u32).to_le_bytes());
        extent.extend_from_slice(&seg);
        assert_eq!(
            decompress(COMPRESS_LZO, &extent, 4096, 4096).unwrap(),
            b"abcabcabcabX"
        );
        // Declared total larger than the buffer.
        let mut bad = extent.clone();
        bad[0..4].copy_from_slice(&(total as u32 + 10).to_le_bytes());
        assert!(decompress(COMPRESS_LZO, &bad, 4096, 4096).is_err());
        // Segment running past the total.
        let mut bad = extent.clone();
        bad[4..8].copy_from_slice(&(seg.len() as u32 + 1).to_le_bytes());
        assert!(decompress(COMPRESS_LZO, &bad, 4096, 4096).is_err());
        // Padding before a sector boundary: place the first segment so that only
        // 2 bytes remain in the sector, the second segment must start at 4096.
        let sector = 4096usize;
        let mut framed = vec![0u8; 0];
        // Segment A is exactly sector - 2 - 8 bytes long: a long literal run
        // (token 0, fifteen zero bytes, 223) of 4066 bytes then the end marker.
        let literals: Vec<u8> = (0..4066u32).map(|i| b'a' + (i % 26) as u8).collect();
        let mut seg_a = vec![0u8];
        seg_a.extend_from_slice(&[0u8; 15]);
        seg_a.push(223);
        seg_a.extend_from_slice(&literals);
        seg_a.extend_from_slice(&[0x11, 0, 0]);
        assert_eq!(seg_a.len(), sector - 4 - 4 - 2);
        framed.extend_from_slice(&0u32.to_le_bytes()); // placeholder total
        framed.extend_from_slice(&(seg_a.len() as u32).to_le_bytes());
        framed.extend_from_slice(&seg_a);
        assert_eq!(framed.len(), sector - 2);
        framed.extend_from_slice(&[0, 0]); // padding: a 4-byte header cannot fit
        framed.extend_from_slice(&(seg.len() as u32).to_le_bytes());
        framed.extend_from_slice(&seg);
        let total = framed.len() as u32;
        framed[0..4].copy_from_slice(&total.to_le_bytes());
        let mut expected = literals.clone();
        expected.extend_from_slice(b"abcabcabcabX");
        assert_eq!(
            decompress(COMPRESS_LZO, &framed, 8192, sector as u32).unwrap(),
            expected
        );
        // Trailing bytes after the end marker are an error, like in the kernel.
        let mut trailing = seg.to_vec();
        trailing.push(0);
        assert!(lzo1x_decompress(&trailing, 64).is_err());
    }
}
