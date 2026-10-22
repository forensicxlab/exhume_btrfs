# Exhume Btrfs

Read-only Btrfs support for the [Exhume](https://github.com/forensicxlab/exhume) toolkit:
a library (`exhume_btrfs`) used by `exhume_filesystem`, and a small CLI to inspect a
Btrfs partition directly.

The Exhume Btrfs documentation is maintained at [forensicxlab.com](https://www.forensicxlab.com/docs/exhume_btrfs/getting-started).

## What is supported

* Superblock (primary at 64 KiB, mirrors at 64 MiB and 256 GiB; the valid copy with the
  highest generation is used), `sys_chunk_array`, chunk tree, root tree.
* Checksums: CRC-32C, XXHASH64, SHA-256, BLAKE2b-256 on the superblock and every metadata
  block. A block with a bad checksum is an error; `--tolerate-bad-checksums` keeps going
  for salvage, logging each bad block once.
* Chunk profiles: single, DUP, RAID1/1C3/1C4 (any copy on this device), RAID0/RAID10/
  RAID5/RAID6 striping (only the stripes stored on this device; data on other devices of a
  multi-device filesystem is reported as unreadable, never zero-filled).
* Subvolumes and snapshots: listed from the root tree with name, path, UUIDs, read-only
  flag, creation time and the default subvolume. The reader exposes the top-level
  subvolume (tree 5) as root, like `mount -o subvolid=5`, so every subvolume and snapshot
  is reachable at the directory where it lives. Entries crossing into a subvolume resolve
  to the child tree only when a root reference backs them from that directory; the stale
  copies a snapshot keeps of its parent's subvolume entries are reported as not reachable,
  which is what the kernel shows as empty directories.
* Every child node is checked against its parent pointer (level, generation, first key),
  so stale copy-on-write blocks at reused addresses are rejected like the kernel does.
* Inodes, `DIR_INDEX` listings, hashed `DIR_ITEM` lookups (collisions included),
  `INODE_REF`/`INODE_EXTREF` names and hard links, extended attributes, symbolic links.
* File extents: inline, regular, preallocated, holes and `no_holes` gaps, extent offsets,
  zlib / LZO (Btrfs segment framing over LZO1X) / zstd compression. Decompressed sizes are
  bounded by `ram_bytes`.
* Features refused explicitly: zoned devices, raid-stripe-tree, extent-tree-v2, unknown
  incompat bits, encrypted extents. An unreplayed log tree (unclean shutdown) is reported
  as a warning; the log is never replayed.

Not covered: data checksum verification (the csum tree is not read), the free-space,
extent and quota trees, deleted file recovery, send streams.

## CLI

```sh
exhume_btrfs -b disk.img -o <partition offset> -s <sectors> --superblock --subvolumes --chunks
exhume_btrfs -b disk.img -o 2048 -s 223232 --path /home/user/file.txt --extents
exhume_btrfs -b disk.img -o 2048 -s 223232 --subvol 258 --inode 257 --dir_entry
exhume_btrfs -b disk.qcow2 -o 2048 -s 223232 --path /subvols/data/project/big.bin --dump
```

`--format` accepts every `exhume_body` format (raw, ewf, vmdk, aff, aff4, qcow2, vhdx, auto).

## Identifiers in exhume_filesystem

Btrfs inode numbers are only unique inside a subvolume. `exhume_filesystem` therefore
publishes `(subvolume slot << 48) | inode`, where the slot is the position of the
subvolume in the sorted subvolume table (0 for the top level). `--record 256` is the root
directory, `--record $((1 << 48 | 256))` the root directory of the first subvolume.

## Tests

```sh
cargo test                                   # unit tests + hand-built synthetic images
cargo test --test mkfs_images -- --ignored    # needs mkfs.btrfs >= 6.x: 13 variants, byte-for-byte comparison, 400 corrupted mutants
```
