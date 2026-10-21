# Diagnosing and recovering damaged metadata

Normal conversion and `-desc` remain strict. Metadata hash errors now identify
the block, payload offset, stored length, expected/computed MD5 and processing
stage. Metadata Zstandard sizes are bounded before allocation. Read errors
include the offset and requested/actual byte counts.
Redirected `-desc` output uses a bounded fallback console width instead of
reading uninitialized console information when no console is attached.

`--recover-plan` is an explicit forensic recovery path for **one unencrypted,
unsplit full image containing one disk**. It creates a full-size disk, restores
individually verified data, and records unrecoverable/reconstructed ranges.
It is not a generic "ignore checksums" switch. Encrypted, incremental, split,
and multiple-disk recovery plans are rejected; the original strict converter
continues to support those formats.

## Build

From a Visual Studio 2022 x64 Native Tools command prompt:

```bat
build-recovery.cmd
```

Alternatively pass an existing compiler environment batch file:

```bat
build-recovery.cmd C:\tools\msvc\setup_x64.bat
```

The tested configuration is MSVC 14.44, Windows SDK 10.0.26100.0, x64 Release,
C++17, `/O2 /MT`, using the repository's bundled OpenSSL/Zstandard/zlib libraries.
The output is `build\img_to_vhdx.exe`.

## Strict diagnostics and conversion

```bat
img_to_vhdx.exe backup.mrimgx -desc > strict.log 2>&1
img_to_vhdx.exe backup.mrimgx -o C:\recovery
```

The original mounted-disk conversion needs administrator rights. Recovery's
offline output option below does not mount a disk or allow Windows filesystem
log replay during conversion.

## Recovery plan

An index descriptor must be established from the actual image, not guessed.
Use intact, hash-verified root JSON for disk geometry and block counts. For a
missing index header, independent boundaries and decoded block hashes must
corroborate the proposed entry array. A zero index entry inside an unverified
container must never be assumed to mean free space.

Install `zstandard`, then fingerprint the descriptor:

```bat
python tools\make_recovery_plan.py backup.mrimgx descriptor.json plan.json
```

The descriptor contains a `partitions` array. Each item supplies:

- `entries_offset`: source offset of the first packed 30-byte data entry.
- `reserved_count` and `reserved_offset`: FAT reserved-sector entries, if any.
- `container_verified`: true only for an intact index container. When true,
  supply `header_offset`; the converter independently verifies its stored hash.
- Optional `overrides`, keyed by logical block number. An override records
  `source_offset`, `stored_length`, `decoded_md5`, and a human-readable `reason`.
  These are always reported as reconstructed/unverified, even when their
  decoded bytes match the plan fingerprint. The fingerprint is not a substitute
  for the missing original digest.

The generator binds the plan to the source length, image ID, strictly verified
root JSON, and exact entry-array bytes. The converter also checks index counts,
overlaps, source/destination bounds, file references, decompression sizes and
every surviving data digest. Metadata and indexes are held in memory; the
backup is always opened read-only.

For NTFS partitions with readable MFT records, `tools/recover_ntfs_indexes.py`
can locate orphan compressed directory frames. It validates NTFS update-sequence
fixups, checks parent-record sequence numbers, and maps each page's VCN through
the parent's surviving `$I30` runlist. Conflicting candidates are excluded.
Supply an independently established boot-block override first if required:

```bat
python tools\recover_ntfs_indexes.py backup.mrimgx plan.json directory-plan.json --partition 2 --scan-start 0 --scan-end 1200000000
```

The scan interval must be chosen from the actual image. The example interval
is not a universal offset. This scanner currently supports 4096-byte NTFS
clusters and index buffers. It never guesses logical positions from compressed
frame ordering, and recovered candidates retain their unverified status.

## Verify or recover

Use fresh output and manifest names; existing ones are refused.

```bat
img_to_vhdx.exe --recover-plan backup.mrimgx plan.json recovered.vhdx verify.jsonl --verify-only
img_to_vhdx.exe --recover-plan backup.mrimgx plan.json recovered.vhdx recovery.jsonl --qemu-img C:\tools\qemu-img.exe
img_to_vhdx.exe --recover-plan backup.mrimgx plan.json direct.vhdx direct.jsonl --direct-vhdx C:\tools\qemu-img.exe
```

Obtain QEMU from the Windows builds linked by [QEMU](https://www.qemu.org/download/).
The tested offline converter is the 2026-08-11 Windows x64 build, checked against
its publisher's SHA-512 file. The native recovery tool writes a sparse
`recovered.vhdx.raw`, invokes `qemu-img` directly (without a shell) to create a
dynamic VHDX, and retains the sparse intermediate. Budget space for both files.
Sparse-file support is required. No source repair, checksum rewriting, or
filesystem repair is performed.

`--direct-vhdx` asks QEMU to create an empty dynamic container, then writes its
payload and block allocation table directly. It avoids the raw intermediate.
This writer accepts only a newly created, empty, standalone VHDX with 2 MiB
blocks and 512-byte logical sectors; it checks header and region checksums,
metadata bounds, and the empty allocation table before writing. It does not
modify existing images, replay logs, or support parent disks. The boundary
harness in `tools/test_offline_vhdx.cpp` exercises payload boundaries and the
interleaved sector-bitmap boundary at 4 GiB. Control-image output was independently
compared with the raw-to-VHDX conversion.

Exit codes: `0` all stored blocks verified; `2` completed partial recovery;
`1` fatal error. A full-size VHDX with exit code 2 is **not** a complete or clean
restore. Missing ranges read as zeros in the new image and are explicitly
identified as substitutions in the JSONL manifest. Fatal target-write or
manifest-write failures abort the run. Interrupted output has no `complete`
manifest event and must not be presented as finished.

Manifest records distinguish verified-container omissions, unknown zero index
entries, reconstructed data, and unrecoverable data. Progress is flushed every
five seconds. Successful ordinary blocks are represented by verified counts;
all exceptions and substitutions have disk offsets and lengths. Source index
arrays and the plan provide the mapping for ordinary blocks.
The converter also records the complete source SHA-256 and checks that source
size and last-write time remain unchanged. This is an audit fingerprint, not
proof that already damaged source content was originally correct.

## Validate

```bat
python tools\test_recovery.py build\img_to_vhdx.exe
qemu-img check recovered.vhdx
qemu-img compare -f raw -F vhdx recovered.vhdx.raw recovered.vhdx
```

The integration suite uses the repository's demo image and temporary mutated
copies. It checks strict metadata rejection, complete control verification,
source/plan mismatch handling, bounds, data-damage manifests, and unchanged
control-source content. It retains test artifacts for audit.

Finally inspect the VHDX through a read-only filesystem reader or read-only
mount. Validate known files against independently recovered copies. Container
checks and raw/VHDX equality do not prove that missing source sectors were
recovered. Use NTFS allocation and MFT runlists to determine affected files
where those structures can themselves be verified.
