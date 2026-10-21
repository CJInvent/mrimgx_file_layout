# Forensic residual recovery

These tools extend explicit recovery without changing the original image,
baseline VHDX, recovery plan, or initial evidence. Outputs use new directories
and refuse replacement. They do not mount filesystems or execute recovered code.

Install Python dependencies with `pip install -r tools/requirements-forensic.txt`.
The VHDX clone and refinement workflow requires Windows. Most mapping tools
currently target a Windows NTFS partition at partition index 2, with 4096-byte
clusters and 143360-byte backup frames; inspect geometry before reuse.

## Workflow

1. Run `forensic_residuals.py SOURCE PLAN MANIFEST EVIDENCE`. It validates the
   plan against source metadata, accounts for incorporated encoded ranges,
   preserves their exact complement and the metadata tail, and catalogs bounded
   Zstandard frames and NTFS records. Coverage is not a historical I/O trace.
2. Run `map_orphan_frames.py SOURCE PLAN MANIFEST EVIDENCE BASELINE MFT OUTPUT`.
   Optional `--file-inventory INVENTORY --pe-anchors --appx-anchors` adds file
   evidence. The MFT cache and inventory must come from the matching baseline.
3. Extend the resulting mapping directory with `extend_appx_mappings.py` for
   hashes spanning known neighbors and newly readable package metadata;
   `extend_cab_mappings.py` for cabinet boundaries; and
   `extend_signed_pe_mappings.py` for a signed-image digest with one missing
   frame. Each tool's `--help` describes its positional inputs.
   `recover_pdf_xrefs.py` also places frames when multiple PDF object headers
   agree through original cross-reference offsets and NTFS physical extents.
   `recover_chakra_offsets.py --record MFT_RECORD` can use multiple independent
   absolute nested-function arrays in serialized Chakra bytecode. It parses the
   bytecode container without loading it into an engine or executing it.
4. `clone_sparse_file.py BASELINE CLONE COPY_LOG` creates an exclusive standalone
   sparse copy. Windows allocated extents retain original physical offsets.
   `refine_vhdx.py SOURCE BASELINE CLONE COPY_LOG BASELINE_MANIFEST MAPPINGS LOG`
   prevalidates all source frames and destinations before writing, patches only
   unresolved baseline ranges, and reads every placement back independently.
5. Run `verify_refined_clone.py BASELINE CLONE COPY_LOG LOG RESULT` to check every
   copied allocated byte against the copy hashes, normalizing only documented
   physical refinement writes from the unchanged baseline. Run `qemu-img check`
   and inspect known files through a read-only filesystem reader.
   To add further mappings, pass `--previous-refinement OLD_LOG` to refinement;
   all previous placements must remain identical. After an earlier full
   preservation check, verification can recheck additional mutations with
   `--previous-refinement OLD_LOG --previous-validation OLD_RESULT` and records
   a hash-linked preservation chain.
6. `export_unresolved.py EVIDENCE MAPPINGS OUTPUT` exports frames whose disk
   addresses remain unresolved, retaining duplicates and provenance. The initial
   evidence continues to preserve every raw residual byte, undecodable input,
   and metadata byte. Adjacent exported frames need not be adjacent on disk.
   `refinement_coverage.py SOURCE EVIDENCE MAPPINGS OUTPUT` additionally reconciles
   selected encoded source ranges and exports their exact remaining complement
   with original offsets and SHA-256 hashes. This accounting closes against the
   complete source length, including the separately retained metadata tail.

`measure_refinement.py` measures allocation and MFT runlist coverage. It does not
claim that filling every recorded missing range validates an entire file.
`inspect_residual_failures.py` retries decoding outside known frame intervals
and searches raw residuals and metadata for fixup-valid records. Nested Zstandard
magic is not an independent frame. `restore_incomplete_clone.py` can roll back
only journaled writes in an interrupted clone, using the read-only baseline;
complete a full clone-extent verification before delivering a retried output.

## Evidence and confidence

- Exact original MD5 matches identify original indexed content. Partial hashes
  require at least eight surviving nonzero bytes and agreeing address or length;
  they remain partial verification, not original full-hash verification.
- Directory mappings require valid NTFS fixups, parent record sequence/type,
  index VCN, physical runlist and frame alignment agreement.
- Chromium cache keys identify filenames via SHA-1, then original MFT runlists
  place their headers. Independent headers must agree on a frame address.
- AppxBlockMap SHA-256 matches identify file blocks and MFT physical extents.
  Cross-frame matches require known neighboring fragments. Package metadata is
  read from the source-derived filesystem, never fetched from another version.
- PE identities use original filename, exact file length and original MFT
  extents. A single PE anchor additionally requires its complete embedded image
  digest; otherwise multiple independent headers must agree. This checks content
  against the embedded Authenticode digest; it does not assert certificate trust.
- Cabinet boundary candidates require a known original CFDATA checksum and
  physical file extent. Every member in every touched compression folder must
  pass a complete 7-Zip decompression test. Unrelated pre-existing archive errors
  remain documented. CAB checksums are XOR, not cryptographic hashes.
- PDF mappings require original `startxref`/EOF and complete xref tables/streams,
  with multiple distinct object headers agreeing through NTFS file extents.
  Rebuilt cross-reference tables and signatures alone are not accepted.
- Chakra mappings require a matching container size/architecture, original MFT
  runlist, multiple independent self-addressing child-function arrays and body
  masks corroborated by surviving bytecode. Source ordering is not used.
- `extend_structured_files.py` requires three distinct complete CRC-checked
  PNG/gzip files and MFT sizes/addresses agreeing on a unique layout. Single
  signatures or file sizes never establish a placement.
- `recover_duplicate_files.py` takes explicit target/donor MFT record pairs.
  It requires equal sizes, an entirely covered donor and agreement of every
  surviving target byte before matching exact orphan SHA-256 file slices.
  Optional boundary recovery requires at least 32 KiB of varied matching bytes
  and exactly one decoded content candidate. It inserts the original orphan
  frame, including its original boundary bytes, never copied donor data.
  An explicit `--allow-metadata-duplicates` mode permits fewer than 4096
  surviving target bytes only with the same filename, size and exact original
  NTFS modification timestamp. Such identity inferences are separately labeled,
  require distinctive orphan bytes and remain weaker than an original digest.
  Large comparisons can stream in bounded chunks with `--stream-large-files`.
  Fragmented uncompressed file runlists are supported. Logical donor slices
  are assembled in physical frame order; every intersecting file extent must
  match. Compressed/sparse streams remain excluded.
  `--allow-partial-donor` can use intact portions of an otherwise incomplete
  donor. It compares only mutually known bytes and removes every unresolved
  donor span from candidate constraints. Its donor observation hash is explicitly
  labeled as incomplete; unknown donor placeholders never become recovery data.
- `discover_duplicate_pairs.py` nominates possible donors from raw cached MFT
  names and sizes, including renamed copies. Nominations alone authorize no
  recovery; the duplicate mapper validates the real records and content.
- `recover_sqlite_wal.py` uses surviving WAL header salts, multiple independently
  checked rolling checksum transitions and a unique file/frame grid position.
  WAL content is parsed without replaying transactions or opening recovered DBs.
- `recover_ese_pages.py` requires multiple full pages with valid four-part
  XOR/ECC checksums, matching embedded page addresses, unique affected-database
  runlist alignment and exact collective DBTIME/OBJID header maxima. Optional
  cross-boundary checks use previously known neighboring bytes. Database identity
  remains a structural inference; the page checksum itself does not identify
  the database. `ese_checksums.py` never corrects bytes and is tested against
  Microsoft's published 32 KiB page checksum vector (see `ESE-LICENSE.txt`).

Different decoded bytes at one destination are conflicts. Identical candidates
are duplicates. Ordinary surviving verified data is never replaced using weaker
structural evidence. Original-source MD5 absence remains explicit even when a
new mapping has strong file-content evidence. Source ordering alone never
establishes a disk address.

`safe_vhdx.py` bounds third-party VHDX reads at payload block boundaries, avoiding
incorrect physical continuation across BAT ZERO/absent blocks in affected Dissect
versions. Regression tests include nonzero physical neighbors across a zero
logical block, full byte comparison, and QEMU checks.

## Bounded bit repair

Build `build-frame-repair.cmd COMPILER_SETUP`. The resulting
`repair_frame_bits.exe ENCODED REPAIRED ORIGINAL_MD5 DECODED_LENGTH` exhaustively
tests each individual encoded-bit flip. It writes a new frame only when exactly
one candidate decodes to the original expected MD5. It never edits input and does
not substitute a newly calculated digest for missing original evidence. A failed
search excludes only this repair class, not all possible repairs.

## Tests and limits

Run `python tools/test_forensic.py`. Set `QEMU_IMG` to enable the Windows sparse
clone/refinement integration test and `FRAME_REPAIR_EXE` for native repair tests.
The original eight native recovery tests remain in `tools/test_recovery.py`.
Synthetic cases cover exact range complements, cross-window frame boundaries,
normalization of common digests, conflicting matches, partial-hash thresholds,
cross-frame SHA-256, cabinet checksum byte order, gzip CRC/truncation, source
preservation and all unchanged virtual bytes in a refined test disk.

No finite collection of mapping methods proves that remaining bytes are
unmappable by every future inference. Export dispositions say **unresolved by
implemented methods**. Preserve raw evidence for additional metadata, content
constraints, decompressor improvements and independently corroborated mappings.

Format references: [Chromium cache format](https://chromium.googlesource.com/chromium/src/+/master/net/disk_cache/simple/simple_entry_format.h),
[Chromium filename hashing](https://chromium.googlesource.com/chromium/src/+/master/net/disk_cache/simple/simple_util.cc),
[Microsoft cabinet specification](https://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/%5Bms-cab%5D.pdf).
[Chakra serialization implementation](https://github.com/chakra-core/ChakraCore/blob/master/lib/Runtime/ByteCode/ByteCodeSerializer.cpp).
