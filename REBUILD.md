# Opt-in forensic rebuild

Normal conversion remains strict. To opt into offline rebuilding after corruption:

```bat
python -m pip install -r tools\requirements-forensic.txt
build\img_to_vhdx.exe --rebuild backup.mrimgx --output rebuilt --qemu-img C:\tools\qemu-img.exe --seven-zip "C:\Program Files\7-Zip\7z.exe"
```

Use `--python C:\path\python.exe` to select the interpreter. Keep the bundled
`tools` directory beside the executable or one directory above it, as in the
repository and CI artifact. Rebuild uses Python parsers and Windows metadata
APIs alongside the native converter; it is not a dependency-free executable.

The source is read-only. Output must be a new directory. The workflow discovers
candidate index arrays from verified root geometry, metadata boundaries,
neighboring containers and sampled original decoded hashes. A missing NTFS boot
frame requires unique BPB/root-geometry/MFT-address agreement and readable MFT
record zero. Ambiguous discovery stops instead of substituting offsets. Native
conversion subsequently verifies every surviving index entry, not just samples.
An existing fingerprinted `--plan plan.json` can replace discovery.

The workflow creates a baseline, preserves residual encoded bytes and metadata,
builds an MFT cache and affected-file inventory, then runs recovery methods until
a complete round produces no additional placements. Each stage has a log and
machine-readable status. It retries methods because new directories, files and
package metadata can expose more constraints. `--rounds N`, `--stages LIST` and
`--per-file-budget N` make bounds explicit; exhausted bounds are not proof that
remaining data is unmappable. Stage failures remain in `summary.json` and are
never described as successful exhaustive analysis.

Before filesystem searches, `residual-audit` retries incremental decoding and
scans raw residual/metadata regions for fixup-valid NTFS records. `bit-repair`
tests single encoded-bit changes against surviving original index MD5 values,
using up to eight native workers and retaining per-frame progress logs. These
stages run by default. `--bit-repair-exe` selects a different repair executable.
Validated index repairs go only into the derived clone, before preparing its MFT;
a separate analysis manifest makes those proven ranges available to later stages.
The original baseline manifest remains the write/preservation authority.
Raw Zstd blocks reuse MD5 prefix states while still testing every encoded bit;
header, compressed-block and checksum cases retain full decoder checks. The
standalone bit-repair tool accepts `--reuse-negative-attempts DIRECTORY` only
when a completed zero-match result records the same original MD5, decoded
length, exhaustive encoded-byte count, and byte-identical original encoded input.
The rebuild wrapper exposes this as `--reuse-bit-negative-attempts DIRECTORY`;
cache paths, digests and reused/new test counts remain in the audit.

The default stages include original/partial index hashes, NTFS directory VCNs
and fixups, Chromium key identities, Appx hashes, cabinet checksums and complete
folder decompression, embedded PE digests, exact duplicate slices, original PDF
cross-reference offsets, Chakra self-offsets, SQLite WAL rolling checksums, ESE
page checksums and addresses, FAT directories/chains/duplicates, joint FAT/NTFS
PE completion, PNG CRC/zlib/scanlines, MSI original file hashes and signed catalog
member hashes. Chakra records and duplicate donors are discovered automatically.
Chromium body completion additionally checks original key identity and stream
CRCs, requiring two crossing CRCs or nested checksum/hash evidence; a single
CRC32 match is insufficient. MFT inventory respects a readable allocation bitmap.
The `zip-files` stage reconstructs one-hole ZIP and Office archive candidates,
requiring original file boundaries and decompression/CRC checks of every member
within expansion bounds. It records which checksums actually survived in original
local headers or the complete surviving central directory. VHDX insertion
requires the complete original central directory to survive, so every member's
CRC and identity are original. A unique candidate with two distinct original
CRCs covering separate missing member bodies (at
least 256 bytes each), plus a unique distinctive full-frame boundary, can be
placed after independent overlay validation. Other candidates remain external;
newly supplied internal CRCs alone never authorize VHDX insertion.
Source order can nominate combinations only; it never authorizes a placement.
MFT nomination scans restore and validate sector update-sequence fixups before
reading filenames or sizes. A sector-trailer stamp must not turn an ordinary
installer/catalog size into an enormous value and silently exclude it.
Competing Chromium/Appx/PE frame candidates are checked against the union of
their bounded original file constraints. Resolution requires one content
digest satisfying every constraint from at least two independent NTFS records;
votes, repeated small icons and source ordering cannot choose a whole frame.
Unavailable or contradictory constraints preserve the ambiguity. The original
proposals and a separate `anchor-consensus.json` report remain available.
Managed satellite resource DLL anchors also require their parsed .NET assembly
name and culture to match the original filename and culture directory. Matching
filename, size, version and a self-consistent signed image digest do not establish
the original language variant by themselves. Parsing never loads the assembly.
Chakra discovery also tests shorter arrays of at least three descending child
pointers, retaining the requirement for two disjoint arrays agreeing on an
address and surviving body masks.
The `metadata-rescue` stage also preserves complete file data behind malformed
UTF-16 filenames outside the image. It keeps original filename bytes, record
references, runlists and matching surviving directory names in JSON. Only a
private parser copy substitutes unpaired surrogate code units; no filesystem
metadata is rewritten. Extension records, attribute lists and incomplete data
remain outside this bounded fallback.
Whole-file hash searches export matching complete files even when a small or
repetitive file cannot establish its entire enclosing frame's placement. These
exports retain package/hash evidence, candidate NTFS paths/runlists and exact
source-frame provenance; the surrounding frame stays unplaced unless separately
validated.
Residual PE carving can also use surviving signature-checked catalog image
digests to rescue complete unsigned DLL/MUI candidates. It records excluded PE
fields and catalog filename hints separately from whole-file and historical
placement proof, and keeps these files outside the VHDX.
The `manifest-hashes` stage reads intact original component manifests, requires
their assembly identity to match the original component directory, and uses
only explicit Identity-transform whole-file hashes. Unknown/reconstructed
manifest bytes cannot authorize another placement. Independently validated
file slices can restore a small file without placing unrelated enclosing bytes.
Component hashes authorize full frames only when their entire contents lie
inside the validated file; other boundaries are restored as file slices.
SHA-256 file matches may stop further file-hash probes; every corpus frame is
still checked for equivalent file boundary bytes before any full-frame placement.

Optional `--metadata-identity` enables the weaker, separately labeled duplicate
inference using matching original filename, size and exact modification time.
Catalog completions require distinctive surviving bytes and a unique candidate;
catalog content/signature validation does not itself prove a historical installed
component version or certificate trust. Evidence retains this distinction.
Catalog searches also try bounded source-sequence combinations for files with
two through eight missing frames. Complete digest matches from that broader
search are exported as candidates, because a bounded search against multiple
catalog versions cannot establish unique historical placement.
An INF candidate can be promoted when its complete surviving original `[Version]`
section names a readable catalog in its original NTFS directory, and that freshly
signature-hash-checked catalog has one unambiguous digest for the original filename
in its `File` member attribute. This binds an original whole-file hash. Source
pieces and all surviving bytes are rechecked; enclosing frame boundaries must
also be unique and distinctive, otherwise only the proven file slices qualify.

## Outputs and placement rules

The original baseline stays unchanged. `rebuilt.vhdx` is a new sparse clone.
Only accepted, nonconflicting source-frame mappings and verified supplemental
file slices/index repairs go into it. Every source
frame and previous placement is checked before writing, then independently
read back. The baseline preservation proof checks copied allocated bytes while
normalizing only journaled mutations. QEMU also checks the resulting container.
These checks do not assert a complete or bootable filesystem.

When a catalog validates a complete file but cannot uniquely bind the enclosing
frame, the tool can restore just the validated missing file bytes at its original
MFT runlist positions. PE checksum/security/certificate exclusions are respected.
`supplemental-placements.json` records those exact byte ranges separately from
full-frame mappings. Other bytes in the enclosing frames stay unresolved and
remain exported; frame-level residual totals therefore include some proven slices.
Single-bit repairs retain the original encoded bytes and separate repaired
derivatives, and must reproduce the original indexed decoded length and MD5.

`recovered_files` is a real directory outside the VHDX:

- `files`: bounded PNG, JPEG, gzip, ZIP, signed PE, PDF and RIFF file candidates, with
  format-specific validation and a `.json` sidecar per file. Files with unknown
  original placement remain here even when internally valid.
- `fragments`: every location-unresolved decoded frame, with its own JSON
  sidecar. Partial files and unrecognized formats are preserved as fragments.
- `candidates`: reconstructed cache files passing their original CRC32 but
  lacking enough independent validation for VHDX insertion. Sidecars retain
  candidate paths/runlists, source frames and the additional validation needed.
- `index.jsonl`: frame provenance and disposition.
- `metadata-enrichment.json`: count of files with candidate NTFS metadata.
- `verified-supplemental-placements.json`: proven sub-frame ranges and index
  repairs, so retained enclosing fragments are not confused with wholly unknown data.
- `incomplete-decoding` and `indexed-bit-repair`: partial decode evidence and
  verified repaired frame derivatives, with provenance JSON.

Sidecars include SHA-256, byte length, source offset, frame offset, validation,
known embedded names, candidate original paths/MFT records/runlists, and explicit
placement uncertainty. Name/size candidates never authorize VHDX insertion.
Raw encoded failures, the encoded complement and original metadata are retained
separately as evidence. Exported fragment adjacency is never disk adjacency.

## Continue an existing investigation

Supply `--baseline`, `--manifest`, `--evidence`, `--mft`, `--inventory`, and
`--mapping-directory` to reuse existing read-only inputs. The plan/evidence
fingerprints must agree. `--search-only` produces mappings and `recovered_files`
without changing an image. To refine an existing derived clone, supply all four:
`--existing-clone`, `--clone-manifest`, `--previous-refinement`, and
`--previous-validation`. The original baseline is still required and unchanged.

Exit 0 means a complete baseline manifest contained no recovery substitutions.
Exit 2 means a forensic partial rebuild/search completed with explicit remaining
uncertainty; inspect stage failures and search bounds. Fatal errors return a
nonzero failure and never create a successful completion report.

## Audit logs

Every initialized run writes `audit-summary.log`, `audit-summary.json`,
`audit-events.jsonl`, and `audit-errors.jsonl`, including fatal discovery/startup
failures. Errors and warnings are appended immediately with tool, stage, file or
record context and traceback. Child-process failures retain their complete stage
logs. Effective arguments include each tool's default search bounds; source-code
and executable fingerprints detect program changes during a run.

Unreadable/unsupported records, operational failures, source corruption and
mapping conflicts remain distinguishable. Expected unsuccessful format/hash
probes are aggregated by exception class/message and source site, with exact
counts and examples; millions of normal nonmatches are not reported as millions
of missing files. `summary.json` links the consolidated audit and reports error
and warning totals. These logs make a partial result auditable; they never turn
bounded searches into proof that every remaining byte is unmappable.

For independent regression comparisons, `tools/compare_rebuild_results.py` reads
actual rebuilt VHDX ranges and recovered artifacts against separately supplied
reference results. References are post-run test inputs; they are never passed
to reconstruction. Matching bytes, audit status and absence of operational
errors are checked separately from mapping counts.

Current mapping stages support one unencrypted, unsplit full image, the tested
FAT EFI partition at index 0, and Windows NTFS at index 2 with 4096-byte clusters
and 143360-byte frames. Other geometry is rejected, not treated as tested support.
Compressed/sparse NTFS duplicate streams remain unsupported. Carving cannot
promise recovery of all files or original names; missing address evidence stays
explicit and all residual bytes remain available for improved methods.
