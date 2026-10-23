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

After an interrupted run, also supply `--resume-run PREVIOUS_OUTPUT` and a
`--mapping-directory` from a successfully completed stage in that run. Supply
the same source, baseline, manifest, plan, evidence, MFT and inventory paths.
The tool retains completed external candidates and supplemental slice requests,
repeats the enabled discovery stages to convergence, and independently validates
every checkpoint addition against the previous run's original mapping base.
Incomplete stage outputs are excluded. Use a new output directory; the previous
run and its incomplete audit remain preserved. Resume does not imply the prior
run completed or that checkpoint proposals were already validated.

Each discovery round also revisits nonresident NTFS attribute lists through the
current recovered overlay. Restoring an attribute-list frame can reveal DATA or
directory extents absent from the initial inventory. These newly visible files
join the normal hash, format and runlist searches automatically; the original
inventory and cached MFT remain unchanged.

The Appx stage also reads original `AppxSignature.p7x` records and verifies their
CMS signatures with Windows CryptoAPI. Signed AXBM, AXCI and AXCT hashes can
rescue missing block maps, code-integrity catalogs and content-type files. Only
their verified file slices are placed; surrounding source bytes stay unresolved.
Recovered block maps can then unlock more Appx file-block matches. Before those
matches authorize writes, independent checks repeat the package signature,
original file/path/sequence binding, source-piece reconstruction, XML block hash
and NTFS runlist projection. No certificate-chain trust claim is made.

The `ntfs-metadata` stage also handles security indexes that carry no filename
parent references. It cross-checks multiple original `$SDS` descriptors and their
hashes against `$Secure` index entries and named-index runlists. Parentless
directory pages can be located by an exact original `$LogFile` LSN, including
bounded multi-page transactions, only when the current directory sequence,
index VCN and runlist independently agree with the logged physical address.
This reads transaction data without replaying it. Unsupported log versions,
missing original log bytes, reused directory records and conflicting addresses
remain explicit rejections.

After refinement, the tool independently redecodes every declared source frame
or supplemental slice and compares it byte-for-byte with the actual VHDX
destination. `placed-content-validation/summary.json` and `range-checks.jsonl`
record all checks. Baseline extent preservation and container checks remain
separate stages.

The `indexed-donors` stage can reconstruct a complete missing indexed frame
from slices of other intact source packets, including packets already used by
native conversion. Matching filenames, sizes or ZIP member metadata nominate
donors; only the full original target index MD5 authorizes the exact original
physical address. Independent validation rereads the raw index entry and all
source packets. Cached reconstructed bodies never authorize placement. Proven
frames are materialized in the working clone before later searches and count
toward convergence, so they can unlock additional hash and metadata recovery.

`orphan-bit-repair` additionally checks undecodable orphan packets against the
entire surviving unplaced original hash set. It does not require the damaged
index's source pointer to identify the packet. A raw residual scan also finds
Zstandard magic damaged by one bit, excluding all already decoded packet spans.
Supported packet boundaries are parsed from block headers; the native helper
tests every encoded bit and requires a complete original target MD5 match.
Boundary failures, absent hashes and complete negative searches are retained
in per-candidate JSON and audit events. A positive result is independently
checked as an original-index reconstruction, including its exact one-bit
source derivative; the source packet itself remains unchanged. This covers
single-bit damage within supported boundaries, not arbitrary multi-bit damage.
The helper also accepts `@digest_list.txt` instead of one MD5 for reusable
batch testing. The decoded size remains a required explicit bound.

`native-baseline-validation` reads every incorporated native block back from
the baseline and checks its recorded digest. An optional
`--reuse-baseline-validation SUMMARY_JSON` accepts a previous successful proof
only for identical source/baseline paths, sizes and write times, source plan and
verifier code. Every declared added range still gets fresh source readback.

The ZIP stage also exports members of affected archives under
`recovered_files/archive-members`, using generated filenames and JSON sidecars.
Single-disk ZIP64 directories are parsed with known original locator/end-record
bounds and agreement of legacy and 64-bit metadata. The same checks serve
indexed-donor nomination and ZIP reconstruction; original CRC evidence remains
required for filesystem placement.
Stored and raw-deflate members are decoded independently; a bad member does
not stop later members. Unknown compressed bytes stop decoding immediately.
CRC-valid members, CRC-failing output and incomplete decoded prefixes carry
distinct validation metadata. Original member names, CRCs, sizes, source
archive record/sequence/path and compressed offsets remain auditable; none
of these extracted files is inserted into the VHDX. Defaults bound output to
16 GiB per member and 256 GiB overall; bound hits and unsupported/encrypted
members are logged. Exact source frame hashes do not guarantee that the
original archive itself was valid; pre-existing CRC errors remain explicit.

When an original directory is unreadable, a bounded local-header scan can
nominate additional members. Complete CRC/size/deflate checks and known source
bytes remain mandatory for a valid decoded record. Sidecars explicitly retain
unproven original active-directory membership; these candidates never authorize
VHDX insertion. Unknown compressed bytes preserve only a decoded prefix, while
encrypted members and descriptor-based local records are reported as skipped.
The default local-header scan bound is 256 MiB per archive and bound hits are logged.

Archive export also inspects known original file headers and the bounded end-record
region of affected streams, regardless of filename extension. This includes XLSB,
self-extracting installers and appended ZIP metadata in otherwise unrelated file
types. Unknown placeholders never nominate content. Classic prefixed ZIP directories
can be read using the adjustment derived from the original end record, with directory
and local-header bounds checked against the original stream. This permits member
export from known trailing overlays as well, such as an installer's certificate
after the ZIP end record; this does not establish certificate trust. End-record
discovery remains bounded to the final 65,557 bytes. This permits member
export and original-index-MD5 donor nomination; the ZIP placement stage still requires
its stricter original file-boundary and independent crossing-CRC proofs. Executable
stubs and recovered programs are never launched. Detection and per-member metadata
record whether the archive was nominated by suffix or known source content.

The external residual export also probes cluster-aligned LZNT1 sequences with
the bounded Windows decoder. Sixteen individually checked complete chunks can
be preserved as a decoded 64 KiB fragment with source packet, compressed offset,
encoded hash and uncertainty metadata. Embedded files are passed through the
same internally checked file carvers. Compression syntax alone never proves
an original file, compression-unit start, logical offset or filesystem address;
these fragments remain outside the VHDX under `compressed-fragments`.
Recovered gzip logs also receive possible original path nominations when their
complete encoded size and embedded start timestamp agree with original MFT
filenames. Sidecars retain record/sequence, original affected ranges and the
MFT-record fingerprint. Missing process identity and historical file digests
remain explicit; these nominations never authorize a VHDX placement.

Exit 0 means a complete baseline manifest contained no recovery substitutions.
Exit 2 means a forensic partial rebuild/search completed with explicit remaining
uncertainty; inspect stage failures and search bounds. Fatal errors return a
nonzero failure and never create a successful completion report.

## Audit logs

Inventory refresh reads newly available NTFS attribute lists through the current
source-backed overlay, while retaining the original corruption ranges for
discovery. A record whose hidden data run is now fully repaired remains in the
affected-file inventory and member-export audit on resumed runs.

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
