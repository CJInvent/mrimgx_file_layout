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

The default stages include original/partial index hashes, NTFS directory VCNs
and fixups, Chromium key identities, Appx hashes, cabinet checksums and complete
folder decompression, embedded PE digests, exact duplicate slices, original PDF
cross-reference offsets, Chakra self-offsets, SQLite WAL rolling checksums, ESE
page checksums and addresses, FAT directories/chains/duplicates, joint FAT/NTFS
PE completion, PNG CRC/zlib/scanlines, MSI original file hashes and signed catalog
member hashes. Chakra records and duplicate donors are discovered automatically.
Source order can nominate combinations only; it never authorizes a placement.

Optional `--metadata-identity` enables the weaker, separately labeled duplicate
inference using matching original filename, size and exact modification time.
Catalog completions require distinctive surviving bytes and a unique candidate;
catalog content/signature validation does not itself prove a historical installed
component version or certificate trust. Evidence retains this distinction.

## Outputs and placement rules

The original baseline stays unchanged. `rebuilt.vhdx` is a new sparse clone.
Only accepted, nonconflicting source-frame mappings go into it. Every source
frame and previous placement is checked before writing, then independently
read back. The baseline preservation proof checks copied allocated bytes while
normalizing only journaled mutations. QEMU also checks the resulting container.
These checks do not assert a complete or bootable filesystem.

`recovered_files` is a real directory outside the VHDX:

- `files`: bounded PNG, JPEG, gzip, ZIP, signed PE, PDF and RIFF file candidates, with
  format-specific validation and a `.json` sidecar per file. Files with unknown
  original placement remain here even when internally valid.
- `fragments`: every location-unresolved decoded frame, with its own JSON
  sidecar. Partial files and unrecognized formats are preserved as fragments.
- `index.jsonl`: frame provenance and disposition.
- `metadata-enrichment.json`: count of files with candidate NTFS metadata.

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

Current mapping stages support one unencrypted, unsplit full image, the tested
FAT EFI partition at index 0, and Windows NTFS at index 2 with 4096-byte clusters
and 143360-byte frames. Other geometry is rejected, not treated as tested support.
Compressed/sparse NTFS duplicate streams remain unsupported. Carving cannot
promise recovery of all files or original names; missing address evidence stays
explicit and all residual bytes remain available for improved methods.
