# Validation record

## Opt-in forensic rebuild

The rebuild is tested separately from native conversion. The frozen forensic
iteration at `27d15bd16ec88bdfdae0d45fd1f22004a02f64f7` passes **100 forensic
tests and 10 native integration tests, with no skips**, on Windows. Its
[Windows CI run](https://github.com/CJInvent/mrimgx_file_layout/actions/runs/40029626768)
also passed. Full-image acceptance of this iteration is still running; these
test counts do not imply that acceptance has finished.

Earlier full-image validation independently accepted 6,444 full-frame mappings
and 31 supplemental destinations. Fresh source decompression and VHDX readback
matched **6,475 ranges / 919,688,460 bytes**, with no failed ranges. The checks
also covered the original source index, native block digests, preservation of
baseline extents, normal NTFS paths, and QEMU container validation. All protected
source, baseline and evidence inputs remained unchanged. Three separate native
conversions were completed; an independent baseline readback checked 1,114,333
original blocks / 158,992,117,760 bytes without a digest failure.

The subsequent inventory-retention iteration also passed complete independent
acceptance, including all 35 outputs of an archive whose missing data had already
been repaired. Its export covered 190 archives, with 6,124 CRC-valid members and
56 uncertain outputs; no operational errors or emitted search-limit warnings
were recorded. Uncertain outputs remain explicitly marked.

Recovery methods include original catalog/manifest hashes and historical
bindings, surviving-byte and runlist constraints, FAT directory and signed PE
evidence, Appx signed block-map hashes, corroborated NTFS metadata, and original
source-index digests for reconstructed donor frames. Proposals are independently
validated before placement. A fresh discovery run receives no previous positive
mapping results or private acceptance references. Iteration continues because
one method can restore the surviving bytes needed by a later pass.

The latest archive improvements were additionally exercised against original
source-backed streams: Python's independent ZIP reader verified 20 ZIP64
directories and 170 members, while fresh compressed-byte/CRC checks verified 17
local Office members and two uncertain prefixes. These are external exports;
local headers alone do not prove historical active directory membership or
authorize filesystem placement. The production implementation receives no
private filenames, record numbers or expected-content lists from these checks.

Further content-based discovery found archive containers outside the suffix
filter. Independent original-header, compressed-byte and standard ZIP-reader
checks verified another 97 CRC-valid members and three uncertain outputs,
400,657,254 bytes in total, from XLSB, an executable wrapper and appended model
metadata. The expanded forensic suite passes 104 tests without skips. Complete
full-image acceptance of these latest changes is pending.

Complete files whose locations remain uncertain, partial files, compressed
fragments and unplaced frames remain under `recovered_files` with JSON metadata.
Original archive CRC failures remain explicitly recorded. `audit-summary.log`,
`audit-summary.json`, `audit-errors.jsonl`, per-member records and stage logs
retain errors, warnings, rejected probes, and effective search bounds.

This source exercises an unencrypted, unsplit full image with FAT and NTFS,
4 KiB clusters and 143,360-byte indexed frames. Unsupported layouts are not
silently treated as recovered. Neither convergence nor a valid VHDX establishes
bootability, file-format validity of every original file, or universal
unmappability of residual data. Source-specific images and private validation
references are retained locally and are excluded from this repository.

## Earlier native conversion validation

The recovery implementation completed a full-disk export using the sparse raw
writer followed by QEMU VHDX conversion. Independent VHDX/NTFS readers resolved
a known file through its normal directory path and matched its previously
verified contents. Source-specific images, plans, filenames, and manifests are
not included in this repository.

The earlier offline build passed all eight demo-image integration tests. Its
control VHDX passed QEMU checks and matched the raw intermediate. The direct
writer's control VHDX also passed QEMU checks and matched the converted control.
Its boundary harness passed writes crossing 2 MiB payload and 4 GiB BAT-chunk
boundaries, plus untouched-zero and out-of-bounds checks.

A later redirected-output test exposed an upstream uninitialized console-size
bug. The source now checks the console API result and uses a bounded fallback.
The final source compiles with MSVC 14.44 x64. Local execution was blocked by
WinError 5 (Access denied), affecting both the rebuilt converter and QEMU.
Independent Windows CI then built commit `cd92823` and **passed all eight
integration tests**, including redirected strict output. The successful run and
its compiled executable artifact are available at:
https://github.com/CJInvent/mrimgx_file_layout/actions/runs/39610668471

The full recovered artifact separately passed read-only checks of both VHDX
header and region-table CRC32Cs, payload BAT states, file bounds and overlapping
payload allocations. These checks validate container structure, not missing
source contents. The converter correctly returned partial-recovery status.
