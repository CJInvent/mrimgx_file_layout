# Validation record

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
