# Macrium image recovery diagnostics

This fork of [Macrium's image-format reference and converter](https://github.com/macrium/mrimgx_file_layout)
adds explicit recovery plans for damaged indexes, detailed hash/read diagnostics,
offline full-size VHDX export, and manifests that distinguish verified,
reconstructed and missing data. It never modifies the source backup.

Normal conversion remains strict. Partial recovery is opt-in and returns exit
code 2; a full-size output is not a guarantee that all original data survived.

- [Build, recovery-plan workflow and validation instructions](RECOVERY.md)
- [Opt-in automated rebuild and external recovered_files export](REBUILD.md)
- [Test results and limitations](VALIDATION.md)
- [Windows CI and executable artifacts](https://github.com/CJInvent/mrimgx_file_layout/actions/workflows/recovery.yml)

Recovery plans currently support one unencrypted, unsplit full image containing
one disk. Forensic offsets must be established from the actual source and
corroborated independently. User images and source-specific recovery plans are
not included in this repository.
