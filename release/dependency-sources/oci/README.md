# Fixed OCI source acquisition and notice materials

These records bind Docker run39024373945 attempt1, source68ffb209ded1f9337f9115741cba24f9f4c63421, all9 exact OCI payloads. Read oci-source-notice-map.json for per-image installed package identities, their original license expressions, origin and exact aports commit. The shared aports directory preserves the complete selected package directories, including target configs, patches and installation scripts. Each file was independently Git-blob verified;236 source-list local entries also matched APKBUILD SHA512.

source-acquisition.json records all38 distinct external source inputs: full HTTP GET, bytes, SHA256, and SHA512 matching each exact APKBUILD. Retrieve the recorded official Alpine distfiles URL, verify SHA512 before use, and apply only the matching retained APKBUILD/patch/config sequence. Bash/readline patch-series inputs and Alpine-baselayout netbase data are included, not just main tarballs. No APKBUILD or source code was executed by this audit. Build dependencies and target-specific build options are in the exact recipes; compilers/SDK binaries are not asserted to be redistributable payload.

Source archive bytes are not duplicated here: fixed verified public acquisition plus local retained recipes/notices is the proposed shared delivery. Their availability was checked2026-10-17; distribution must keep the mappings accessible with actual binary assets. New runs must regenerate real base/package bindings; these nine immutable OCI archives must not be relabeled as new source. The exact GPL/MIT/MPL/LGPL and other package expressions remain as recorded, not flattened to a blanket image license. This is engineering evidence, not legal certification.

All299 original Git modes are now independently verified. Three entries are mode120000 symlink blobs (bash post-upgrade twice and alpine-baselayout post-upgrade once); this materials tree deliberately stores their literal target bytes as source evidence, and the mapping records target/mode. Restore modes from this mapping or acquire the original exact Git checkout before building; do not execute these blob snapshots directly.

## alpha.12.2 exact publisher selection

`selections/39887556943-attempt1/selection-manifest.json` binds product
`c6c0d8b3b83ab4d6e7b953dd2dbdb7efe6f8021a`, tree
`32c0e3d8c59ad5e41f5ccdbc68e14a644b503e94`, annotated tag
`v1.15.0-polaris-alpha.12.2` / `db094db3498ea6982ccc601289acbd0c8adcecac`,
and Docker run `39887556943` attempt `1`. Its nine API/archive/image/core
identities and current native-index/source-archive anchors are separate from
historical dependency materials; no old producer receipt is relabelled.

All nine base dependency and repository identities match the original
`supplements/39791192772-attempt1` directory.
Of 243 installed seven-field package associations, 241 reuse that immutable
material closure. Only loong64 `libncursesw` and `ncurses-terminfo-base` changed
to `6.6_p20261017-r0`, recipe commit
`8b3f794ac226c47c66f0900fa1cd44f8d2c4e116`. The current selection includes the
two original recipe files, SHA512-verified original ncurses source archive,
GET evidence and eight unmodified copyright/license-text members. The original
53-file supplement remains unchanged. The current audit bundle contains those
53 files plus the 20 current selection files (73 total), each at its original
repository path. Source acquisition is evidence of retrieved bytes, not a
legal certification or a new license acceptance.

The publisher uses a finite two-selection registry, with no guessed or
permissive selection fallback. It still validates actual OCI descriptors,
provenance, ordered layer replacement, packages, core and native source bytes.
The first diagnostic extraction incorrectly selected a base-layer installed
database for five architectures; its 188-package summary is not accepted.
The final reviewed identities use the last effective installed database in
manifest layer order, with protected-path/whiteout checks retained.

Run the existing publisher contract gate (`test_github_release.py`, which
imports the current registry regressions) and `test_oci_material_reuse.py`.
Publishing remains a separate inventory/validate/publish operation at one
reviewed publisher revision. These materials do not assert that publication,
store signing, notarization, registry push or deployment has occurred.
