# Final c002 desktop consumer: frozen asset and transport increment

## Result and frozen identity

- App base: `174f97c9ab2ec8e551f89951aad0a44f95631071`, tree `48b260c892517b4bb0dad4e9cdbe1dd46dbe4e00`.
- Previously reviewed 30-path tree: `d1ef3cd95952b6b7cb3a273a0db01fd965c2082a`. Its report remains `/workspace/shared/review-formal-consumer-20261018/REVIEW.md`, SHA-256 `995d51b7a2586de164183e0df069dec88d2187b44c8de35daf8caf1405ca6ddb`.
- Final combined tree: `0ed32043ebf8dbf2a6430bb05357e4b8ceff312c`.
- Full delta versus main: 43 paths, including two added JSON files; 26 changed paths versus the reviewed tree; no deletions. All 2,576 leaves match the frozen tree. Historical local HEAD was not used as the baseline.
- Full manifest SHA-256: `ddc947d11cbe8ae42b73465fe9782be6a258f5c6992dd943b8c02d1223f06a43`.
- Incremental manifest SHA-256: `dc6bba0f881b003b3e95b34a5f4cb21dc665318255318e2f546d83110435702c`.
- Full leaf manifest SHA-256: `bd1fe38c752e2e42739edb5d980478b84a1d114745b12c155954ee3a3f18e5fc`.

Source is stopped. No commit, remote write, CI dispatch or target-kernel execution occurred. Current local source selects the actual c002 formal desktop release; App runtime/package acceptance is still unobserved.

## Actual selected identities

Repository `polaris-arch/sing-box-polaris`; source `c0023dbc6dcd7b6eb2f54dd036ae150168bd8e6e`; tree `cf520419eafa63bc789a67f12417b7a82e3d7bd9`; tag `v1.15.0-polaris-alpha.12`; annotated object `a85a5332432a92e1de502cfc9c680206371540b8`; public prerelease `416392475`; original All producer `39116499788`, attempt 1. The actual public publisher was `39119599342`.

The canonical contract is 3,902,818 bytes, SHA-256 `c8230c97b5e2c8ccdcdebc29cf08dd2ade302e48b5ec6d77a3d726a452edcec2`. `desktopRelease`, pending selection, bilingual NOTICE, updater selection and private c002 check admission agree with it. Original rows are unchanged; archive layout and public branding remain distinct. Historical 577d formal contract bytes are retained exactly in `historical-release-contract-577d4b9.json`; fe182 temporary contract/source evidence remains unchanged and explicitly historical.

| Platform | Public asset ID | Bytes | Original package SHA-256 |
| --- | ---: | ---: | --- |
| Linux amd64 | 653246529 | 32,630,733 | `51019c0cacd636295f540ec33d2a2dfced984178960ad1eb0e34778af947c0a2` |
| Windows amd64 | 653248759 | 33,831,400 | `05b4ae42d8b029f29f431cc5ebd4fff6ee78a76e638e37643236a8a516b053ba` |
| macOS amd64 | 653246026 | 32,431,849 | `a70a6a0905af899ee326cabb77f51da0026d233df8627b706c7467c137162304` |
| macOS arm64 | 653246095 | 29,953,454 | `ef6696a0f94266c1262ac4447c931b896e5420156216e67bfdbc5617d4024c4d` |

All four public ID/name/URL/size/digest facts match the original Actions index and cached fresh release API readback. The original packages were downloaded once, retained in `/workspace/shared/final-core-consumer-20261018/materials/desktop-cache`, and reverified through the original strict archive extractor. They were not repacked or rebuilt.

## Removal of the two internal public-sidecar dependencies

The explicit `committed-index-github-source-v1` material transport uses:

1. Entire original native index committed as `scripts/desktop-core/release-asset-index.json`: 6,519,600 bytes, SHA-256 `3b8d8db9ee9261ec7bf724ea7877544a0252a848da663b4706d457cf93c8b391`. Strict loading verifies its bytes/hash and source/tag/producer/legal/full selected rows. No Actions artifact credential, environment path or regenerated index substitutes for it.
2. Fixed automatic source URL: `https://github.com/polaris-arch/sing-box-polaris/archive/c0023dbc6dcd7b6eb2f54dd036ae150168bd8e6e.tar.gz`. Actual 8,078,155-byte transport SHA-256 is `b0f0a3b85affa1cbc6d54cada961cd871f0e48ac982af52e0b898d23ea12e02f`. Only its exact same-commit anonymous codeload redirect is allowed.
3. The existing source-archive validator proves the complete expanded tree `cf520419eafa63bc789a67f12417b7a82e3d7bd9`, module hashes, local replacements and reviewed Meta source policy. All 762 legal rows are compared to actual source files, including root LICENSE and release/licenses. Separately observed gitlinks remain: Android `ae93152f21457723af77d144f28c1f7be7362aec`; Apple `e232aaf22d6d68773196ffc8e6e79684a6be717c`; desktop `50f503849148dd73fa4f4bc231119acf5b2f3d7a`. Gitlink content is not falsely claimed as expanded source.
4. Original custom source tar remains separately pinned by `producerSourceArchive`: 7,996,159 bytes, SHA-256 `f0862fada6162401e059944a0e98129921ee28f16910f35205f774ada9e59f84`. Its old hash is never assigned to the different automatic archive.

`contractPublicAssets` now requires only the four package assets. Acquisition and installed-carrier revalidation use the new automatic archive, while original source/index/producer identities remain bound. Public repository/tag/release/producer/native jobs are still read back before and after acquisition. API credentials remain API-only; neither package/CDN nor source/codeload redirects receive Authorization.

This source no longer depends on release assets `653244600` (native index) or `653251914` (custom source). Their eventual deletion does not alter the four package pins. This report is evidence for independent review, not authorization to delete remote assets. No additional public readiness/provenance sidecar or new transport framework was created.

## Narrow code changes requiring review

- `upstream-release.mjs`, `release-consumer.mjs`, `release-archive.py`: explicit strict material-mode branch, committed index loading, fixed source URL/root, original-source separation, source legal-file checks, same-commit anonymous redirect. Legacy formal/temporary validation remains separately strict.
- Actual canonical contract/selection/NOTICE and exact historical archive file; historical fixture tests now explicitly use old evidence rather than implicitly treating it as the current default. Packaging inventory still rejects alias members, missing legal bytes and temporary-carrier relabels.
- Windows directory source-built tests: upstream rows do not contain `buildCommand`. The script now validates the selected formal contract, reads `release/LDFLAGS` from the clean exact selected source, preserves actual tags/version/SourceRevision and writes a scoped `directory-test-build-only` input record. It does not invent a package producer command. The exact Go toolchain resolver supports the true upstream row/source pair. SYSTEM/event/privilege conditions and actual protocol assertions remain unchanged.
- Same PlainTcpCheckV1 receives one private identity-data row for the exact c002 Linux ELF `b754ac8223b27f4c20b40ced82d9ad5d58fee8fb4c5bfa48c38566e805c570ae` and canonical contract digest. Its label says runtime evidence pending. Historical rows, execution/sealing/budgets/timeout/cleanup/config whitelist and closed managed-launch boundary remain unchanged. Source/contract/ELF substitution and arbitrary environment selectors are negative controls. Admission allows the existing Linux Test gate to collect evidence; it does not claim prior execution.

The previously reviewed compiled provider/helper/cleaner/default-resolver/ordinary workflow/mobile-input implementation is unchanged except the precise new identities and test migrations listed above. No new consumer, duplicated Rust/UI build commands or per-version execution type was introduced.

## Actual validation and limitations

- Focused Node union: **334 total, 333 passed, 0 failed, 1 existing opt-in tiny-Go fixture skipped**. Negative fixture traceback output is expected; final result is green. `final-focused-node.log`.
- Source archive: **7/7 passed**; Windows directory toolchain: **8/8 passed**. New Windows PowerShell recipe itself has source-contract controls but was not executed on Windows here.
- Private check source controls: **8/8 passed**, including exact historical row preservation and byte-identical execution/protection/selection/launch-boundary bodies versus d1ef. These are source checks, not Rust execution.
- All four actual cores passed unchanged byte/header/raw and parsed BuildInfo/module/source/tag checks and actual BuildID comparison. All four actual BuildIDs are empty strings. Linux/Windows Cronet static ABI checks passed. `final-material-validation.json`, `metadata-validation.json`, associated logs and scripts record exact paths/argv/results.
- Exact committed index, formal selector and bilingual NOTICE validation passed. This does not assert missing App resource installation or final carrier readiness.
- Official cargo 1.99.1 / rustfmt 1.10.0 ran whole-workspace formatting and fixed-point check. `cargo-fmt-all.log`; `git diff --check` passed.
- The previous mobile input tests and source readback are unchanged: 29 focused passes; full suite 301/302 with an existing AF_UNIX socket negative control blocked by sandbox EPERM. No skip, bypass, new permission or fictitious pass was added. The prior report remains the evidence for those unchanged paths.

### Go environment correction

Initial partial bin/tool extraction lacked the official builtin-tool source, so original `go tool buildid` reported no such tool. The initial report incorrectly treated this as a distribution/tool limitation. That report is preserved as `HISTORICAL-PARTIAL-GOROOT-REPORT.md`. Complete official GOROOT resolves it: Go's own tool command builds/runs its official builtin metadata tool, offline in the isolated cache. The original verifier succeeds unchanged; no fallback implementation remains. The earlier per-platform logs were refreshed with final observations, so the preserved historical report is the record of the initial failure, not a claim that original stderr files remain.

The reused official Go archive SHA-256 is `ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5`. `complete-metadata-tool-provenance.json` records official source/tool hashes and exact GOROOT/environment. Only this authorized official metadata-tool build occurred. No kernel, Cronet, product Go/SDK or Rust compilation/execution occurred.

## Real remaining gates and publication boundary

1. Existing package/ordinary CI/native four-host jobs must validate the actual c002 App carrier, true same-build helper/cleaner, native Mac signature observation, schema/config/dependency/wire/TLS/Cronet/API and lifecycle/stats behavior. They have not run on this tree. The sealed-check tests are in ordinary Linux `cargo test --workspace --no-fail-fast`; the crate-only four-host workflow does not replace the App sealed-check caller.
2. Source-only admission permits collecting c002 sealed evidence, including source replacement and closed standard-FD cases, while preserving required-core failure behavior. No fe182 result transfers to c002.
3. Mobile source/tool/ABI inputs are bound, but actual component/SDK receipts remain required through the existing App producer contract. All AAR/XCFramework filenames/hashes alone cannot prove DirectoryRetirementSourceIdentity, expected input-digest BuildID or App ABI/tool provenance. App/device/PacketTunnel acceptance remains separate.
4. Installer/package artifact creation is distinct from actual App public release/promotion. The unchanged `assertSourceFirstRelease` deliberately rejects any `desktopRelease` in the historical source-first publication clearance. Its existing release/promotion jobs therefore remain blocked for this selection. This is not an unknown runtime receipt field or a newly implemented acceptance schema. No publishing bypass was added. The frozen consumption-plan phrase “requires its actual App acceptance contract” should be read with this explicit qualification; the parent/reviewer were notified of that wording imprecision.

## Reproduction and cache handoff

`incremental-manifest.json` / `incremental.diff` cover only the 26 new paths versus d1ef. `manifest.json` / `changes.diff` cover the 43-path combined source versus main. `full-leaves.json` covers all 2,576 leaves; `changed-source.zip` contains only changed source; `freeze.py` uses a separate index and validates every leaf. No raw desktop package is duplicated in the source ZIP.

Actual material cache: `/workspace/shared/final-core-consumer-20261018/materials`. `DESKTOP-CACHE-INDEX.json` SHA-256 `5f5fb1308e71c17dec93cde0ea841d708ac5619b364a01bb2cb467aba555751e` enumerates exact reused files. `DESKTOP-VALIDATION-REPORT.md` is the focused transport/tool report. Test commands and remaining evidence boundaries are recorded in `TESTS.json`.
