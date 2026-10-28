# Independent narrow review: final c002 consumer, 0ed32043

## Conclusions

**PASS: exact four-package consumer identity and independence from the two public index/source sidecars.** This conclusion supports retiring Release asset IDs `653244600` and `653251914` after integration of this reviewed consumer source and the publisher's separately reviewed evidence-reference contract. It is not App/runtime acceptance or permission to perform remote writes.

**Known P2 integration blocker remains in this frozen tree:** `scripts/assert-pc-runtime-release.mjs:72` unconditionally rejects desktopRelease. The selected formal source therefore cannot pass that existing source-first entry. The final docs paragraph saying an “actual App acceptance contract” is required must not be interpreted as an existing fillable receipt. Root and author have already isolated a follow-on guard/tests delta; review that delta before treating the combined batch as publication-ready. This does not restore either public-sidecar dependency and does not invalidate the transport conclusion above.

No other P1/P2 found in the 26-path increment relative to the previously reviewed d1ef tree. Earlier source/identity/lifecycle review remains applicable to unchanged code.

## Exact frozen source

- Base commit `174f97c9ab2ec8e551f89951aad0a44f95631071`, tree `48b260c892517b4bb0dad4e9cdbe1dd46dbe4e00`.
- Prior reviewed tree `d1ef3cd95952b6b7cb3a273a0db01fd965c2082a`.
- Current tree `0ed32043ebf8dbf2a6430bb05357e4b8ceff312c`.
- Full manifest SHA256 `ddc947d11cbe8ae42b73465fe9782be6a258f5c6992dd943b8c02d1223f06a43`; incremental manifest `dc6bba0f881b003b3e95b34a5f4cb21dc665318255318e2f546d83110435702c`.
- Independently hashed all 2576 worktree leaves/Git blobs, reconstructed the exact tree, verified all 43 frozen changed paths and original baseline bytes, and compared both complete and incremental diff bytes to Git objects. Two JSON files added; no deletion.

## Consumer and asset identity

Current desktopRelease binds c002/tree cf520419, tag object a85a533, Release `416392475`, producer `39116499788` attempt 1. Canonical contract SHA256 is `c8230c97b5e2c8ccdcdebc29cf08dd2ade302e48b5ec6d77a3d726a452edcec2`. Historical fe182 and 577d evidence stays separately retained; no dual active temporary/formal selection. The historical 577d contract retains its original exact bytes/hash.

Independently read and hashed all four cached original packages and compared their original IDs/names/lengths/digests with the saved Release API snapshot; independently ran the actual strict archive verifier for each and checked each extracted core digest against the canonical contract:

- Linux asset `653246529`: package SHA256 `51019c0cacd636295f540ec33d2a2dfced984178960ad1eb0e34778af947c0a2`.
- Windows asset `653248759`: `05b4ae42d8b029f29f431cc5ebd4fff6ee78a76e638e37643236a8a516b053ba`.
- Intel macOS asset `653246026`: `a70a6a0905af899ee326cabb77f51da0026d233df8627b706c7467c137162304`.
- ARM macOS asset `653246095`: `ef6696a0f94266c1262ac4447c931b896e5420156216e67bfdbc5617d4024c4d`.

Strict metadata verifier code is unchanged. Reviewed actual metadata evidence reports all four byte/header/Go BuildInfo/module/source/tag checks and actual empty BuildID comparisons passing using complete official Go 1.27.2 GOROOT. The earlier partial-GOROOT tool failure is corrected environment evidence; there is no fallback verifier in this increment. Those metadata observations were reviewed rather than re-executed here. Native macOS signature observation and target code execution are not claimed.

## Public-sidecar retirement proof

The entire original 6,519,600-byte native index is committed at the fixed `scripts/desktop-core/release-asset-index.json` path and is byte-identical to the producer material, SHA256 `3b8d8db9ee9261ec7bf724ea7877544a0252a848da663b4706d457cf93c8b391`. Hash/size/schema/selected original row validation remains mandatory. No environment path, new credentials or cross-repository Actions download replaces it.

The source URL fixes the c002 commit in the existing GitHub archive route. Its actual automatic archive is 8,078,155 bytes, SHA256 `b0f0a3b85affa1cbc6d54cada961cd871f0e48ac982af52e0b898d23ea12e02f`; the old custom producer tar hash remains a separate provenance field. The archive verifier reconstructs the complete expected Git tree with the three separately pinned gitlinks and verifies source/module/replacement policy and all 762 legal files. Credential forwarding and redirect checks remain constrained to existing trusted routes.

The active public-asset requirement contains only the four original desktop packages. Both load and consumption use the committed index; source acquisition uses the fixed automatic archive. Neither retiring public asset ID is needed for fresh consumption, source validation or installed legal/provenance payloads. Original source/index audit copies must remain retained; removing public hosting is not removal of evidence.

## Check-only and Windows boundaries

The new private c002 row pins actual Linux ELF `b754ac8223b27f4c20b40ced82d9ad5d58fee8fb4c5bfa48c38566e805c570ae` and the exact compiled source/contract pair to existing PlainTcpCheckV1. It expressly labels runtime evidence pending. Existing seals, config whitelist, budgets, cleanup, helper launch, wire protocol and closed managed-launch path remain unchanged. Arbitrary caller/environment hashes cannot admit identities. Prior fe182 runtime evidence is not transferred.

Windows directory tests take flags from the exact clean selected source's regular release/LDFLAGS, preserve selected tags/version and source/compiler identity, and record directory-test-only provenance. No package buildCommand is fabricated, and existing SYSTEM/event scope is unchanged. PowerShell execution was not performed here.

## Verification and remaining boundaries

Independent runs: 158 selected Node tests passed; 8 Windows-toolchain tests passed; 8 check-identity source assertions passed; 4 real strict package archive validations passed. Source-transport specialist independently ran 7 source-archive controls and 27 upstream-release tests, all passed. It also verified the actual automatic source through the real Python verifier, rejected seven altered-source/tree/gitlink/legal/producer-tar substitutions, and exercised consumeRelease with only the four package assets advertised: 14 mocked metadata/source reads reached the native-package boundary with no public index/custom-source request; failure cleanup removed the lock. These are offline/source/static proofs, not product execution.

Remaining App validation follows the existing DAG: Linux Test must produce its own c002 sealed/runtime evidence; existing native carrier/helper/cleaner/lifecycle/package/signature gates remain in force. Mobile requires its existing compile/ABI/component receipts; ARM cross-compilation and Apple compile-only without IPA remain acceptable within the user's stated scope. Hardware execution not covered here is disclosed, not converted into a new mandatory task. AppAccepted remains false.

Next: narrowly review the known source-first guard delta, then let the publisher add exact reviewed report references and clear only the two named deferrals. Fresh same-publisher-revision inventory, successful recovery preparation, existing authorization/environment gates and final 168-asset readback are still required for reconciliation.
