# Polaris branded GitHub prerelease

## Exact release identity

Repository: `polaris-arch/sing-box-polaris` (1421657509).
Tag and title: `v1.15.0-polaris-alpha.12`.
Native/internal version: `1.15.0-polaris-alpha.12`.
Public asset filename version: `1.15.0-alpha.12` (remove only `-polaris` from the validated version).
Future accepted family: `MAJOR.MINOR.PATCH-polaris-{alpha,beta,rc}.NUMBER`, with no leading zero in NUMBER.
The GitHub-only publisher separately pins this exact release. It never creates or moves the source tag. Ordinary `publish` is create-only; the bounded replacement and metadata maintenance paths are described below.

The reference release `https://github.com/shtorm-7/sing-box-extended/releases/tag/v1.14.1-extended-2.7.2` has no explicit title. Its native archives use `sing-box-1.14.1-extended-2.7.2-*`, and its SFA/SFL/SFW filenames similarly carry the branded version. Polaris retains that branded version inside native archives and metadata. Public filenames instead follow the pinned SagerNet names with only the core product prefix changed; no archive is wrapped/repacked. The reference's additional compressed variants do not replace or reduce the pinned SagerNet matrix.

## Filenames and unchanged interfaces

The following names describe producer paths/archive identities. The public
GitHub filename is a separate mapping: core `sing-box` becomes
`sing-box-polaris`, SFA/SFI/SFL/SFM/SFW keep their original abbreviations, and
all versioned public names use the upstream version. Android application
`-unsigned.apk` becomes `.apk` only in the outer filename. The actual unsigned
state remains explicit in the Release body and audit metadata. The one public
Android metadata filename is `SFA-version-metadata.json`.

- All 44 CLI archives retain `sing-box-${VERSION}-${OS}-${ARCH}${VARIANT}.tar.gz` (Windows `.zip`) and the identical root. GOARM, softfloat, 386, libc and legacy suffixes remain exactly the upstream matrix. The executable remains `sing-box`/`sing-box.exe` and shared Cronet filenames remain unchanged.
- Linux packages retain `sing-box_${VERSION}_linux_${PACKAGE_ARCH}.{deb,rpm,pkg.tar.zst,apk}` and OpenWrt `sing-box_${VERSION}_openwrt_${ARCH}.{ipk,apk}`. Independent distro packages use `sing-box-polaris_${VERSION}_linux_${ARCH}.{deb,rpm}`.
- Android app names use `SFA-${VERSION}-...apk`; Windows uses `SFW-${VERSION}-{x64,x86,arm64}.exe`; Linux client packages use `SFL-${VERSION}-...`.
- Standalone macOS uses `SFM-${VERSION}-{Apple,Intel,Universal}.pkg` and `SFM-${VERSION}.dSYMs.zip`; jailbreak package names retain their upstream shape and full branded version. Unsigned Apple store archives are `unsigned-${VERSION}-{ios,macos,tvos}.xcarchive.tar`.
- Library transport names used between build jobs remain upstream-compatible. These internal audit transport names are retained without wrapping: `libbox-${VERSION}-android-${arch}.aar`, `libbox-legacy-${VERSION}-android-${arch}.aar`, `Libbox-${VERSION}-${slice}.tar`.
- OCI image exports are retained as audit/channel outputs named `sing-box-${VERSION}-oci-${platformPair}.tar`; container build binaries are separately namespaced. This does not push a registry image.
- `polaris-upstream-native-assets.json` remains the v2 index filename. Its 44 rows use the branded version. The source archive remains `sing-box-polaris-source-${sourceCommit}.tar.gz` and is bound to the exact Git tree.

Go module paths, imported package paths, executable names and existing installed service/config paths are unchanged. Existing gVisor, Cronet, OpenWrt and G4 source patches are retained. Historical v1 consumers remain a separate old-format protocol.

## Internal version mapping

Artifact naming alone is not numeric metadata validation:

- Android application APK `VERSION_NAME` retains the entire branded string. The existing helper updates the committed upstream `VERSION_CODE` by its established +1 rule only when metadata changes; it does not consult or fabricate a store release history. `--allow-ci-update` makes isolated CI regeneration explicit while the default `--ci` fail-closed rule remains. The produced version metadata asset records the actual VERSION_NAME/VERSION_CODE. A signed store rollout would additionally require actual owned store version-code admission.
- Windows keeps full semver for application version/filename/channel (`polaris-alpha`). Existing electron-builder converts the numeric resource components to MAJOR.MINOR.PATCH.BUILD_NUMBER. BUILD_NUMBER is the actual GitHub workflow run number, explicitly bounded to 1..65535; it is a CI counter, not an invented prior release or globally monotonic store history. Unsigned recipes do not claim an Authenticode signature or verified resource stamping.
- Apple standalone branded marketing version becomes numeric `1.15.0`, while kernel version and artifact name keep the full brand. Legacy upstream formats keep their previous helper behavior. Unsigned Apple project build numbers use the actual GitHub run number for each platform. App Store/TestFlight marketing remains the upstream numeric `1.15.1000` helper rule; signed store project-number selection remains the real existing ASC query path and is not simulated without credentials. No unsigned CI counter is evidence of store admission.
- Alpine and OpenWrt **package-manager APK** metadata maps `1.15.0-polaris-alpha.12` to `1.15.0_alpha12-r0` using apk-tools syntax. This is separate from Android application APK VERSION_NAME. Producer package filenames and embedded kernel version keep the brand; public filenames use the separate upstream-version mapping. Other FPM packages retain the existing hyphen-to-tilde version normalization (`1.15.0~polaris~alpha.12`).

The actual outputs must still be inspected in the platform runs. Source-level compatibility is not proof that Xcode, Gradle, electron-builder or package-manager tools accepted the generated metadata.

## Signed and unsigned scope

Full generation matrices remain present. The GitHub-only unsigned prerelease requires successful complete All, Linux repository-package and Docker export runs, each exact-source/run/attempt bound. CLI archives, AAR/XCFramework libraries, Linux/OpenWrt packages, OCI exports, unsigned Windows EXE, unsigned standalone macOS PKG+dSYM and jailbreak DEB can be generated without owned signing credentials. Android unsigned application APK can be generated but is not an installable signed release. Apple unsigned xcarchive files are build archives, not installable signed IPA/PKG.

Signed iOS/tvOS IPA, signed macOS App Store export and signed/notarized standalone PKG remain explicitly blocked without owned certificates/provisioning/identities. Signed workflows remain implemented. Missing signing credentials do not block the independent unsigned workflows or GitHub-only publication of its complete disclosed scope. Store submissions, TestFlight and registry/Fury uploads are separate explicit permissions and are never side effects of this publisher.

Before publishing, produce and review the actual full file inventory, hashes, provenance and blocked-signature list. The publisher validates all three producer runs and their complete scope receipts, re-downloads actual files, verifies the existing annotated source tag, and refuses partial inventory or filename collisions. The gate uses a reviewed inventory hash, not guessed artifact IDs. Preparing publisher source does not itself create or modify a Release.

## Source gates

The existing G4 source gate includes the five affected version packages in its same Go-race invocation, with branded parser/order/legacy compatibility, numeric Apple mapping and explicit helper opt-in tests. Existing CI contract checks include producer/publisher schema and scope checks. They must pass on the final source before the campaign spends resources on all platform matrices. No per-change micro-workflow is added.

## Source freeze and final-evidence sequence

1. Freeze the complete candidate on the development branch. Complete its independent source review, then dispatch the existing `build.yml` entry at that SHA with `build=Source` and `evidence_mode=staging`. This runs the concentrated G4/CI-contract gates on Linux/macOS without tags or product builds. The added source-only menu choice retains every original product choice and matrix. It also works while the new standalone source workflow files are not yet on the default branch.
2. The user explicitly authorized an alpha.12 repackage without a new alpha.13 version. Preserve the old alpha.12 annotated tag object and its original source/build evidence first. Report the final accepted source SHA and the same-name tag update plan before any ref update. Update only the authorized tag with an expected-old-object lease to a new annotated object directly targeting that final accepted source. Once the new campaign starts, keep that object fixed through every build, inventory and readback. A full build does not create or update a tag.
3. Dispatch unsigned All at that exact SHA with `evidence_mode=final`, the Linux package workflow with the same version/SHA, and Docker with the same tag/SHA. All preflights the annotated tag before product builds; Docker checks out the dispatch SHA in each actual binary and image job, compares the captured tag object, and rechecks before uploading artifacts.
4. Final index assembly validates the preflight tag object again and emits the final schema. `evidence_mode=staging` always emits staging with `tagObject=null`, even if a matching tag exists. It is useful only for candidate checks. Neither GitHub publisher nor signed GitHub publication admits staging as a formal release input.
5. Review the actual complete inventory from the three successful runs. The GitHub publisher requires final schema, exact source commit/tree/tag/object, all 44 native identities, original index/source basenames and actual hashes. Its separate write phase repeats validation, uses the draft's validated complete `https://uploads.github.com/...` endpoint, and retains the draft on any failure. It never auto-accepts a staging index. Ordinary `publish` remains create-only; the one-shot alpha.12 replacement below is a separately selected protected operation.

This ordering does not grant store, Fury, registry or signed-distribution authorization. Real absent signing identities remain blocked as listed above.


### Same-name alpha.12 rebuilt replacement

The replacement path is limited to Release `416392475` and the exact original
228-asset snapshot. It never relabels c002 binaries as a new source. Freeze and
independently review the complete publisher/source revision on `polaris-main`
before moving the existing annotated version tag; do not add publisher changes
between tag selection and product builds.

1. On that frozen publisher revision, run `prepare-replacement` with original
   source `c0023dbc6dcd7b6eb2f54dd036ae150168bd8e6e`. This read-only preparation
   checks the entire old snapshot and pinned inventory `39124650790`, preserves
   the original public receipt, and records recoverable original producer
   artifacts for every other old asset. The recovery run must finish successfully
   before the tag moves. Its 90-day receipt retention does not extend the
   separately recorded producer-artifact expirations.
2. Update only `v1.15.0-polaris-alpha.12`, with an expected-old-object lease, to a
   new annotated object directly targeting the frozen source. Immediately run
   `stage-replacement` from that exact tag with the new source and recovery run.
   Its existing protected job makes the same Release a draft without removing
   assets. Confirm the draft before starting producers. Tag movement and draft
   staging are separate GitHub transactions: queue/reviewer delays can expose a
   temporary old-assets/new-tag window. There is no atomic or zero-window claim.
3. Dispatch the existing unsigned All/final, Linux and Docker producers from
   `polaris-main`, after verifying its head is the frozen new source; do not
   update main through producer/inventory confirmation and protected replacement.
   All three dispatched runs must confirm that exact head. Their
   source/tag preflights still bind the same new annotated object. This preserves
   the proven producer entry: tag-ref All run 39107787500 previously failed when
   checkout flattened its local annotated tag, while main-ref dispatch succeeded.
   The protected publisher staging/replacement still runs from the exact version
   tag. Run and independently review a fresh inventory from that same publisher
   revision. The old inventory is recovery evidence only. New native
   index, source archive, producer IDs and every selected byte must bind the new
   source/tree/tag object. Keep the fallback fe182 Release available.
4. Select `replace` from the same tag, with the reviewed new inventory hash,
   three successful producer runs and original recovery run. The protected job
   repeats complete producer validation once, uploads all 168 new products under
   bounded temporary names, verifies them, retires only the 228 original IDs,
   restores canonical names and publishes only the exact complete 168-file set.
   Full snapshots run at phase boundaries and every 80 writes; API upload/rename
   responses bind each new ID/name/size/digest/label. Unknown state, expired
   recovery copies, insufficient authenticated API budget or uncertain responses
   stop the operation. Known completed writes resume idempotently; an incomplete
   upload (`starter`) requires inspection rather than automatic deletion.
5. Retain the final new IDs/hashes and source/index audit for the App consumer's
   updated contract and independent verification. Remove the fallback only after
   new public delivery and consumer integration are both verified.

All workflow write modes retain the existing protected environment, reviewer, publication
variable and non-cancelling concurrency group. No environment allowlist change,
registry/store publication, signing or fabricated attestation is part of this path.

### Metadata-only alpha.12 public-name alignment

The rebuilt Release `416392475` contains 168 products from source
`a4d0858605b51b7f5b3c29a9969a6f2c3ae5a0ae`, tree
`830f7256af499e5ad3e7da9a79f0a377ca38fc77`, annotated tag object
`916d9533ba0a6092e34bc53f63dace63e11fa85e`. The tag remains
`v1.15.0-polaris-alpha.12`. `github-release-name-alignment.json` pins every
actual asset ID, old/new name, size and SHA-256 plus the exact Release metadata
and source/tag identity. Its hash is fixed in the existing publisher.

The permanent `publication()` mapping now applies the public-name rule above
after the unchanged complete producer selection. Native index `archive.name`,
`archive.root`, historical `archive.releaseName`, internal version/BuildInfo,
package contents and producer receipts remain exact original evidence; they are
not rewritten to make outer filenames look internal. Future inventories and
assembled public upload paths use the new mapping. The old c002 reconciliation
uses its historical mapping only within its original source/tag/ID-bound plan.

For this already published source, no producer, inventory, rebuild, recompression,
retag or Release-body write is needed. The current body already explicitly
states the signing/notarization limits. The existing script offers bounded
maintenance commands (not new workflow-dispatch options):

```
python scripts/ci/github_release.py check-names \
  --source a4d0858605b51b7f5b3c29a9969a6f2c3ae5a0ae --audit naming-preflight
POLARIS_GITHUB_PUBLISH_ENABLED=true python scripts/ci/github_release.py rename-names \
  --source a4d0858605b51b7f5b3c29a9969a6f2c3ae5a0ae --audit naming-result
```

Run these only through the independently reviewed, user-authorized repository
metadata-maintenance task with existing authenticated access. This operation
does not dispatch the protected product-publishing workflow or change its
environment rules. If the execution tool denies access, stop and report it;
do not switch routes to evade the denial. Do not invoke the old tag's publisher, regenerate a new product inventory,
or re-run `replace` to perform a rename. The new main revision is publisher code,
not a replacement product source for these existing a4d085 bytes.

`check-names` fully checks the repository, source tree, tag object, Release body
(including unsigned disclosure), exact 168 IDs/names/sizes/digests and label.
Target names are unique and disjoint from all old names, so no temporary names
or overwrites are necessary. After sufficient authenticated API budget is
confirmed, `rename-names` repeats the full snapshot, GET-checks each exact asset,
PATCHes only its `name`, and verifies the returned ID/size/digest/label unchanged.
Full paginated snapshots run after every 80 successful changes and at completion.
No bytes are downloaded, uploaded or deleted. Unknown state or an uncertain
response stops immediately; re-run preflight and the same reviewed command to
resume recognized old/new names, never blindly reissue uncertain writes. A fully
renamed set is a zero-write success. The saved result is local audit, not a new
public asset. Renames are individual GitHub transactions: mixed old/new outer
names are temporarily visible, and the API has no atomic name compare-and-swap;
concurrent changes elsewhere are detected at the next full checkpoint.

Coordinate consumers' public lookup names/URLs while preserving all four native
IDs and digests and the exact internal archive/source verification. Asset-ID
URLs remain the stable transport during this metadata-only operation. A missing
upstream immutable-release attestation is not a missing product and does not
authorize fabricated attestations or security-setting changes.

### alpha.12 repackaged client source inputs

The core native index's `sourceIdentity.sourceOverlay=0` describes only the
kernel source. It does not describe these client builds. The exact client
repository/gitlink/tree plus the source-owned `release/ci/client-overlays.json`
are inputs to each client producer. Its candidate metadata contains the actual
client diff and per-file before/after SHA-256, including generated version
metadata. The release inventory validates the overlay manifest and exact file
identities; the publisher audit receipt preserves this evidence. Compatibility
overlays apply to signed and unsigned clients; credential-removal overlays apply
only to the unsigned producer. Unsupported platform AutoRedirect reports false
and an explicit error, while explicit interface binding must bind or fail.

This repackage changes source while retaining the user-selected alpha.12 version.
The existing alpha.12 tag object and original producer outputs remain historical
evidence for their original source. New builds must use the new accepted source,
new annotated tag object and fresh exact-source run identities; the old tag's
source or evidence cannot stand in for them. No tag update or platform acceptance
is asserted by these source changes themselves.


The follow-up client source receipt composes compatibility, reviewed owned
identity and version metadata and replays the real diff against its pinned
baseline. Newly introduced compatibility/identity source is explicitly declared;
unknown nonignored untracked input is rejected. See `RELEASE-GATES.md` for the
owned-patch file inventory and evidence limits. This source change does not
activate the absent owned signing configuration or assert a new platform result.

### Exact version templates and Docker diagnostics

`github-release.json` is the source-owned current version input shared by the
publisher and producer run receipts. All/Linux/signed payload rules use the
literal `{version}` token, rendered with `re.escape` only for that exact reviewed
version; old or mixed versions fail the original complete payload check. Internal
library/OCI transport names remain unversioned where already specified, and the
public mapping derives the upstream filename version from that exact validated version. Workflow defaults
and publisher concurrency are checked against the same current contract.

The Docker OCI producer explicitly sets `DOCKER_BUILD_RECORD_UPLOAD=false` on
its existing build action. This suppresses automatic diagnostic `.dockerbuild`
artifacts, preserving the exact 10 binary + 9 OCI + 1 producer-receipt scope.
The publisher still rejects all unexpected artifacts, duplicates and missing
products. Existing diagnostic originals remain historical evidence; they are not
core release payloads. No platform, real payload rule or matrix row is removed.

All and signed scopes require both `.ipk` and package-manager `.apk` for each of
the same 32 OpenWrt architectures, one exact file per format. Windows and Linux
client payload rules bind the full version and each target/format's architecture
spelling, including Debian/RPM/pacman differences. Adjacent versions such as
alpha.120, wrong architectures, missing APKs and mixed old versions are rejected.


### Preserve upstream distribution tracks

`testing` remains the upstream synchronization branch; the patched default
`polaris-main` follows that same testing line. `.github/detect_track.sh` contains
one branch-name normalization for this relationship. It otherwise retains the
upstream priority `stable`, then `testing`, then `oldstable`. Only a commit on
`stable` with an exact tag containing a hyphen becomes `beta`; an alpha string
in a workflow version input does not select a track. The emitted `PACKAGE_NAME` retains the upstream package identity `sing-box`
and its `-beta`, `-testing` and `-oldstable` suffixes. `NAME` changes only the
external asset prefix to `sing-box-polaris`, retaining those same suffixes.
Container `latest-*` track tags are unchanged.

Unsigned Linux, signed Linux and the owned container publication path call this
same helper instead of hardcoding a Polaris-only track. Their existing full
history checkouts, matrices, signatures, environment/enable gates and owned
publication destinations are unchanged. Current `polaris-main` Linux repository
package filenames therefore have the `sing-box-polaris-testing_` prefix, while
the DEB/RPM package identity remains `sing-box-testing`. Both Linux workflows
pass `PACKAGE_NAME` to fpm and use `NAME` only for output filenames; binary,
service, configuration and installation paths remain `sing-box`. The current
publisher scope pins all 22 exact testing DEB/RPM names rather than accepting
arbitrary/mixed tracks. These are internal/separate-channel products, not the
168 All products selected for GitHub Release. A future release from another
track must review its corresponding source-owned inventory contract as usual.

This source-only correction does not rebuild, rename or replace any existing
alpha.12 product, move its tag, enable signed/Fury/GHCR/App Store publication, or
change the currently approved unsigned GitHub-only scope. Existing App delivery
continues against the verified a4d085 source and asset IDs. It takes effect only
when a subsequent authorized producer run uses the updated source.
