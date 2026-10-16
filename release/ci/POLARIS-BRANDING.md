# Polaris branded GitHub prerelease

## Exact release identity

Repository: `polaris-arch/sing-box-polaris` (1421657509).
Tag and title: `v1.15.0-polaris-alpha.13`.
Native/public version: `1.15.0-polaris-alpha.13`.
Future accepted family: `MAJOR.MINOR.PATCH-polaris-{alpha,beta,rc}.NUMBER`, with no leading zero in NUMBER.
The GitHub-only publisher separately pins this exact release. It never creates or moves the source tag and refuses any existing Release.

The reference release `https://github.com/shtorm-7/sing-box-extended/releases/tag/v1.14.1-extended-2.7.2` has no explicit title. Its native archives use `sing-box-1.14.1-extended-2.7.2-*`, and its SFA/SFL/SFW filenames similarly carry the branded version. Polaris follows that native version naming method, rather than wrapping/repacking native core archives. The reference's additional compressed variants do not replace or reduce the pinned SagerNet matrix.

## Filenames and unchanged interfaces

- All 44 CLI archives retain `sing-box-${VERSION}-${OS}-${ARCH}${VARIANT}.tar.gz` (Windows `.zip`) and the identical root. GOARM, softfloat, 386, libc and legacy suffixes remain exactly the upstream matrix. The executable remains `sing-box`/`sing-box.exe` and shared Cronet filenames remain unchanged.
- Linux packages retain `sing-box_${VERSION}_linux_${PACKAGE_ARCH}.{deb,rpm,pkg.tar.zst,apk}` and OpenWrt `sing-box_${VERSION}_openwrt_${ARCH}.{ipk,apk}`. Independent distro packages use `sing-box-polaris_${VERSION}_linux_${ARCH}.{deb,rpm}`.
- Android app names use `SFA-${VERSION}-...apk`; Windows uses `SFW-${VERSION}-{x64,x86,arm64}.exe`; Linux client packages use `SFL-${VERSION}-...`.
- Standalone macOS uses `SFM-${VERSION}-{Apple,Intel,Universal}.pkg` and `SFM-${VERSION}.dSYMs.zip`; jailbreak package names retain their upstream shape and full branded version. Unsigned Apple store archives are `unsigned-${VERSION}-{ios,macos,tvos}.xcarchive.tar`.
- Library transport names used between build jobs remain upstream-compatible. On GitHub publication, actual bytes are renamed without wrapping: `libbox-${VERSION}-android-${arch}.aar`, `libbox-legacy-${VERSION}-android-${arch}.aar`, `Libbox-${VERSION}-${slice}.tar`.
- OCI image exports are published as `sing-box-${VERSION}-oci-${platformPair}.tar`; container build binaries are separately namespaced. This does not push a registry image.
- `polaris-upstream-native-assets.json` remains the v2 index filename. Its 44 rows use the branded version. The source archive remains `sing-box-polaris-source-${sourceCommit}.tar.gz` and is bound to the exact Git tree.

Go module paths, imported package paths, executable names and existing installed service/config paths are unchanged. Existing gVisor, Cronet, OpenWrt and G4 source patches are retained. Historical v1 consumers remain a separate old-format protocol.

## Internal version mapping

Artifact naming alone is not numeric metadata validation:

- Android application APK `VERSION_NAME` retains the entire branded string. The existing helper updates the committed upstream `VERSION_CODE` by its established +1 rule only when metadata changes; it does not consult or fabricate a store release history. `--allow-ci-update` makes isolated CI regeneration explicit while the default `--ci` fail-closed rule remains. The produced version metadata asset records the actual VERSION_NAME/VERSION_CODE. A signed store rollout would additionally require actual owned store version-code admission.
- Windows keeps full semver for application version/filename/channel (`polaris-alpha`). Existing electron-builder converts the numeric resource components to MAJOR.MINOR.PATCH.BUILD_NUMBER. BUILD_NUMBER is the actual GitHub workflow run number, explicitly bounded to 1..65535; it is a CI counter, not an invented prior release or globally monotonic store history. Unsigned recipes do not claim an Authenticode signature or verified resource stamping.
- Apple standalone branded marketing version becomes numeric `1.15.0`, while kernel version and artifact name keep the full brand. Legacy upstream formats keep their previous helper behavior. Unsigned Apple project build numbers use the actual GitHub run number for each platform. App Store/TestFlight marketing remains the upstream numeric `1.15.1000` helper rule; signed store project-number selection remains the real existing ASC query path and is not simulated without credentials. No unsigned CI counter is evidence of store admission.
- Alpine and OpenWrt **package-manager APK** metadata maps `1.15.0-polaris-alpha.13` to `1.15.0_alpha13-r0` using apk-tools syntax. This is separate from Android application APK VERSION_NAME. External package filenames and embedded kernel version keep the brand. Other FPM packages retain the existing hyphen-to-tilde version normalization (`1.15.0~polaris~alpha.13`).

The actual outputs must still be inspected in the platform runs. Source-level compatibility is not proof that Xcode, Gradle, electron-builder or package-manager tools accepted the generated metadata.

## Signed and unsigned scope

Full generation matrices remain present. The GitHub-only unsigned prerelease requires successful complete All, Linux repository-package and Docker export runs, each exact-source/run/attempt bound. CLI archives, AAR/XCFramework libraries, Linux/OpenWrt packages, OCI exports, unsigned Windows EXE, unsigned standalone macOS PKG+dSYM and jailbreak DEB can be generated without owned signing credentials. Android unsigned application APK can be generated but is not an installable signed release. Apple unsigned xcarchive files are build archives, not installable signed IPA/PKG.

Signed iOS/tvOS IPA, signed macOS App Store export and signed/notarized standalone PKG remain explicitly blocked without owned certificates/provisioning/identities. Signed workflows remain implemented. Missing signing credentials do not block the independent unsigned workflows or GitHub-only publication of its complete disclosed scope. Store submissions, TestFlight and registry/Fury uploads are separate explicit permissions and are never side effects of this publisher.

Before publishing, produce and review the actual full file inventory, hashes, provenance and blocked-signature list. The publisher validates all three producer runs and their complete scope receipts, re-downloads actual files, verifies the existing annotated source tag, and refuses partial inventory or filename collisions. The gate uses a reviewed inventory hash, not guessed artifact IDs. No release has been created by preparing this source.

## Source gates

The existing G4 source gate includes the five affected version packages in its same Go-race invocation, with branded parser/order/legacy compatibility, numeric Apple mapping and explicit helper opt-in tests. Existing CI contract checks include producer/publisher schema and scope checks. They must pass on the final source before the campaign spends resources on all platform matrices. No per-change micro-workflow is added.

## Source freeze and final-evidence sequence

1. Freeze the complete candidate on the development branch. Complete its independent source review, then dispatch the existing `build.yml` entry at that SHA with `build=Source` and `evidence_mode=staging`. This runs the concentrated G4/CI-contract gates on Linux/macOS without tags or product builds. The added source-only menu choice retains every original product choice and matrix. It also works while the new standalone source workflow files are not yet on the default branch.
2. Create the reviewed annotated `v1.15.0-polaris-alpha.13` exactly once, directly targeting that same source commit. Never move or recreate it. A full build does not create a tag.
3. Dispatch unsigned All at that exact SHA with `evidence_mode=final`, the Linux package workflow with the same version/SHA, and Docker with the same tag/SHA. All preflights the annotated tag before product builds; Docker checks out the dispatch SHA in each actual binary and image job, compares the captured tag object, and rechecks before uploading artifacts.
4. Final index assembly validates the preflight tag object again and emits the final schema. `evidence_mode=staging` always emits staging with `tagObject=null`, even if a matching tag exists. It is useful only for candidate checks. Neither GitHub publisher nor signed GitHub publication admits staging as a formal release input.
5. Review the actual complete inventory from the three successful runs. The GitHub publisher requires final schema, exact source commit/tree/tag/object, all 44 native identities, original index/source basenames and actual hashes. Its separate write phase repeats validation, uses the draft's validated complete `https://uploads.github.com/...` endpoint, and retains the draft on any failure. It never auto-accepts a staging index or overwrites a release.

This ordering does not grant store, Fury, registry or signed-distribution authorization. Real absent signing identities remain blocked as listed above.

### alpha.13 client source inputs

The core native index's `sourceIdentity.sourceOverlay=0` describes only the
kernel source. It does not describe these client builds. The exact client
repository/gitlink/tree plus the source-owned `release/ci/client-overlays.json`
are inputs to each client producer. Its candidate metadata contains the actual
client diff and per-file before/after SHA-256, including generated version
metadata. The release inventory validates the overlay manifest and exact file
identities; the public aggregate receipt preserves this evidence. Compatibility
overlays apply to signed and unsigned clients; credential-removal overlays apply
only to the unsigned producer. Unsupported platform AutoRedirect reports false
and an explicit error, while explicit interface binding must bind or fail.

This candidate changes source and version. Existing alpha.12 annotated tag and
successful original producer outputs remain their original identities; they are
not publication inputs for alpha.13. No new tag or platform acceptance is
asserted by the source changes themselves.


The follow-up client source receipt composes compatibility, reviewed owned
identity and version metadata and replays the real diff against its pinned
baseline. Newly introduced compatibility/identity source is explicitly declared;
unknown nonignored untracked input is rejected. See `RELEASE-GATES.md` for the
owned-patch file inventory and evidence limits. This source change does not
activate the absent owned signing configuration or assert a new platform result.
