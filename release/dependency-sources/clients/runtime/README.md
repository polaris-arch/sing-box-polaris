# Fixed-client runtime notice evidence

This is a finite source/notice acquisition, not a complete runtime BOM or a legal-compliance conclusion. No product was built or executed. Original notice bytes are in `release/licenses/clients/runtime`; `index.json` maps every text to the original source and checksum. Complete third-party source archives are not copied into this delivery.

## Scope and actual package comparison

- Desktop: 145 npm package/version candidates selected from actual desktop TS/CSS imports, dashboard production-lock dependencies, and generated Material icon input. All npm tarballs passed the exact lockfile integrity check. Build/lint tooling and type-only packages are excluded. The generated theme source is fixed iTerm2-Color-Schemes commit `8c84dd1a859f36ec8601b082bd97b4ec888f0f4d`.
- The real SFL arm64 deb's ASAR contains 17 original notice files representing 16 distinct byte hashes. All 16 hashes match the acquired source notices. The 150 other distinct source-notice hashes are conservative candidates, not 150 proven omissions. `actual-SFL-arm64-asar-notice-diff.json` separates these states.
- Electron/Chromium notices and Noto Color Emoji OFL were already verified in that actual package. They are not claimed missing or copied as a redundant 20 MB Chromium notice. The actual renderer CSS also contains a complete xterm MIT notice. Shared source notice content does not require repeating the acquisition for every architecture.
- Apple: 23 runtime-candidate root Package.resolved pins; SwiftLint is excluded as build-only. The CodeLanguagesContainer nested lock supplies a bounded 37-grammar source set. macOS CodeEdit imports, iOS Runestone/JSON5 imports, and iOS/macOS Ghostty platform filters are preserved in source evidence and recipes. Package.resolved alone is not proof every package is linked into every target.
- Android: the actual unsigned producer builds `other` and `otherLegacy`, not `play`. The selection contains 70 distinct directly declared coordinates across those two flavors, including the desugaring input. It excludes the two play-only SDKs, compileOnly Xposed APIs, KSP processors, and other build tools. **It is not the resolved transitive runtime BOM.**

## Android evidence coverage, exactly

The 70 direct coordinates divide into:

1. 43 with original notice material recovered from their exact versioned Maven artifacts: 40 have standalone notices in sources JARs; smali-dexlib2 and the two EditorKit coordinates supply original licensing headers from exact sources JARs.
2. 18 further coordinates have original upstream notice supplements at version-tag-resolved immutable commits. These cover ZXing, Kotlin coroutines/serialization, Guava, Material, Sora, android-tree-sitter, libsu, Reorderable, compose-markdown, and the four libghostty coordinates. A version-tag source relationship is recorded; no binary reproducibility claim is made.
3. Nine have POM license declarations but no original notice text recovered by this pass. Eight have downloaded fixed sources JARs without a standalone notice/header: appcompat 1.7.1; preference-ktx 1.2.1; legacy Compose material3 1.3.1, ui 1.7.6, ui-tooling-preview 1.7.6, runtime-livedata 1.7.6; Shizuku api/provider 13.1.5. The ninth is desugar_jdk_libs 2.1.5: its runtime JAR was fetched and hashed, but zero standalone notice files were identified and its sources-JAR endpoint returned 404. This is an evidence classification, not a claim those components are unlicensed or the APK is non-compliant.

All 70 exact POMs were fetched, including the three JitPack coordinates through the repository actually configured by the client. 66 exact sources JARs were fetched and hashed. No transitive Maven resolution or R8-retention result is inferred from this list. In particular, multiplatform facade coordinates can resolve to additional Android/JVM artifacts.

## Copyleft source/build material

- Sora 0.23.6 is declared LGPL-2.1. The full original source archive at `b1777d0d465b42515739ffe529b4ec1634ac2175` was fetched and hashed; its original LGPL text and relevant Gradle/build recipes are retained.
- android-tree-sitter 4.3.2 is declared LGPL-2.1. The full source archive at `797150222de664181e31be53e9a5b253056ba9b0` was fetched and hashed. The actual declared native inputs are bounded to core `tree-sitter-lib` at `ca7d15add61bf77391d387d26441599b96c0eb9c` and JSON grammar at `3b129203f4b72d532f58e72c5310c0a7db3b8e6d`; both complete archives were fetched and their original notices/necessary recipes retained. Unused language grammars were not imported.
- desugar_jdk_libs 2.1.5's exact runtime JAR was fetched and hashed, but yielded zero standalone notice files after strict filename/text validation. Its POM declares GPL-2.0 with Classpath exception; that declaration is not an acquired original license text. The checked sources-JAR endpoint returned 404 and the examined GitHub tags expose no 2.1.5 source tag. This pass therefore does not assert a source-revision-to-emitted-runtime mapping. That specific correspondence is a remaining evidence item if its code is emitted into the distributed APK; it is not a claim that upstream sources do not exist.
- This research did not modify third-party sources. The actual unsigned client build also applies the existing root repository's unsigned/version overlays. Those existing overlay scripts and the producer source revision must remain with corresponding-source/build instructions; an unmodified client source pin alone does not describe that derivative build.

## Minimal Android producer evidence, without a full product rebuild

The current workflow's `build_android` job has matrix tasks `:app:assembleOtherRelease` and `:app:assembleOtherLegacyRelease`. Its Build step copies merged libbox AARs into `clients/android/app/libs`, enters `clients/android`, then runs Gradle. Immediately after that copy, the following report task can run independently of assemble:

- Other: `./gradlew :app:dependencies --configuration otherReleaseRuntimeClasspath --console=plain`
- Legacy: `./gradlew :app:dependencies --configuration otherLegacyReleaseRuntimeClasspath --console=plain`

Retain stdout as flavor-named dependency reports next to the candidate metadata, before the workflow's candidate recording/upload step. These Gradle tasks resolve/report dependencies; they do not compile the product. For byte-bound notice harvesting, also serialize the chosen configuration's `incoming.resolutionResult` component/variant selections and resolved artifacts' coordinates, filenames and SHA-256 values. The already-used core-library-desugaring input must be recorded separately because it is not necessarily part of the app runtime classpath. This is the concrete missing evidence in the current retained set; another full product build is not required to obtain it. Inspect notices in those exact resolved JAR/AAR files and match their retained code to the already-produced APK/R8 evidence as needed.

## Bounded observations that are not automatic omissions

- codemirror-json5 1.0.3 declares MIT in its manifest but neither its exact npm tarball nor its exact registry gitHead source archive contains a standalone license text. CodeEditLanguages and CodeEditSymbols likewise have no standalone license filename in their fixed source trees; the retrieved READMEs contained no license text. Full source-file licensing-header scans were not performed for these three components (see notice-observation-scope.json). No replacement copyright attribution was invented, and absence of a file is not classified as a confirmed legal violation.
- protobuf-es 2.14.0 declares Apache-2.0 AND BSD-3-Clause. Its full Google BSD notice is in fixed-source `packages/protobuf/src/wire/varint.ts`, not the repository's Apache-only root LICENSE. Both original texts are retained.
- GhosttyTheme's original iTerm2-derived MIT notice is retained even though the fixed Swift Package.swift excludes that LICENSE from target resources. The package separately copies its MIT bash-preexec resource notice. This is a source packaging observation, not a determination that the final app omits all applicable notices.

## Shared Apple prebuilt ZIP inspection

CodeLanguagesContainer's fixed 34,388,755-byte ZIP was fetched fully, SHA-256 `c6ee69d9d373a9c3cf93d239e05369d9b941275d31cd7956d0dc83b5a5c3e152`, and its Git blob matched the fixed repository tree. The ZIP contains 24 entries and no standalone LICENSE/NOTICE/COPYING/manifest entries. GhosttyKit's fixed release ZIP has 77,203,207 bytes and 38 entries; range/central-directory inspection likewise found no such standalone entries. Its manifest pins SHA-256 `80e9bbfc89f5bd23ee028cff03024e3a788509f87812ab0bc9d697bf22a9472b`; this inspection does not claim a full-download verification of that digest.

These are shared binary-source facts, obtainable without compiling any app. The 37 CodeLanguagesContainer grammar source notices remain the bounded candidate material. Ghostty's fixed wrapper recipe explicitly disables custom shaders, the inspector, Sentry, and the native application shell, so importing those entire unused dependency sets would be incorrect. The wrapper's own MIT, bash-preexec MIT, and theme MIT texts are retained. The upstream Ghostty core and actually linked native-library source notices must be reconciled against the bounded static archive member evidence, rather than against an indiscriminate upstream dependency list. This pass does not certify that reconciliation complete.

The source/notice observations above are frozen evidence. No additional source retrieval or product builds are prerequisites for accepting these evidence files; incomplete runtime source/notice closure must remain false until the specific remaining correspondence checks are satisfied.

### Final Ghostty archive-member result

The shared prebuilt iOS arm64 `libghostty.a` ZIP entry was read and ZIP-CRC verified without executing it: 19,551,440 bytes, SHA-256 `0fd53ae56ac9b02d8fad9033c47cf7cf64674536eef2ba0af031b438fedeadd6`, 167 ar members. Member names provide concrete evidence for FreeType, libpng, zlib, Oniguruma, simdutf, Highway, gettext/libintl, stb, Wuffs, Ghostty, compiler runtime and libc++ compatibility objects in that archive. The complete member list is retained. These object families still need mapping to their exact fixed dependency sources/original notices; in particular the wrapper's license-check script scans its own tracked source tree and does not prove that native static-library members have only MIT obligations. No license-family conclusion is derived solely from a member name.

Archive-member presence is distinct from final-app retention: static linking may discard unused members. The final report does not assert that every listed object survives into the app, nor automatically treat every candidate or absent standalone LICENSE as a confirmed release blocker. `FROZEN-REMAINING-EVIDENCE.json` gives the precise frozen scope and remaining checks. No further source acquisition was started after the freeze request.

## Correction to preliminary acquisition

The first Android binary-JAR scan used an unanchored `ofl` filename substring and incorrectly classified 27 Java `OfLong.class` entries as OFL notices. Those binary files and all notice mappings to them have been removed. The earlier claims of 27 desugar notices and 193 total original texts are withdrawn. The corrected delivery contains **166 distinct original UTF-8 notice texts with 305 component/source mappings**. Every delivered notice was decoded strictly as UTF-8, checked for NUL bytes, and hash-checked against the index. The exact excluded paths are retained only as an exclusion record in CORRECTED-FALSE-POSITIVE-EXCLUSIONS.json, not as legal notice content. Desugar's correct standalone-notice count is zero in the inspected JAR; this is not a claim about all possible upstream licensing locations.
