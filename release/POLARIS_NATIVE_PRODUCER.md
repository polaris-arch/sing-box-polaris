# Native candidate producer review slice

`polaris-native-candidate.yml` is dispatch-only and grants `contents: read`.
It builds unsigned review candidates and uploads short-lived Actions artifacts.
It has no tag, Release, old-asset deletion, consumer edit or deployment operation.
The integration owner must first freeze the independently reviewed source SHA;
producer and source checkouts are separate. This candidate pins the OTHERS/FIFO
correction a01da7a942b3a0dbbfdfda2bba5bd63d5bd9d932; its parent 92a remains
immutable. Neither source review nor hosted native validation is pre-signed. Source SHA/tree are checked before
building, and source overlays/dirty files are rejected. Never dispatch the
inherited upstream `build.yml` as a substitute: it writes version tags and
publishes/replaces its own assets.

## Implemented native CLI group

| Target | Runner | Cronet | Acceptance implemented by this producer |
|---|---|---|---|
| Linux amd64 | ubuntu-24.04 | sibling SO, purego | exact module/blob/byte identity, ELF64 machine/deps/versions/255 exports, native engine version, package extraction/reload |
| Linux arm64 | ubuntu-24.04-arm | sibling SO, purego | same checks on a native ARM64 host |
| Windows amd64 | windows-2025 | sibling DLL, purego | exact identity, PE machine/imports/delay imports/255 exports (253 base + two float C exports), native load/version, extraction/reload |
| Windows arm64 | windows-11-arm | sibling DLL, purego | same checks; native kernel and Go host architecture checked |
| macOS amd64 | macos-15-intel | static archive, CGO | exact identity, native archive ABI symbols, final thin Mach-O CPU/load commands/deps, native version, extraction/reload |
| macOS arm64 | macos-15 | static archive, CGO | same checks; macOS 13 compiler minimum; Rosetta execution rejected |

Go is 1.25.5, CGO is 0 for shared Linux/Windows and 1 for macOS static linking.
Build concurrency is `-p 1`, GOMAXPROCS 2, workflow max-parallel 2. Actual source
release tags and linker flags are recorded. The final internal executable remains
sing-box(.exe); no invented Darwin dylib is included. Known licenses/NOTICE,
member checksums and provenance accompany each candidate. Native Cronet checks
create/version/destroy an engine and start no network, proxy or system TUN.
Shared-mode native negative cases run in fresh subprocesses: missing argument/path,
wrong digest/version, same-size changed bytes, actual foreign-architecture Cronet
bytes with a matching digest, and a native library missing the Cronet ABI. Static
mode rejects sidecar options and wrong version. Fixture hashes and outcomes are
recorded; fixture libraries are never included in the candidate archive.
Archive member paths/types/duplicates/exact bytes are checked before extraction;
checks do not accept same-size or ELF BuildID exceptions.

Windows certificate tables and macOS code-signature inspection are observations,
not publisher-trust acceptance. The producer performs no distribution signing.
The static archive object inventory is byte-bound to the exact module/blob; it
is not evidence that the mobile or PacketTunnel final application has linked.
Constructor tests prove capability/selection only, not actual gVisor packet flow.

## Explicitly deferred groups

The pinned manifest has four Android static archives (arm/arm64/386/amd64) and
three iOS static archives (arm64 device, arm64 simulator, amd64 simulator). They
are `NOT_BUILT_BY_THIS_WORKFLOW`, with no invented final AAR/XCFramework hash.

Android requires four final AAR/JNI builds, Java API and linked ELF proof, compiler
selected by the helper/effective NDK revision and actual native linkage. Apple
requires all three final framework slices, SDK/architecture/deployment checks,
Swift/ObjC/Go API roundtrip, PacketTunnel final link and signing receipts. Device
networking and App consumption are separate owner/window acceptance. The old
local cross-built CLI batch is never accepted as any native hosted job result.
Legacy OS/custom Go toolchains and upstream's extra OTHERS targets are outside
this six-host packaging group; their gVisor compilation proof is separate.

## Licensing and distribution blocker

Each of the 13 candidate library input rows identifies a real module version/sum,
module origin, wrapper-tree Git blob, raw SHA256 and observed native metadata.
Known license files are byte-pinned: sing-box GPL notice, Cronet module GPL notice,
full GPL-3 text, exact Naiveproxy BSD and Chromium BSD texts, and NOTICE with fixed
source addresses. The NOTICE says that complete Chromium third-party notices and
Corresponding Source/build-input closure for these prebuilt bytes are unattested.
Actual linked Go dependencies also require their applicable license/source closure.

The module package exports libraries/headers plus a wrapper LICENSE; a top-level
BSD/GPL bundle cannot identify the complete dependency graph of the prebuilt
Chromium library. No authoritative per-library build dependency/third-party
notice receipt has been supplied. Obtain that receipt for the exact bytes or
rebuild from the exact sources/toolchain while generating the actual linked
notice inventory. Do not infer closure from a moving Chromium branch, guessed
license list or archive symbol count. `publicationEligible` remains false; no
publication action exists in this slice. A future publisher must separately
verify complete licensing/source closure, source review, hosted platform outputs,
post-sign member/archive hashes and the integration owner's new version/tag.
The existing source-only D tag/release and consumer inputs remain unchanged.
