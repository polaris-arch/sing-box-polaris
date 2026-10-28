# Polaris-box desktop CLI prerelease preparation

Six native targets: Linux amd64/arm64, Windows amd64/arm64 and macOS amd64/arm64.
Proposed tag: polaris-box-v1.15.0-alpha.11-2, targeting exactly
 a01da7a942b3a0dbbfdfda2bba5bd63d5bd9d932.
The embedded version is still1.15.0-alpha.11.polaris.candidate-a01da7a9.

This distribution reuses the six verified original core/Cronet binaries without
rebuilding or signing. Full268-record conservative notices, controlled source
index, finite coverage decisions and acquisition/build instructions are added.
Archive hashes are new; core/sidecar, original producer/run provenance and all
signature bytes remain identical. Original candidate flags are historical and
preserved, not relabelled as a later license/platform/device approval.

The exact271716261-byte six-platform v4 source asset is supplied beside the six
native archives, plus this note, a release receipt and SHA256SUMS (ten assets).
The source SHA256 is70ff6e51660cc8ea140a30513c42c7b842b4fdb62ba41d863b08405db63ea5ed.
Public availability is accepted only after all ten public downloads match the
fixed upload manifest; current local candidates are unpublished and await review.

Go1.25.5 builds these CLI kernels. Original Cronet libraries use their separate
fixed driver/compiler identities. Mobile alpha8 carriers and future Windows DNS
compatibility sources have distinct fingerprints and are not updated by this batch.
Distribution signing, notarization and device DNS/TUN acceptance are not asserted.

Old source-only release cleanup is a separate operation. Preserve it while any
consumer still pins its source/tag/object, and retain an approved rollback path.
