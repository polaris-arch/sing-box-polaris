# Exact desktop source and prebuilt Cronet acquisition

These six CLI kernels were built from a01da7a942b3a0dbbfdfda2bba5bd63d5bd9d932
(tree 0bd19d8461347887c884f10250a402aa85decfe6, no overlay), using Go1.25.5.
The compiled version remains 1.15.0-alpha.11.polaris.candidate-a01da7a9.
The new distribution tag is an envelope; no binary version or provenance is rewritten.

Download the corresponding source asset beside these native archives:
https://github.com/polaris-arch/polaris-box/releases/download/polaris-box-v1.15.0-alpha.11-2/polaris-box-a01-desktop-source-candidate-six-platforms-v4.tar.gz
Expected size271716261; SHA256
70ff6e51660cc8ea140a30513c42c7b842b4fdb62ba41d863b08405db63ea5ed.
This URL is proposed until publication and public readback succeed.

Verify the outer release SHA256SUMS first. Extract the source package in an
empty directory and verify its SHA256SUMS. SOURCE-INDEX.json binds the full
kernel archive,148 source module ZIPs, complete Go1.25.5 source/runtime and root
LICENSE/PATENTS/VERSION, fixed Cronet driver and two explicitly distinguished
Naiveproxy source archives,268 raw notice records, six original native receipts
and fixed producer build recipes. Candidate booleans in that historical index
remain unchanged; COVERAGE-DECISIONS.json records the later finite review boundary.

Use the source archive polaris-kernel-a01-source.tar for the kernel. The fixed
producer workflow and scripts are under build-recipes/producer-226e88/. Original
accepted Linux/Windows-amd64 receipts record producer720ead16; repaired Windows-
arm64/macOS receipts record producer226e88. Follow each actual receipt's tags,
CGO_ENABLED, ldflags, buildCommand and native library identity rather than
substituting a different platform's command. Install Go1.25.5 locally, not by
changing a shared machine's global toolchain. The module ZIPs use the Go proxy
cache layout modules/<escaped module>/@v/<version>.zip; reconstruct the download
cache with Go's matching go.sum verification or download each pinned version
from the standard Go module proxy and check its recorded h1 and ZIP SHA256.

Cronet is acquired prebuilt for every target. The fixed wrapper module is
github.com/sagernet/cronet-go@v0.0.0-20260929213745-4d18a60dc3a8.
The six library modules are github.com/sagernet/cronet-go/lib/<os>_<arch>
@v0.0.0-20260929213014-a1cafd93eb1f. Acquire the exact module with
`go mod download -json <module>@<version>` and verify the h1 and library SHA256
against the platform entry in SOURCE-INDEX.json and the original native receipt.
Linux uses its .so and Windows its .dll beside the core; macOS links its .a while
building Go. Do not compile Chromium merely to acquire an available binary.
The acquisition-module ZIP is provenance/binary transport, not engine source.

Engine corresponding source is the complete fixed Naiveproxy source at
be1be963131154ba82761a7ed85ba426b2027319 and driver at
abcdebebd23da6e74cf9c55ab63024ce66fc0f7b. Original GitHub archive export bytes and
the Git-byte-exact derivative are both retained;30 CRLF export differences are
labelled in the controlled index. The driver source and its original scripts
are supplied for optional engine rebuilding; the original build used Go1.26.8,
Clang24 development snapshot and Android NDKr24. Those identities differ from
the Go1.25.5 CLI build and mobile tools. Engine rebuilding/SDK/PGO bit-for-bit
reproduction is a separate reproducibility exercise, not the normal CLI build.

No distribution signing is added. Windows PE certificate tables are absent;
macOS amd64 is unsigned; macOS arm64's linker ad-hoc signature is preserved.
No signature trust, notarization, device TUN/DNS or mobile carrier acceptance is
asserted by this repackaging. See preserved provenance.json, distribution.json
and the release receipt for separate evidence scopes.
