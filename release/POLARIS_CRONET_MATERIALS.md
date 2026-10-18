# Fixed Cronet and desktop source/notice review inputs

The current native archives contain six primary license files. This materials
slice freezes a conservative source/notice candidate and offline assembly
recipe for independent review. It does not change the native producer,
product source, package contents, licenseClosure, or publicationEligible.
The product source remains a01da7a942b3a0dbbfdfda2bba5bd63d5bd9d932,
tree 0bd19d8461347887c884f10250a402aa85decfe6, overlay 0.
This materials branch is not a CI dispatch target.

## Actual native receipts

The original run 38072592310 from producer 720ead161c71415e23f38a82c29d314a4754ab9c
passed Linux amd64/arm64 and Windows amd64. The affected-platform repair run
38074825396 from producer 226e88cab62b8818620668a28b496d833c01c953 passed
Windows arm64 and macOS amd64/arm64. Each platform retains its actual run,
producer, source, module list, artifact digest, archive hash and core hash in
polaris-six-native-actual-receipts.json. Do not repin the old three to producer 226.
All six actual archive core headers were independently parsed as ELF, PE or
Mach-O with their expected architecture; polaris-six-core-header-verification.json
records those results. Hosted initial-load and extracted-archive reload smoke
checks passed. These checks do not establish device networking, signing, mobile
carrier acceptance, or source/notice publication completeness.

Existing prebuilt libraries are downloaded and verified. Linux/Windows use
.so/.dll; macOS links the supplied .a while compiling only the Go kernel.
No Cronet/Chromium rebuild or global tool upgrade was performed.

## Recovered original Cronet lineage

Library origin a1cafd93eb1f748f354378309f84de3e2d4a71e4 records the fixed
build-driver source abcdebebd23da6e74cf9c55ab63024ce66fc0f7b. Its Naiveproxy
Gitlink is be1be963131154ba82761a7ed85ba426b2027319.
[Official build run 36628634540](https://github.com/SagerNet/cronet-go/actions/runs/36628634540)
has that exact source head. Workflow Git blob 111a69ef1985b39ca6c4dd8f9d2658c460d1e618
and publish logs bind the library and wrapper 4d18a60dc3a8d327065b058f92fbbfc9391b84bc.
All 13 selected official artifact digests and library SHA256/Git blobs were
verified. Their archives contain library/include/Go files but no notice bundle,
GN arguments, original link graph, SBOM or attestation. That original run does
not substitute for the Polaris native receipts above.

## Source-byte preservation

The fixed Naiveproxy tree contains 35452 tracked blobs and no Gitlinks.
The original GitHub archive contains 30 CRLF export differences in zstd Windows
project files. Preserve its exact original bytes and mismatches. A separately
labelled derived archive restores only bytes that match the fixed Git blobs;
all 35452 blobs/modes then match. The original driver archive matches 133 tracked
blobs/modes. The fixed kernel archive matches 1689 blobs/modes; its three unused
client Gitlinks remain metadata and do not become desktop CLI source dependencies.
Both original and derived archives are retained in the bounded source candidate.

The compiler-rt comparison is now concrete: curated atomic.c comments out one
_Static_assert spanning two lines; assembly.h and int_endianness.h match the
pinned upstream bytes. The actual curated source and patch are retained, rather
than replacing that source with the upstream file. Its headers carry Apache-2.0
WITH LLVM-exception. The recovered pinned LICENSE.TXT and Chromium README are
conservative notice inputs. Compiler-injected runtime and this explicitly
curated component are tracked separately; a source difference alone does not
establish a license gap. See desktop-source-candidate/evidence/compiler-rt-difference-investigation.json.

## Bounded candidate and controlled inputs

The retained historical original-three-platform source union has 150 actual BuildInfo modules:
147 source ZIPs and three Cronet binary-acquisition modules. All source ZIP h1
values were independently recomputed and matched BuildInfo plus the fixed a01
go.sum. The new six-platform union is 154: keybase/go-keychain and three additional
Cronet acquisition modules are now incorporated into the controlled index and
separate v4 source package, retaining their verified ZIP SHA256/h1 bindings.

The historical three-platform v3 notice text has 264 raw records: 185 module
filename candidates, 71 curated-engine texts/README metadata, five supplemental
upstream files, one compiler-rt README, and Go LICENSE/PATENTS. Raw byte offsets,
lengths and SHA256s are indexed, including CRLF bytes preserved by .gitattributes.
The index provides per-platform module, library acquisition and source bindings.
It is a candidate superset, not a claim that all these components are linked or
that every applicable notice has already been identified.

The offline helper scripts/polaris_desktop_source_candidate.py validates each
controlled notice slice, source archive, module ZIP, recipe and frozen native
receipt before assembly. It rejects mismatched hashes, traversal, escaping
symlinks, duplicate package names and reuse of an existing output directory.
The retained v3 package is actually assembled by this helper, bounded below 300 MB,
and independently verified against every one of its 170 members and SHA256SUMS.
The immutable historical v3 filename, byte size and SHA256 remain in
desktop-source-candidate/bounded-source-package-receipt-v3.json. The current six
platform controlled input has 268 records and 148 source ZIPs; the actual v4
member count/size/hash is in bounded-source-package-receipt-v4.json.
It contains 147 source ZIPs, exact kernel/driver/Naiveproxy source, derived Go 1.25.5
standard-library source, notice text, compiler-rt investigation, three original
native receipts and ten exact producer 226 build-recipe files. Library binary
ZIPs are acquisition records and are not labelled Chromium source.
Large source/archive bytes stay outside Git. Local retention does not supply a
stable public source download; public delivery is still pending review.

For validation use Python3.11+ with the saved source evidence/cache inputs:

```sh
python3 scripts/polaris_desktop_source_candidate.py \
  --evidence-root /path/to/retained-evidence \
  --stage-dir release/desktop-source-candidate \
  --module-cache /path/to/go/pkg/mod/cache/download \
  --go-toolchain-zip /path/to/go1.25.5-toolchain.zip \
  --validate-only
```

For assembly replace --validate-only with --output-dir pointing to a fresh
output directory outside this checkout. No network or compilation is involved.
The saved producer recipes and actual receipts supply Go 1.25.5, exact tags,
ldflags, build commands and prebuilt library identities. The original Cronet
build-driver source documents upstream construction, including original
Go 1.26.8, Clang llvmorg-24-init-3796-g20e97c4b-27 and mobile-library NDK r24.
These versions do not describe current Go/gomobile or final-carrier NDK inputs.

## Graph interpretation and remaining acceptance

The reconstructed Linux amd64 cronet/cronet_static metadata graph is a 625-target
superset with 5329 source paths. Each root is structurally partitioned into 386
candidate linked-code targets and 239 tool/generation targets, stopping at action,
copy and executable boundaries. Shared runtime/tool code remains a candidate
runtime component. This is a heuristic on a reconstruction, not the original
link map of the 13 library builds. Perfetto/protobuf supplemental notice source
bindings are preserved; other host graphs remain unverified. OS imports are
runtime dependencies unless actual payload contains them; do not equate system
libraries with bundled files. Compiler/SDK/PGO binary reproducibility is distinct
from applicable shipped-code/source/notice obligations and is not a blanket
requirement to archive every compiler binary before desktop publication.

Independent review must assess applicable notices/runtime coverage and the
updated six-platform controlled input/assembly recipe. See the explicit
inline/nested/generated/runtime and platform boundaries in
desktop-source-candidate/POLARIS_DESKTOP_SOURCE_COVERAGE.md. After review, adopt the
notice input in packaging and verify the new actual archive bytes; do not flip
publicationEligible or relabel existing archives. Retain a bounded source package
at a stable public download location with reviewed build/acquisition instructions.
The original link-map gap remains explicit and may be bounded by fixed official
run/source/library provenance plus a conservative reviewed superset. This is not
a legal compliance guarantee. Android/Apple final carriers, NDK and load/byte
acceptance form a separate batch and do not block these six desktop CLI results.
No release, tag, deployment or device network change is made by this materials
slice. publicationEligible remains false.

## Six-platform increment and desktop publication preparation

The updated helper validates the exact six-target set and receipt/module/notice
bindings, not merely a count of successful platforms. The four additional modules,
three raw repair receipts and four new raw notice slices expand the actual scope
to all six desktop targets. Final members are checked against frozen expected
hashes; a deterministic post-preflight same-length source replacement is rejected.
The old v3 bytes are never overwritten or presented as six-platform source.

Stable public source delivery can use one bounded source asset beside all six
native packages in the same new prerelease, after independent materials and
publication-flow review. This slice only prepares source/notice inputs and the
local asset. Existing native archives still carry only six primary licenses;
reviewed notice adoption and final new archive/member checks remain necessary.
Android/Apple final carriers and NDK/gomobile validation are separate batches
and do not block the six desktop CLI publication gate.
