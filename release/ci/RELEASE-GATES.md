# Complete upstream matrix with explicit distribution gates

Baseline: SagerNet/sing-box dfb80349bf5779ec0a3f834c9ec2794345bff8f0. New fork: polaris-arch/sing-box-polaris, repository ID1421657509. The product source, existing gVisor/Cronet/OpenWrt patches and G4 SDK integration are retained; CI adaptation does not replace their source.

The independently added `POLARIS-BRANDING.md` and GitHub-only publisher describe the requested branded prerelease and actual unsigned-scope publication. Signing/account configuration below applies to the signed distribution entries, not the independent GitHub-only publisher.

## Implemented entries

- build.yml: manual-only unsigned full artifacts, with a pre-tag `Source` mode for the concentrated Linux/macOS G4 and CI-contract gates. All upstream CLI/client/library matrices remain. Android, Windows and macOS unsigned adapters are checked against exact upstream client git blobs and fail on unknown source. Apple store targets produce unsigned xcarchive.tar; these are build evidence, not installable IPA/pkg or store acceptance.
- linux.yml: manual unsigned repository packages; docker.yml: all nine container platforms as OCI archives (ten upstream binary build rows retained).
- signed-release.yml: complete upstream signed recipe, including signed Apple store exports. All-only GitHub publication waits for every product job including store exports and includes both binary-* and signed-apple-store-* artifacts. Explicit publish_github and publish_stores default false. Existing releases are rejected; a new draft is uploaded and API size/digests verified before publication.
- signed-linux.yml: eleven distro package rows with explicit owned Gemfury publication. publish-container.yml: full upstream image matrix with explicit owned GHCR publication. No upstream registry or package-account destination is used.
- lint.yml/test.yml and ci-contract.yml: polaris-main push/PR developer checks, no publication. G4 candidate source gates remain a separate required entry before the platform campaign.

## Native facts and consumer contract

native_release_index.py reads actual archives, validates portable safe member paths and actual hashes, parses actual raw Go buildinfo and all replacement records, and binds local replacement source trees. It verifies every row's actual GOOS/GOARCH/GOARM/GOMIPS/GO386 and exact archive identity/variant against the pinned 44-row matrix, plus each row's Linux/OpenWrt package counts.

Four separate native jobs execute the actual final-package Cronet command with pinned expected Cronet version and sidecar hash. They check gVisor/Naive/linkage/core facts. Cross-architecture rows remain smoke=null. Numeric native job IDs are obtained from the same run/attempt GitHub jobs API, not invented from GITHUB_JOB. Full index downloads only native CLI and smoke artifacts. Final evidence mode preflights the exact-source annotated tag before building, captures its object and rechecks it during assembly. Explicit staging mode always emits staging with a null tag object; publishers and consumers reject it for production.

Source tar is git archive of the exact committed kernel tree with deterministic gzip, including tracked replacements and source/license materials. Client gitlinks are not tar file content; independent source-tree validation supplements only authenticated GitHub tree gitlink entries. Legal files are actual UTF-8 source bytes with path/content/hash consistency and duplicate conflict rejection.

## Real blockers and required configuration

No owned-distribution.json is shipped: no signing identity/account information has been provided or independently verified. Every signed entry requires that reviewed public configuration, POLARIS_DISTRIBUTION_ENABLED=true, and the polaris-distribution GitHub Environment. An authorized owner must configure its intended approval/secret policy; workflow code does not establish environment protection by itself.

The public config must bind repository/id, reviewed=true, and exact client identity patch path/SHA256/client commit for each signed client. Apple additionally requires credentialMode=team, owned appId/groupId/issuerId/keyId and exact application/installer signing certificate fingerprints matching the POLARIS_* variables. Upstream app/group/certificate IDs and zero UUIDs are rejected. AuthKey filename, Go ASC helper issuer, altool issuer and notarytool issuer consistently use the reviewed owned team-key mode. Individual-key mode is deliberately blocked rather than guessed. Private keys/certificates/passwords remain in the authorized environment secret store.

Signed distributions also need reviewed owned Android/store package identities, Windows certificates, GPG identity, and the appropriate credentials. Genuine signed Apple IPA/pkg exports and store submission cannot be represented by unsigned archives. The retained xcode-27 label is evidenced as GitHub-hosted, not SagerNet-private: Polaris run 38838767067, successful component job 116774136860, reports Hosted Compute Agent/MacCloud image xcode-27-arm64 20261012.0260.1, Xcode 27.1 build 27A9275 and iPhone/simulator SDK 27.1. The same label is therefore reused without reducing the Apple matrix. Scheduling and full kernel-client builds in the new fork remain unexecuted; this is availability evidence from Polaris, not a new-fork build PASS.

GHCR version publication has a per-repository/version concurrency lock, cancel-in-progress=false, and rechecks tag absence while serialized. It does not update a mutable latest alias. GHCR does not offer an atomic create-only tag API; registry publication therefore also requires a reviewed exclusive-writer policy (registryExclusiveWriterReviewed=true and the fixed owned registryImage). If external writers remain possible, keep this entry blocked. The workflow does not promise atomic protection against independent external writers.

Before any actual publication, inspect the real new tag/source, run-bound whole-matrix outputs and signatures, and obtain the required explicit authorization. A G4 source-tag push, candidate build or source push never authorizes store/registry/release publication.

## Verification status

Only static YAML/matrix checks, parser/security fixtures and pinned unsigned overlay tests have run. No Actions workflow, platform package build, real Go compiler, Xcode runner, signing, native smoke, release upload, anonymous readback or final consumer/device acceptance ran in this environment. Earlier handoff checks were source-only. The current consolidated regression controls must execute on the reviewed candidate in remote CI. Matrix parity checks establish configuration parity only, not built artifact completeness or runtime success.


### Client source transformations and receipt

Compatibility inputs apply first. Unsigned builds then use their explicit
unsigned transformations; signed `owned_distribution.py apply` composes the
compatibility inputs with the reviewed owned identity patch in that order.
Version metadata generation follows. A late second compatibility pass is not
allowed. The owned configuration remains absent/blocked until its actual public
identities and source patch have been independently reviewed.

Each future `clientIdentityPatches.<platform>` entry must keep its existing
`path`, raw `sha256` and `clientCommit`, and include an exact `files` map. Each
file declares `baseGitBlob` (original gitlink file, null only for an explicitly
new file), `beforeSHA256` and `beforeMode` of the compatibility result,
`afterSHA256` and `afterMode` of the owned patch result, and resulting `bytes`.
Regular-file modes are `100644`/`100755`; null after identity means an explicit
deletion with zero resulting bytes. Desktop applies the same reviewed desktop
identity in the Windows/Linux producer appropriate to the actual job.

The producer records original baseline bytes once per changed file, real binary
Git diff, file before/after digests and byte counts, and source-owned identity
configuration/patch digests. The reader replays the diff and the declared
transform composition with Git and verifies actual row data; a self-declared
diff digest alone is insufficient. Unknown nonignored untracked source files
are rejected; declared new compatibility/identity files are explicitly included
in the diff. Build outputs/dependencies and secret signing credentials keep their
existing producer/secret handling and are not relabeled as source overlays.
The native core's `sourceOverlay=0` does not describe these client differences.

Limits are 64 changed source files, 1MiB original and resulting source bytes,
1MiB source diff, and 3MiB serialized client evidence. These are file/scratch
limits, not a measured process-RSS claim. No unsigned workflow consumes signing
secrets. Windows checkout uses LF with autocrlf disabled before the submodule's
first checkout, and a failed overlay command stops the step before pnpm.
`POLARIS_UNSIGNED_CLIENT=1` is confined to that unsigned Windows build/receipt;
it disables required signing in the builder and skips only daemon/native
signing, retaining their presence checks. Signed mode keeps strict signing.

Android retains both original variants and their minSDK ranges. API21/22 reject
explicit interface binding before resolving Network/loading the isolated API23
implementation. API23+ duplicates/binds/closes its own descriptor and propagates
failures. The same existing Android producer invokes the pure JVM policy tests
alongside its original assemble task; no new platform or separate CI is implied.
Actual API21/22 device execution remains distinct from those JVM policy cases.
