# Polaris-box production distribution contract

The new planned title/version is `1.15.0-alpha.12`, tag `v1.15.0-alpha.12`. The core-reported version, archive name/root, package source identity and asset index align with that version. The existing `v1.15.0-alpha.12.polaris.1` release remains immutable while the active Polaris consumer migrates. Do not move its tag or relabel its original bytes.

This batch covers six desktop CLI archives and four OpenWrt packages. The four existing App targets remain Linux amd64 (`linux`), Windows amd64 (`win`), macOS amd64 (`mac-x64`) and macOS arm64 (`mac-arm64`). Extra Linux/Windows ARM64 CLI rows and OpenWrt rows do not create new App targets. Mobile AAR/XCFramework, other upstream architecture variants, upstream client applications and final Polaris carriers are separate agreed scopes.

## Layout and capabilities

Desktop roots are exactly `polaris-box-<version>-<os>-<arch>`. Linux/macOS use `.tar.gz`; Windows `.zip`; executables remain `sing-box` / `sing-box.exe`. Linux/Windows include the fixed prebuilt Cronet `.so` / `.dll` in the same archive. macOS statically links its fixed prebuilt Cronet archive. All six cores are freshly built from the actual final source, Go1.25.5, exact full feature tags and measured source-derived BuildID. The original module name, 256-file modified local sing-tun source and existing Polaris patches remain intact. Windows replacement regressions retain full-package vet and the seven existing platform tests.

OpenWrt assets are `polaris-box-<version>-openwrt-<architecture>.ipk/.apk`. Architectures are `x86_64` (GOAMD64=v1) and `aarch64_generic` (GOARM64=v8.0). IPK targets OpenWrt24.10/opkg; APK targets25.12/apk3. The fixed musl `.a` is linked with CGO1, `with_musl`, `with_naive_outbound`, `with_gvisor` and the existing full preset; `with_purego` is forbidden. Clang CC/CXX use the exact OpenWrt target/sysroot and LLD contract; SDK, Clang archive, GCC runtime/musl and Cronet pins are source-owned. No Chromium rebuild, desktop glibc library or OpenSSL replacement is used. [OpenWrt installation and migration](POLARIS_OPENWRT.md) documents dependencies, explicit conflicts, disabled defaults, configuration retention and recovery.

## Whole-batch remote validation

Polaris-box already has remote CI. Complete the batch's feature/interface/build/package/publisher code together, then commit/push once to the authorized batch branch. Review the whole candidate and aggregate issues; complete related corrections before the next unified verification. Compiler failures, including interface/design errors, have no single-change build/test/CI exception. Do not compile locally or start per-feature CI. Existing valid runs remain untouched; final necessary gates still require the accurate candidate SHA.

The manual production workflow runs the Python/source contract suite, six native desktop builds, two actual static musl core/package builds, four official isolated OpenWrt guest lifecycle/runtime gates and same-run assembly. Each core requires clean standalone source and actual BuildInfo/BuildID. Guests verify generic CPU profiles, official kernel/root hashes, real package dependencies, explicit 0:0 archive/control/directory ownership, conflict rejection, true old-prerm→new-preinst active upgrade/configuration retention/removal/reinstall, procd, CA-bundle, real Naive TLS-H2 plus wrong-CA rejection, and actual gVisor TUN traffic. User-mode VM networking is isolated; no physical device, host TAP or host routes are changed. Actual guest checks do not certify every board/CPU or replace physical-device acceptance.

IPK uses host fakeroot for numeric root ownership. APK uses the SDK-native account database to map the private staging UID/GID to root names; its bundled loader never inherits a host GLIBC preload. Final IPK tar/APK ADB metadata and all installed paths still require root ownership. This preserves the pinned SDK and leaves system toolchains unchanged.

The aggregate index keeps `platforms` as the original six desktop producer rows and records OpenWrt separately in `openwrtPlatforms`. Same source/tree/version/run/attempt and actual archive/core/package bytes must match. Formal native CI cannot be replaced by old local fixtures or historical green runs. Candidate publication remains false until the parent approves the whole source/license/layout and actual output batch.

## CI scheduling and runner resource admission

The manual whole-batch entry retains its non-cancelling production concurrency group and optional main-only provenance gate. `plan` emits the same eight allowlisted inputs in two lanes. Six desktop calls and two OpenWrt calls share one internal native workflow, the same exact checkout SHA, existing runner labels, Go/library/toolchain pins, artifact names and build/diagnostic checks. There is no fixed cross-runner `max-parallel`; GitHub's existing account capacity schedules these separate hosted machines. No larger/paid runner or permission is added.

OpenWrt guests need only `plan` and both OpenWrt producers, and can run while desktop compilation continues. The final `assemble` job still needs **all six desktops, both OpenWrt producers and all four guests**. Same-run source/tree/attempt, package/core/archive hashes, source availability and optional attestation are unchanged. This is one whole-batch validation DAG, not partial acceptance or per-platform dispatch.

`polaris_runner_resources.py` measures the current runner's effective CPU count/affinity (and Linux root cgroup quota), CPU load, available memory and free scratch disk. Windows uses physical available memory plus a short idle/kernel/user CPU sample; macOS uses its actual VM page size and free + inactive + speculative pages. Apple vm_stat subtracts speculative from displayed free, so speculative is added back exactly once; purgeable is not added. Linux only reads visible root cgroup v2 files; nested cgroups/v1 limits are not guaranteed. Admission subtracts headroom estimates of max(1 GiB, 20% of measured physical/root-limited memory) and 2 GiB free disk, with working-space estimates of 4 GiB desktop, 8 GiB OpenWrt, 3 GiB self-check and 1 GiB contracts. A package worker budgets 2 GiB memory. Invalid metrics retain the original error and remain an implementation failure. Low sampled memory or estimated working-space pressure selects the existing single-package lane and is logged, rather than treating a guessed 2 GiB worker cost as a new capacity prerequisite. The 2 GiB estimate and all headroom figures stay unchanged; they limit extra parallel workers, not the known working serial build. Actual compilation, OS/resource failures and all product gates remain failures. These are sampled admission estimates, not atomic memory/disk reservations, measured peak guarantees or a fleet-wide load controller. A busy/single-CPU machine admits one worker; otherwise one CPU and observed load are kept outside the worker budget.

Production retains its strictly verified `go build/test -p 1` commands. `POLARIS_COMPILE_GOMAXPROCS` bounds the actual build subprocess only; native regression processes keep their prior GOMAXPROCS=2 environment. Self-check caps package jobs via process-local `GOFLAGS` and explicit `-p`, applying its compile GOMAXPROCS only to build/run/install commands. It never exports job-wide GOMAXPROCS: race, monitor, patch and optional instance tests keep their original Go default/inherited multi-P runtime, default `-parallel`, and the explicit iOS `-parallel 2`. Compilers inside `go test` share its runtime environment; package-level concurrency is capped, without changing test semantics. There is no global Go setting or SDK change. Native failure handoffs include the runner-budget JSON; success and rejected admission both print the same bounded, secret-free resource JSON into original logs before attempting the scratch write, so observation is retained even if that write fails. Self-check logs distinguish workflow/source/tool identity. Current source and workflow commits remain distinct in manual historical-source checks: the helper is read from the fixed workflow Git object into runner scratch, not overlaid onto the source checkout.

Historical capacity evidence and peak observations are separate. The same standard `macos-15` 3-CPU/7-GiB runner class successfully built the 577d native ARM core with the original `-p 1`; the three `macos-latest` Apple self-checks also succeeded on 577d. The VMs are ephemeral, so this is same runner class, not the identical physical VM. Their original complete logs contain no maximum-RSS measurement; no historical peak can be inferred from success or a current free-page sample. This candidate records macOS `/usr/bin/time -l` workload max-RSS in the **next necessary existing build/test jobs**, without a benchmark or extra platform dispatch. The OS-reported maximum is not a simultaneous sum of descendant RSS. The raw `vm_stat` snapshot is retained alongside the conservative free+inactive+speculative estimate; active/purgeable/cache/compression reclaim behavior is not guessed into extra available memory. Visible Linux root cgroup limits and Mac VM capacity are not relabelled as per-process hard limits.

Only future automatic **branch-tip** self-checks share the branch cancellation group. Manual fixed-source audits and tag milestones have run-specific groups and are not cancelled by another tip or input mode. All original full/desktop/mobile, symbol, baseline, patch-only and instance-test controls remain. Production and self-check answer different questions; the latter is not deleted. The observed `52b512` manual and push runs had equivalent visible test scope, but represented pre-integration and post-integration evidence on different refs; this change does not suppress either required gate solely because their source SHA matches.

Historical timing evidence (not a new benchmark): run38275593790 took 57m58s; eight native jobs totalled 88m13s, with a 47m31s native barrier and a 21m42s Darwin/amd64 job. Four guests then added 8m08s before 1m44s assembly. Replaying the original job durations with independent runner availability and the new dependency graph gives approximately 24 minutes, versus about 40 minutes for merely increasing the old native matrix cap to four. This is a counterfactual critical-path estimate, **not a promised elapsed time**: account/OS queueing, the newly measured per-runner thread budget, cache/network/SDK variation and optional attestation require a reviewed exact-source remote run. Existing published assets and tag remain immutable; any new candidate has its own source/provider/BuildID evidence and cannot reuse old successful receipts.

## Corresponding source

No separately uploaded source package is generated. Automatic GitHub Source code archives provide the fixed product source, including the complete modified replacement. `sourceDelivery` provides exact public Go module ZIP/h1 pins, Go distribution source, fixed driver/engine Git trees (including gitlink and archive omissions), and GCC/musl sources with the exact OpenWrt source/patch tree and runtime exception. Same-run assembly verifies full module/source bytes and exact Git blobs. The fixed thirty CRLF/export exceptions are handled before member validation with exact path/raw SHA/Git blob pins; other differences are rejected. The distributor remains responsible for equivalent copying access and ongoing availability under applicable licenses. A homepage or prebuilt-library ZIP alone does not supply the engine's corresponding source.

## Explicit publication

The build workflow has read-only repository permissions and never tags or publishes. After whole-batch review of the actual final index and required source/platform outputs, retain the parent's actual review message as raw, hash-pinned evidence bound to the exact source/index. Do not manufacture an approval JSON from CI success. Parent source/license/artifact review is recorded in its actual scope. App-owner contract signoff remains pending unless a separate actual, hash-pinned owner message binds this source/version/tag; it cannot be inferred from the parent source review. `polaris_production_publish.py prepare` freezes exactly twelve upload assets: six desktop archives, four OpenWrt packages, `polaris-box-assets.json`, `SHA256SUMS`. It prepares an annotated tag object and title `1.15.0-alpha.12`; no remote write occurs during preparation.

Explicit `stage-draft` creates only the new exact tag and draft, `resume-*` uploads missing immutable assets only. Draft metadata may use one observed bounded GitHub `untagged-<hex>` URL component; repository/name/ID/digest and tag-object identity remain strict. `publish` PATCH explicitly pins `tag_name` and source `target_commitish`, requires the exact complete inspected draft, and public URLs must all be canonical. All twelve final public assets are downloaded anonymously and checked in full against the frozen expected sizes/hashes; release/asset IDs and canonical URLs are captured with tag/source/tree before and after readback. `consumerContract` projects the original four App rows with actual published index/asset IDs and keeps App/mobile/device/signature trust pending. New production App pins are separately owned by the App integrator and must originate from these final bytes.

Existing in-use tags/releases remain available until the actual consumer migration closes. No automatic cleanup, tag movement, upstream write, deployment or physical-network change is part of this producer/publisher.


## Complete CI workflow coverage and acquisition efficiency

The reviewed `a635e534` scheduling baseline remains intact. Its complete successful
production run measured 24m14s versus the original 57m58s; different temporary
hosted machines and times prevent treating that comparison as a controlled
benchmark. The eight native inputs, independent OpenWrt guest dependency, resource
fallback and self-check tip/audit cancellation groups are retained.

All eleven current workflows are accounted for below. Retention is an explicit
coverage decision, not an omitted flow. The six inherited files remain byte
identical to `a635e534`; their GitHub API state at this batch's inventory was
`disabled_manually`. This batch does not enable them or change their publishing,
maintenance, credentials or permissions. Source `build.yml` and `docs/changelog.md`
continue to require the exact upstream blobs in production admission.

| Workflow | Purpose and decision |
| --- | --- |
| `build.yml` | stable/testing/unstable and thirteen manual build choices; 38 binary variants, mobile libraries and external client/signing/publication inputs differ from Polaris production. Retain unchanged. |
| `lint.yml` | four upstream PR/push branches and ten target lint profiles using their original toolchain. Retain; not a duplicate of polaris-main self-check. |
| `test.yml` | four upstream PR/push branches, three OS x two Go versions, different tags and privileged/native tests. Retain all compatibility coverage. |
| `docker.yml` | release/manual image publication; all jobs are SagerNet-only and skipped on this fork. Retain unchanged; no fork runner saving to claim. |
| `linux.yml` | upstream signed Linux packages; all jobs are SagerNet-only and skipped on this fork. Retain unchanged. |
| `stale.yml` | scheduled issue/PR maintenance without compilation. Retain behavior and disabled state. |
| `polaris-native-candidate.yml` | historical manual selected targets from fixed a01 source, original cap2 and native/package checks. Keep inputs; add bounded pending queue, deadline and failure observations. |
| `polaris-dns-native-candidate.yml` | historical manual four-core DNS diagnostics from fixed aafc source, original cap1/mocks/Cronet/BuildInfo checks. Keep inputs; add bounded pending queue, deadline and observations. |
| `polaris-selfcheck.yml` | current or historical source/role/symbol/baseline/instance checks. Keep real execution; cache only the fixed NDK archive, classify narrowly audited prose on automatic main tips, preserve bounded observations on every path. |
| `polaris-production-native.yml` | same-source six desktop and two musl producers. Restore/save only byte-pinned SDK/Clang archives, freshly extract and reverify; all actual build/native/package/source checks remain. Stream handoff hashes and preserve observations outside the archives. |
| `polaris-production-release.yml` | whole contracts, eight native producers, four guests, exact same-run twelve assets/source checks and optional main-only attestation. Keep all gates; bounded pending queue, command observations and zero outer compression for already-compressed final archives. |

### Cache authority and finite inputs

Only immutable compressed acquisition inputs are added to the cache: one NDK
archive, three OpenWrt SDK archives and one common Clang archive. Keys bind the
actual content SHA-256, host OS and architecture; no source SHA creates another
copy of an identical download. The common APK-host SDK and Clang archive share
their content keys across the two OpenWrt targets. NDK is bounded at2GiB, each SDK
at512MiB and Clang at its exact56,889,948 bytes. Cache hits never stand in for
compilation, test success, raw binary identity, a producer receipt or public source
availability. SDK/Clang consumers still hash the archives and extract into fresh
private roots; NDK is hashed before fresh unzip. No extracted compiler, patched
GOROOT, success result or current-run handoff is cached.

The existing setup-go implementation remains pinned and its dependency inputs
explicitly include the root and local replacement go.mod/go.sum. Its compiler
cache remains governed by Go's actual tool/input IDs; original -count=1/race,
tags and instance opt-in tests are not skipped on a hit. Optional input-cache
restore/save failures fall back to the original verified acquisition path; an
actual corrupt cached input fails before use; regular failed bytes within the declared archive limits are retained, and oversized/nonregular retention gaps are explicitly recorded. Source/network
availability gates always make their original fresh public reads.

The current repository cache inventory was21 entries/8,362,233,928 bytes. This
batch adds at most five keys for the current pinned archives and does not raise
paid cache limits, delete another owner’s evidence, add a cache-GC permission or
build a cache service. Existing GitHub cache scope/quota/eviction rules still
apply. Cold/warm/corrupt/missing/oversized/symlink controls are part of the one
whole contract gate; they do not certify an unmeasured warm-run speedup.

### Conservative prose classification

Only `release/POLARIS_PRODUCTION_RELEASE.md`, an instruction guide not read by the
runtime/build/schema/install or NOTICE generators, is currently allowlisted for
skipping Go jobs on an automatic `polaris-main` push. The classification job and
its negative controls still execute. All other docs and Markdown, including the
licensed root README, docs schemas/install scripts, NOTICE/LICENSE, source-owned
release inputs/licenses, Go modules/replacement, workflows and unknown paths,
require full validation. Missing/forced/deleted/malformed context, unavailable
before objects, dirty checkout, unsafe file modes, non-prose or possible Go embed
inputs also keep full validation. Manual audits, tags, source-role/symbol/base
changes and instance opt-in always preserve the original applicable Go jobs.
Production/attestation never use this prose classification to omit a gate.

### Deadlines, observations and fixed pending inputs

Each owned command keeps its original shell, arguments and environment inside an
observed phase; it is not replaced by a cached result. Bounded periodic heartbeats
and stdout/stderr streaming make a long phase observable. Per-command deadlines
leave time inside the job budget to preserve failure evidence. Failure codes and
cancel signals propagate. Only the invocation's own POSIX process group or
Windows PID tree is terminated; this is not a global process/image kill.

The extra command artifact retains a32MiB prefix with its truncation status while
the original GitHub job log receives the complete stream and the observer hashes
all bytes. OS child ru_maxrss (Unix) or direct-child peak working set (Windows)
is recorded when available, null otherwise; neither is simultaneous descendant
RSS sum nor a continuous memory reservation. The existing per-runner compile
budget and test runtime policy are unchanged. Observations are outside product
archives and never rewrite producer/provider/raw signature identities.

Three fixed manual workflows use the official `queue: max` with cancellation
false, allowing up to100pending submissions per ref group. A full queue cancels
excess requests; FIFO is based on beginning to wait, not dispatch ordering.
Self-check's existing run-specific fixed-audit and replaceable automatic-tip
concurrency groups remain unchanged. No extra runs are dispatched merely to
benchmark caching/queueing. In-flight accurate runs are not cancelled or relabeled.

The complete implementation is reviewed once as a whole candidate and validated
with the necessary exact-source remote gates. No local compile/project tests,
per-item CI, release/tag changes, paid runners or permission expansion accompany
this efficiency batch. Formal App/mobile carriers, real devices, distribution
signature trust and mesh root cause remain separately owned acceptance boundaries.

### Consolidated f08f review correction controls

All five owned workflows execute the generated command with
`bash --noprofile --norc -e -o pipefail`; strictness applies to the actual child,
including baseline checks and test pipelines. Guest receipts and both historical
candidate archives retain their original upload roots. Command observations use
separate artifacts so the assembler still reads exactly four
`artifact-name/guest-receipt.json` files with the same source/tree/run/attempt.
The production join keeps all original package/core and eleven guest behavior checks.

A shared monotonic job clock starts before checkout/preparation. Each command
receives the lesser of its phase cap and the remaining original job time minus
the evidence reserve and 60-second safety margin. Patch phases share the 90-minute
job; iOS phases share 120 minutes. Native reserves 30 minutes for archive recheck,
failed-input preservation, handoff and upload; Android reserves 25 minutes for
symbol/naming and AAR/observation uploads; guests reserve 10 minutes for their two
uploads, other observed jobs reserve 15 minutes. Original job deadlines remain
unchanged. Preparation steps have explicit caps. Every optional archive cache
restore/save gets a fresh remaining-budget probe (at most two minutes); saves
follow successful mandatory evidence upload, even when the producer failed.
Timeout/cancellation of the GitHub runner itself still depends on GitHub always-step
scheduling; the reserve is not a guarantee against runner loss or service failure.

The observer uses a bounded reader queue and bounded drain, rather than waiting
indefinitely for pipe EOF. POSIX cleanup checks the owned group after leader exit,
interrupts first for existing producer finally cleanup, then escalates within a
finite interval. Windows assigns a bootstrap to a private kill-on-close Job Object
before permitting the original command, retaining ownership when its parent exits.
Incomplete tree cleanup or drain fails explicitly; no global PID/image kill.
Windows memory observation identifies the owned bootstrap only, not the native
compiler or simultaneous process-tree RSS.
The cleanup/drain budget is 15 seconds, separate from the command grant. Windows
controls also run on the actual selfcheck Windows host, outside historical source.
This uses the documented [Windows Job Object process-tree contract](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

Impact enumeration uses NUL-separated Git paths, including Unicode Go filenames.
Go embed character classes remain full validation because Python fnmatch and
Go path.Match classes differ; no uncertain pattern exempts compilation. Cache
validation and failure preservation independently lstat the complete ancestor
chain before reading; symlink/reparse ancestry produces metadata only. Safe
regular hash/size failures remain preservable within the original byte limit.

Controls cover strict-shell fail/pipeline/baseline stops, real ZIP common-root
projection and exact four same-run receipts (plus wrong run/attempt/source/tree),
leader-exit/held-pipe descendants including Windows, incomplete cleanup, EOF
without process exit, shared short two-phase budget and slow-cache reserve,
Unicode embed, Go negated classes, ancestor links and safe bad-byte preservation.
They are source candidates until the reviewed exact SHA runs the unified remote
whole-batch and full selfcheck gates. No local tests/builds or per-finding CI.

### Explicit runner Bash after the e35 Windows execution failure

All owned command wrappers bind the actual enclosing Bash executable (`$BASH`)
at job start and carry it through `POLARIS_RUNNER_BASH`. Windows converts that
path using bundled `cygpath -w` before passing it to native Python. The observer
receives the absolute executable, never a bare `bash` name resolved via Windows
PATH (which selected the WSL shim in e35). Strict child `-e -o pipefail`, original
script bodies, budgets, process ownership and all formal gates remain unchanged.
No WSL distribution installation or upgrade is required.

The Windows observer gate adds an actual-script control with a space-containing
path and System32 ahead of PATH. The script's marker must be observed before
false/pipeline/wrong-baseline failures, and post-failure markers must be absent.
The original POSIX strict/signal/detached-owner controls still skip on Windows;
the new Windows-specific strict execution control runs there and skips on Linux.
The platform shell contract is documented by
[GitHub Actions shell selection](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idstepsshell)
and [MSYS2 native path conversion](https://www.msys2.org/docs/filesystem-paths/).
This repair is source-only until its reviewed exact SHA passes both unified gates;
e35 partial platform successes remain attributed to e35.
