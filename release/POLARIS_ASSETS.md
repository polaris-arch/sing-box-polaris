# Polaris kernel and platform-library asset contract

The publisher takes its desktop workflow inputs from the
[checked producer scope](ci/publisher-upstream-scope.json). Historical tags,
archives, and receipts retain their original identities. The Android/Apple build
helper and the non-Naive presets are source capabilities. Mobile builds and
device validation use the App's separate verification flows.
See [fork maintenance](POLARIS_FORK_MAINTENANCE.md) for the original functionality,
released-baseline policy and invalidated receipt responsibilities.

## gVisor and stack selection

The upstream `sing-tun` baseline is `5c2edb183cc92eb190d41c04dedfa5519ca3e78c`.
The product's `go.mod` selects the local replacement under `third_party/sing-tun`,
including the Windows DNS changes. The product source commit identifies the
exact replacement tree.
`stack.go` selects `NewGo` for the empty stack and `go`; explicit `system`, `mixed`
and `gvisor` select their respective implementations. Compiling `with_gvisor`
provides a capability and does not change that default or the App's configuration.
`mixed` uses system TCP and gVisor UDP. Both `mixed` and `system` reject Network
Extension `includeAllNetworks`; `gvisor` and `go` remain separate choices.
Linux `multi_queue` requires the Go stack. Linux/Android, Darwin/iOS and Windows
have native gVisor TUN adapters, guarded by `with_gvisor`. Go's Android build also
selects Linux files; iOS also selects Darwin files.

All Polaris CLI release presets and the Android/Apple libbox build helper include
`with_gvisor`. The source preset `DEFAULT_BUILD_TAGS_OTHERS` also includes
`with_gvisor` and omits Cronet. The wider and legacy upstream rows belong to the
pinned upstream matrix. The Polaris release workflow uses the published CLI
matrix below.
Windows retains `with_purego`, independently: Cronet's MSVC DLL
cannot be linked by the Go MinGW CGO path at this dependency revision. Netstack's
32-bit implementations must be evaluated by compilation; Google's runsc host
restrictions do not establish restrictions of the SagerNet Netstack dependency.
The constructor regression opens no system TUN and does not prove packet routing
through a real Wintun, VpnService or Network Extension.

## Published CLI matrix

The [12.42 prerelease](https://github.com/polaris-arch/sing-box-polaris/releases/tag/v1.15.0-polaris-alpha.12.42)
contains these five desktop archives. In the filenames, `<version>` is the
archive version, for example `1.15.0-alpha.12.42`.

| OS / architecture | Cronet integration | Public filename |
|---|---|---|
| Linux amd64, arm64 | glibc, `with_purego`, sibling `libcronet.so` | `sing-box-polaris-<version>-linux-<arch>.tar.gz` |
| Windows amd64 | `with_purego`, sibling `libcronet.dll` | `sing-box-polaris-<version>-windows-amd64.zip` |
| macOS amd64, arm64 | CGO links the matching static `libcronet.a` | `sing-box-polaris-<version>-darwin-<arch>.tar.gz` |

OpenWrt `.ipk` and `.apk` packages belonged to the earlier publication matrix.
The 12.42 fw4 acceptance applies to a separately built static CLI without Naive.
Android AAR and Apple XCFramework inputs link the matching static Cronet
libraries and use separate App build and verification flows.

Android ABI names are `armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`. Android mobile
libraries are not CLI executables; Apple framework slices are not macOS CLI
binaries. Do not add a second `libcronet.so` to Android or an invented Cronet dylib
to Apple packages. The current pin supplies no Apple/Android shared Cronet library.
Windows 386 has no prebuilt Cronet DLL and is unsupported by the complete Naive
CLI preset at this pin, even if gVisor alone compiles. Linux 386/arm have Cronet
static/shared libraries but their complete CLI and purego ABI require separate
validation; do not promote them from dependency inventory alone. tvOS and other
Linux architectures are outside the established Polaris delivery matrix.

Keep internal `sing-box`/`sing-box.exe`, `libcronet.so`/`.dll`, JNI `libbox.so`,
`Libbox.framework`, ObjC/Swift modules and Go module names unchanged. The producer
run's native asset index records the executable and required sibling library in
each CLI archive. The release page provides the public archive digests.

## Cronet source, ABI and operating-system limits

Wrapper `github.com/sagernet/cronet-go` / `all` is pinned to
`4d18a60dc3a8d327065b058f92fbbfc9391b84bc`; `lib/<target>` modules to
`a1cafd93eb1f748f354378309f84de3e2d4a71e4`. Their library version is
`154.0.8037.49`. Use the exact source go.mod and go.sum, never a latest Release or
an unrelated core's tag. Record module path, pseudo-version, checksum, upstream
commit/blob identity, raw library SHA-256 and final packaged SHA-256 separately.
The wrapper commit's library blobs match the pinned module bytes; its Naiveproxy
submodule is `be1be963131154ba82761a7ed85ba426b2027319`.

CGO files call the Cronet C ABI and link `.a`; purego files register the C functions
through Dlopen/Dlsym (Unix) or LoadLibrary/GetProcAddress (Windows). The pinned
Unix loader requires 255 symbols. On Windows amd64/arm64, loader_windows.go
registers 253 C exports and loader_windows_float.go registers two additional
network-thread-priority C exports, for the same total of 255. Both include custom
engine and dialer interfaces; a version string or string count alone is not ABI proof.
The Windows imports are OS DLLs, not evidence of a bundled Visual C++ runtime.
Validate all imports on the actual supported OS; ELF DT_NEEDED, libc symbol
versions, ELF/PE machine/class and Mach-O CPU/platform/deployment commands must be
recorded from the final bytes. No arbitrary same-size or ELF BuildID exception is
allowed for a byte-hash discrepancy.

Current Darwin `.a` objects declare macOS 13, even though the dependency README
says 12. Final native link/deployment checks must use the actual objects and cannot
claim macOS 12 support. iOS objects declare iOS 15 with separate device/simulator
platforms. The libbox helper already requests macOS 13 and iOS 15. Linux glibc
builds require the actual DT_NEEDED libraries and symbol versions. The published
Windows archive requires validation on an amd64 Windows host. Any future arm64
archive would require separate validation.

## Load and package verification

For purego, the upstream runtime loader searches the executable directory then
LD_LIBRARY_PATH (Unix), DYLD_LIBRARY_PATH (Darwin), or PATH (Windows), then Unix
system directories. LoadLibrary caches its first success or failure for the
process; DLL dependent-library search is a separate OS loader operation. Each
validation runs in a fresh process with an explicit absolute library path:

```
sing-box tools cronet --library /absolute/path/libcronet.so \
  --sha256 <expected-raw-sha256> --expected-version 154.0.8037.49
```

Use `.dll` on Windows. This command checks all bytes before loading that explicit
path, registers the actual ABI, allocates an engine, reads its version, destroys
it, and emits JSON containing OS/arch, Go, linkage, library digest and the compiled
gVisor capability. It starts no engine, proxy, network connection or system TUN.
For static CLI builds use only `--expected-version`; sidecar arguments are rejected.
The diagnostic verifies fixed bytes in an immutable build/package environment;
it is not a sandbox against a concurrent hostile file replacement. It does not
change normal outbound runtime search behavior. Dynamic-loader negative checks
must run as separate subprocesses: missing path, wrong digest, wrong machine,
missing symbol, and mismatched version. A same-size changed-byte test is required.

Extract the actual archive and repeat the load/version check against the extracted
binary and sibling, with ambient loader overrides removed. Preserve exact member
paths and reject extra shared libraries, wrong architecture, traversal and broken
links. gVisor native acceptance is separate: compiled capability plus the explicit
stack constructor gate is not real packet/device acceptance.

## Provenance, licensing and signing gates

Every native producer receipt pins source commit/tree, baseline, source role,
workflow SHA/run/job, Go/gomobile/gobind, CGO, complete tags/linker flags, compiler
and effective SDK/NDK version, architecture, raw/member/final archive hashes,
Cronet module/blob identity, native ABI/dependencies and load result. Downloaded
NDK archive revision is not proof of the compiler selected by the helper.
The publisher verifies the native index and inventory before attaching the
desktop archives. GitHub records each archive digest under the unsigned
prerelease policy in [the publication settings](ci/github-release.json).
Mobile receipts additionally record all JNI or framework slice binaries and
final native link evidence. Obtain digests from built artifacts.

Package sing-box/Cronet Go wrapper GPL-3.0-or-later license/source instructions,
matching Naiveproxy/Chromium BSD license texts and all required third-party
notices. A wrapper LICENSE alone does not cover the entire Chromium dependency
graph. Binary publication stays gated on Corresponding Source and the complete
third-party notice inventory; preserve exact source links and source overlay=0.

Raw Windows DLLs at this pin have no Authenticode certificate table. Do not claim
publisher trust from a hash. If signing transforms a file, record pre-sign and
post-sign bytes and verify the final package against the post-sign receipt. macOS
CLI static Cronet needs no separate dylib signature; sign/verify the actual CLI,
helper/framework/app nested components in the consumer's established order.
Apple final PacketTunnel link, three slices, Swift/ObjC/Go native roundtrip,
package signing and real VpnService/Network Extension/device networking remain
separate gates and require the appropriate owner/window.

Old source-only release/tag deletion is deferred until all consumer references
have migrated to the verified replacement, source rebuild is proven and a full
recovery record covers Git objects and release metadata/assets. Report exact
objects and irreversible metadata loss before the integration owner obtains any
needed deletion confirmation. Creating this contract never authorizes deletion.
