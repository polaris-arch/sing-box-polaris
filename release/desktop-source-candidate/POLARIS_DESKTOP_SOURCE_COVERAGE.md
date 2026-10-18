# Six desktop source and notice coverage review

The controlled index now covers the actual six desktop targets: Linux amd64/
arm64, Windows amd64/arm64 and macOS amd64/arm64. The exact target set,
original producer/run identity, source a01/tree/overlay, native receipt bytes,
platform module membership/h1, complete actual module union, Cronet acquisition
identity and module-to-notice record bindings are validated by the packaging
helper. Final archive members are compared to those initial controlled expected
hashes, rather than newly calculated source hashes. The original three-platform
v3 archive remains immutable historical evidence; six-platform assembly has a
separate v4 name and receipt.

## Actual platform differences

The verified module union is154:148 source ZIPs and six Cronet binary-acquisition
modules. Relative to the original-three union150, the additional code module is
github.com/keybase/go-keychain v0.0.1 (source ZIP and LICENSE); Darwin amd64/arm64
and Windows arm64 add three fixed Cronet acquisition modules. All four ZIP h1
values were independently recomputed and matched actual BuildInfo and frozen
a01 go.sum. Each library remains bound to its original official Cronet artifact,
source/build-driver/Naiveproxy origin, actual library SHA256 and Git blob.

| Platform | Actual modules | Run / producer | Observed dynamic dependencies (core plus Cronet sidecar) |
| --- | ---: | --- | --- |
| linux/amd64 | 140 | 38072592310 / 720ead16 | libdl.so.2, libpthread.so.0, libc.so.6, libdl.so.2, libpthread.so.0, libm.so.6, libgcc_s.so.1, libc.so.6, ld-linux-x86-64.so.2 |
| linux/arm64 | 140 | 38072592310 / 720ead16 | libdl.so.2, libpthread.so.0, libc.so.6, libdl.so.2, libpthread.so.0, libm.so.6, libgcc_s.so.1, libc.so.6, ld-linux-aarch64.so.1 |
| windows/amd64 | 135 | 38072592310 / 720ead16 | kernel32.dll, KERNEL32.dll, ADVAPI32.dll, dbghelp.dll, WS2_32.dll, SHELL32.dll, IPHLPAPI.DLL, WINMM.dll, SHLWAPI.dll, ole32.dll, WINHTTP.dll, USER32.dll, Secur32.dll, CRYPT32.dll, api-ms-win-core-winrt-l1-1-0.dll, ntdll.dll |
| darwin/arm64 | 130 | 38074825396 / 226e88ca | /System/Library/Frameworks/Foundation.framework/Versions/C/Foundation, /System/Library/Frameworks/IOKit.framework/Versions/A/IOKit, /System/Library/Frameworks/IOUSBHost.framework/Versions/A/IOUSBHost, /usr/lib/libobjc.A.dylib, /System/Library/Frameworks/Network.framework/Versions/A/Network, /System/Library/Frameworks/Security.framework/Versions/A/Security, /usr/lib/libresolv.9.dylib, /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation, /usr/lib/libbsm.0.dylib, /usr/lib/libpmenergy.dylib, /usr/lib/libpmsample.dylib, /System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics, /System/Library/Frameworks/CoreText.framework/Versions/A/CoreText, /System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices, /System/Library/Frameworks/AppKit.framework/Versions/C/AppKit, /System/Library/Frameworks/OpenDirectory.framework/Versions/A/OpenDirectory, /System/Library/Frameworks/CFNetwork.framework/Versions/A/CFNetwork, /System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices, /System/Library/Frameworks/SystemConfiguration.framework/Versions/A/SystemConfiguration, /System/Library/Frameworks/UniformTypeIdentifiers.framework/Versions/A/UniformTypeIdentifiers, /System/Library/Frameworks/CryptoTokenKit.framework/Versions/A/CryptoTokenKit, /System/Library/Frameworks/LocalAuthentication.framework/Versions/A/LocalAuthentication, /usr/lib/libSystem.B.dylib |
| darwin/amd64 | 130 | 38074825396 / 226e88ca | /System/Library/Frameworks/Foundation.framework/Versions/C/Foundation, /System/Library/Frameworks/IOKit.framework/Versions/A/IOKit, /System/Library/Frameworks/IOUSBHost.framework/Versions/A/IOUSBHost, /usr/lib/libobjc.A.dylib, /System/Library/Frameworks/Network.framework/Versions/A/Network, /System/Library/Frameworks/Security.framework/Versions/A/Security, /usr/lib/libresolv.9.dylib, /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation, /usr/lib/libSystem.B.dylib, /usr/lib/libbsm.0.dylib, /usr/lib/libpmenergy.dylib, /usr/lib/libpmsample.dylib, /System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics, /System/Library/Frameworks/CoreText.framework/Versions/A/CoreText, /System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices, /System/Library/Frameworks/AppKit.framework/Versions/C/AppKit, /System/Library/Frameworks/OpenDirectory.framework/Versions/A/OpenDirectory, /System/Library/Frameworks/CFNetwork.framework/Versions/A/CFNetwork, /System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices, /System/Library/Frameworks/SystemConfiguration.framework/Versions/A/SystemConfiguration, /System/Library/Frameworks/UniformTypeIdentifiers.framework/Versions/A/UniformTypeIdentifiers, /System/Library/Frameworks/CryptoTokenKit.framework/Versions/A/CryptoTokenKit, /System/Library/Frameworks/LocalAuthentication.framework/Versions/A/LocalAuthentication |
| windows/arm64 | 135 | 38074825396 / 226e88ca | kernel32.dll, KERNEL32.dll, ADVAPI32.dll, dbghelp.dll, WS2_32.dll, SHELL32.dll, IPHLPAPI.DLL, WINMM.dll, SHLWAPI.dll, ole32.dll, WINHTTP.dll, USER32.dll, Secur32.dll, CRYPT32.dll, api-ms-win-core-winrt-l1-1-0.dll, ntdll.dll |

These are actual dependency observations, not additional bundled payload files.
The downloaded archive member lists contain the core and, on Linux/Windows,
the fixed Cronet sidecar; macOS statically links the fixed .a into the core.
The original six binary archives still contain only six primary license files.
They have not adopted the268-record notice superset or this source index.
New notice adoption requires reviewed packaging and new final archive/member
receipts. Old archive/core hashes and producer identities must remain truthful.

## Conservative source preservation versus notice applicability

Kernel source: the a01 Git archive preserves all1689 tracked blobs and modes.
Unused client Gitlinks are retained as metadata and are not CLI compilation
inputs. All148 source module ZIPs preserve complete distribution bytes, including
inline headers, nested licenses, generated code and go:embed inputs that those
modules contain; their ZIP SHA256/h1 and actual native membership are fixed.
Six acquisition module ZIPs are provenance records, not Chromium source.
The Cronet Go wrapper is one of the source ZIPs.

Cronet engine/driver: the full fixed Naiveproxy source contains all35452 tracked
blobs/modes, including nested third_party, source-header notices, generator code,
templates and tracked generated outputs. Retain original GitHub archive bytes
and the separately labelled Git-byte-exact derived archive with30 documented
CRLF export differences. The driver archive preserves its133 tracked blobs/modes.
These full source archives are a conservative superset of candidate source
components. They do not establish the original six-target link map or recover
untracked generated outputs from the original build. The metadata-only Linux
GN reconstruction classifies386 candidate-code targets and239 tool/generation
targets per root; actions/executables in the625-target superset are not silently
labelled runtime code. Shared runtime/tool code remains conservatively included.

Go standard-library/runtime: derive the complete Go1.25.5 src tree plus root
LICENSE/PATENTS/VERSION from a privately snapshotted ZIP whose SHA256 equals the
controlled toolchain input. Preserve ZIP file modes and all contained source,
nested notices and generated data. The ZIP also contains tool/compiler source;
that does not make compiler binaries part of the shipped kernel payload.

Curated compiler-rt: retain the actual be1 source and the two commented assertion
lines in atomic.c, along with pinned upstream comparison and LICENSE/README.
Its source-header Apache-2.0 WITH LLVM-exception is distinct from any additional
compiler-injected runtime. The latter remains bounded by original Clang/build
metadata and actual imports/object observations; it is not automatically proved
covered by the three curated compiler-rt files. Imported OS libraries/frameworks
are distinguished from bundled/runtime code. Applicability and any required
additional runtime source/notices must be assessed by the independent reviewer.
Compiler/SDK/PGO binary byte reproducibility is tracked separately and is not a
blanket requirement to archive every compiler binary before desktop publication.

The268-record notice text is a controlled conservative filename/README selection,
with raw byte offsets, lengths, SHA256 and module/engine source bindings. Full
source archives preserve additional inline/nested/generated texts for review.
Neither that selection nor matching raw hashes alone proves applicable notice
completeness. Original link-map absence, platform generated/runtime differences
and applicability remain explicit review boundaries. Complete Corresponding
Source/Third-Party-Notices and publicationEligible are not declared true here.

## Desktop acceptance and mobile acceptance are separate

Desktop publication preparation requires independent review of applicable
source/runtime/notice coverage, source and acquisition/build instructions, final
native package adoption of the approved inputs, actual new archive/member hashes,
and stable public delivery of the exact bounded source asset. The source asset
can be uploaded beside the six native packages in the same new prerelease after
the materials and publication flow are reviewed; nothing is uploaded publicly
by this preparation. The current candidate source and publication plan are
retained locally with their actual hashes.

Android AAR and Apple libbox carriers, gomobile/NDK alignment, signing/device
network checks and their final link/load/byte acceptance form separate batches.
They are not prerequisites for publishing these six desktop CLI packages.
A future Windows DNS compatibility source change also has a new source identity;
these a01 receipts remain the baseline and are never relabelled.
