# Ghostty finite native-source and notice increment

Scope: the already-observed iOS arm64 `libghostty.a` in the fixed `GhosttyKit.xcframework.zip` release. Its 167 ar members comprise 166 object members and one archive symbol index. Every member name has a bounded source-family/recipe correspondence. This is **not** a complete client runtime BOM, final-Mach-O retention proof, reproducible-build attestation, or legal-compliance certification. The earlier client-runtime frozen delivery is unchanged.

## Fixed evidence chain

- Swift wrapper package revision: `cffef22c16dd61d22ebef539ae2ff1624db77363` in [Lakr233/libghostty-spm](https://github.com/Lakr233/libghostty-spm/tree/cffef22c16dd61d22ebef539ae2ff1624db77363).
- Binary release: [upstream.35a81a980bb9](https://github.com/Lakr233/libghostty-spm/releases/tag/upstream.35a81a980bb9). The asset tag resolves to wrapper `e037035e17ce07618d48e70b1282ffdca01c318e`; the retained key workflow, scripts, 18 patches and license match the package revision by Git blob.
- Ghostty upstream: [`35a81a980bb9fce09a1ea762a68b55f8eb3477ed`](https://github.com/ghostty-org/ghostty/tree/35a81a980bb9fce09a1ea762a68b55f8eb3477ed). Fixed `Ghostty.ref`, root/package `.zon` manifests and actual build recipes are retained.
- Package.swift expected ZIP SHA256: `80e9bbfc89f5bd23ee028cff03024e3a788509f87812ab0bc9d697bf22a9472b`. This research did not independently full-GET verify that ZIP checksum. Prior ZIP range reads verified the exact entry CRC and its SHA256 `0fd53ae56ac9b02d8fad9033c47cf7cf64674536eef2ba0af031b438fedeadd6` (19,551,440 bytes).
- All captured raw Ghostty blobs are checked against the fixed Git tree. Captured native-source tarballs have independent compressed SHA256 receipts, and their manifest-declared Zig package hashes are retained. Zig's package-tree hash was not independently recomputed; compressed SHA256 and Zig package hash are different algorithms/representations and are not conflated.

## Object families and exact source versions

| Family | Observed members | Fixed source/version evidence |
|---|---:|---|
| FreeType | 42 | 2.13.2, confirmed by `freetype.h` macros |
| libpng | 15 | 1.6.43, confirmed by `png.h` |
| zlib | 15 | 1.3.1, confirmed by `zlib.h` |
| Oniguruma | 48 | 6.9.9, confirmed by `oniguruma.h` |
| simdutf | 1 | Vendored source says **9.0.0**; package-shell `.zon` still says 5.2.8. The Ghostty-fixed vendor bytes are authoritative. Supplementary upstream 9.0.0 original notices are pinned at `ca7acbcea967b5dcbab490066e99e3a6e6925539`. |
| Highway | 4 | Upstream `66486a10623fa0d72fe91260f96c892e41aceb06`, CMake 1.2.0. Three local C++ runtime shims explicitly describe their modifications; `libhighway_zcu.o` corresponds to Ghostty's Zig target detection. |
| gettext/libintl | 30 | GNU gettext 0.24; package-shell 0.24.0. Every listed C compilation unit has a matching archive member. |
| stb | 1 | Fixed vendored `stb_image` 2.28 and `stb_image_resize` 0.97; exact embedded license alternatives retained. |
| Wuffs | 1 | Upstream `7411f488fe2e2c205c3d3b3d28638b7356522930`; generated C says 0.4.0-alpha.10+3966.20260623. The `pixels` dependency is unit-test image data and was not selected. |
| Ghostty macOS glue | 2 | `zig_macos.c`, `ext.c` at fixed Ghostty commit |
| Ghostty SIMD glue | 4 | `base64.cpp`, `codepoint_width.cpp`, `index_of.cpp`, `vt.cpp` at fixed Ghostty commit |
| Ghostty aggregate core | 1 | `libghostty_zcu.o`; fixed source association only, not enumeration of every folded Zig dependency or asset |
| compiler runtime | 1 | Zig 0.16.0 source at `24fdd5b7a4c1c8b5deb5b56756b9dbc8e08c86a8`; source recipes explicitly bundle compiler runtime, subject to libc symbol localization |
| libc++ compatibility | 1 | Wrapper-authored, header-free abort shim explicitly added by `build-ghostty.sh`; this object name does not prove a bundled LLVM libc++ library |

## Important original notice details

- [SharedDeps.zig](https://github.com/ghostty-org/ghostty/blob/35a81a980bb9fce09a1ea762a68b55f8eb3477ed/src/build/SharedDeps.zig) explicitly bundles libintl for Apple targets. A wrapper description saying the build is trimmed does not remove the observed 30 libintl members.
- GNU gettext's original `COPYING.LIB` and 29 direct source license headers state LGPL 2.1 or later. `plural.c` additionally contains a GNU Bison 3.8.2 generated parser skeleton: retain its GPL 3-or-later notice **with the original Bison special exception**, plus the LGPL user-grammar notice. A parser-generator tool was not mechanically added to the runtime BOM; its emitted skeleton notice is selected because that source is compiled into observed `plural.o`.
- FreeType's root license expressly refers to BDF/PCF README notices, hash-table code, its gzip copy, and HarfBuzz-derived helper notices. Those original referenced texts/headers are captured, with conservative applicability where compile-time options can exclude code. Both root licensing alternatives are preserved; this research does not choose a license on the distributor's behalf.
- simdutf's vendored header retains a separate BSD-3-Clause PyTorch/TH attribution. It is copied verbatim rather than replaced with a generic MIT/Apache text.
- Highway's local shim modifications and original Apache/BSD notices are preserved. A blanket assumption that every file shares one interchangeable license is avoided.
- Zig's compiler-runtime source includes musl- and LLVM-derived functions. The finite source receipts and original notices are retained; the exact functions emitted into this `compiler_rt.o` have not been resolved. libc++/libc++abi source notices are conditional header/runtime evidence, not proof their libraries were statically shipped.

## Corresponding source and build inputs

The source side contains fixed source URLs, captured archive SHA256 values, original `.zon` URL/hash pairs, Ghostty's `pkg/libintl/config.h` and `libintl.h`, native recipes, and the wrapper's ordered 0001–0018 patch set plus build/apply/merge scripts. These are useful source-reconstruction inputs; they do not establish byte-identical rebuilding. Do not execute those scripts merely to collect notices.

The wrapper applies `.patch` files using git apply (with its documented fallback) and executes the `.sh` patches. No retained patch names a `pkg/libintl` source modification or gettext modification. Patch 0017 does modify fetched libxev/aro source in place; that fact is preserved in the patch input and must not be hidden by citing only a pristine dependency hash. The wrapper's older libxev URL substitution in patch 0005 does not match this fixed upstream manifest, so its optimistic message is not evidence the older dependency was selected.

The parent distribution's complete client/app source, its actual build overlays and any relinking/install instructions remain outside this incremental native notice directory. Source correspondence is not satisfied by license text alone, and the upstream comment claiming LGPL compliance is not adopted as a conclusion here.

## Remaining concrete verification limits

1. The ZIP checksum remains a manifest pin plus verified ZIP-entry evidence, not independent full-archive checksum verification.
2. Matching fixed source recipes/member names and identical wrapper inputs do not prove the release binary was reproducibly built from them.
3. Archive members can be discarded or partly retained by the final Apple link. No final Mach-O, link map, or retained-function inventory was inspected here.
4. The aggregate Ghostty and compiler-runtime objects are not decomposed into every embedded dependency/function. The named native families have finite source/notice correspondence; this is not a full linked BOM.
5. Zig package content hashes are preserved but not independently recalculated; wrapper cache modifications are separately preserved.

No Android graph work, new review of the three earlier no-standalone-license observations, product compilation, or changes to the frozen delivery were performed.
