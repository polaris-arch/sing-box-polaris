# Fixed Ghostty wrapper and Zig runtime source-notice mapping

## Outcome and scope

This is a finite, read-only acquisition and source-recipe mapping. No source build, patch execution, GitHub write, LLVM source archive download, binary reproduction, or final app linking test was performed. All new outputs are confined to this wrapper evidence directory. Existing client-runtime and delivery materials were not changed.

- Fixed Swift wrapper: `Lakr233/libghostty-spm@cffef22c16dd61d22ebef539ae2ff1624db77363` (package version `2.2.2026100703`).
- Asset tag `upstream.35a81a980bb9` resolves to wrapper commit `e037035e17ce07618d48e70b1282ffdca01c318e`.
- Both wrappers pin Ghostty `35a81a980bb9fce09a1ea762a68b55f8eb3477ed` in `Ghostty.ref`.
- The retained release API record identifies `GhosttyKit.xcframework.zip`, 77,203,207 bytes, SHA-256 `80e9bbfc89f5bd23ee028cff03024e3a788509f87812ab0bc9d697bf22a9472b`, matching the existing fixed `Package.swift` checksum. The release is not marked immutable. The release digest is not an independent reproduction result.
- The build workflow at both wrapper commits declares Zig `0.16.0`, macOS 15 build runners and a macOS 26 merge runner. This is source-recipe evidence of the requested toolchain, not a verified actual compiler executable hash, build attestation, or exact Xcode/SDK environment.
- Zig `0.16.0` resolves on its official Codeberg source to commit `24fdd5b7a4c1c8b5deb5b56756b9dbc8e08c86a8`; annotated release-tag object `44d9672fed001115e674fd5ddb32747ef43a7af4`. The equivalent GitHub tag is absent; no different Zig version was substituted.

## Retained exact source evidence

`ACQUISITION.json` lists 36 wrapper texts with original paths, source URLs, byte counts, SHA-256, computed Git blob IDs, and matching blob IDs from the previously retained fixed wrapper tree. Every one is also identical at the asset-tag wrapper revision. These include all 18 numbered Ghostty patches, both patch READMEs, workflow/build/apply/merge/support scripts, the compatibility C source, root MIT license and wrapper README. The patch directory is about 300 KiB, not a source archive.

`upstream/src/build/` retains `GhosttyLib.zig`, `LibsystemOverrideStep.zig`, and `libsystem_override.sh` at the exact Ghostty commit; each sidecar verifies its Git blob against the separately retained upstream tree.

`zig-0.16.0/ACQUISITION.json` retains 20 exact Zig source/notice files with SHA-256 and Git blob matches against bounded official, nonrecursive Codeberg tree metadata. Root, library and selected subdirectory tree metadata are retained. Selected compiler-runtime headers/source files document provenance; they are not the full compiler-runtime function graph. Metadata records and expected 404/time-out results are distinguished from verified source files.

`llvm-port/` retains only the exact LLVM compiler-rt license and `fp_add_impl.inc` cited by Zig's `addf3.zig`, at LLVM commit `02d85149a05cb1f6dc49f0ba7a2ceca53718ae17`; both Git blobs match independent GitHub contents metadata. No LLVM archive was fetched.

`musl-port/` retains exact official cgit `log.c` and `logf.c` texts at the historical commits explicitly referenced by Zig's `log.zig`. Their source bytes and SHA-256 are recorded. Their computed Git blob IDs have not been checked against independent Git tree metadata and are explicitly marked unverified. They supplement, rather than replace, the Git-verified musl COPYRIGHT shipped in Zig 0.16.0.

## Why the two observed archive members are present

### compiler_rt.o

`GhosttyLib.initStatic` explicitly sets `bundle_compiler_rt = true` and `bundle_ubsan_rt = true`, explaining that they prevent undefined symbols in the static library, then combines the dependency archives into a single static archive. On Darwin it passes this through `LibsystemOverrideStep`.

The override shell script extracts `compiler_rt.o`, localizes its well-known libc/libm symbols using `nmedit`, and reinserts it. This lets other archive members bind ordinary libc/libm symbols to Apple's libSystem while keeping intrinsics not supplied there, including f128 conversions, *q math and sincos variants. Localization is not removal of the runtime object's bytes. Source comments describe debug stack-probing/UBSan examples; they do not prove which examples are live in the inspected ReleaseFast iOS member.

### libcxx-verbose-abort-compat.o

`Script/build-ghostty.sh` compiles the wrapper's own `Script/support/libcxx-verbose-abort-compat.c` with `zig cc -target "$ZIG_TARGET" -Os -fno-sanitize=undefined`, then explicitly merges the resulting object with the built library using Apple `libtool`. The header-free C shim defines a hidden symbol for `std::__1::__libcpp_verbose_abort`, calls `abort`, and is intended to cover older Apple OS versions whose system libc++ does not export that symbol. The wrapper source places it under its root MIT license, copyright 2026 @Lakr233; there is no separate license header or copied LLVM implementation in this 811-byte file.

The shim's name is not evidence that libc++ or libc++abi static libraries are included. The compatibility rationale is documented by wrapper source; it was not independently tested against Apple OS versions here.

## Notice mapping and limits

- Wrapper/shim: exact root MIT text, copyright 2026 @Lakr233, retained in `source/LICENSE`.
- Zig original runtime/source: exact root MIT (Expat), copyright Zig contributors, retained in `zig-0.16.0/LICENSE`.
- LLVM-derived arithmetic: Zig's `addf3.zig` expressly cites the fixed LLVM `fp_add_impl.inc`. That original file has `Apache-2.0 WITH LLVM-exception`; the complete license and exceptions at that revision are retained in `llvm-port/compiler-rt/LICENSE.TXT`. This is a concrete source-derivation link, not a claim that the whole LLVM compiler is shipped.
- musl-derived math: retained Zig source files expressly attribute ports to musl. `zig-0.16.0/lib/libc/musl/COPYRIGHT` gives the MIT notice and its third-party exceptions. The separately retained, explicitly cited historical `log.c` identifies Arm's MIT code; `logf.c` preserves Sun's copyright and permission notice. Root Zig MIT alone must not be represented as exhaustive third-party runtime notice coverage.
- libc++/libc++abi: complete versioned `LICENSE.TXT` files from Zig 0.16.0 retain Apache-2.0 with LLVM Exceptions and legacy license sections. Treat these as conditional toolchain/header notice evidence. This pass did not prove that either full static runtime is present in the release library or final app.

The current binary observation supplied to this task is 167 `ar` members in the iOS arm64 `libghostty.a`, including `compiler_rt.o` and the compatibility object. Member names plus source recipes do not resolve every function selected from compiler_rt, its complete original third-party source-header provenance, symbol stripping/localization, per-platform variations, actual build provenance, or final-app linker inclusion. Full compiler_rt notice closure and final Mach-O inclusion therefore remain explicitly open. UBSan bundling is declared in the source; a live standalone UBSan object or final linked sanitizer code is not established here.

## Wrapper patch/config findings

`apply-patches.sh` iterates the filename glob in the numbered 0001–0018 order, skips Markdown, runs `.sh` files and applies `.patch` files with `git apply` checks and a `--3way` fallback. Patch 0002 is conditionally skipped if upstream already exposes the host-managed IO enum. Exact scripts and ordering must be preserved; do not treat every textual patch as necessarily active on this source revision.

No retained patch names `pkg/libintl`, gettext, or a libintl dependency hash. `libintl` occurs in patch 0013's explanation of archive-member preservation. Patch 0013 changes archive assembly and suppresses a separate VT dylib install, so it can affect inclusion of an otherwise unmodified libintl archive.

Patch 0005 contains literal substitutions from old libxev commit `34fa50878aec6e5fa8f532867001ab3c36fae23e` to `7e7d2f2ab4700544657f8ec268715c8ef320d839` and an associated Zig package hash. The fixed Ghostty manifest instead pins `9ce8e8e6ff89e583258a7f8e7adeeeaeae8611bf`; neither old substitution literal is present. Static text inspection therefore shows that section does not change the fixed manifest, despite its unconditional success echo after the substitutions.

Patch 0017 fetches packages if necessary and changes unpacked libxev/aro source files in place, without changing their dependency hashes: Catalyst event-loop selection, Apple target macros and blocks support. Patch 0009 changes highway/simdutf C++ availability flags (and conditionally Ghostty SIMD flags). Other Apple patches change SDK/target selections and generated-code paths. These changes are part of the derivative archive source recipe; the parent native-dependency analysis remains authoritative for exact native versions and license texts.

See `SOURCE-RECIPE.md` for the bounded reconstruction instructions and precise proof boundary.
