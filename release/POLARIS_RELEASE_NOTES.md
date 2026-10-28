## Features

- Add OpenWrt `x86_64` and `aarch64_generic` packages: `.ipk` for 24.10/opkg and `.apk` for 25.12/apk3.
- Statically link the fixed musl Cronet library for Naive; include the Go gVisor stack through the preserved `with_gvisor` build tag. No separate Cronet/OpenSSL library or user build is required.
- Preserve six desktop CLI archives, with Linux/Windows Cronet libraries in the same archive and static integration on macOS.

## Fixes and compatibility

- Use the upstream musl Clang/LLD target and sysroot contract for prebuilt Cronet objects.
- Keep existing user configuration across package install, upgrade and removal. New services start disabled; upgrades restart only an already running service.
- Declare the `polaris-box` package conflict with `sing-box` explicitly. Migration requires an independent config backup and explicit removal of the old package.
- Provide fixed public corresponding-source references alongside automatic GitHub Source code archives, avoiding a redundant uploaded source package.

## Baseline and scope

Based on upstream `1.15.0-alpha.12` (upstream notes: “Fixes and improvements”), with the existing Polaris patches retained. Fixed product source: `<SOURCE_COMMIT>`.

Use the actual published asset index for source, SDK/toolchain, core/library/package hashes, measured build identities and isolated validation scope. Original signature observations do not assert trust. OpenWrt kernel dependencies must match the installed system. Physical devices, mobile artifacts and final Polaris App carrier acceptance remain separate. The previous release stays available while active consumers migrate.
