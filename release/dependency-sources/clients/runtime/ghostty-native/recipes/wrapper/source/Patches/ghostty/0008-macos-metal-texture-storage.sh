#!/bin/bash

set -euo pipefail

SOURCE_DIR="${1:?Usage: $0 <ghostty-source-dir>}"

# =============================================================================
# Split Metal buffer and texture storage modes on macOS
# =============================================================================
#
# MTLStorageModeShared is valid for textures on Apple GPUs, while Intel and AMD
# macOS GPUs require managed textures even when hasUnifiedMemory is true.
# Buffers keep upstream's default_storage_mode; textures get
# default_texture_storage_mode, chosen from the Metal GPU family as Apple
# recommends for CPU-updated textures.
#
# The device and its metadata live in src/renderer/metal/Device.zig, shared by
# every renderer (upstream 40d5b860d2); Metal.zig reads them through
# `self.device`. Exact anchors (Script/support/anchored_edit.py), and a count
# tripwire on the storage-mode call sites: four are textures, one
# (bufferOptions) is a buffer.
# =============================================================================

PYTHONPATH="$(cd "$(dirname "$0")/../../Script/support" && pwd)" python3 - "$SOURCE_DIR" <<'PY'
import sys

from anchored_edit import Source

source_dir = sys.argv[1]

device = Source(source_dir, "src/renderer/metal/Device.zig")
device.insert_after(
    """default_storage_mode: mtl.MTLResourceOptions.StorageMode,
""",
    """
/// The default storage mode to use for MTLTexture resources.
default_texture_storage_mode: mtl.MTLResourceOptions.StorageMode,
""",
)
device.replace(
    """    const max_texture_size = queryMaxTextureSize(device);
    log.debug(
        "device properties default_storage_mode={} max_texture_size={}",
        .{ default_storage_mode, max_texture_size },
    );
""",
    """    // LIBGHOSTTY_SPM_TEXTURE_STORAGE_PATCH
    // MTLStorageModeShared is valid for textures on Apple GPUs, while Intel
    // and AMD macOS GPUs require managed textures even when hasUnifiedMemory is
    // true. Keep buffer storage unchanged, but choose texture storage from the
    // Metal GPU family as Apple recommends for CPU-updated textures.
    const default_texture_storage_mode: mtl.MTLResourceOptions.StorageMode = switch (comptime builtin.os.tag) {
        .ios => .shared,
        .macos => if (device.msgSend(
            bool,
            objc.sel("supportsFamily:"),
            .{mtl.MTLGPUFamily.apple1},
        )) .shared else .managed,
        else => default_storage_mode,
    };
    const max_texture_size = queryMaxTextureSize(device);
    log.debug(
        "device properties default_storage_mode={} default_texture_storage_mode={} max_texture_size={}",
        .{ default_storage_mode, default_texture_storage_mode, max_texture_size },
    );
""",
    marker="    // LIBGHOSTTY_SPM_TEXTURE_STORAGE_PATCH\n",
)
device.insert_after(
    """        .default_storage_mode = default_storage_mode,
""",
    """        .default_texture_storage_mode = default_texture_storage_mode,
""",
)
device.save()

metal = Source(source_dir, "src/renderer/Metal.zig")
buffer_mode = ".storage_mode = self.device.default_storage_mode"
texture_mode = ".storage_mode = self.device.default_texture_storage_mode"
buffer_options = "pub inline fn bufferOptions(self: Metal) bufferpkg.Options {"
if metal.text.count(texture_mode) != 4:
    metal.expect_count(buffer_mode, 5)
    metal.expect_count(buffer_options, 1)
    start = metal.text.index(buffer_options)
    buffer_site = metal.text.index(buffer_mode, start)
    metal.text = (
        metal.text[:buffer_site].replace(buffer_mode, texture_mode)
        + metal.text[buffer_site:buffer_site + len(buffer_mode)]
        + metal.text[buffer_site + len(buffer_mode):].replace(buffer_mode, texture_mode)
    )
    metal.changed = True
metal.expect_count(texture_mode, 4)
metal.expect_count(buffer_mode, 1)
metal.save()
PY
