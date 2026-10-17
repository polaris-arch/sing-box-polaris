#!/bin/bash
# Screen coordinates include scrollback, not just the visible grid.
set -euo pipefail

SOURCE_DIR=${1:?Usage: 0018-screen-text-history.sh <source_dir>}
SCRIPT_DIR="$(cd "$(dirname "$0")/../../Script/support" && pwd)"
PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 - "$SOURCE_DIR" <<'PY'
import sys
from anchored_edit import Source

source = Source(sys.argv[1], "src/apprt/embedded.zig")
source.replace(
    "            const clamped_y = @min(self.y, screen.pages.rows -| 1);",
    """            // Screen-relative text reads must reach every scrollback row.
            const coordinate_rows: usize = switch (tag) {
                .screen => screen.pages.total_rows,
                else => screen.pages.rows,
            };
            const clamped_y: u32 = @intCast(@min(self.y, coordinate_rows -| 1));""",
)
source.save()
PY
