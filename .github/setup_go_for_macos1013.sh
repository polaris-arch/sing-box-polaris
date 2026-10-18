#!/usr/bin/env bash
set -euo pipefail
# Verified official Go plus the source-owned Go1.27 compatibility patch set.
exec python3 "$(dirname "$0")/setup_legacy_go.py" macos1013
