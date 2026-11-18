#!/usr/bin/env python3
"""Select the prebuilt source-owned CI tool when the workflow supplies it."""
import os


def ci_command(*args):
    tool = os.environ.get('POLARIS_CI')
    return [tool, *args] if tool else ['go', 'run', '-mod=readonly', '-buildvcs=false', './cmd/internal/ci', *args]
