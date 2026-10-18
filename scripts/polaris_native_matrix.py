#!/usr/bin/env python3
"""Select only allowlisted native jobs for a reviewed candidate dispatch."""
import json
import os

TARGETS = [
    {'os': 'linux', 'arch': 'amd64', 'tool_arch': 'x64', 'runner': 'ubuntu-24.04'},
    {'os': 'linux', 'arch': 'arm64', 'tool_arch': 'arm64', 'runner': 'ubuntu-24.04-arm'},
    {'os': 'windows', 'arch': 'amd64', 'tool_arch': 'x64', 'runner': 'windows-2025'},
    {'os': 'windows', 'arch': 'arm64', 'tool_arch': 'arm64', 'runner': 'windows-11-arm'},
    {'os': 'darwin', 'arch': 'amd64', 'tool_arch': 'x64', 'runner': 'macos-15-intel'},
    {'os': 'darwin', 'arch': 'arm64', 'tool_arch': 'arm64', 'runner': 'macos-15'},
]


def select_targets(platform):
    if platform == 'all':
        return TARGETS
    requested = platform.split(',')
    allowed = {target['os'] + '/' + target['arch'] for target in TARGETS}
    if len(requested) != len(set(requested)) or not set(requested) <= allowed:
        raise ValueError('unknown or duplicate candidate platform: ' + repr(platform))
    return [target for target in TARGETS if target['os'] + '/' + target['arch'] in requested]



if __name__ == '__main__':
    value = json.dumps(select_targets(os.environ['CANDIDATE_PLATFORM']), separators=(',', ':'))
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        output.write('matrix=' + value + '\n')
