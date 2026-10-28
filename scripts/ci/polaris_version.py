#!/usr/bin/env python3
"""Canonical Polaris identity; package-manager spellings never replace the raw version."""
import argparse
import os
import re

NUMBER = r'(?:0|[1-9][0-9]*)'
CORE = rf'{NUMBER}\.{NUMBER}\.{NUMBER}'
CHANNEL = r'(?:alpha|beta|rc)'
PATTERN = rf'{CORE}-polaris-{CHANNEL}\.{NUMBER}(?:\.{NUMBER})?'


def validate(value):
    """Accept one optional Polaris patch, not another upstream prerelease number."""
    if not isinstance(value, str) or not re.fullmatch(PATTERN, value):
        raise ValueError('expected MAJOR.MINOR.PATCH-polaris-{alpha,beta,rc}.NUMBER[.PATCH] (canonical decimal numbers)')
    return value


def schema_pattern(tag=False):
    """ECMAScript-compatible, strict end-of-input pattern for generated JSON Schemas."""
    return '^' + ('v' if tag else '') + PATTERN + r'(?![\s\S])'


def apk_version(value):
    """Map only APK metadata: alpha.12.1 -> _alpha12_p1, preserving upstream forms."""
    if '-polaris-' in value:
        validate(value)
        core, prerelease = value.split('-polaris-')
    else:
        if not re.fullmatch(rf'{CORE}(?:-{CHANNEL}\.{NUMBER})?', value):
            raise ValueError('expected a stable/upstream or canonical Polaris package version')
        core, _, prerelease = value.partition('-')
    if not prerelease:
        return core + '-r0'
    channel, number, *patch = prerelease.split('.')
    return core + '_' + channel + number + ('_p' + patch[0] if patch else '') + '-r0'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', action='store_true', help='emit APK package metadata version only')
    parser.add_argument('version', nargs='?', default=os.environ.get('CANDIDATE_VERSION'))
    parser.add_argument('build_number', nargs='?')
    args = parser.parse_args()
    if args.apk:
        if args.build_number is not None or args.version is None:
            parser.error('--apk requires one version and no Windows build number')
        print(apk_version(args.version))
        return
    value = validate(args.version)
    if args.build_number is not None:
        if not re.fullmatch(NUMBER, args.build_number) or not 0 < int(args.build_number) <= 65535:
            raise ValueError('CI build number exceeds Windows numeric resource range')
        if any(int(x) > 65535 for x in value.split('-')[0].split('.')):
            raise ValueError('Windows numeric version component exceeds 65535')
    print(value)


if __name__ == '__main__':
    main()
