#!/usr/bin/env python3
"""Conservative automatic-tip classification; never reuse an execution result."""
import argparse
import fnmatch
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess

# This instruction guide is not a compiler/schema/install/NOTICE input. All
# other Markdown, including the licensed root README, remains full validation.
PROSE = frozenset({'release/POLARIS_PRODUCTION_RELEASE.md'})
# Only these Python contract tests and historical data are non-runtime inputs.
# Classifier code, all active workflows, runtime tools and unknown files stay full.
CI_ONLY = frozenset({
    'scripts/test_polaris_ci_impact.py',
    'scripts/test_polaris_runner_resources.py',
    'scripts/test_polaris_production_release.py',
    'scripts/ci/test_ci_contract.py',
    'scripts/testdata/historical-workflows/README.md',
    'scripts/testdata/historical-workflows/polaris-dns-native-candidate.yml',
    'scripts/testdata/historical-workflows/polaris-native-candidate.yml',
    'scripts/testdata/historical-workflows/polaris-production-native.yml',
    'scripts/testdata/historical-workflows/polaris-production-release.yml',
})
SHA = re.compile(r'[0-9a-f]{40}\Z')
LIMIT = 1024 * 1024


def git(repo, *arguments):
    return subprocess.check_output(['git', '-C', str(repo), *arguments], stderr=subprocess.PIPE, timeout=120)


def classify_changes(changes):
    if not changes:
        return False
    return all(row['path'] in PROSE | CI_ONLY and row['status'] in ('A', 'M', 'D')
               and row['oldMode'] in ('000000', '100644')
               and row['newMode'] in ('000000', '100644') for row in changes)


def parse_raw(raw):
    if len(raw) > LIMIT:
        raise ValueError('diff budget exceeded')
    fields = raw.split(b'\0')
    if fields[-1] != b'' or (len(fields) - 1) % 2:
        raise ValueError('malformed raw diff')
    rows = []
    for n in range(0, len(fields) - 1, 2):
        metadata = fields[n].decode('ascii').split()
        if len(metadata) != 5 or not metadata[0].startswith(':'):
            raise ValueError('malformed diff metadata')
        rows.append({'path': fields[n + 1].decode('utf-8'), 'oldMode': metadata[0][1:],
                     'newMode': metadata[1], 'status': metadata[4]})
    return rows


def embed_may_consume_guide(repo, head, paths=PROSE):
    """Conservative Go embed check, including directory and all: patterns."""
    files = [name.decode('utf-8') for name in git(repo, 'ls-tree', '-r', '-z', '--name-only', head).split(b'\0') if name]
    for name in files:
        if not name.endswith('.go'):
            continue
        package = PurePosixPath(name).parent
        possible = []
        for guide in paths:
            try:
                possible.append(str(PurePosixPath(guide).relative_to(package)))
            except ValueError:
                pass  # Go embed cannot escape its package directory.
        if not possible:
            continue
        data = git(repo, 'show', head + ':' + name)
        if len(data) > LIMIT:
            return True
        for line in data.decode('utf-8').splitlines():
            if '//go:embed' not in line:
                continue
            match = re.fullmatch(r'\s*//go:embed\s+(.+)', line)
            if not match or '\\' in match[1] or '`' in match[1]:
                return True
            for pattern in shlex.split(match[1]):
                # Go path.Match character classes are not Python fnmatch's.
                # Until equivalence is proved, every class stays full.
                if '[' in pattern or ']' in pattern:
                    return True
                pattern = pattern.removeprefix('all:')
                for path in possible:
                    parts = path.split('/')
                    if any(fnmatch.fnmatchcase('/'.join(parts[:n]), pattern)
                           for n in range(1, len(parts) + 1)):
                        return True
    return False


def classify(repo, event, event_name, ref, workflow_sha):
    result = {'schema': 'polaris-ci-impact-v1', 'runFull': True,
              'reason': 'fixed-audit-or-unknown-context', 'workflowCommit': workflow_sha,
              'prosePaths': sorted(PROSE), 'changed': []}
    if event_name != 'push' or ref != 'refs/heads/polaris-main':
        return result
    before, after = event.get('before'), event.get('after')
    repository = event.get('repository')
    if (not isinstance(repository, dict) or repository.get('full_name') != 'polaris-arch/sing-box-polaris'
            or repository.get('id') != 1421657509
            or event.get('deleted') is not False or event.get('forced') is not False
            or not isinstance(before, str) or not SHA.fullmatch(before)
            or before == '0' * 40 or not SHA.fullmatch(workflow_sha)
            or after != workflow_sha):
        return result
    try:
        if git(repo, 'rev-parse', 'HEAD').decode().strip() != after:
            return result
        if git(repo, 'status', '--porcelain=v1', '--untracked-files=all'):
            return result
        try:
            git(repo, 'cat-file', '-e', before + '^{commit}')
        except subprocess.CalledProcessError:
            git(repo, 'fetch', '--no-tags', '--depth=1', 'origin', before)
        changes = parse_raw(git(repo, 'diff', '--raw', '--no-abbrev', '--no-renames', '-z', before, after))
        result['changed'] = changes
        if classify_changes(changes) and not embed_may_consume_guide(repo, after, [row['path'] for row in changes]):
            result.update(runFull=False, reason='only-contract-tests-or-audited-prose')
        else:
            result['reason'] = 'runtime-contract-or-unrecognized-change'
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        result['reason'] = 'uncertain-diff-full-validation'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--event-file', type=Path, required=True)
    parser.add_argument('--event-name', required=True)
    parser.add_argument('--ref', required=True)
    parser.add_argument('--workflow-sha', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--github-output', type=Path, required=True)
    args = parser.parse_args()
    try:
        raw = args.event_file.read_bytes()
        if len(raw) > 8 * LIMIT:
            raise ValueError('event budget exceeded')
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError('object event required')
        result = classify(args.repo, event, args.event_name, args.ref, args.workflow_sha)
    except (OSError, ValueError, TypeError):
        result = {'schema': 'polaris-ci-impact-v1', 'runFull': True,
                  'reason': 'unreadable-event-full-validation', 'workflowCommit': args.workflow_sha}
    encoded = json.dumps(result, sort_keys=True) + '\n'
    print(encoded, end='', flush=True)
    args.output.write_text(encoded)
    with args.github_output.open('a') as out:
        out.write('run_full=' + ('true' if result['runFull'] else 'false') + '\n')


if __name__ == '__main__':
    main()
