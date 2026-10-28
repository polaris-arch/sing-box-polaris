"""Authorize only an explicitly approved, clean workflow/source SHA for netns."""

import argparse
import os
import re
import subprocess


def authorized(env):
    approved = env.get('GOVERNANCE_NETNS_SHA', '')
    if not (re.fullmatch('[0-9a-f]{40}', approved)
            and env.get('GITHUB_REPOSITORY') == 'polaris-arch/sing-box-polaris'
            and env.get('GITHUB_REPOSITORY_ID') == '1421657509'
            and env.get('GITHUB_EVENT_NAME') in ('push', 'workflow_dispatch')
            and env.get('GITHUB_REF') in ('refs/heads/polaris-main', 'refs/heads/ci/governance')
            and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and env.get('RUNNER_OS') == 'Linux'
            and env.get('GITHUB_SHA') == approved
            and env.get('SOURCE_COMMIT') == approved):
        return False
    try:
        actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
        if actual != approved:
            return False
        dirty = subprocess.check_output(
            ['git', 'status', '--porcelain', '--untracked-files=no'], text=True).strip()
        return not dirty
    except (OSError, subprocess.SubprocessError):
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true',
                        help='Recheck immediately before elevation; return nonzero if denied')
    args = parser.parse_args()
    allowed = authorized(os.environ)
    print('Exact netns SHA window authorized=' + str(allowed).lower())
    if args.check:
        return 0 if allowed else 1
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write('authorized=' + str(allowed).lower() + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
