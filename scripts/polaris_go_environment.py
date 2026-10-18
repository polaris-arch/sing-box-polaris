#!/usr/bin/env python3
"""Use the same frozen-source Go environment for collectors and actual builds."""
import argparse
import os
from pathlib import Path
import subprocess


def isolated_go_environment(base=None):
    environment = dict(os.environ if base is None else base)
    environment.update(GOENV='off', GOWORK='off', GOFLAGS='', GOTOOLCHAIN='local')
    return environment


def validate_go_arguments(arguments):
    if not arguments or arguments[0] not in ('build', 'test', 'list', 'env', 'version'):
        raise ValueError('only build/test/list/env/version are supported')
    if arguments[0] == 'env' and '-w' in arguments:
        raise ValueError('persistent Go environment writes are not supported')
    for argument in arguments:
        if argument.lstrip('-').split('=', 1)[0] in ('overlay', 'modfile', 'C'):
            raise ValueError('external overlay/modfile/working-directory overrides are forbidden')


def verify_source(repo, expected_head):
    head = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
    status = subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain', '--untracked-files=all'], text=True)
    if head != expected_head or status:
        raise ValueError('actual Go invocation requires the exact clean frozen source HEAD')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    arguments = args.arguments[1:] if args.arguments[:1] == ['--'] else args.arguments
    validate_go_arguments(arguments)
    verify_source(args.repo, args.expected_head)
    result = subprocess.run([str(args.go), *arguments], cwd=args.repo, env=isolated_go_environment())
    verify_source(args.repo, args.expected_head)
    raise SystemExit(result.returncode)
