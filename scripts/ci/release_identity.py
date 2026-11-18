#!/usr/bin/env python3
"""Bind actual producer checkout to dispatch SHA and one immutable annotated tag."""
import json
import os
import re
import subprocess


def require(condition, message):
    if not condition:
        raise ValueError(message)


def public_product_name(name):
    """Rename only the public product prefix; candidate/internal identities stay exact."""
    require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.+ -]+', name) and name not in ('.', '..'),
            'public product filename must be a safe basename')
    if name.startswith(('sing-box-polaris-', 'sing-box-polaris_')):
        return name
    for separator in ('-', '_'):
        prefix = 'sing-box' + separator
        if name.startswith(prefix):
            return 'sing-box-polaris' + separator + name[len(prefix):]
    return name


def ci_command(*args):
    tool = os.environ.get('POLARIS_CI')
    return [tool, *args] if tool else ['go', 'run', '-mod=readonly', '-buildvcs=false', './cmd/internal/ci', *args]


def release_tag_object(scope, tag, source, expected=None):
    args = ci_command('release-identity', '--scope', scope, '--tag', tag, '--source', source)
    if expected is not None:
        args.extend(['--expected-tag-object', expected])
    env = {**os.environ, 'GOWORK': 'off', 'GOTOOLCHAIN': 'local'}
    return json.loads(subprocess.check_output(args, env=env))['tagObject']
