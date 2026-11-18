#!/usr/bin/env python3
"""Bind actual producer checkout to dispatch SHA and one immutable annotated tag."""
import json
import math
import os
import re
import subprocess


def require(condition, message):
    if not condition:
        raise ValueError(message)


def same_identity(actual, expected):
    """Compare nested evidence identities without Python bool/int/float coercion."""
    if type(actual) is not type(expected):
        return False
    if type(actual) is dict:
        return (actual.keys() == expected.keys() and all(type(key) is str for key in actual)
                and all(same_identity(actual[key], expected[key]) for key in actual))
    if type(actual) in (list, tuple):
        return len(actual) == len(expected) and all(same_identity(a, b) for a, b in zip(actual, expected))
    if type(actual) is float and not math.isfinite(actual):
        return False
    return actual == expected


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


def validate_publication_index(index, source, tag, tag_object, tree=None):
    """Shared final-source and eligibility gate, before any release mutation."""
    require(isinstance(index, dict), 'final native index must be an object')
    require(index.get('schema') == 'polaris-upstream-native-assets-v1' and
            index.get('tag') == tag and index.get('tagObject') == tag_object and
            index.get('sourceCommit') == source, 'assembled final index no longer matches source tag')
    if tree is not None:
        require(index.get('sourceTree') == tree, 'assembled final index source tree differs')
    materials = index.get('distributionMaterials')
    require(isinstance(materials, dict) and materials.get('publicationEligible') is True,
            'current source/notice review remains unresolved')
