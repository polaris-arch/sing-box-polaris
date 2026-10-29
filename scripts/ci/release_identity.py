#!/usr/bin/env python3
"""Bind actual producer checkout to dispatch SHA and one immutable annotated tag."""
import argparse
import json
import math
import os
from pathlib import Path
import re
import subprocess
from polaris_version import validate as validate_version

REPO = 'polaris-arch/sing-box-polaris'
RID = 1421657509


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


def api(path):
    return json.loads(subprocess.check_output(['gh', 'api', path]))


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


def remote_tag_identity(tag, source, expected_object=None):
    require(isinstance(tag, str) and tag.startswith('v'), 'versioned source tag required')
    validate_version(tag[1:])
    require(isinstance(source, str) and re.fullmatch(r'[0-9a-f]{40}', source), 'full source SHA required')
    if expected_object is not None:
        require(isinstance(expected_object, str) and re.fullmatch(r'[0-9a-f]{40}', expected_object), 'full expected tag object required')
    ref = api(f'repos/{REPO}/git/ref/tags/{tag}')
    require(ref['object']['type'] == 'tag', 'annotated tag required')
    oid = ref['object']['sha']
    require(re.fullmatch(r'[0-9a-f]{40}', oid), 'invalid tag object')
    require(expected_object is None or oid == expected_object, 'source tag object moved')
    obj = api(f'repos/{REPO}/git/tags/{oid}')
    require(obj['sha'] == oid and obj['tag'] == tag and obj['object']['type'] == 'commit' and obj['object']['sha'] == source,
            'annotated tag must directly identify dispatch source')
    return oid


def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()


def verify_checkout(tag, source, expected_object=None):
    require(os.environ.get('GITHUB_REPOSITORY') == REPO and os.environ.get('GITHUB_REPOSITORY_ID') == str(RID), 'wrong producer repository')
    require(source == os.environ.get('GITHUB_SHA'), 'expected source differs from dispatch SHA')
    require(git('rev-parse', 'HEAD') == source, 'actual producer checkout differs from dispatch SHA')
    require(not git('status', '--porcelain', '--untracked-files=no'), 'tracked producer source is dirty')
    oid = remote_tag_identity(tag, source, expected_object)
    require(git('cat-file', '-t', 'refs/tags/' + tag) == 'tag', 'local annotated tag missing')
    require(git('rev-parse', 'refs/tags/' + tag) == oid, 'local and remote tag objects differ')
    require(git('rev-parse', 'refs/tags/' + tag + '^{commit}') == source, 'local tag differs from dispatch source')
    return oid


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


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--tag', required=True)
    p.add_argument('--source', default=os.environ.get('GITHUB_SHA'))
    p.add_argument('--expected-tag-object')
    p.add_argument('--github-output', type=Path)
    a = p.parse_args()
    oid = verify_checkout(a.tag, a.source, a.expected_tag_object)
    if a.github_output:
        with a.github_output.open('a') as f:
            f.write('tag_object=' + oid + '\n')
    print(json.dumps({'sourceCommit': a.source, 'tag': a.tag, 'tagObject': oid}))


if __name__ == '__main__':
    main()
