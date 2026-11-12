#!/usr/bin/env python3
"""Run in every producer, with explicit workflow inputs; contains no secrets."""
import json
import os
from pathlib import Path
import subprocess
from polaris_version import validate as validate_version


def native_bool(env, name):
    value = env[name]
    assert value in ('true', 'false'), 'invalid native receipt selection: ' + name
    return value == 'true'


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        assert key not in value, 'duplicate native needs field'
        value[key] = item
    return value


def validate_needs(env):
    # Selection comes only from native workflow inputs/context; every direct need must succeed.
    generate = native_bool(env, 'RECEIPT_SOURCE_GENERATE_ONLY')
    assert not generate, 'source generation is not a complete producer role'
    needs = json.loads(env['NEEDS_JSON'], object_pairs_hook=unique_object)
    assert type(needs) is dict and needs, 'native direct needs missing'
    for name, item in needs.items():
        assert type(item) is dict and set(item) == {'result', 'outputs'}, 'invalid native needs entry: ' + name
        assert type(item['outputs']) is dict, 'invalid native job outputs: ' + name
        assert item['result'] == 'success', 'producer job did not reach selected terminal result: ' + name


role = os.environ['PUBLISHER_ROLE']
assert role == 'all'
assert os.environ['GITHUB_EVENT_NAME'] == 'workflow_dispatch'
assert os.environ['GITHUB_REPOSITORY'] == 'polaris-arch/sing-box-polaris'
assert os.environ['GITHUB_REPOSITORY_ID'] == '1421657509'
assert os.environ['RELEASE_BUILD'] == 'All'
release = json.loads(Path('release/ci/github-release.json').read_text(encoding='utf-8'))
assert (release['repository'], release['repositoryId']) == ('polaris-arch/sing-box-polaris', 1421657509)
version = validate_version(os.environ['RELEASE_VERSION'])
assert os.environ['GITHUB_REF'] == 'refs/tags/v' + version, 'producer ref must be the release version tag'
validate_needs(os.environ)
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
assert head == os.environ['GITHUB_SHA']
record = {'repository': os.environ['GITHUB_REPOSITORY'], 'repositoryId': int(os.environ['GITHUB_REPOSITORY_ID']),
          'sourceCommit': head, 'runId': os.environ['GITHUB_RUN_ID'], 'attempt': int(os.environ['GITHUB_RUN_ATTEMPT']),
          'version': os.environ['RELEASE_VERSION'], 'build': os.environ['RELEASE_BUILD'], 'role': role}
Path('publisher-run-receipt.json').write_text(json.dumps(record, indent=2)+'\n', encoding='utf-8', newline='\n')
