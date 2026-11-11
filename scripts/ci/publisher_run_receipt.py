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


def validate_needs(role, release, env):
    # Selection comes only from native workflow inputs/context and this source's
    # direct-needs contract. Upstream outputs never redefine an optional job.
    mode = env['RECEIPT_EVIDENCE_MODE']
    assert mode in ('final', 'staging'), 'invalid receipt evidence mode'
    generate = native_bool(env, 'RECEIPT_SOURCE_GENERATE_ONLY')
    assert not generate, 'source generation is not a complete producer role'
    ref = env['GITHUB_REF']
    assert ref.startswith(('refs/tags/', 'refs/heads/')), 'missing native producer ref'
    if ref.startswith('refs/tags/'):
        assert ref == 'refs/tags/' + release['tag'], 'producer tag differs from release plan'
    scope = json.loads(Path('release/ci/publisher-upstream-scope.json').read_text(encoding='utf-8'))[role]
    policies = scope['receiptJobs']
    assert policies and set(policies) == set(scope['requiredJobs']), 'incomplete source-owned receipt job set'
    needs = json.loads(env['NEEDS_JSON'], object_pairs_hook=unique_object)
    assert type(needs) is dict and set(needs) == set(policies), 'native direct needs differ from source-owned receipt jobs'
    for name, policy in policies.items():
        item = needs[name]
        assert type(item) is dict and set(item) == {'result', 'outputs'}, 'invalid native needs entry: ' + name
        assert type(item['outputs']) is dict, 'invalid native job outputs: ' + name
        assert policy == 'required', 'unknown source-owned receipt policy'
        assert item['result'] == 'success', 'producer job did not reach selected terminal result: ' + name


role = os.environ['PUBLISHER_ROLE']
assert role == 'all'
assert os.environ['GITHUB_EVENT_NAME'] == 'workflow_dispatch'
assert os.environ['GITHUB_REPOSITORY'] == 'polaris-arch/sing-box-polaris'
assert os.environ['GITHUB_REPOSITORY_ID'] == '1421657509'
assert os.environ['RELEASE_BUILD'] == 'All'
release = json.loads(Path('release/ci/github-release.json').read_text(encoding='utf-8'))
assert (release['repository'], release['repositoryId']) == ('polaris-arch/sing-box-polaris', 1421657509)
version = validate_version(release['version'])
assert release['tag'] == 'v' + version
assert os.environ['RELEASE_VERSION'] == version
assert os.environ.get('PUBLISH_STORES', 'false') == 'false'
assert os.environ.get('PUBLISH_REGISTRY', 'false') == 'false'
validate_needs(role, release, os.environ)
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
assert head == os.environ['GITHUB_SHA']
record = {'repository': os.environ['GITHUB_REPOSITORY'], 'repositoryId': int(os.environ['GITHUB_REPOSITORY_ID']),
          'sourceCommit': head, 'runId': os.environ['GITHUB_RUN_ID'], 'attempt': int(os.environ['GITHUB_RUN_ATTEMPT']),
          'version': os.environ['RELEASE_VERSION'], 'build': os.environ['RELEASE_BUILD'], 'role': role,
          'publishStores': False, 'publishRegistry': False}
Path('publisher-run-receipt.json').write_text(json.dumps(record, indent=2)+'\n', encoding='utf-8', newline='\n')
