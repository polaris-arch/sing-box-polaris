#!/usr/bin/env python3
"""Run in every producer, with explicit workflow inputs; contains no secrets."""
import json
import os
from pathlib import Path
import subprocess
from polaris_version import validate as validate_version

role = os.environ['PUBLISHER_ROLE']
assert role in ('all', 'linux', 'docker', 'signed')
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
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
assert head == os.environ['GITHUB_SHA']
record = {'repository': os.environ['GITHUB_REPOSITORY'], 'repositoryId': int(os.environ['GITHUB_REPOSITORY_ID']),
          'sourceCommit': head, 'runId': os.environ['GITHUB_RUN_ID'], 'attempt': int(os.environ['GITHUB_RUN_ATTEMPT']),
          'version': os.environ['RELEASE_VERSION'], 'build': os.environ['RELEASE_BUILD'], 'role': role,
          'publishStores': False, 'publishRegistry': False}
Path('publisher-run-receipt.json').write_text(json.dumps(record, indent=2)+'\n', encoding='utf-8', newline='\n')
