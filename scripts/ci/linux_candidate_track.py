"""Unsigned candidate identity; production branch-track detection stays unchanged."""
import json
import os
from pathlib import Path

from polaris_version import validate
from release_identity import REPO, RID, require, same_identity, verify_checkout

ROOT = Path(__file__).resolve().parents[2]
POLICY = {'schema': 'polaris-linux-candidate-track-v1', 'repository': REPO,
          'repositoryId': RID, 'track': 'testing'}


def bind(root=ROOT, env=os.environ):
    require(env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'unsigned candidate requires manual dispatch')
    require(env.get('GITHUB_SHA') == env.get('GITHUB_WORKFLOW_SHA') and bool(env.get('GITHUB_SHA')),
            'unsigned candidate workflow source differs')
    version = validate(env.get('CANDIDATE_VERSION'))
    tag = 'v' + version
    require(env.get('GITHUB_REF') == 'refs/tags/' + tag, 'unsigned candidate dispatch ref differs from version')
    require(env.get('GITHUB_WORKFLOW_REF') == REPO + '/.github/workflows/linux.yml@refs/tags/' + tag,
            'unsigned candidate workflow identity differs')
    policy = json.loads((root / 'release/ci/linux-candidate-track.json').read_bytes())
    require(same_identity(policy, POLICY), 'unsigned candidate testing-track policy differs')
    release = json.loads((root / 'release/ci/github-release.json').read_bytes())
    require(same_identity(release, {'repository': REPO, 'repositoryId': RID, 'version': version,
            'tag': tag, 'publication': 'github-only-unsigned-prerelease'}), 'unsigned candidate release identity differs')
    expected = env.get('EXPECTED_TAG_OBJECT')
    require(expected is None or expected != '', 'unsigned candidate expected tag object missing')
    oid = verify_checkout(tag, env.get('GITHUB_SHA'), expected)
    return {'tag_object': oid, 'TRACK': 'testing', 'NAME': 'sing-box-polaris-testing',
            'PACKAGE_NAME': 'sing-box-testing', 'DOCKER_TAG': 'latest-testing'}


def main():
    values = bind()
    # Write nothing until every source, tag and policy predicate has succeeded.
    with Path(os.environ['GITHUB_ENV']).open('a') as output:
        output.write(''.join(key + '=' + value + '\n' for key, value in values.items() if key != 'tag_object'))
    if os.environ.get('GITHUB_OUTPUT'):
        with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
            output.write('tag_object=' + values['tag_object'] + '\n')


if __name__ == '__main__':
    main()
