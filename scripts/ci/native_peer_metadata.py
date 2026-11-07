"""Authenticated artifact admission runs separately from credential-free native peers."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import time

from release_identity import REPO, RID, require, same_identity
from polaris_version import validate as validate_version
from protocol_peer_cases import case_matrix

SCHEMA = 'polaris-native-peer-artifact-admission-v1'
ARTIFACT = 'binary-linux_amd64-purego'
MAX_BYTES = 2 * 1024 * 1024
MAX_PAGES = 4
TOTAL_SECONDS = 120


def actions_context(env=os.environ):
    require(env.get('GITHUB_ACTIONS') == 'true' and env.get('RUNNER_OS') == 'Linux', 'metadata admission requires Linux Actions')
    require(env.get('GITHUB_REPOSITORY') == REPO and env.get('GITHUB_REPOSITORY_ID') == str(RID), 'metadata admission repository differs')
    require(env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'metadata admission requires manual dispatch')
    source = env.get('GITHUB_SHA', '')
    require(re.fullmatch(r'[0-9a-f]{40}', source) is not None and env.get('GITHUB_WORKFLOW_SHA') == source,
            'metadata admission workflow source differs')
    for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
        require(re.fullmatch(r'[1-9][0-9]*', env.get(key, '')) is not None, 'metadata admission run identity missing')
    ref = env.get('GITHUB_REF', '')
    require(re.fullmatch(r'refs/(?:heads|tags)/[A-Za-z0-9_./-]+', ref) is not None, 'metadata admission ref invalid')
    require(env.get('GITHUB_WORKFLOW_REF') == REPO + '/.github/workflows/build.yml@' + ref,
            'metadata admission workflow identity differs')
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    require(head == source, 'metadata admission checkout source differs')
    require(not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], text=True).strip(),
            'metadata admission tracked checkout is dirty')
    return {'repository': REPO, 'repositoryId': RID, 'sourceCommit': source,
            'workflowCommit': source, 'runId': int(env['GITHUB_RUN_ID']),
            'runAttempt': int(env['GITHUB_RUN_ATTEMPT']), 'ref': ref}


def bind_row(directory, context):
    rows = list(directory.glob('native-row-*.json'))
    require(len(rows) == 1 and not rows[0].is_symlink() and rows[0].stat().st_size <= MAX_BYTES,
            'metadata admission requires one bounded native row')
    raw = rows[0].read_bytes()
    row = json.loads(raw)
    tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip()
    require(row.get('sourceCommit') == context['sourceCommit'] and row.get('sourceTree') == tree,
            'metadata admission native row source differs')
    version = validate_version(row.get('version'))
    require(row.get('tag') == 'v' + version and row.get('target') == 'linux/amd64'
            and row.get('variant', {}).get('linkage') == 'shared-purego', 'metadata admission native row identity differs')
    return dict(context, sourceTree=tree, version=version, tag=row['tag'],
                producerRowSHA256=hashlib.sha256(raw).hexdigest())


def timestamp(value):
    require(type(value) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', value) is not None,
            'metadata timestamp invalid')
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def validate_run(run, context):
    expected = {'id': context['runId'], 'run_attempt': context['runAttempt'],
                'head_sha': context['sourceCommit'], 'head_branch': context['ref'].split('/', 2)[2],
                'event': 'workflow_dispatch', 'path': '.github/workflows/build.yml'}
    require(type(run) is dict and all(same_identity(run.get(k), v) for k, v in expected.items()), 'metadata producer run differs')
    for key in ('repository', 'head_repository'):
        require(type(run.get(key)) is dict and same_identity(run[key].get('id'), RID)
                and run[key].get('full_name') == REPO, 'metadata producer repository differs')
    require(timestamp(run.get('run_started_at')) <= datetime.now(timezone.utc), 'metadata producer attempt starts in the future')
    return run['run_started_at']


def validate_artifact(item, context, run_started_at, now=None):
    require(type(item) is dict and item.get('name') == ARTIFACT, 'metadata artifact name differs')
    require(type(item.get('id')) is int and item['id'] > 0 and type(item.get('size_in_bytes')) is int
            and 0 < item['size_in_bytes'] <= 512 * 1024 * 1024, 'metadata artifact numeric identity invalid')
    require(item.get('expired') is False and isinstance(item.get('digest'), str)
            and re.fullmatch(r'sha256:[0-9a-f]{64}', item['digest']) is not None, 'metadata artifact expired or digest missing')
    created, expires = (timestamp(item.get(key)) for key in ('created_at', 'expires_at'))
    now = now or datetime.now(timezone.utc)
    require(timestamp(run_started_at) <= created, 'metadata artifact predates current run attempt')
    require(created <= now < expires, 'metadata artifact creation or expiry differs')
    binding = {'id': context['runId'], 'repository_id': RID, 'head_repository_id': RID,
               'head_sha': context['sourceCommit'], 'head_branch': context['ref'].split('/', 2)[2]}
    require(same_identity(item.get('workflow_run'), binding), 'metadata artifact producer binding differs')
    return {key: item[key] for key in ('id', 'name', 'digest', 'size_in_bytes', 'created_at', 'expires_at')}


def acquire(context, records):
    from github_read_transport import read_get, RetryBudget
    deadline = time.monotonic() + TOTAL_SECONDS
    budget = RetryBudget()

    def get(suffix, phase):
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'metadata admission total deadline exhausted')
        sink = io.BytesIO()
        read_get(f"repos/{REPO}/actions/runs/{context['runId']}" + suffix, sink, MAX_BYTES,
                 budget=budget, attempt_seconds=min(15, remaining), total_seconds=min(45, remaining),
                 max_retry_wait=4, record=lambda **event: records.append(dict(phase=phase, **event)))
        return json.loads(sink.getvalue())

    run = get('', 'producer_run_metadata')
    run_started_at = validate_run(run, context)
    matches, seen, total = [], set(), None
    for page in range(1, MAX_PAGES + 1):
        result = get(f'/artifacts?per_page=100&page={page}', 'artifact_inventory')
        require(type(result) is dict and type(result.get('total_count')) is int
                and 0 <= result['total_count'] <= MAX_PAGES * 100 and type(result.get('artifacts')) is list
                and len(result['artifacts']) <= 100, 'metadata artifact inventory shape differs')
        # Other producers can finish while this same-run inventory is paginated.
        # Reject an unstable inventory instead of admitting an incomplete selection.
        if total is None:
            total = result['total_count']
        require(total == result['total_count'], 'metadata artifact inventory changed during pagination')
        for item in result['artifacts']:
            require(type(item) is dict and type(item.get('id')) is int and item['id'] not in seen, 'metadata artifact inventory duplicate or invalid')
            seen.add(item['id'])
            if item.get('name') == ARTIFACT:
                matches.append(item)
        if len(result['artifacts']) < 100:
            break
    require(len(seen) == total, 'metadata artifact inventory incomplete')
    require(len(matches) == 1, 'same-run Linux artifact is not unique')
    artifact = validate_artifact(matches[0], context, run_started_at)
    return {'schema': SCHEMA, 'context': context, 'producerRun': run_binding(run),
            'artifact': {**artifact, 'expired': False, 'workflow_run': matches[0]['workflow_run']}}


def run_binding(run):
    result = {key: run[key] for key in ('id', 'run_attempt', 'run_started_at', 'head_sha', 'head_branch', 'event', 'path')}
    for key in ('repository', 'head_repository'):
        result[key] = {field: run[key][field] for field in ('id', 'full_name')}
    return result


def load(path, context):
    require(not path.is_symlink() and path.is_file() and path.stat().st_size <= MAX_BYTES, 'metadata admission file missing or unsafe')
    document = json.loads(path.read_bytes())
    require(type(document) is dict and set(document) == {'schema', 'context', 'producerRun', 'artifact'}
            and document.get('schema') == SCHEMA and same_identity(document.get('context'), context), 'metadata admission context differs')
    run_started_at = validate_run(document['producerRun'], context)
    require(same_identity(document['producerRun'], run_binding(document['producerRun'])), 'metadata admission producer run shape differs')
    item = document['artifact']
    require(type(item) is dict and set(item) == {'id', 'name', 'digest', 'size_in_bytes', 'created_at', 'expires_at', 'expired', 'workflow_run'},
            'metadata admission artifact shape differs')
    return validate_artifact(item, context, run_started_at)


def failure_receipt(output, context, error, records):
    from protocol_peer_diagnostic import safe_exception
    from github_read_transport import ReadFailure
    receipt = {'schema': 'polaris-native-controlled-peer-v1', 'status': 'FAIL',
               'stage': 'artifact_metadata_admission', 'context': context,
               'errorType': type(error).__name__, 'error': safe_exception(error),
               'publicationEligible': False, 'metadataReads': records,
               'cases': [{'kind': kind, 'mutation': mutation, 'status': 'NOT_RUN',
                          'reason': 'artifact_metadata_admission_failed'} for kind, mutation in case_matrix()]}
    if isinstance(error, ReadFailure):
        receipt['transportFailure'] = {'kind': error.kind, 'status': error.status, 'headers': error.headers}
    output.mkdir(parents=True, exist_ok=False)
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--failure-output', required=True, type=Path)
    parser.add_argument('--native', required=True, type=Path)
    args = parser.parse_args()
    context, records = {}, []
    try:
        context = actions_context()
        context = bind_row(args.native, context)
        require(bool(os.environ.get('GH_TOKEN')), 'metadata acquisition requires existing read-only Actions token')
        document = acquire(context, records)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x') as output:
            output.write(json.dumps(document, indent=2) + '\n')
    except Exception as error:
        failure_receipt(args.failure_output, context, error, records)
        raise SystemExit('native peer artifact metadata admission failed; sanitized receipt retained') from None


if __name__ == '__main__':
    main()
