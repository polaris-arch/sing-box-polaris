#!/usr/bin/env python3
"""Read existing protection; this receipt never proves SYSTEM execution.

GitHub's Get environment and List deployment branch policies document Actions
repository permission (read), not Administration write. We never create or
modify environments, protection, tags, runners, credentials or permissions:
https://docs.github.com/en/rest/deployments/environments#get-an-environment
https://docs.github.com/en/rest/deployments/branch-policies#list-deployment-branch-policies

Linux obtains exactly three bounded GETs. Windows consumes only that data and
its actual local annotated checkout; it never performs network/token access.
"""
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

from github_read_transport import _attempt, SAFE_HEADERS
from native_peer_metadata import validate_run, timestamp
from polaris_version import validate as validate_version
from release_identity import REPO, RID, require, same_identity
from windows_native_execution import exact_json

SCHEMA = 'polaris-windows-native-admission-v1'
ENVIRONMENT = 'polaris-windows-native-proof'
ROOT = Path(__file__).resolve().parents[2]
MAX_BYTES = 1024 * 1024
RECEIPT_BYTES = 65536
TOTAL_SECONDS = 90
PHASES = ('current_run', 'protected_environment', 'exact_tag_policy')
CONTEXT_FIELDS = {'repository', 'repositoryId', 'sourceCommit', 'workflowCommit', 'runId', 'runAttempt', 'ref'}


def positive(value, name, maximum=0xffffffffffffffff):
    require(type(value) is int and 0 < value <= maximum, 'Windows admission integer differs: ' + name)
    return value


def oid(value, name):
    require(type(value) is str and re.fullmatch('[0-9a-f]{40}', value) is not None and int(value, 16) != 0,
            'Windows admission object identity differs: ' + name)
    return value


def context(env=os.environ):
    fields = ('GITHUB_ACTIONS', 'GITHUB_EVENT_NAME', 'WINDOWS_NATIVE_PROOF_REQUESTED', 'WINDOWS_NATIVE_BUILD',
              'WINDOWS_NATIVE_EVIDENCE_MODE', 'WINDOWS_NATIVE_SOURCE_GENERATE_ONLY', 'GITHUB_REPOSITORY',
              'GITHUB_REPOSITORY_ID', 'GITHUB_SHA', 'GITHUB_WORKFLOW_SHA', 'WINDOWS_NATIVE_VERSION',
              'GITHUB_REF', 'GITHUB_WORKFLOW_REF', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')
    require(all(type(env.get(key)) is str for key in fields), 'Windows proof dispatch string fields missing')
    require(env['GITHUB_ACTIONS'] == 'true' and env['GITHUB_EVENT_NAME'] == 'workflow_dispatch',
            'Windows proof requires explicit manual Actions')
    require(env['WINDOWS_NATIVE_PROOF_REQUESTED'] == 'true' and env['WINDOWS_NATIVE_BUILD'] in ('All', 'Binary')
            and env['WINDOWS_NATIVE_EVIDENCE_MODE'] == 'final' and env['WINDOWS_NATIVE_SOURCE_GENERATE_ONLY'] == 'false',
            'Windows proof dispatch scope differs')
    require(env['GITHUB_REPOSITORY'] == REPO and env['GITHUB_REPOSITORY_ID'] == str(RID), 'Windows proof repository differs')
    source = oid(env['GITHUB_SHA'], 'source')
    require(env['GITHUB_WORKFLOW_SHA'] == source, 'Windows proof workflow source differs')
    version = validate_version(env['WINDOWS_NATIVE_VERSION'])
    ref = 'refs/tags/v' + version
    require(env['GITHUB_REF'] == ref and env['GITHUB_WORKFLOW_REF'] == REPO + '/.github/workflows/build.yml@' + ref,
            'Windows proof requires exact product tag workflow')
    for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
        require(re.fullmatch('[1-9][0-9]{0,19}', env[key]) is not None, 'Windows proof run identity missing')
        positive(int(env[key]), key)
    return {'repository': REPO, 'repositoryId': RID, 'sourceCommit': source, 'workflowCommit': source,
            'runId': int(env['GITHUB_RUN_ID']), 'runAttempt': int(env['GITHUB_RUN_ATTEMPT']), 'ref': ref}


def _environment_facts(environment):
    require(type(environment) is dict and environment.get('name') == ENVIRONMENT, 'Windows proof environment identity differs')
    positive(environment.get('id'), 'environment ID')
    require(same_identity(environment.get('deployment_branch_policy'),
                          {'protected_branches': False, 'custom_branch_policies': True}),
            'Windows proof environment lacks exact tag deployment policy')
    rules = environment.get('protection_rules')
    require(type(rules) is list and 1 <= len(rules) <= 16, 'Windows proof protection rule shape differs')
    seen = set()
    for rule in rules:
        require(type(rule) is dict and rule.get('type') in ('required_reviewers', 'wait_timer', 'branch_policy'),
                'Windows proof unknown/malformed protection rule')
        identity = positive(rule.get('id'), 'protection rule ID')
        require(identity not in seen, 'Windows proof duplicate protection rule')
        seen.add(identity)
        if rule['type'] == 'wait_timer':
            require(type(rule.get('wait_timer')) is int and 0 <= rule['wait_timer'] <= 43200,
                    'Windows proof wait timer shape differs')
    reviews = [rule for rule in rules if rule['type'] == 'required_reviewers']
    require(len(reviews) == 1, 'Windows proof environment lacks unique required reviewers')
    rule = reviews[0]
    require(type(rule.get('prevent_self_review')) is bool, 'Windows proof review flag shape differs')
    reviewers = rule.get('reviewers')
    require(type(reviewers) is list and 1 <= len(reviewers) <= 6, 'Windows proof reviewers missing')
    principals = []
    for item in reviewers:
        require(type(item) is dict and item.get('type') in ('User', 'Team') and type(item.get('reviewer')) is dict,
                'Windows proof reviewer identity differs')
        identity = positive(item['reviewer'].get('id'), 'reviewer ID')
        principals.append({'type': item['type'], 'id': identity})
    require(len({(item['type'], item['id']) for item in principals}) == len(principals), 'Windows proof duplicate reviewers')
    return {'id': environment['id'], 'name': ENVIRONMENT, 'reviewRuleId': rule['id'],
            'preventSelfReview': rule['prevent_self_review'], 'reviewers': principals}


def _policy_facts(policies, tag):
    require(type(policies) is dict and type(policies.get('total_count')) is int and policies['total_count'] == 1
            and type(policies.get('branch_policies')) is list and len(policies['branch_policies']) == 1,
            'Windows proof deployment policy is not exact and complete')
    policy = policies['branch_policies'][0]
    require(type(policy) is dict and policy.get('type') == 'tag' and policy.get('name') == tag,
            'Windows proof deployment does not restrict the exact annotated tag')
    positive(policy.get('id'), 'tag policy ID')
    return {'tagPolicyId': policy['id'], 'tagPolicyName': tag, 'tagPolicyType': 'tag'}


def environment_facts(environment, policies, tag):
    return {**_environment_facts(environment), **_policy_facts(policies, tag)}


def _git(deadline, *args):
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'Windows admission checkout deadline')
    # Disable optional index refresh and fsmonitor execution. No network command,
    # credential helper or repository script is part of this offline check.
    raw = subprocess.check_output(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-C', str(ROOT), *args],
                                  stderr=subprocess.DEVNULL, timeout=min(10, remaining))
    require(type(raw) is bytes and len(raw) <= RECEIPT_BYTES, 'Windows admission git output bound')
    return raw.decode('utf-8', errors='strict').strip()


def local_checkout(expected, tag_object, deadline):
    oid(tag_object, 'annotated tag')
    require(_git(deadline, 'rev-parse', 'HEAD') == expected['sourceCommit'], 'Windows proof actual checkout source differs')
    require(not _git(deadline, 'status', '--porcelain', '--untracked-files=no'), 'Windows proof tracked source dirty')
    tag = expected['ref'].split('/', 2)[2]
    ref = 'refs/tags/' + tag
    require(_git(deadline, 'cat-file', '-t', ref) == 'tag', 'Windows proof actual annotated tag missing')
    require(_git(deadline, 'rev-parse', ref) == tag_object, 'Windows proof actual annotated tag object differs')
    # A nested tag resolving to the right commit is insufficient: inspect the
    # actual annotated object's direct target and tag name, without a remote GET.
    header = _git(deadline, 'cat-file', '-p', ref).split('\n\n', 1)[0].splitlines()
    for key, value in [('object', expected['sourceCommit']), ('type', 'commit'), ('tag', tag)]:
        require([line for line in header if line.startswith(key + ' ')] == [key + ' ' + value],
                'Windows proof annotated tag direct identity differs')
    return tag_object


def read_record(value, phase):
    keys = {'phase', 'readAttempt', 'readStatus', 'readHeaders', 'readBytes', 'readSHA256', 'readError', 'extraGETs'}
    require(type(value) is dict and set(value) == keys and value['phase'] == phase,
            'Windows admission GET receipt fields differ')
    require(same_identity(value['readAttempt'], 1) and same_identity(value['readStatus'], 200)
            and same_identity(value['extraGETs'], 0) and value['readError'] is None,
            'Windows admission requires exactly one successful GET per endpoint')
    positive(value['readBytes'], 'GET bytes', MAX_BYTES)
    require(type(value['readSHA256']) is str and re.fullmatch('[0-9a-f]{64}', value['readSHA256']) is not None,
            'Windows admission GET digest differs')
    headers = value['readHeaders']
    require(type(headers) is dict and set(headers) <= SAFE_HEADERS, 'Windows admission unsafe GET header names')
    require(all(type(key) is str and type(item) is str and item.isascii() and len(item) <= 256
                and not any(ord(c) < 32 or ord(c) == 127 for c in item) for key, item in headers.items()),
            'Windows admission unsafe GET header values')


def receipt_shape(receipt):
    # Reject numeric aliases/non-JSON values and bound depth before serializing.
    def wire(value, depth=0):
        require(depth <= 12, 'Windows admission receipt nesting bound')
        if type(value) is dict:
            require(len(value) <= 64 and all(type(key) is str for key in value), 'Windows admission object shape differs')
            for item in value.values(): wire(item, depth + 1)
        elif type(value) is list:
            require(len(value) <= 64, 'Windows admission list bound')
            for item in value: wire(item, depth + 1)
        else:
            require(value is None or type(value) in (str, bool, int), 'Windows admission JSON value differs')
            if type(value) is str: require(len(value) <= RECEIPT_BYTES, 'Windows admission string bound')
    wire(receipt)
    require(len(json.dumps(receipt, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')) <= RECEIPT_BYTES,
            'Windows admission receipt byte bound')
    require(type(receipt) is dict and set(receipt) == {'schema', 'context', 'tagObject', 'runStartedAt', 'checkedAt', 'environment', 'reads'}
            and receipt['schema'] == SCHEMA, 'Windows admission receipt shape differs')
    require(type(receipt['context']) is dict and set(receipt['context']) == CONTEXT_FIELDS, 'Windows admission context fields differ')
    oid(receipt['tagObject'], 'receipt tag')
    require(type(receipt['reads']) is list and len(receipt['reads']) == 3, 'Windows admission GET family incomplete')
    for record, phase in zip(receipt['reads'], PHASES): read_record(record, phase)


def acquire(env=os.environ):
    deadline = time.monotonic() + TOTAL_SECONDS
    expected = context(env)
    require(env.get('RUNNER_OS') == 'Linux', 'Windows protection metadata must run outside native execution')
    tag = expected['ref'].split('/', 2)[2]
    # calculate_version already resolved the remote annotated object. Rebind its
    # required output to this actual checkout without two hidden extra GETs.
    tag_object = local_checkout(expected, env.get('EXPECTED_RELEASE_TAG_OBJECT'), deadline)
    audit = []

    def get(suffix, phase):
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'Windows proof metadata total deadline')
        sink = io.BytesIO()
        # Shared bounded transport's single-attempt primitive, intentionally no
        # retry loop: exactly these three GETs, including failures/timeouts.
        result = _attempt('repos/' + REPO + suffix, sink, MAX_BYTES, min(15, remaining))
        require(time.monotonic() <= deadline, 'Windows proof metadata total deadline')
        raw = sink.getvalue()
        require(type(result) is dict and same_identity(result.get('status'), 200)
                and same_identity(result.get('bytes'), len(raw)) and 0 < len(raw) <= MAX_BYTES
                and result.get('sha256') == hashlib.sha256(raw).hexdigest(), 'Windows metadata GET result integrity differs')
        record = {'phase': phase, 'readAttempt': 1, 'readStatus': result['status'], 'readHeaders': result['headers'],
                  'readBytes': len(raw), 'readSHA256': result['sha256'], 'readError': None, 'extraGETs': 0}
        read_record(record, phase)
        audit.append(record)
        return exact_json(raw)

    run = get('/actions/runs/' + str(expected['runId']), PHASES[0])
    started = validate_run(run, expected)
    environment = get('/environments/' + ENVIRONMENT, PHASES[1])
    facts = _environment_facts(environment)
    policies = get('/environments/' + ENVIRONMENT + '/deployment-branch-policies?per_page=100&page=1', PHASES[2])
    facts.update(_policy_facts(policies, tag))
    require(time.monotonic() <= deadline, 'Windows proof metadata total deadline')
    receipt = {'schema': SCHEMA, 'context': expected, 'tagObject': tag_object, 'runStartedAt': started,
               'checkedAt': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'environment': facts, 'reads': audit}
    receipt_shape(receipt)
    return receipt


def consume(receipt, env=os.environ):
    expected = context(env)
    # This is caller job context, never a substitute for native OS/token facts.
    require(env.get('RUNNER_OS') == 'Windows', 'Windows admission consumer requires Windows job context')
    receipt_shape(receipt)
    require(same_identity(receipt['context'], expected), 'Windows admission receipt source/run/attempt differs')
    require(timestamp(receipt['runStartedAt']) <= timestamp(receipt['checkedAt']) <= datetime.now(timezone.utc),
            'Windows admission attempt times differ')
    facts = receipt['environment']
    fields = {'id', 'name', 'reviewRuleId', 'preventSelfReview', 'reviewers', 'tagPolicyId', 'tagPolicyName', 'tagPolicyType'}
    require(type(facts) is dict and set(facts) == fields, 'Windows admission protected environment fields differ')
    reviewers = facts['reviewers']
    require(type(reviewers) is list and 1 <= len(reviewers) <= 6, 'Windows admission reviewers missing')
    require(all(type(item) is dict and set(item) == {'type', 'id'} for item in reviewers), 'Windows admission reviewer shape differs')
    reconstructed = {'id': facts['id'], 'name': facts['name'],
        'deployment_branch_policy': {'protected_branches': False, 'custom_branch_policies': True},
        'protection_rules': [{'id': facts['reviewRuleId'], 'type': 'required_reviewers',
                              'prevent_self_review': facts['preventSelfReview'],
                              'reviewers': [{'type': item['type'], 'reviewer': {'id': item['id']}} for item in reviewers]}]}
    policy = {'total_count': 1, 'branch_policies': [{'id': facts['tagPolicyId'], 'type': facts['tagPolicyType'], 'name': facts['tagPolicyName']}]}
    require(same_identity(environment_facts(reconstructed, policy, expected['ref'].split('/', 2)[2]), facts),
            'Windows admission environment binding differs')
    local_checkout(expected, receipt['tagObject'], time.monotonic() + 60)
    return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--acquire', action='store_true')
    args = parser.parse_args()
    if args.acquire:
        receipt = acquire()
        raw = json.dumps(receipt, sort_keys=True, separators=(',', ':'))
        require(len(raw.encode()) <= RECEIPT_BYTES, 'Windows proof admission output bound')
        with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as stream:
            stream.write('receipt=' + raw + '\n')
    else:
        raw = os.environ.get('POLARIS_WINDOWS_NATIVE_ADMISSION_RECEIPT', '')
        require(type(raw) is str and len(raw.encode()) <= RECEIPT_BYTES, 'Windows admission input bound')
        consume(exact_json(raw))


if __name__ == '__main__': main()
