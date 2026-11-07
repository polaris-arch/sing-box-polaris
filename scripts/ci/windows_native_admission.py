#!/usr/bin/env python3
"""Bind an explicit proof request to its current run and annotated checkout.

This metadata receipt grants no SYSTEM resource authority or native execution
proof. Linux obtains one bounded current-run GET. Windows consumes only that
data and its actual local annotated checkout, without network/token access.
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
ROOT = Path(__file__).resolve().parents[2]
MAX_BYTES = 1024 * 1024
RECEIPT_BYTES = 65536
TOTAL_SECONDS = 90
PHASES = ('current_run',)
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
    require(type(receipt) is dict and set(receipt) == {'schema', 'context', 'tagObject', 'runStartedAt', 'checkedAt', 'reads'}
            and receipt['schema'] == SCHEMA, 'Windows admission receipt shape differs')
    require(type(receipt['context']) is dict and set(receipt['context']) == CONTEXT_FIELDS, 'Windows admission context fields differ')
    oid(receipt['tagObject'], 'receipt tag')
    require(type(receipt['reads']) is list and len(receipt['reads']) == 1, 'Windows admission GET family incomplete')
    for record, phase in zip(receipt['reads'], PHASES): read_record(record, phase)


def acquire(env=os.environ):
    deadline = time.monotonic() + TOTAL_SECONDS
    expected = context(env)
    require(env.get('RUNNER_OS') == 'Linux', 'Windows run metadata must run outside native execution')
    # calculate_version already resolved the remote annotated object. Rebind its
    # required output to this actual checkout without two hidden extra GETs.
    tag_object = local_checkout(expected, env.get('EXPECTED_RELEASE_TAG_OBJECT'), deadline)
    audit = []

    def get(suffix, phase):
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'Windows proof metadata total deadline')
        sink = io.BytesIO()
        # Shared bounded transport's single-attempt primitive, intentionally no
        # retry loop: exactly one current-run GET, including failures/timeouts.
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
    require(time.monotonic() <= deadline, 'Windows proof metadata total deadline')
    receipt = {'schema': SCHEMA, 'context': expected, 'tagObject': tag_object, 'runStartedAt': started,
               'checkedAt': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'reads': audit}
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
