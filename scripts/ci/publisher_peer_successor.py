"""Successor peer preparation from measured producer data; no release authority.

No source SHA, tag object, run, attempt or artifact digest is predicted here.
The separately reviewed exact selector is mandatory before publisher admission.
Historical selections remain in their immutable modules.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import stat

import publisher_peer_validation as v
from release_identity import REPO, RID, same_identity

VERSION = '1.15.0-polaris-alpha.12.18'
PATH = 'release/ci/publisher-peer-evidence-12.18.json'
INDEX_LIMIT = 16 * 1024 * 1024
DISPOSITION = v.DISPOSITION
JSON_LIMIT = v.JSON_LIMIT
CASES = v.CASES
require = v.require
strict_json = v.strict_json
digest = v.digest
scoped = v.scoped
members = v.members
cross_bind = v.cross_bind


def bounded(path, maximum):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum,
            'successor input must be bounded regular file')
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    require(0 < len(raw) <= maximum and len(raw) == info.st_size, 'successor input size changed')
    return raw


def selection(raw):
    s = strict_json(raw)
    require(type(s) is dict, 'successor selection must be object')
    for key in ('sourceCommit', 'sourceTree', 'tagObject'):
        value = s.get(key)
        require(type(value) is str and re.fullmatch('[0-9a-f]{40}', value)
                and int(value, 16) != 0, 'successor Git identity missing')
    return v.validate_selection(raw, expected_source=s['sourceCommit'], expected_version=VERSION,
                                run_id=s.get('runId'), run_attempt=s.get('runAttempt'))


def load(root):
    return selection(bounded(Path(root) / PATH, JSON_LIMIT))


def select(root, source, version, tag, tree=None, tag_object=None):
    s, hashed = load(root)  # No selector means a closed gate, never a historical fallback.
    require(same_identity((source, version, tag), (s['sourceCommit'], VERSION, 'v' + VERSION)),
            'successor source/version/tag mismatch')
    require(tree is None or same_identity(tree, s['sourceTree']), 'successor source tree mismatch')
    require(tag_object is None or same_identity(tag_object, s['tagObject']), 'successor tag object mismatch')
    return {'selection': s, 'sha256': hashed}


def mapping(root, role, artifact, relative, source):
    if type(source) is not str or artifact != 'native-controlled-peer-' + source:
        return None
    s, _ = load(root)
    require(same_identity(source, s['sourceCommit']), 'successor mapping source mismatch')
    return v.mapping(root, role, artifact, relative, source, expected_source=source, load=load)


def check_api(policy, role, run, artifact):
    return v.check_api(policy, role, run, artifact, expected_source=policy['selection']['sourceCommit'])


def summary(policy):
    return v.summary(policy, expected_source=policy['selection']['sourceCommit'])


def validate_receipt(policy, measured, receipt):
    return v.validate_receipt(policy, measured, receipt,
                              expected_source=policy['selection']['sourceCommit'], summary=summary)


def record(policy, publisher):
    return v.record(policy, publisher, path=PATH, summary=summary)


def check_inventory(root, actual, publisher):
    return v.check_inventory(root, actual, publisher, expected_source=actual['sourceCommit'],
                             expected_version=VERSION, select=select, record=record, summary=summary)


def derive(run, artifacts, index_raw, row_raw, receipt_raw, *, source, tree, tag_object, expected_run_id, expected_attempt):
    """Prepare a selector from real fetched metadata/bytes; publisher remeasures it.

    This pure data operation proves no native execution, permission, artifact
    authenticity or public eligibility on its own. The existing inventory gate
    still refetches Actions metadata and ZIPs, validates the whole Final index,
    matches all native archives, and validates the same-run peer receipt.
    """
    require(type(run) is dict and type(artifacts) is list, 'successor producer API shape')
    run_id, attempt = run.get('id'), run.get('run_attempt')
    require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0,
            'successor actual run/attempt missing')
    require(same_identity((run_id, attempt), (expected_run_id, expected_attempt)),
            'successor caller-fixed run/attempt mismatch')
    for key in ('repository', 'head_repository'):
        require(type(run.get(key)) is dict and same_identity(run[key].get('id'), RID)
                and same_identity(run[key].get('full_name'), REPO), 'successor foreign run')
    require(same_identity(run.get('head_sha'), source)
            and run.get('head_branch') == 'v' + VERSION
            and run.get('path') == '.github/workflows/build.yml'
            and run.get('event') == 'workflow_dispatch' and run.get('status') == 'completed'
            and run.get('conclusion') == 'success', 'successor run identity/status differs')
    require(type(index_raw) is bytes and 0 < len(index_raw) <= INDEX_LIMIT, 'successor index budget')
    # Keep duplicate-key/non-finite checks while using the existing index byte budget.
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate successor index key')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('controlled peer: non-finite successor index number')
    def floating(_):
        raise ValueError('controlled peer: successor index numeric type differs')
    index = json.loads(index_raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=floating)
    row, receipt = strict_json(row_raw), strict_json(receipt_raw)
    require(type(index) is dict and index.get('schema') == 'polaris-upstream-native-assets-v1'
            and same_identity((index.get('sourceCommit'), index.get('sourceTree'), index.get('tag'), index.get('tagObject')),
                              (source, tree, 'v' + VERSION, tag_object)), 'successor final index source/tag mismatch')
    require(type(index.get('platforms')) is list and len(index['platforms']) == 44,
            'successor full 44 native rows required')
    producer = index.get('producer', {})
    require(same_identity((producer.get('repository'), producer.get('repositoryId'), producer.get('workflow'),
                           producer.get('workflowCommit'), producer.get('runId'), producer.get('runAttempt')),
                          (REPO, RID, run['path'], source, run_id, attempt)), 'successor index producer mismatch')
    require(same_identity((row.get('sourceCommit'), row.get('sourceTree'), row.get('version'), row.get('tag'), row.get('target')),
                          (source, tree, VERSION, 'v' + VERSION, 'linux/amd64')), 'successor smoke row identity differs')
    require(type(receipt) is dict and type(receipt.get('identity')) is dict, 'successor receipt identity missing')
    names, ids = [], []
    for artifact in artifacts:
        require(type(artifact) is dict, 'successor artifact metadata shape')
        names.append(artifact.get('name')); ids.append(artifact.get('id'))
    require(all(type(n) is str for n in names) and len(set(names)) == len(names)
            and all(type(i) is int and i > 0 for i in ids) and len(set(ids)) == len(ids),
            'successor duplicate/invalid API artifact identity')
    def api_artifact(name):
        matches = [a for a in artifacts if a['name'] == name]
        require(len(matches) == 1, 'successor exact API artifact missing')
        a = matches[0]
        origin = a.get('workflow_run', {})
        require(a.get('expired') is False
                and same_identity((origin.get('id'), origin.get('head_sha'), origin.get('repository_id'), origin.get('head_repository_id')),
                                  (run_id, source, RID, RID)), 'successor API artifact origin/expiry differs')
        from datetime import datetime
        require(datetime.fromisoformat(a['created_at'].replace('Z', '+00:00')) >=
                datetime.fromisoformat(run['run_started_at'].replace('Z', '+00:00')),
                'successor API artifact predates attempt')
        return {key: a[key] for key in ('id', 'name', 'size_in_bytes', 'digest')}
    s = {'schema': 'polaris-exact-controlled-peer-selection-v1', 'repository': REPO, 'repositoryId': RID,
         'version': VERSION, 'tag': 'v' + VERSION, 'sourceCommit': source, 'sourceTree': tree,
         'tagObject': tag_object, 'workflow': run['path'], 'runId': run_id, 'runAttempt': attempt,
         'artifact': api_artifact('native-controlled-peer-' + source),
         'member': {'path': 'receipt.json', 'bytes': len(receipt_raw), 'sha256': v.digest(receipt_raw)},
         'nativeIndexSHA256': v.digest(index_raw),
         'smokeRow': {'artifact': 'smoke-linux-amd64-purego', 'path': 'native-row-' + row['archive']['root'] + '.json',
                      'bytes': len(row_raw), 'sha256': v.digest(row_raw)},
         'carrierArtifact': api_artifact('binary-linux_amd64-purego'), 'identity': copy.deepcopy(receipt['identity']),
         'archive': copy.deepcopy(row['archive']), 'publicationEligible': False, 'publicationDisposition': DISPOSITION}
    raw = (json.dumps(s, sort_keys=True, indent=2) + '\n').encode()
    s, hashed = selection(raw)
    policy = {'selection': s, 'sha256': hashed}
    validate_receipt(policy, {key: s['member'][key] for key in ('bytes', 'sha256')}, receipt)
    # Use the original API metadata rather than inventing carrier or smoke IDs.
    by_name = {a['name']: a for a in artifacts}
    smoke = api_artifact(s['smokeRow']['artifact'])
    entry = {'artifacts': {
        s['carrierArtifact']['name']: {'id': s['carrierArtifact']['id'],
            'archiveBytes': s['carrierArtifact']['size_in_bytes'], 'archiveSha256': s['carrierArtifact']['digest'],
            'files': {s['archive']['name']: {key: s['archive'][key] for key in ('bytes', 'sha256')}}},
        smoke['name']: {'id': smoke['id'], 'archiveBytes': smoke['size_in_bytes'], 'archiveSha256': smoke['digest'],
            'files': {s['smokeRow']['path']: {key: s['smokeRow'][key] for key in ('bytes', 'sha256')}}}}}
    cross_bind(policy, index, v.digest(index_raw), entry)
    check_api(policy, 'all', run, by_name[s['artifact']['name']])
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('run', 'artifacts', 'index', 'row', 'receipt', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source', 'tree', 'tag-object'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--run-id', type=int, required=True)
    parser.add_argument('--run-attempt', type=int, required=True)
    args = parser.parse_args()
    raw = derive(strict_json(bounded(args.run, JSON_LIMIT)), strict_json(bounded(args.artifacts, JSON_LIMIT)),
                 bounded(args.index, INDEX_LIMIT), bounded(args.row, JSON_LIMIT), bounded(args.receipt, JSON_LIMIT),
                 source=args.source, tree=args.tree, tag_object=args.tag_object,
                 expected_run_id=args.run_id, expected_attempt=args.run_attempt)
    # Explicit output only; no default repository write, overwrite or network.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    print(json.dumps({'path': str(args.output), 'bytes': len(raw), 'sha256': v.digest(raw),
                      'reviewed': False, 'publicationEligible': False}))


if __name__ == '__main__':
    main()
