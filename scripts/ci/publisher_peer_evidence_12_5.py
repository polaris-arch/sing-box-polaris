"""One immutable, nonpublic peer selection; never a general artifact exception."""
import copy
import hashlib
import json
import math
from pathlib import Path
import re
import stat

PATH = 'release/ci/publisher-peer-evidence-12.5.json'
DISPOSITION = 'controlled-peer-evidence'
JSON_LIMIT = 1024 * 1024
VERSION = '1.15.0-polaris-alpha.12.5'
SOURCE = '332935c310e78e15319d434f33a9103329200931'
CASES = [(kind, mutation) for kind in ('naive-h2', 'naive-h3')
         for mutation in (None, 'wrong-auth', 'wrong-ca', 'wrong-sni')] + [
         ('masque-h3', mutation) for mutation in (None, 'wrong-auth', 'wrong-ca', 'wrong-sni', 'wrong-path')
         ] + [('masque-h3-on-demand', None)]


def require(ok, message):
    if not ok:
        raise ValueError('controlled peer: ' + message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('controlled peer: non-finite JSON number')
    def finite(number):
        value = float(number)
        require(math.isfinite(value), 'non-finite JSON number')
        return value
    require(len(raw) <= JSON_LIMIT, 'JSON exceeds evidence budget')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=finite)


def load(root):
    path = Path(root) / PATH
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= JSON_LIMIT, 'selection must be bounded regular file')
    raw = path.read_bytes()
    s = strict_json(raw)
    require(type(s) is dict and set(s) == {
        'schema', 'repository', 'repositoryId', 'version', 'tag', 'sourceCommit', 'sourceTree',
        'tagObject', 'workflow', 'runId', 'runAttempt', 'artifact', 'member', 'nativeIndexSHA256',
        'smokeRow', 'carrierArtifact', 'identity', 'archive', 'publicationEligible', 'publicationDisposition'},
        'selection fields differ')
    require(s['schema'] == 'polaris-exact-controlled-peer-selection-v1'
            and s['repository'] == 'polaris-arch/sing-box-polaris'
            and type(s['repositoryId']) is int and s['repositoryId'] == 1421657509
            and s['sourceCommit'] == SOURCE and s['version'] == VERSION and s['tag'] == 'v' + VERSION
            and s['workflow'] == '.github/workflows/build.yml'
            and type(s['runId']) is int and s['runId'] == 40320061915
            and type(s['runAttempt']) is int and s['runAttempt'] == 1
            and s['publicationEligible'] is False and s['publicationDisposition'] == DISPOSITION,
            'selection identity/type differs')
    for key in ('sourceTree', 'tagObject'):
        require(type(s[key]) is str and re.fullmatch('[0-9a-f]{40}', s[key]), 'selection Git identity')
    require(re.fullmatch('[0-9a-f]{64}', s['nativeIndexSHA256']) is not None, 'index digest')
    for key, name in [('artifact', 'native-controlled-peer-' + SOURCE), ('carrierArtifact', 'binary-linux_amd64-purego')]:
        a = s[key]
        require(type(a) is dict and set(a) == {'id', 'name', 'size_in_bytes', 'digest'}
                and type(a['id']) is int and a['id'] > 0 and a['name'] == name
                and type(a['size_in_bytes']) is int and a['size_in_bytes'] > 0
                and type(a['digest']) is str and re.fullmatch('sha256:[0-9a-f]{64}', a['digest']),
                'selection artifact identity/type')
    for key in ('member', 'smokeRow'):
        m = s[key]
        require(type(m) is dict and set(m) == ({'path', 'bytes', 'sha256'} if key == 'member'
                else {'artifact', 'path', 'bytes', 'sha256'}) and type(m['bytes']) is int
                and 0 < m['bytes'] <= JSON_LIMIT and type(m['sha256']) is str
                and re.fullmatch('[0-9a-f]{64}', m['sha256']), 'selection member identity/type')
    require(s['member']['path'] == 'receipt.json'
            and s['smokeRow']['artifact'] == 'smoke-linux-amd64-purego'
            and s['smokeRow']['path'] == 'native-row-' + s['archive']['root'] + '.json', 'selection member path')
    require(s['identity']['source'] == SOURCE and s['identity']['version'] == VERSION
            and s['identity']['profile']['linkage'] == 'shared-purego', 'selection native identity')
    return s, digest(raw)


def select(root, source, version, tag, tree=None, tag_object=None):
    # A wrong run or source must not disable the required current selection.
    if source != SOURCE and version != VERSION and tag != 'v' + VERSION:
        return None
    s, hashed = load(root)
    require((source, version, tag) == (s['sourceCommit'], s['version'], s['tag']), 'source/version/tag mismatch')
    if tree is not None:
        require(tree == s['sourceTree'], 'source tree mismatch')
    if tag_object is not None:
        require(tag_object == s['tagObject'], 'tag object mismatch')
    return {'selection': s, 'sha256': hashed}


def scoped(scope, policy, runs):
    if policy is None:
        return scope
    s = policy['selection']
    require(runs.get('all') == str(s['runId']), 'All producer run mismatch')
    scope = copy.deepcopy(scope)
    a = s['artifact']['name']
    require(a not in scope['all']['requiredArtifacts'] and a not in scope['all']['payloadRules'], 'selection duplicates historical scope')
    require(scope['all']['workflow'] == s['workflow'], 'scope workflow mismatch')
    scope['all']['requiredArtifacts'].append(a)
    scope['all']['payloadRules'][a] = [{'pattern': r'receipt\.json', 'count': 1}]
    return scope


def mapping(root, role, artifact, relative, source):
    # No prefix allow rule: only this one selected full name can be nonpublic.
    if artifact != 'native-controlled-peer-' + SOURCE:
        return None
    s, _ = load(root)
    require(role == 'all' and source == SOURCE and relative == s['member']['path'], 'nonpublic mapping identity')
    return None, DISPOSITION


def check_api(policy, role, run, a):
    s = policy['selection']
    require(role == 'all' and run['run_attempt'] == s['runAttempt']
            and type(run['run_attempt']) is int and run['path'] == s['workflow'], 'peer run/role/attempt mismatch')
    require({k: a.get(k) for k in s['artifact']} == s['artifact'], 'peer API artifact mismatch')
    require(a.get('expired') is False, 'peer expired')
    ar = a.get('workflow_run', {})
    require((ar.get('id'), ar.get('head_sha'), ar.get('repository_id'), ar.get('head_repository_id')) ==
            (s['runId'], SOURCE, s['repositoryId'], s['repositoryId']), 'peer API origin mismatch')


def members(policy, items):
    s = policy['selection']
    require(len(items) == 1 and not items[0].is_dir() and items[0].filename == 'receipt.json'
            and items[0].file_size == s['member']['bytes'], 'exact one regular root receipt required')


def summary(policy):
    s = policy['selection']
    return {'schema': 'polaris-validated-controlled-peer-evidence-v1', 'sourceCommit': SOURCE,
            'runId': s['runId'], 'runAttempt': s['runAttempt'], 'caseCount': 14, 'passed': 14,
            'processesGraceful': 42, 'publicationEligible': False,
            'coreSHA256': s['identity']['coreSHA256'], 'sidecarSHA256': s['identity']['sidecar']['sha256'],
            'nativeIndexSHA256': s['nativeIndexSHA256'], 'smokeRowSHA256': s['smokeRow']['sha256']}


def validate_receipt(policy, measured, r):
    s = policy['selection']
    require(measured == {k: s['member'][k] for k in ('bytes', 'sha256')}, 'receipt bytes changed')
    require(type(r) is dict and r.get('schema') == 'polaris-native-controlled-peer-v1'
            and r.get('status') == 'PASS' and r.get('publicationEligible') is False
            and not any(k in r for k in ('diagnosticOnly', 'reusedProduct', 'producer', 'runner')),
            'receipt type/status/origin mismatch')
    require(r.get('context') == {'sourceCommit': SOURCE, 'sourceTree': s['sourceTree'],
            'runId': s['runId'], 'runAttempt': s['runAttempt'], 'workflowCommit': SOURCE}
            and type(r['context']['runId']) is int and type(r['context']['runAttempt']) is int,
            'receipt source/run identity mismatch')
    require({k: r.get('artifact', {}).get(k) for k in s['carrierArtifact']} == s['carrierArtifact']
            and {k: r.get('identity', {}).get(k) for k in s['identity']} == s['identity']
            and r.get('producerRowSHA256') == s['smokeRow']['sha256'] and r.get('archive') == s['archive'],
            'receipt native identity mismatch')
    require(r.get('privateWorkspaceDeleted') is True and r.get('privateOriginalConfigurationArchived') is False
            and r.get('descendantRetirement') == {'remaining': [], 'forcedKill': False, 'retired': []}, 'suite cleanup incomplete')
    cases = r.get('cases')
    require(type(cases) is list and [(c.get('kind'), c.get('mutation')) for c in cases] == CASES, 'exact 14 cases required')
    identities = set()
    for c in cases:
        require(c.get('status') == 'PASS' and c.get('continuationSafe') is True
                and c.get('identityUncertain') is False and c.get('fixturesJoined') is True
                and c.get('rawConfigurationPubliclyRetained') is False and c.get('privateFilesDeletedAtSuiteEnd') is True
                and c.get('descendantRetirement') == {'remaining': [], 'forcedKill': False, 'retired': []}, 'case not safely passed')
        require(c.get('portsReleased') and all(p.get('released') is True for p in c['portsReleased']), 'ports not released')
        require(type(c.get('cleanup')) is list and len(c['cleanup']) == 3, 'case process scope changed')
        for process in c['cleanup']:
            birth = process.get('startIdentity', {})
            pid, ticks = birth.get('pid'), birth.get('startTicks')
            require(type(pid) is int and pid > 0 and type(ticks) is int and ticks > 0
                    and process.get('pid') == pid and (pid, ticks) not in identities, 'duplicate/invalid process identity')
            identities.add((pid, ticks))
            require(type(process.get('exitCode')) is int and process['exitCode'] == 0
                    and process.get('forcedKill') is False and process.get('gracefulCleanupProven') is True
                    and process.get('exitBeforeTerminate') is None and process.get('closeOperationFailure') is None
                    and process.get('resourceCloseErrors') == [] and process.get('remainingGroup') == []
                    and process.get('cleanupErrorLog') is False and process.get('boundCoreSHA256') == s['identity']['coreSHA256'],
                    'process cleanup incomplete')
            actions = process.get('terminationActions')
            require(type(actions) is list and len(actions) == 1 and actions[0].get('signal') == 'SIGTERM'
                    and actions[0].get('pidfdBound') is True and actions[0].get('pid') == pid
                    and actions[0].get('startTicks') == ticks and actions[0].get('coreSHA256') == s['identity']['coreSHA256'],
                    'own graceful termination not proven')
    require(len(identities) == 42, 'exact process count changed')
    return summary(policy)


def cross_bind(policy, index, index_sha, all_entry):
    s = policy['selection']
    require(index_sha == s['nativeIndexSHA256'], 'final index bytes differ')
    rows = [r for r in index['platforms'] if r['id'] == s['archive']['root']]
    require(len(rows) == 1, 'native row absent/ambiguous')
    row = copy.deepcopy(rows[0])
    require(row['archive'].pop('releaseName', None) == 'sing-box-polaris-' + s['archive']['name'].removeprefix('sing-box-'),
            'index public name enrichment differs')
    require(digest(json.dumps(row, sort_keys=True).encode()) == s['identity']['nativeRowSHA256']
            and row['archive'] == s['archive'] and row['core']['sha256'] == s['identity']['coreSHA256']
            and row['sidecar'] == s['identity']['sidecar'] and row['variant'] == s['identity']['profile'], 'final row identity differs')
    carrier = all_entry['artifacts'][s['carrierArtifact']['name']]
    require((carrier['id'], carrier['archiveBytes'], carrier['archiveSha256']) ==
            tuple(s['carrierArtifact'][k] for k in ('id', 'size_in_bytes', 'digest')), 'actual carrier API identity differs')
    archive = carrier['files'][s['archive']['name']]
    require((archive['bytes'], archive['sha256']) == (s['archive']['bytes'], s['archive']['sha256']), 'actual carrier archive differs')
    smoke = all_entry['artifacts'][s['smokeRow']['artifact']]['files'][s['smokeRow']['path']]
    require((smoke['bytes'], smoke['sha256']) == (s['smokeRow']['bytes'], s['smokeRow']['sha256']), 'actual smoke row differs')


def record(policy, publisher):
    require(type(publisher) is str and re.fullmatch('[0-9a-f]{40}', publisher), 'publisher SHA required')
    return {'path': PATH, 'sha256': policy['sha256'], 'publisherCommit': publisher, 'evidence': summary(policy)}


def check_inventory(root, actual, publisher):
    if (actual['sourceCommit'] != SOURCE and actual.get('version') != VERSION
            and actual.get('tag') != 'v' + VERSION and 'controlledPeerEvidence' not in actual):
        return  # Only genuinely historical non-peer release identities are outside this selection.
    policy = select(root, actual['sourceCommit'], actual['version'], actual['tag'], actual['sourceTree'], actual['tagObject'])
    if policy is None:
        require('controlledPeerEvidence' not in actual, 'unexpected historical peer selection')
        return
    s = policy['selection']
    require(actual.get('controlledPeerEvidence') == record(policy, publisher), 'inventory selection differs')
    run = actual['runs']['all']
    require((run['id'], run['attempt'], run['workflow']) == (str(s['runId']), s['runAttempt'], s['workflow']), 'inventory producer differs')
    a = run['artifacts'][s['artifact']['name']]
    require((a['id'], a['archiveBytes'], a['archiveSha256']) ==
            tuple(s['artifact'][k] for k in ('id', 'size_in_bytes', 'digest')) and set(a['files']) == {'receipt.json'},
            'inventory peer artifact differs')
    f = a['files']['receipt.json']
    require(f == {'bytes': s['member']['bytes'], 'sha256': s['member']['sha256'],
                 'releaseName': None, 'publicationDisposition': DISPOSITION, 'controlledPeerEvidence': summary(policy)},
            'inventory peer mapping/evidence differs')
