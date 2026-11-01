"""Strict validation shared by immutable, nonpublic controlled-peer selections."""
import copy
import hashlib
import json
import math
from pathlib import Path
import re
import stat
from release_identity import same_identity

DISPOSITION = 'controlled-peer-evidence'
JSON_LIMIT = 1024 * 1024
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


def load(root, *, path, expected_source, expected_version, run_id):
    path = Path(root) / path
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= JSON_LIMIT, 'selection must be bounded regular file')
    raw = path.read_bytes()
    s = strict_json(raw)
    require(type(s) is dict and set(s) == {
        'schema', 'repository', 'repositoryId', 'version', 'tag', 'sourceCommit', 'sourceTree',
        'tagObject', 'workflow', 'runId', 'runAttempt', 'artifact', 'member', 'nativeIndexSHA256',
        'smokeRow', 'carrierArtifact', 'identity', 'archive', 'publicationEligible', 'publicationDisposition'},
        'selection fields differ')
    require(same_identity(s['schema'], 'polaris-exact-controlled-peer-selection-v1')
            and same_identity(s['repository'], 'polaris-arch/sing-box-polaris')
            and type(s['repositoryId']) is int and same_identity(s['repositoryId'], 1421657509)
            and same_identity(s['sourceCommit'], expected_source) and same_identity(s['version'], expected_version) and same_identity(s['tag'], 'v' + expected_version)
            and same_identity(s['workflow'], '.github/workflows/build.yml')
            and type(s['runId']) is int and same_identity(s['runId'], run_id)
            and type(s['runAttempt']) is int and same_identity(s['runAttempt'], 1)
            and s['publicationEligible'] is False and same_identity(s['publicationDisposition'], DISPOSITION),
            'selection identity/type differs')
    for key in ('sourceTree', 'tagObject'):
        require(type(s[key]) is str and re.fullmatch('[0-9a-f]{40}', s[key]), 'selection Git identity')
    require(re.fullmatch('[0-9a-f]{64}', s['nativeIndexSHA256']) is not None, 'index digest')
    for key, name in [('artifact', 'native-controlled-peer-' + expected_source), ('carrierArtifact', 'binary-linux_amd64-purego')]:
        a = s[key]
        require(type(a) is dict and set(a) == {'id', 'name', 'size_in_bytes', 'digest'}
                and type(a['id']) is int and a['id'] > 0 and same_identity(a['name'], name)
                and type(a['size_in_bytes']) is int and a['size_in_bytes'] > 0
                and type(a['digest']) is str and re.fullmatch('sha256:[0-9a-f]{64}', a['digest']),
                'selection artifact identity/type')
    for key in ('member', 'smokeRow'):
        m = s[key]
        require(type(m) is dict and set(m) == ({'path', 'bytes', 'sha256'} if key == 'member'
                else {'artifact', 'path', 'bytes', 'sha256'}) and type(m['bytes']) is int
                and 0 < m['bytes'] <= JSON_LIMIT and type(m['sha256']) is str
                and re.fullmatch('[0-9a-f]{64}', m['sha256']), 'selection member identity/type')
    require(same_identity(s['member']['path'], 'receipt.json')
            and same_identity(s['smokeRow']['artifact'], 'smoke-linux-amd64-purego')
            and same_identity(s['smokeRow']['path'], 'native-row-' + s['archive']['root'] + '.json'), 'selection member path')
    require(type(s['archive']['bytes']) is int and s['archive']['bytes'] > 0
            and type(s['identity']['sidecar']['bytes']) is int and s['identity']['sidecar']['bytes'] > 0
            and type(s['identity']['profile']['legacy']) is bool, 'selection native scalar type differs')
    require(same_identity(s['identity']['source'], expected_source) and same_identity(s['identity']['version'], expected_version)
            and same_identity(s['identity']['profile']['linkage'], 'shared-purego'), 'selection native identity')
    return s, digest(raw)


def select(root, source, version, tag, tree=None, tag_object=None, *, expected_source, expected_version, load):
    # A wrong run or source must not disable the required current selection.
    if source != expected_source and version != expected_version and tag != 'v' + expected_version:
        return None
    s, hashed = load(root)
    require(same_identity((source, version, tag), (s['sourceCommit'], s['version'], s['tag'])), 'source/version/tag mismatch')
    if tree is not None:
        require(same_identity(tree, s['sourceTree']), 'source tree mismatch')
    if tag_object is not None:
        require(same_identity(tag_object, s['tagObject']), 'tag object mismatch')
    return {'selection': s, 'sha256': hashed}


def scoped(scope, policy, runs):
    if policy is None:
        return scope
    s = policy['selection']
    require(same_identity(runs.get('all'), str(s['runId'])), 'All producer run mismatch')
    scope = copy.deepcopy(scope)
    a = s['artifact']['name']
    require(a not in scope['all']['requiredArtifacts'] and a not in scope['all']['payloadRules'], 'selection duplicates historical scope')
    require(same_identity(scope['all']['workflow'], s['workflow']), 'scope workflow mismatch')
    scope['all']['requiredArtifacts'].append(a)
    scope['all']['payloadRules'][a] = [{'pattern': r'receipt\.json', 'count': 1}]
    return scope


def mapping(root, role, artifact, relative, source, *, expected_source, load):
    # No prefix allow rule: only this one selected full name can be nonpublic.
    if artifact != 'native-controlled-peer-' + expected_source:
        return None
    s, _ = load(root)
    require(role == 'all' and source == expected_source and same_identity(relative, s['member']['path']), 'nonpublic mapping identity')
    return None, DISPOSITION


def check_api(policy, role, run, a, *, expected_source):
    s = policy['selection']
    require(role == 'all' and same_identity(run['run_attempt'], s['runAttempt'])
            and type(run['run_attempt']) is int and same_identity(run['path'], s['workflow']), 'peer run/role/attempt mismatch')
    require(same_identity({k: a.get(k) for k in s['artifact']}, s['artifact']), 'peer API artifact mismatch')
    require(a.get('expired') is False, 'peer expired')
    ar = a.get('workflow_run', {})
    require(same_identity((ar.get('id'), ar.get('head_sha'), ar.get('repository_id'), ar.get('head_repository_id')), (s['runId'], expected_source, s['repositoryId'], s['repositoryId'])), 'peer API origin mismatch')


def members(policy, items):
    s = policy['selection']
    require(len(items) == 1 and not items[0].is_dir() and items[0].filename == 'receipt.json'
            and same_identity(items[0].file_size, s['member']['bytes']), 'exact one regular root receipt required')


def summary(policy, *, expected_source):
    s = policy['selection']
    return {'schema': 'polaris-validated-controlled-peer-evidence-v1', 'sourceCommit': expected_source,
            'runId': s['runId'], 'runAttempt': s['runAttempt'], 'caseCount': 14, 'passed': 14,
            'processesGraceful': 42, 'publicationEligible': False,
            'coreSHA256': s['identity']['coreSHA256'], 'sidecarSHA256': s['identity']['sidecar']['sha256'],
            'nativeIndexSHA256': s['nativeIndexSHA256'], 'smokeRowSHA256': s['smokeRow']['sha256']}


def validate_receipt(policy, measured, r, *, expected_source, summary):
    s = policy['selection']
    require(same_identity(measured, {k: s['member'][k] for k in ('bytes', 'sha256')}), 'receipt bytes changed')
    require(type(r) is dict and same_identity(r.get('schema'), 'polaris-native-controlled-peer-v1')
            and same_identity(r.get('status'), 'PASS') and r.get('publicationEligible') is False
            and not any(k in r for k in ('diagnosticOnly', 'reusedProduct', 'producer', 'runner')),
            'receipt type/status/origin mismatch')
    require(same_identity(r.get('context'), {'sourceCommit': expected_source, 'sourceTree': s['sourceTree'],
            'runId': s['runId'], 'runAttempt': s['runAttempt'], 'workflowCommit': expected_source})
            and type(r['context']['runId']) is int and type(r['context']['runAttempt']) is int,
            'receipt source/run identity mismatch')
    require(same_identity({k: r.get('artifact', {}).get(k) for k in s['carrierArtifact']}, s['carrierArtifact'])
            and same_identity({k: r.get('identity', {}).get(k) for k in s['identity']}, s['identity'])
            and same_identity(r.get('producerRowSHA256'), s['smokeRow']['sha256']) and same_identity(r.get('archive'), s['archive']),
            'receipt native identity mismatch')
    require(r.get('privateWorkspaceDeleted') is True and r.get('privateOriginalConfigurationArchived') is False
            and same_identity(r.get('descendantRetirement'), {'remaining': [], 'forcedKill': False, 'retired': []}), 'suite cleanup incomplete')
    cases = r.get('cases')
    require(type(cases) is list and same_identity([(c.get('kind'), c.get('mutation')) for c in cases], CASES), 'exact 14 cases required')
    identities = set()
    for c in cases:
        require(same_identity(c.get('status'), 'PASS') and c.get('continuationSafe') is True
                and c.get('identityUncertain') is False and c.get('fixturesJoined') is True
                and c.get('rawConfigurationPubliclyRetained') is False and c.get('privateFilesDeletedAtSuiteEnd') is True
                and same_identity(c.get('descendantRetirement'), {'remaining': [], 'forcedKill': False, 'retired': []}), 'case not safely passed')
        require(c.get('portsReleased') and all(p.get('released') is True for p in c['portsReleased']), 'ports not released')
        require(type(c.get('cleanup')) is list and len(c['cleanup']) == 3, 'case process scope changed')
        for process in c['cleanup']:
            birth = process.get('startIdentity', {})
            pid, ticks = birth.get('pid'), birth.get('startTicks')
            require(type(pid) is int and pid > 0 and type(ticks) is int and ticks > 0
                    and same_identity(process.get('pid'), pid) and (pid, ticks) not in identities, 'duplicate/invalid process identity')
            identities.add((pid, ticks))
            require(type(process.get('exitCode')) is int and same_identity(process['exitCode'], 0)
                    and process.get('forcedKill') is False and process.get('gracefulCleanupProven') is True
                    and process.get('exitBeforeTerminate') is None and process.get('closeOperationFailure') is None
                    and same_identity(process.get('resourceCloseErrors'), []) and same_identity(process.get('remainingGroup'), [])
                    and process.get('cleanupErrorLog') is False and same_identity(process.get('boundCoreSHA256'), s['identity']['coreSHA256']),
                    'process cleanup incomplete')
            actions = process.get('terminationActions')
            require(type(actions) is list and len(actions) == 1 and same_identity(actions[0].get('signal'), 'SIGTERM')
                    and actions[0].get('pidfdBound') is True and same_identity(actions[0].get('pid'), pid)
                    and same_identity(actions[0].get('startTicks'), ticks) and same_identity(actions[0].get('coreSHA256'), s['identity']['coreSHA256']),
                    'own graceful termination not proven')
    require(len(identities) == 42, 'exact process count changed')
    return summary(policy)


def cross_bind(policy, index, index_sha, all_entry):
    s = policy['selection']
    require(same_identity(index_sha, s['nativeIndexSHA256']), 'final index bytes differ')
    rows = [r for r in index['platforms'] if same_identity(r['id'], s['archive']['root'])]
    require(len(rows) == 1, 'native row absent/ambiguous')
    row = copy.deepcopy(rows[0])
    require(row['archive'].pop('releaseName', None) == 'sing-box-polaris-' + s['archive']['name'].removeprefix('sing-box-'),
            'index public name enrichment differs')
    require(same_identity(digest(json.dumps(row, sort_keys=True).encode()), s['identity']['nativeRowSHA256'])
            and same_identity(row['archive'], s['archive']) and same_identity(row['core']['sha256'], s['identity']['coreSHA256'])
            and same_identity(row['sidecar'], s['identity']['sidecar']) and same_identity(row['variant'], s['identity']['profile']), 'final row identity differs')
    carrier = all_entry['artifacts'][s['carrierArtifact']['name']]
    require(same_identity((carrier['id'], carrier['archiveBytes'], carrier['archiveSha256']), tuple(s['carrierArtifact'][k] for k in ('id', 'size_in_bytes', 'digest'))), 'actual carrier API identity differs')
    archive = carrier['files'][s['archive']['name']]
    require(same_identity((archive['bytes'], archive['sha256']), (s['archive']['bytes'], s['archive']['sha256'])), 'actual carrier archive differs')
    smoke = all_entry['artifacts'][s['smokeRow']['artifact']]['files'][s['smokeRow']['path']]
    require(same_identity((smoke['bytes'], smoke['sha256']), (s['smokeRow']['bytes'], s['smokeRow']['sha256'])), 'actual smoke row differs')


def record(policy, publisher, *, path, summary):
    require(type(publisher) is str and re.fullmatch('[0-9a-f]{40}', publisher), 'publisher SHA required')
    return {'path': path, 'sha256': policy['sha256'], 'publisherCommit': publisher, 'evidence': summary(policy)}


def check_inventory(root, actual, publisher, *, expected_source, expected_version, select, record, summary):
    if (actual['sourceCommit'] != expected_source and actual.get('version') != expected_version
            and actual.get('tag') != 'v' + expected_version and 'controlledPeerEvidence' not in actual):
        return  # Only genuinely historical non-peer release identities are outside this selection.
    policy = select(root, actual['sourceCommit'], actual['version'], actual['tag'], actual['sourceTree'], actual['tagObject'])
    if policy is None:
        require('controlledPeerEvidence' not in actual, 'unexpected historical peer selection')
        return
    s = policy['selection']
    require(same_identity(actual.get('controlledPeerEvidence'), record(policy, publisher)), 'inventory selection differs')
    run = actual['runs']['all']
    require(same_identity((run['id'], run['attempt'], run['workflow']), (str(s['runId']), s['runAttempt'], s['workflow'])), 'inventory producer differs')
    a = run['artifacts'][s['artifact']['name']]
    require(same_identity((a['id'], a['archiveBytes'], a['archiveSha256']), tuple(s['artifact'][k] for k in ('id', 'size_in_bytes', 'digest'))) and set(a['files']) == {'receipt.json'},
            'inventory peer artifact differs')
    f = a['files']['receipt.json']
    require(same_identity(f, {'bytes': s['member']['bytes'], 'sha256': s['member']['sha256'],
                 'releaseName': None, 'publicationDisposition': DISPOSITION, 'controlledPeerEvidence': summary(policy)}),
            'inventory peer mapping/evidence differs')
