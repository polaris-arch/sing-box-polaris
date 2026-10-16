"""Check the actual selected core's capability JSON and configuration admission.

No network handshake is claimed here. Handshakes belong to the raced Go suite.
Native callers supply the original producer row and retain its schema unchanged.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
UTLS_MODULES = ('github.com/refraction-networking/utls', 'github.com/metacubex/utls')


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def expected_profiles():
    source = (ROOT / 'option/tls.go').read_text()
    match = re.search(r'Fingerprint\s+string\s+`[^`]*enum:"([^"]+)"', source)
    if not match:
        raise ValueError('source-owned fingerprint enum missing')
    return set(match[1].split(','))


def source_module_pins():
    source = (ROOT / 'go.mod').read_text()
    sums = {}
    for line in (ROOT / 'go.sum').read_text().splitlines():
        path, version, value = line.split()
        sums[path, version] = value
    result = {}
    for path in UTLS_MODULES:
        version = re.search(r'^\s*' + re.escape(path) + r'\s+(v\S+)\s*$', source, re.M)
        if not version:
            raise ValueError('direct uTLS source pin missing: ' + path)
        result[path] = (version[1], sums[path, version[1]])
    return result


def linked_module_pins():
    """Actual BuildInfo identities, including the one source-owned Meta delta.

    The upstream h1 is baseline provenance, not the checksum of modified code.
    The producer's sourceCommit/tree and localReplacement tree bind those bytes.
    """
    pins=source_module_pins()
    expected={path:{'path':path,'version':version,'sum':checksum} for path,(version,checksum) in pins.items()}
    module='github.com/metacubex/utls';local='./third_party/metacubex-utls'
    manifest=json.loads((ROOT/'release/dependency-sources/metacubex-utls-replacement.json').read_text())
    if (manifest['schema'],manifest['module'],manifest['upstreamVersion'],manifest['upstreamH1'],manifest['replacementPath']) != (
            'polaris-repository-module-replacement-v1',module,*pins[module],local):
        raise ValueError('source-owned Meta baseline/replacement differs from direct source pins')
    if not re.search(r'^replace '+re.escape(module)+r' => '+re.escape(local)+r'$',(ROOT/'go.mod').read_text(),re.M):
        raise ValueError('missing exact source-owned Meta replacement')
    root=ROOT/local[2:]
    if root.is_symlink() or not root.is_dir():
        raise ValueError('source-owned Meta root must be a real directory')
    actual={p.relative_to(root).as_posix():p for p in root.rglob('*') if p.is_file()}
    if set(actual)!=set(manifest['files']) or any(p.is_symlink() for p in root.rglob('*')):
        raise ValueError('source-owned Meta file inventory mismatch')
    for name,p in actual.items():
        if sha(p)!=manifest['files'][name]['afterSHA256'] or p.stat().st_size!=manifest['files'][name]['bytes']:
            raise ValueError('source-owned Meta bytes differ: '+name)
    if sha(ROOT/manifest['patch'])!=manifest['patchSHA256']:
        raise ValueError('source-owned Meta delta digest differs')
    expected[module]={'path':module,'version':pins[module][0],'sum':'',
                      'replace':{'path':local,'version':'(devel)','sum':''}}
    return expected


def producer_module_identities(graph):
    identities={}
    for row in graph['normalModules']+graph['localReplacements']:
        if row['module'] not in UTLS_MODULES:continue
        if row['module'] in identities:raise ValueError('duplicate actual producer uTLS module')
        item={'path':row['module'],'version':row['version'],'sum':row['h1']}
        if 'replacement' in row:
            replacement=row['replacement']
            item['replace']={'path':replacement['module'],'version':replacement['version'],'sum':replacement['h1']}
        identities[row['module']]=item
    return identities


def validate(document, *, source, version, go_version, target, enabled=True, expected_modules=None):
    import jsonschema
    schema = json.loads((ROOT / 'release/ci/tls-fingerprint-capabilities.schema.json').read_text())
    jsonschema.Draft202012Validator(schema).validate(document)
    osname, arch = target.split('/')
    for key, expected in [('sourceCommit', source), ('coreVersion', version),
                          ('goVersion', go_version), ('requiredGoVersion', 'go' + (ROOT / 'release/GO_VERSION').read_text().strip()),
                          ('os', osname), ('arch', arch), ('enabled', enabled), ('sourceModified', False)]:
        # bool is not an interchangeable integer in this contract.
        if type(document[key]) is not type(expected) or document[key] != expected:
            raise ValueError('selected-core capability binding mismatch: ' + key)
    ids = [profile['id'] for profile in document['profiles']]
    aliases = document['legacyChromeAliases']
    if len(set(ids)) != len(ids) or set(ids).intersection(aliases):
        raise ValueError('duplicate/ambiguous runtime profile IDs')
    if enabled and (set(ids) | set(aliases)) != expected_profiles():
        raise ValueError('actual capabilities differ from source-owned accepted IDs')
    if not enabled and (ids or aliases):
        raise ValueError('stub advertises fingerprint support')
    if document['defaultFingerprint'] != 'chrome':
        raise ValueError('default mapping changed')
    if not document['randomSemantics'] or not document['randomizedSemantics'] or not document['negotiationEvidence']:
        raise ValueError('selection/negotiation boundary missing')
    if enabled:
        profiles = {p['id']: p for p in document['profiles']}
        for key, template in [('chrome', '155'), ('chrome_155', '155'), ('chrome_133', '133'),
                              ('firefox', '148'), ('firefox_148', '148'), ('firefox_120', '120'),
                              ('safari', '26.3'), ('safari_26_3', '26.3'), ('safari_16_0', '16.0')]:
            if profiles[key]['templateVersion'] != template:
                raise ValueError('actual template version mismatch: ' + key)
        if profiles['random']['selection'] != 'process-browser' or profiles['randomized']['selection'] != 'process-seeded-generator':
            raise ValueError('random/randomized meanings changed')
        if profiles['randomized']['templateOffersX25519MLKEM768'] is not None:
            raise ValueError('random generator cannot promise a concrete PQ offer')
        modules = {}
        for module in document['modules']:
            if module['path'] in modules:
                raise ValueError('duplicate uTLS module')
            modules[module['path']] = module
        pins = linked_module_pins()
        if expected_modules is not None and expected_modules != pins:
            raise ValueError('producer module graph differs from source-owned direct pins')
        if modules != pins:
            raise ValueError('actual linked uTLS module identities differ from producer/source pins')
    return document


def outbound_config(fingerprint=None, enabled=True):
    utls = {'enabled': enabled}
    if fingerprint is not None:
        utls['fingerprint'] = fingerprint
    return {'log': {'level': 'error'}, 'outbounds': [{'type': 'trojan', 'tag': 'probe',
            'server': '127.0.0.1', 'server_port': 443, 'password': 'local-config-admission-only',
            'tls': {'enabled': True, 'server_name': 'tls.invalid', 'utls': utls}}]}


def check_configs(core, document):
    accepted = [p['id'] for p in document['profiles']] + document['legacyChromeAliases'] if document['enabled'] else []
    cases = [(name, True, True) for name in accepted]
    cases += [(None, True, document['enabled']), ('', True, document['enabled']), (None, False, True)]
    cases += [(name, True, False) for name in ['polaris_unknown_profile', 'default', 'disabled', 'follow', 'safari_15_3', 'safari_15_5']]
    observations = []
    with tempfile.TemporaryDirectory(prefix='tls-admission-') as temporary:
        config = Path(temporary) / 'config.json'
        for name, enabled, passes in cases:
            config.write_text(json.dumps(outbound_config(name, enabled)))
            result = subprocess.run([str(core), 'check', '-c', str(config)], text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
            observations.append({'fingerprint': name, 'enabled': enabled, 'expectedPass': passes,
                                 'exitCode': result.returncode, 'output': result.stdout})
            if (result.returncode == 0) != passes:
                raise ValueError('actual core configuration admission mismatch: ' + json.dumps(observations[-1]))
            if not passes and document['enabled'] and 'unknown uTLS fingerprint' not in result.stdout:
                raise ValueError('negative control failed for an unrelated reason: ' + result.stdout)
        # Exercise the real outbound construction entry, not just a JSON enum.
        if document['enabled']:
            for ech in [False, True]:
                candidate = outbound_config('chrome')
                out = candidate['outbounds'][0];out['type'] = 'shadowtls';out['version'] = 3
                if ech: out['tls']['ech'] = {'enabled': True}
                config.write_text(json.dumps(candidate))
                result = subprocess.run([str(core), 'check', '-c', str(config)], text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
                observations.append({'outbound': 'shadowtls', 'version': 3, 'realECH': ech,
                                     'expectedPass': not ech, 'exitCode': result.returncode, 'output': result.stdout})
                if (result.returncode == 0) != (not ech) or (ech and 'cannot be combined with real ECH' not in result.stdout):
                    raise ValueError('ShadowTLS ECH boundary mismatch: ' + result.stdout)
    return observations


def probe(core, *, source, version, go_version, target, enabled=True, expected_sha=None, expected_modules=None):
    core = Path(core).resolve(strict=True)
    digest = sha(core)
    if expected_sha is not None and digest != expected_sha:
        raise ValueError('actual selected core bytes differ from producer row')
    command = [str(core), 'tools', 'tls-fingerprints']
    try:
        result = subprocess.run(command, text=True, capture_output=True, timeout=30)
        query = {'command': command, 'exitCode': result.returncode,
                 'stdout': result.stdout, 'stderr': result.stderr, 'timedOut': False}
    except subprocess.TimeoutExpired as error:
        def output_text(value):
            return value.decode(errors='replace') if isinstance(value, bytes) else (value or '')
        query = {'command': command, 'exitCode': None, 'stdout': output_text(error.stdout),
                 'stderr': output_text(error.stderr), 'timedOut': True}
    core.with_name(core.name + '-capability-query.json').write_text(json.dumps(query, indent=2) + '\n')
    if query['exitCode'] != 0:
        raise ValueError('actual core capability query failed: ' + json.dumps(query))
    document = json.loads(query['stdout'])
    validate(document, source=source, version=version, go_version=go_version, target=target,
             enabled=enabled, expected_modules=expected_modules)
    observations = check_configs(core, document)
    if sha(core) != digest:
        raise ValueError('selected core changed during capability/configuration probe')
    receipt = {'schema': 'polaris-tls-fingerprint-runtime-probe-v1', 'coreSHA256': digest,
               'coreBytes': core.stat().st_size, 'capabilities': document,
               'configurationChecks': observations, 'networkHandshakeValidated': False}
    print('TLS_FINGERPRINT_PROBE ' + json.dumps(receipt, sort_keys=True), flush=True)
    return receipt
