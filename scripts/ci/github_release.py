#!/usr/bin/env python3
"""GitHub-only, create-only release gate. Inventory is read-only; never auto-review it."""
import argparse
import hashlib
from datetime import datetime
from urllib.parse import quote, urlsplit, urlunsplit

from release_identity import remote_tag_identity
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile

REPO = 'polaris-arch/sing-box-polaris'
RID = 1421657509
VERSION = '1.15.0-polaris-alpha.12'
TAG = 'v' + VERSION
ROOT = Path(__file__).resolve().parents[2]
SCOPE = ROOT / 'release/ci/publisher-upstream-scope.json'
CONFIG = ROOT / 'release/ci/github-release.json'
RECEIPT = 'polaris-github-release-receipt-' + VERSION + '.json'
BLOCKED = [
    'Signed installable iOS and tvOS IPA exports require owned signing and provisioning.',
    'Signed macOS App Store PKG and Developer ID signed/notarized standalone PKG require owned signing.',
    'Store/TestFlight submissions and registry pushes are outside this GitHub-only release.',
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def api(path, method='GET', payload=None):
    args = ['gh', 'api', '--method', method, path]
    if payload is not None:
        args += ['--input', '-']
    return json.loads(subprocess.check_output(args, input=json.dumps(payload).encode() if payload is not None else None))


def pages(path, key=None):
    result = []
    for page in range(1, 10001):
        data = api(path + ('&' if '?' in path else '?') + f'per_page=100&page={page}')
        batch = data[key] if key else data
        result.extend(batch)
        if len(batch) < 100:
            return result
    raise ValueError('pagination bound exceeded')


def portable(name):
    p = PurePosixPath(name)
    require(not p.is_absolute() and '..' not in p.parts and '\\' not in name and ':' not in name, 'unsafe artifact path')
    require(p.parts and all(re.fullmatch(r'[A-Za-z0-9_.+ -]+', x) and x not in ('.', '..') for x in p.parts), 'unsafe filename')
    return p


def extract(archive, directory):
    seen = set()
    with zipfile.ZipFile(archive) as z:
        for item in z.infolist():
            p = portable(item.filename)
            if item.is_dir():
                continue
            require(stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG), 'non-regular archive entry')
            require(p.as_posix().casefold() not in seen, 'duplicate ZIP path')
            seen.add(p.as_posix().casefold())
            target = directory.joinpath(*p.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(item) as src, target.open('xb') as dst:
                shutil.copyfileobj(src, dst)


def identity(source, source_dir):
    require(re.fullmatch(r'[0-9a-f]{40}', source), 'full source SHA required')
    require(os.environ.get('GITHUB_REPOSITORY') == REPO and os.environ.get('GITHUB_REPOSITORY_ID') == str(RID), 'wrong workflow repository')
    require(api(f'repos/{REPO}')['id'] == RID, 'remote repository ID mismatch')
    require(command('git', '-C', str(source_dir), 'rev-parse', 'HEAD') == source, 'publisher checkout differs from source')
    require(not command('git', '-C', str(source_dir), 'status', '--porcelain', '--untracked-files=no'), 'tracked source is dirty')


def tag_identity(source):
    return remote_tag_identity(TAG, source)


def upload_endpoint(release, name):
    require(type(release.get('id')) is int and release['id'] > 0, 'invalid release ID')
    url = release.get('upload_url')
    require(isinstance(url, str), 'release upload URL missing')
    parsed = urlsplit(url.removesuffix('{?name,label}'))
    require(parsed.scheme == 'https' and parsed.netloc == 'uploads.github.com'
            and parsed.path == f'/repos/{REPO}/releases/{release["id"]}/assets'
            and not parsed.query and not parsed.fragment, 'unexpected release upload endpoint')
    require(len(portable(name).parts) == 1, 'upload filename must be a basename')
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, 'name=' + quote(name, safe=''), ''))


def validate_final_index(index, source, tree, tag_object, run_id, attempt, workflow):
    # A staging index is useful evidence, but never a production publication input.
    require(index.get('schema') == 'polaris-upstream-native-assets-v1', 'final native index schema required; staging forbidden')
    import jsonschema
    jsonschema.Draft202012Validator(json.loads((ROOT / 'release/ci/native-release-index.schema.json').read_text())).validate(index)
    for key, value in [('repository', REPO), ('repositoryId', RID), ('version', VERSION), ('tag', TAG),
                       ('tagObject', tag_object), ('sourceCommit', source), ('sourceTree', tree)]:
        require(index[key] == value, 'final native index binding mismatch: ' + key)
    producer = index['producer']
    require((producer['repository'], producer['repositoryId'], producer['workflow'], producer['workflowCommit'],
             producer['runId'], producer['runAttempt']) == (REPO, RID, workflow, source, int(run_id), attempt),
            'final native producer identity mismatch')
    from native_release_index import expected_native
    expected = expected_native(VERSION)
    require(len(index['platforms']) == 44 and {x['id'] for x in index['platforms']} == set(expected), 'exact 44 native identities required')
    for row in index['platforms']:
        require((row['sourceCommit'], row['sourceTree'], row['version'], row['tag']) == (source, tree, VERSION, TAG), 'mixed source native row')
        require((row['target'], row['variant']) == (expected[row['id']]['target'], expected[row['id']]['variant']), 'native row matrix mismatch')
        suffix = '.zip' if row['target'].startswith('windows/') else '.tar.gz'
        require(row['archive']['root'] == row['id'] and row['archive']['name'] == row['id'] + suffix, 'native archive identity mismatch')
    require(index['sourceArchive']['name'] == 'sing-box-polaris-source-' + source + '.tar.gz', 'immutable source archive basename required')


def default_name(role, artifact, relative):
    if role == 'signed' and not artifact.startswith('signed-apple-store-'):
        return None
    p = PurePosixPath(relative)
    if artifact.startswith('libbox-android-') and p.name in ('libbox.aar', 'libbox-legacy.aar'):
        return p.stem + '-' + VERSION + '-android-' + artifact.removeprefix('libbox-android-') + '.aar'
    if artifact.startswith('libbox-apple-') and p.name.startswith('Libbox-'):
        return 'Libbox-' + VERSION + '-' + artifact.removeprefix('libbox-apple-') + '.tar'
    if role == 'docker' and artifact.startswith('oci-') and p.name == 'image.tar':
        return 'sing-box-' + VERSION + '-' + artifact + '.tar'
    if role == 'docker' and artifact.startswith('binary-'):
        return 'sing-box-' + VERSION + '-container-' + artifact.removeprefix('binary-')
    # Provenance remains in the aggregate receipt; do not flatten repeated metadata.
    if p.name.startswith(('polaris-candidate-manifest-', 'native-row-')):
        return None
    return p.name


def verify_payloads(files, rules, artifact):
    payloads = {p for p in files if not PurePosixPath(p).name.startswith(('polaris-candidate-manifest-', 'native-row-'))}
    if artifact.startswith('smoke-'):
        require(not payloads and len(files) == 1, 'smoke evidence scope mismatch')
        return
    matched = set()
    for rule in rules:
        found = {p for p in payloads if re.fullmatch(rule['pattern'], p)}
        require(len(found) == rule['count'] and not matched.intersection(found), 'required package/file scope mismatch: '+artifact)
        matched.update(found)
    require(matched == payloads, 'unlisted payload file in '+artifact)


def inventory(runs, source, work, source_tree, tag_object):
    scope = json.loads(SCOPE.read_text())
    require(set(runs) in ({'all', 'linux', 'docker'}, {'all', 'linux', 'docker', 'signed'}), 'all, linux and docker runs are mandatory')
    result = {'repository': REPO, 'repositoryId': RID, 'version': VERSION, 'sourceCommit': source,
              'scopeSha256': sha(SCOPE), 'reviewed': False, 'runs': {}, 'signedOnlyBlockers': BLOCKED,
              'sourceTree': source_tree, 'tag': TAG, 'tagObject': tag_object}
    for role, rid in runs.items():
        require(re.fullmatch(r'[1-9][0-9]*', rid), 'invalid run ID')
        run = api(f'repos/{REPO}/actions/runs/{rid}')
        require(run['repository']['id'] == RID and run['head_repository']['id'] == RID, 'foreign run')
        require(run['head_sha'] == source and run['path'] == scope[role]['workflow'], 'wrong source or workflow')
        require(run['status'] == 'completed' and run['conclusion'] == 'success', 'unsuccessful input run')
        require(run['event'] == 'workflow_dispatch', 'explicit build dispatch required')
        artifacts = pages(f'repos/{REPO}/actions/runs/{rid}/artifacts', 'artifacts')
        names = [x['name'] for x in artifacts]
        require(len(names) == len(set(names)), 'duplicate Actions artifact names')
        require(set(names) == set(scope[role]['requiredArtifacts']), f'{role}: incomplete or unexpected artifact scope: missing={set(scope[role]["requiredArtifacts"])-set(names)}, extra={set(names)-set(scope[role]["requiredArtifacts"])}')
        entry = {'id': rid, 'attempt': run['run_attempt'], 'workflow': run['path'], 'artifacts': {}}
        for a in artifacts:
            require(not a['expired'], 'expired artifact')
            require(datetime.fromisoformat(a['created_at'].replace('Z', '+00:00')) >= datetime.fromisoformat(run['run_started_at'].replace('Z', '+00:00')), 'artifact predates current run attempt')
            arun = a.get('workflow_run', {})
            require(arun.get('id') == int(rid) and arun.get('head_sha') == source, 'artifact source mismatch')
            directory = work / role / a['name']
            directory.mkdir(parents=True)
            with tempfile.NamedTemporaryFile() as zipped:
                subprocess.run(['gh', 'api', f'repos/{REPO}/actions/artifacts/{a["id"]}/zip'], stdout=zipped, check=True)
                zipped.flush()
                digest = 'sha256:' + sha(zipped.name)
                require(a.get('digest') == digest, 'Actions artifact digest missing or mismatched')
                extract(zipped.name, directory)
            files = {}
            for p in sorted(directory.rglob('*')):
                if p.is_file():
                    relative = p.relative_to(directory).as_posix()
                    files[relative] = {'bytes': p.stat().st_size, 'sha256': sha(p), 'releaseName': default_name(role, a['name'], relative)}
                    if p.name.startswith('polaris-candidate-manifest-'):
                        provenance = json.loads(p.read_text())
                        require(provenance['sourceCommit'] == source and str(provenance['workflowRunId']) == rid and int(provenance['workflowAttempt']) == run['run_attempt'], 'candidate manifest source/run mismatch')
            require(files, 'empty artifact')
            verify_payloads(files, scope[role]['payloadRules'][a['name']], a['name'])
            entry['artifacts'][a['name']] = {'id': a['id'], 'archiveSha256': digest, 'files': files}
        receipt = json.loads((work / role / 'publisher-run-receipt' / 'publisher-run-receipt.json').read_text())
        require(receipt == {'repository': REPO, 'repositoryId': RID, 'sourceCommit': source, 'runId': rid,
                            'attempt': run['run_attempt'], 'version': VERSION, 'build': 'All', 'role': role,
                            'publishStores': False, 'publishRegistry': False}, 'explicit All/version/run-attempt receipt mismatch')
        entry['artifacts']['publisher-run-receipt']['files']['publisher-run-receipt.json']['releaseName'] = None
        result['runs'][role] = entry
        if role in ('all', 'signed'):
            index = json.loads((work / role / 'binary-native-index' / 'polaris-upstream-native-assets.json').read_text())
            validate_final_index(index, source, source_tree, tag_object, rid, run['run_attempt'], scope[role]['workflow'])
            indexed_names = set()
            for record in [x['archive'] for x in index['platforms']] + [index['sourceArchive']]:
                require(record['name'] not in indexed_names, 'duplicate native index name')
                indexed_names.add(record['name'])
                matches = [f for a in entry['artifacts'].values() for name, f in a['files'].items() if name == record['name']]
                require(len(matches) == 1 and matches[0]['sha256'] == record['sha256'] and matches[0]['bytes'] == record['bytes'], 'native index actual hash mismatch')
    return result


def assemble(actual, config, work, output):
    require(config.get('reviewed') is True, 'public release file scope is not reviewed')
    for field in ('repository', 'repositoryId', 'version', 'sourceCommit', 'sourceTree', 'tag', 'tagObject', 'scopeSha256'):
        require(actual[field] == config[field], 'release contract differs: ' + field)
    require(set(actual['runs']) == set(config['runs']), 'run scope differs')
    # Every artifact and every path must be reviewed. No globs or silent exclusions.
    output.mkdir(exist_ok=False)
    destinations = set()
    receipt = dict(actual, signatureState='unsigned-builds-with-explicit-signed-only-blockers', fullSignedRelease=False)
    receipt['assets'] = []
    for role, run in actual['runs'].items():
        expected = config['runs'][role]
        require(run['id'] == expected['id'] and run['attempt'] == expected['attempt'], 'run/attempt differs from reviewed contract')
        require(set(run['artifacts']) == set(expected['artifacts']), 'artifact scope differs')
        for artifact, a in run['artifacts'].items():
            contract = expected['artifacts'][artifact]
            require(a['id'] == contract['id'] and a['archiveSha256'] == contract['archiveSha256'], 'artifact identity changed')
            require(set(a['files']) == set(contract['files']), 'file scope differs')
            for relative, f in a['files'].items():
                review = contract['files'][relative]
                require(f['bytes'] == review['bytes'] and f['sha256'] == review['sha256'], 'actual file hash differs')
                name = review['releaseName']
                if name is None:
                    require(artifact == 'publisher-run-receipt' or relative.startswith(('polaris-candidate-manifest-', 'native-row-')) or role == 'signed', 'payload omission forbidden')
                    continue
                require(len(portable(name).parts) == 1 and name.casefold() not in destinations, 'duplicate release filename')
                require(VERSION in name or name == 'polaris-upstream-native-assets.json' or name == 'sing-box-polaris-source-'+actual['sourceCommit']+'.tar.gz', 'public filename lacks exact Polaris version')
                require(name != RECEIPT, 'receipt name reserved')
                # Native index/source public names are immutable protocol names too.
                basename = PurePosixPath(relative).name
                if basename in ('polaris-upstream-native-assets.json', 'sing-box-polaris-source-'+actual['sourceCommit']+'.tar.gz'):
                    require(name == basename, 'native index/source rename forbidden')
                # CLI archive names referenced by the native index cannot be changed.
                if PurePosixPath(relative).name.startswith('sing-box-'+VERSION) and relative.endswith(('.tar.gz', '.zip')):
                    require(name == PurePosixPath(relative).name, 'native archive rename forbidden')
                destinations.add(name.casefold())
                shutil.copyfile(work / role / artifact / relative, output / name)
                receipt['assets'].append(dict(f, releaseName=name, role=role, artifact=artifact, artifactPath=relative,
                    signatureState='unverified-signed-build' if role == 'signed' else 'unsigned-candidate'))
    require(receipt['assets'], 'empty release')
    (output / RECEIPT).write_text(json.dumps(receipt, indent=2)+'\n')
    return receipt


def publish(output, source):
    before = tag_identity(source)
    index = json.loads((output / 'polaris-upstream-native-assets.json').read_text())
    require(index['schema'] == 'polaris-upstream-native-assets-v1' and index['tag'] == TAG
            and index['tagObject'] == before and index['sourceCommit'] == source, 'assembled final index no longer matches source tag')
    # Listing includes drafts visible to the token; no 404-as-absence shortcut.
    require(not any(r['tag_name'] == TAG for r in pages(f'repos/{REPO}/releases')), 'existing Release (including draft) will never be changed')
    expected = {p.name: {'size': p.stat().st_size, 'digest': 'sha256:'+sha(p)} for p in output.iterdir() if p.is_file()}
    notes = 'GitHub-only unsigned build/package prerelease from '+source+'. Not a complete signed installable release.\n\n'+'\n'.join('- '+x for x in BLOCKED)+'\n\nSee '+RECEIPT+' for actual hashes, run IDs, scope and signature states.'
    release = api(f'repos/{REPO}/releases', 'POST', {'tag_name': TAG, 'target_commitish': source, 'name': TAG, 'body': notes, 'draft': True, 'prerelease': True})
    release_id = release['id']
    # No --clobber. Any upload/validation error leaves this newly created draft intact.
    for p in sorted(output.iterdir()):
        subprocess.run(['gh', 'api', '--method', 'POST', upload_endpoint(release, p.name),
                        '-H', 'Content-Type: application/octet-stream', '--input', str(p)], check=True, stdout=subprocess.DEVNULL)
    checked = api(f'repos/{REPO}/releases/{release_id}')
    assets = pages(f'repos/{REPO}/releases/{release_id}/assets')
    require(checked['draft'] is True and checked['tag_name'] == TAG, 'draft state changed')
    require(len(assets) == len(expected) and {a['name'] for a in assets} == set(expected), 'remote asset scope mismatch; retained as draft')
    for a in assets:
        require(a['state'] == 'uploaded' and a['size'] == expected[a['name']]['size'] and a.get('digest') == expected[a['name']]['digest'], 'remote bytes/hash mismatch; retained as draft')
    require(tag_identity(source) == before, 'tag changed; retained as draft')
    require([r['id'] for r in pages(f'repos/{REPO}/releases') if r['tag_name'] == TAG] == [release_id], 'competing release; retained as draft')
    published = api(f'repos/{REPO}/releases/{release_id}', 'PATCH', {'draft': False, 'make_latest': 'false'})
    require(published['draft'] is False, 'publication not confirmed')
    print(published['html_url'])


def reviewed_contract(run_id, digest, source):
    require(re.fullmatch(r'[1-9][0-9]*', run_id or ''), 'inventory run ID required')
    require(re.fullmatch(r'[0-9a-f]{64}', digest or ''), 'explicit reviewed inventory SHA-256 required')
    run = api(f'repos/{REPO}/actions/runs/{run_id}')
    require(run['repository']['id'] == RID and run['head_repository']['id'] == RID, 'foreign inventory run')
    require(run['path'] == '.github/workflows/publish-github.yml' and run['head_sha'] == os.environ['GITHUB_SHA'], 'inventory publisher revision mismatch')
    require(run['conclusion'] == 'success' and run['status'] == 'completed', 'inventory run failed')
    candidates = [a for a in pages(f'repos/{REPO}/actions/runs/{run_id}/artifacts', 'artifacts') if a['name'] == 'github-release-validation']
    require(len(candidates) == 1 and not candidates[0]['expired'], 'inventory artifact missing/ambiguous/expired')
    with tempfile.TemporaryDirectory() as temp:
        archive = Path(temp)/'inventory.zip'
        with archive.open('wb') as f:
            subprocess.run(['gh', 'api', f'repos/{REPO}/actions/artifacts/{candidates[0]["id"]}/zip'], stdout=f, check=True)
        require(candidates[0].get('digest') == 'sha256:'+sha(archive), 'inventory archive digest mismatch')
        extract(archive, Path(temp)/'extracted')
        proposal = Path(temp)/'extracted/release-inventory-proposal.json'
        require(sha(proposal) == digest, 'inventory differs from explicitly reviewed hash')
        contract = json.loads(proposal.read_text())
        require(contract['sourceCommit'] == source, 'inventory source mismatch')
        contract['reviewed'] = True
        return contract


def main():
    p = argparse.ArgumentParser()
    p.add_argument('mode', choices=['inventory', 'validate', 'publish'])
    p.add_argument('--source', required=True)
    p.add_argument('--source-dir', type=Path, default=Path('reviewed-source'))
    for role in ['all', 'linux', 'docker', 'signed']:
        p.add_argument('--'+role+'-run', required=role != 'signed')
    p.add_argument('--inventory-run')
    p.add_argument('--inventory-sha256')
    p.add_argument('--output', type=Path, default=Path('github-release-dist'))
    args = p.parse_args()
    public = json.loads(CONFIG.read_text())
    require(public == {'repository': REPO, 'repositoryId': RID, 'version': VERSION, 'tag': TAG, 'publication': 'github-only-unsigned-prerelease'}, 'public GitHub release configuration mismatch')
    identity(args.source, args.source_dir)
    runs = {role: getattr(args, role+'_run') for role in ['all', 'linux', 'docker', 'signed'] if getattr(args, role+'_run')}
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        source_tree = command('git', '-C', str(args.source_dir), 'rev-parse', 'HEAD^{tree}')
        tag_object = tag_identity(args.source)
        actual = inventory(runs, args.source, work, source_tree, tag_object)
        require(tag_identity(args.source) == tag_object, 'tag changed while collecting release inventory')
        if args.mode == 'inventory':
            require(not args.output.exists(), 'inventory output already exists')
            args.output.write_text(json.dumps(actual, indent=2)+'\n')
            print('Inventory SHA-256: '+sha(args.output))
            return
        tag_identity(args.source)
        assemble(actual, reviewed_contract(args.inventory_run, args.inventory_sha256, args.source), work, args.output)
        if args.mode == 'publish':
            require(os.environ.get('POLARIS_GITHUB_PUBLISH_ENABLED') == 'true', 'GitHub publication disabled')
            publish(args.output, args.source)


if __name__ == '__main__':
    main()
