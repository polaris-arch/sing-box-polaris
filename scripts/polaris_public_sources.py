#!/usr/bin/env python3
"""Build corresponding-source references from actual module graphs, without a source asset."""
import copy
import base64
import hashlib
import json
from pathlib import Path
import shutil
import sys
import urllib.request
import zipfile
sys.dont_write_bytecode = True
from polaris_native_distribution import encode, file_info
from polaris_dns_identity import canonical

INPUTS = 'release/polaris-public-source-inputs.json'

def require(ok, message):
    if not ok:raise ValueError(message)

def delivery(repo, config, source, tree, graphs):
    template = json.loads((repo / INPUTS).read_bytes())
    require(template['schema'] == 'polaris-public-source-inputs-v1', 'source template differs')
    normal = {(d['module'], d['version'], d['h1']) for g in graphs for d in g['normalModules']}
    acquisition = {(d['module'], d['version'], d['h1']) for g in graphs for d in g['prebuiltAcquisitionModules']}
    rows = {(d['module'], d['version'], d['h1']): d for d in template['modules']}
    require(len(rows) == len(template['modules']) and normal | acquisition <= rows.keys(),
            'actual complete module union exceeds fixed public sources')
    replacements = [g['localReplacement'] for g in graphs]
    require(replacements and all(x == replacements[0] for x in replacements), 'mixed local replacement')
    ow = json.loads((repo / 'release/polaris-openwrt-inputs.json').read_bytes())
    return {'schema': 'polaris-public-source-delivery-v1', 'method': 'fixed-public-source-references',
        'productSource': {'repository': config['repository'], 'commit': source, 'tree': tree,
            'gitUrl': 'https://github.com/' + config['repository'] + '.git',
            'archiveUrl': 'https://github.com/' + config['repository'] + '/archive/' + source + '.tar.gz',
            'tagArchiveUrl': 'https://github.com/' + config['repository'] + '/archive/refs/tags/' + config['tag'] + '.tar.gz',
            'sourceOwnedReplacement': {**json.loads((repo/'release/dependency-sources/sing-tun-replacement.json').read_bytes()), 'bindingSha256':hashlib.sha256((repo/'release/dependency-sources/sing-tun-replacement.json').read_bytes()).hexdigest()}},
        'modules': [copy.deepcopy(rows[k]) for k in sorted(normal | acquisition)],
        'normalSourceModuleCount': len(normal), 'prebuiltAcquisitionModuleCount': len(acquisition),
        **{k: copy.deepcopy(template[k]) for k in ['go', 'driver', 'engine', 'naiveArchiveRestoration']},
        'openwrtToolchainCorrespondingSources': ow['toolchainCorrespondingSources'],
        'openwrtApkToolSource': ow['apkToolSource'],
        'clangPrebuiltInput': ow['clangInput'],
        'instructions': 'Automatic GitHub Source code archives provide this exact product source, including the complete modified third_party/sing-tun tree. No additional source archive is uploaded. Fetch all unmodified dependencies at their fixed module ZIP/source URLs below; module h1/ZIP SHA pins identify them. Recover the driver naiveproxy gitlink from the exact engine Git commit, including the listed files omitted by GitHub archives. Rebuild with Go1.25.5 and source-owned scripts/SDK/Clang pins; static musl packages use Clang CC/CXX --target --sysroot with LLD and the unmodified fixed prebuilt Cronet .a. GCC libgcc runtime uses GCC Runtime Library Exception3.1; the exact GCC/musl sources and OpenWrt build+patch tree are specified. No system OpenSSL replacement or Chromium compilation is needed to build the core using these prebuilt inputs. Source access/ongoing availability remains distributor responsibility under applicable licenses, including GPLv3 section6(d); restore equivalent fixed copying access if an external source becomes unavailable.',
        'reviewState': 'candidate; independent corresponding-source applicability review pending',
        'sourceAvailability': 'pending same-run full-byte public source verification'}

def fetch(record, destination):
    require(not destination.exists(), 'preserve existing source check')
    url = record.get('zipUrl', record.get('url'))
    expected_size = record.get('zipBytes', record.get('bytes'))
    expected_hash = record.get('zipSha256', record.get('sha256'))
    require(url.startswith('https://') and expected_hash, 'fixed source bytes required')
    h, count = hashlib.sha256(), 0
    with urllib.request.urlopen(url, timeout=90) as response, destination.open('xb') as output:
        while chunk := response.read(1024 * 1024):
            count += len(chunk);require(count <= (expected_size or 512 * 1024 * 1024), 'source response exceeds fixed bytes')
            h.update(chunk);output.write(chunk)
    require((expected_size is None or count == expected_size) and h.hexdigest() == expected_hash, 'public source byte pin differs')
    return {'url': url, 'bytes': count, 'sha256': h.hexdigest(), 'anonymousFullGetVerified': True}

def verify_public(value, work):
    require(not work.exists(), 'fresh source availability check required')
    work.mkdir(parents=True)
    records = []
    for n, row in enumerate(value['modules']):
        path = work / (str(n) + '.zip');seen = fetch(row, path)
        with zipfile.ZipFile(path) as reader:
            require(reader.testzip() is None, 'public module ZIP CRC mismatch')
            inner = hashlib.sha256()
            for name in sorted(reader.namelist()):
                require('\n' not in name and '\r' not in name, 'unsafe Go ZIP hash filename')
                inner.update((hashlib.sha256(reader.read(name)).hexdigest()+'  '+name+'\n').encode())
            require('h1:'+base64.b64encode(inner.digest()).decode() == row['h1'], 'public source ZIP h1 differs')
        records.append({'module': row['module'], 'version': row['version'], 'h1': row['h1'], **seen})
        path.unlink()  # Only this invocation's bounded scratch download; pins/log remain.
    go = value['go']['exactDistributionSource'];path = work / 'go-toolchain.zip'
    records.append({'role': 'exact-Go-distribution-source', **fetch(go, path)})
    with zipfile.ZipFile(path) as reader:require(reader.testzip() is None, 'Go source ZIP CRC mismatch')
    path.unlink()
    # Immutable engine/driver/product commit/tree identities are checked through their
    # public Git object APIs, not by trusting mutable branch names or landing pages.
    for role in ['productSource', 'driver', 'engine']:
        row = value[role];url = 'https://api.github.com/repos/' + row['repository'] + '/git/commits/' + row['commit']
        req = urllib.request.Request(url, headers={'User-Agent': 'polaris-source-check'})
        with urllib.request.urlopen(req, timeout=90) as response:raw = response.read()
        obj = json.loads(raw);require(obj['sha'] == row['commit'] and obj['tree']['sha'] == row['tree'], 'public commit/tree differs')
        records.append({'role': role, 'url': url, 'commit': obj['sha'], 'tree': obj['tree']['sha'],
                        'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'scope': 'Git identity; full engine source availability is separately reviewed'})
    for role in ['driver', 'engine']:
        records.append(verify_git_source(role, value[role], work, value['naiveArchiveRestoration'] if role=='engine' else []))
    tool = value['openwrtToolchainCorrespondingSources']
    for role in ['gcc', 'musl']:
        path=work/(role+'-source');records.append({'role':role,**fetch(tool[role],path)});path.unlink()
    records.append(verify_git_source('openwrt-patches',{'repository':'openwrt/openwrt',**tool['openwrt']},work))
    (work / 'PUBLIC-SOURCE-BYTE-READBACK.json').write_bytes(encode(records))
    return {'schema': 'polaris-public-source-verification-v1', 'modules': records,
            'recordSha256': hashlib.sha256(encode(records)).hexdigest(),
            'scope': 'actual complete module ZIP union and Go distribution full bytes; complete fixed driver/engine Git source blobs with restored omissions; compiler source access and independent applicability remain explicit gates'}

def verify_git_source(role, row, work, restorations=None):
    """Anonymous full archive bytes checked against exact public Git blob identities."""
    prefix = 'https://api.github.com/repos/' + row['repository']
    def get(url):
        req = urllib.request.Request(url, headers={'User-Agent': 'polaris-source-closure'})
        with urllib.request.urlopen(req, timeout=90) as response:return response.read()
    tree = json.loads(get(prefix + '/git/trees/' + row['tree'] + '?recursive=1'))
    require(tree.get('truncated') is False and tree['sha'] == row['tree'], 'complete public source Git tree required')
    blobs = {entry['path']: entry for entry in tree['tree'] if entry['type'] == 'blob'}
    gitlinks = {entry['path']: entry['sha'] for entry in tree['tree'] if entry['type'] == 'commit'}
    path = work / (role + '-source.tar.gz');url = row['archiveUrl']
    with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent':'polaris-source-closure'}), timeout=90) as response, path.open('xb') as output:
        shutil.copyfileobj(response, output)
    record = {'role': role, 'url': url, **file_info(path), 'tree': row['tree'], 'commit': row['commit']}
    import tarfile
    verified = set();export_restorations=[]
    pins={entry['path']:entry for entry in (restorations or [])}
    require(len(pins)==len(restorations or []),'duplicate source export restoration path')
    require(not pins or role=='engine' and row['commit']=='be1be963131154ba82761a7ed85ba426b2027319', 'restoration only for fixed engine')
    for name,pin in pins.items():
        require(name in blobs and pin['gitBlob']==blobs[name]['sha'] and pin['url']=='https://raw.githubusercontent.com/'+row['repository']+'/'+row['commit']+'/'+name, 'restoration not bound to fixed source Git tree')
    with tarfile.open(path, 'r:gz') as reader:
        for member in reader:
            if member.isdir():continue
            parts = member.name.split('/', 1)
            require(len(parts) == 2 and parts[1] not in verified, 'unsafe/duplicate Git source member')
            name = parts[1];require(name in blobs, 'source archive contains foreign blob')
            raw = reader.extractfile(member).read() if member.isfile() else member.linkname.encode() if member.issym() else None
            require(raw is not None,'nonregular source archive member')
            def retrieve(pin):
                target=work/'source-export-restoration'
                seen=fetch(pin,target);data=target.read_bytes();target.unlink();return data,seen
            resolved,observation=resolve_exported_blob(row,name,raw,blobs[name]['sha'],pins.get(name),retrieve)
            if observation:export_restorations.append(observation)
            verified.add(name)
    missing = set(blobs) - verified
    # Github archive export-ignore omissions are available from the exact Git commit.
    for name in sorted(missing):
        if name in pins:
            target=work/'source-export-restoration';seen=fetch(pins[name],target);raw=target.read_bytes();target.unlink()
            require(git_blob(raw)==blobs[name]['sha'],'missing pinned source restoration differs')
            export_restorations.append({'path':name,'reason':'archive omission','source':seen,'gitBlob':blobs[name]['sha']})
        else:
            raw = get('https://raw.githubusercontent.com/' + row['repository'] + '/' + row['commit'] + '/' + name)
            require(git_blob(raw)==blobs[name]['sha'],'missing archive source blob restoration differs')
        verified.add(name)
    record.update(verifiedBlobs=len(verified), restoredOmissions=sorted(missing), exportRestoration=export_restorations, gitlinks=gitlinks,
                  anonymousFullGetVerified=True, exactCompleteGitSourceVerified=True)
    if role == 'driver':
        require(gitlinks.get(row['submodule']['path']) == row['submodule']['commit'], 'driver engine Git link differs')
    path.unlink()
    return record

def git_blob(raw):
    return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()

def resolve_exported_blob(row,name,archive_bytes,expected_blob,pin,retrieve):
    """Bound CRLF/export substitution happens before per-member Git verification."""
    actual=git_blob(archive_bytes)
    if actual==expected_blob:
        if pin:require(len(archive_bytes)==pin['bytes'] and hashlib.sha256(archive_bytes).hexdigest()==pin['sha256'] and pin['gitBlob']==expected_blob,'matching source export pin differs')
        return archive_bytes,None
    require(pin is not None and row['commit']=='be1be963131154ba82761a7ed85ba426b2027319'
        and pin['path']==name and pin['gitBlob']==expected_blob,'unlisted archive Git blob mismatch: '+name)
    raw,seen=retrieve(pin)
    require(len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256'] and git_blob(raw)==expected_blob,
        'fixed raw source export restoration differs')
    return raw,{'path':name,'reason':'known existing archive CRLF/export difference',
        'archiveBytes':len(archive_bytes),'archiveSha256':hashlib.sha256(archive_bytes).hexdigest(),
        'archiveGitBlob':actual,'gitBlob':expected_blob,'source':seen}
