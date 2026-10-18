"""Replay exact source-owned client transforms and preserve their real source diff.

Compatibility/unsigned -> reviewed owned identity -> generated version metadata.
No source hash normalization, hidden untracked input, signing or publication.
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / 'release/ci/client-overlays.json'
JOBS = {'build_android':'android','publish_android':'android','build_windows_client':'windows',
        'build_linux_client':'linux','build_apple':'apple','build_apple_app_store':'apple'}
MAX_SOURCE_BYTES = 1024 * 1024
MAX_DIFF_BYTES = 1024 * 1024
MAX_SOURCE_FILES = 64


def sha(raw): return hashlib.sha256(raw).hexdigest()
def blob(raw): return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def git(directory,*args): return subprocess.check_output(['git','-C',str(directory),*args])
def definition(platform): return json.loads(MANIFEST.read_text(encoding='utf-8'))['platforms'][platform]
def selected(spec,unsigned): return [e for e in spec['files'] if e['kind']!='unsigned' or unsigned]


def portable(path):
    if not isinstance(path,str):raise ValueError('unsafe client source path')
    p=PurePosixPath(path)
    if '.git' in p.parts or not isinstance(path,str) or not p.parts or p.is_absolute() or str(p)!=path or any(
            part in ('.','..') or part.endswith(('.', ' ')) or re.fullmatch(r'(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?',part)
            for part in p.parts) or any(c in path for c in '\\:\x00\t\n\r'):
        raise ValueError('unsafe client source path')
    return p


def edits(raw,entry):
    if raw is None:
        if entry['beforeGitBlob'] is not None or entry['beforeSHA256'] is not None:
            raise ValueError('new client source has a fictitious baseline')
        after=entry['content'].encode()
    else:
        if blob(raw)!=entry['beforeGitBlob'] or sha(raw)!=entry['beforeSHA256']:
            raise ValueError('client overlay baseline mismatch: '+entry['path'])
        text=raw.decode()
        for change in entry['edits']:
            if text.count(change['old'])!=change['count']:
                raise ValueError('client overlay anchor mismatch: '+entry['path'])
            text=text.replace(change['old'],change['new'])
        after=text.encode()
    if sha(after)!=entry['afterSHA256']:
        raise ValueError('client overlay result identity mismatch')
    return after


def checkout(platform):
    spec=definition(platform);directory=ROOT/spec['path']
    if directory.is_symlink():raise ValueError('client checkout root must be a real directory')
    head=git(directory,'rev-parse','HEAD').decode().strip()
    row=git(ROOT,'ls-tree','HEAD',spec['path']).decode().split()
    if head!=spec['commit'] or git(directory,'rev-parse','HEAD^{tree}').decode().strip()!=spec['tree'] or row[:3]!=['160000','commit',head]:
        raise ValueError('client checkout differs from exact gitlink/tree')
    return spec,directory


def identity_definition(platform,unsigned):
    if unsigned:return None
    path=ROOT/'release/ci/owned-distribution.json'
    if path.is_symlink() or not path.is_file():raise ValueError('reviewed owned client identity is not configured')
    config=json.loads(path.read_text(encoding='utf-8'))
    if config.get('reviewed') is not True or config.get('repository')!='polaris-arch/sing-box-polaris' or config.get('repositoryId')!=1421657509:
        raise ValueError('owned client identity configuration is not reviewed')
    key='desktop' if platform in ('windows','linux') else platform
    entry=config.get('clientIdentityPatches',{}).get(key)
    if not isinstance(entry,dict) or entry.get('clientCommit')!=definition(platform)['commit'] or not entry.get('files'):
        raise ValueError('owned identity needs exact commit and complete file transform inventory')
    patchpath=portable(entry['path'])
    if not patchpath.as_posix().startswith('release/ci/'):
        raise ValueError('owned identity patch outside source-owned release inputs')
    if (ROOT/patchpath).is_symlink():raise ValueError('owned identity patch must be a regular source-owned file')
    raw=(ROOT/patchpath).read_bytes()
    if sha(raw)!=entry['sha256']:raise ValueError('owned identity patch digest mismatch')
    if len(raw)>MAX_DIFF_BYTES or len(entry['files'])>MAX_SOURCE_FILES:
        raise ValueError('owned identity source input exceeds bounded budget')
    for name,row in entry['files'].items():
        portable(name)
        for field in ['baseGitBlob','beforeSHA256','afterSHA256','beforeMode','afterMode','bytes']:
            if field not in row:raise ValueError('owned identity missing file transform field: '+field)
        for mode in [row['beforeMode'],row['afterMode']]:
            if mode not in (None,'100644','100755'):raise ValueError('non-regular owned identity source')
        for field in ['beforeSHA256','afterSHA256']:
            value=row[field]
            if value is not None and not re.fullmatch(r'[0-9a-f]{64}',value):raise ValueError('invalid owned file digest')
        if row['baseGitBlob'] is not None and not re.fullmatch(r'[0-9a-f]{40}',row['baseGitBlob']):raise ValueError('invalid owned baseline blob')
        if type(row['bytes']) is not int or not 0<=row['bytes']<=MAX_SOURCE_BYTES:raise ValueError('invalid owned source size')
    return {'configurationSHA256':sha(path.read_bytes()),'patchPath':entry['path'],'patchSHA256':entry['sha256'],
            'clientCommit':entry['clientCommit'],'files':entry['files']}


def baseline_definition(spec,entries,identity):
    bases={path:dict(value) for path,value in spec['baselineFiles'].items()}
    for entry in entries:
        name=entry['path'];portable(name)
        if name not in bases:bases[name]={'gitBlob':entry['beforeGitBlob'],'mode':entry['beforeMode']}
    if identity:
        for name,row in identity['files'].items():
            if name in bases and bases[name]['gitBlob']!=row['baseGitBlob']:
                raise ValueError('identity original baseline conflicts with compatibility/version input')
            bases.setdefault(name,{'gitBlob':row['baseGitBlob'],'mode':row['beforeMode']})
    return bases


def check_baseline(data,bases):
    if len(data)>MAX_SOURCE_FILES or sum(len(raw) for raw in data.values() if raw is not None)>MAX_SOURCE_BYTES:
        raise ValueError('client baseline snapshot exceeds budget')
    for name,raw in data.items():
        portable(name)
        if name not in bases or (None if raw is None else blob(raw))!=bases[name]['gitBlob']:
            raise ValueError('client baseline snapshot is not the source-owned original: '+name)


def apply_diff(data,modes,diff,paths):
    if not isinstance(diff,str) or len(diff.encode())>MAX_DIFF_BYTES:
        raise ValueError('client source diff exceeds budget')
    if diff=='':
        if paths:raise ValueError('client source rows have no actual diff')
        return dict(data),dict(modes)
    # Git applies only inside this bounded scratch snapshot, with no repository,
    # inherited index or path-changing configuration. It is not a source checkout.
    env={k:v for k,v in os.environ.items() if k not in ('GIT_DIR','GIT_WORK_TREE','GIT_INDEX_FILE','GIT_COMMON_DIR','GIT_CONFIG_PARAMETERS','GIT_CONFIG_COUNT')}
    with tempfile.TemporaryDirectory(prefix='client-source-proof-') as temp:
        root=Path(temp)
        env['GIT_CEILING_DIRECTORIES']=str(root)
        for name,raw in data.items():
            if raw is not None:
                p=root/portable(name);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(int(modes.get(name) or '100644',8)&0o777)
        def command(*args):
            result=subprocess.run(['git','-c','core.autocrlf=false','-c','core.eol=lf','apply',*args,'-'],cwd=root,env=env,input=diff.encode(),capture_output=True)
            if result.returncode:raise ValueError('client diff cannot replay: '+result.stderr.decode(errors='replace')[:2000])
            return result.stdout
        names=[]
        for row in command('--numstat','-z').split(b'\0'):
            if not row:continue
            fields=row.split(b'\t',2)
            if len(fields)!=3:raise ValueError('unsupported client diff rename encoding')
            name=fields[2].decode();portable(name);names.append(name)
        if len(names)!=len(set(names)) or set(names)!=set(paths):
            raise ValueError('client diff paths and source rows differ')
        for mode in re.findall(r'(?m)^(?:old mode|new mode|new file mode|deleted file mode) (\d+)$',diff):
            if mode not in ('100644','100755'):raise ValueError('client diff contains non-regular source')
        for count in re.findall(r'(?m)^literal (\d+)$',diff):
            if int(count)>MAX_SOURCE_BYTES:raise ValueError('binary client source exceeds budget')
        command('--check','--binary');command('--binary')
        result={};result_modes={}
        size=sum((root/portable(name)).stat().st_size for name in data if (root/portable(name)).is_file())
        if size>MAX_SOURCE_BYTES:raise ValueError('replayed client source exceeds budget')
        for name in data:
            p=root/portable(name)
            if p.is_symlink() or (p.exists() and not p.is_file()):raise ValueError('client diff created non-regular input')
            result[name]=p.read_bytes() if p.exists() else None
            result_modes[name]=('100755' if p.stat().st_mode&0o111 else '100644') if p.exists() else None
        if sum(len(raw) for raw in result.values() if raw is not None)>MAX_SOURCE_BYTES:raise ValueError('replayed client source exceeds budget')
        return result,result_modes


def overlay_result(spec,entries,identity,baseline):
    data=dict(baseline);modes={name:row['mode'] for name,row in baseline_definition(spec,entries,identity).items() if name in data}
    for entry in entries:
        name=entry['path'];data[name]=edits(data[name],entry);modes[name]=modes.get(name) or '100644'
    if identity:
        for name,row in identity['files'].items():
            raw=data[name]
            if (None if raw is None else sha(raw))!=row['beforeSHA256'] or modes[name]!=row['beforeMode']:
                raise ValueError('owned identity must consume exact compatibility result: '+name)
        patch=(ROOT/identity['patchPath']).read_bytes().decode()
        data,modes=apply_diff(data,modes,patch,identity['files'])
        for name,row in identity['files'].items():
            raw=data[name]
            if (None if raw is None else sha(raw))!=row['afterSHA256'] or (len(raw) if raw is not None else 0)!=row['bytes'] or modes[name]!=row['afterMode']:
                raise ValueError('owned identity actual patch result differs: '+name)
    return data,modes


def source_bytes(directory,name):
    p=directory
    for part in portable(name).parts:
        p=p/part
        if p.is_symlink():raise ValueError('client source path traverses a symlink')
    if p.is_symlink() or (p.exists() and not p.is_file()):raise ValueError('non-regular actual client source')
    if p.exists() and p.stat().st_size>MAX_SOURCE_BYTES:raise ValueError('actual client source exceeds budget')
    return p.read_bytes() if p.exists() else None


def original_bytes(directory,spec,name,base):
    if base['gitBlob'] is None:return None
    raw=git(directory,'show',spec['commit']+':'+name)
    if blob(raw)!=base['gitBlob']:raise ValueError('client committed baseline blob mismatch')
    return raw


def apply(platform,unsigned=False):
    spec,directory=checkout(platform);entries=selected(spec,unsigned);identity=identity_definition(platform,unsigned)
    paths={e['path'] for e in entries}|(set(identity['files']) if identity else set())
    bases=baseline_definition(spec,entries,identity)
    baseline={name:original_bytes(directory,spec,name,bases[name]) for name in paths};check_baseline(baseline,bases)
    # Every transform, including the whole identity patch, validates before the
    # checkout receives any write. No silently overlapping single-stage hashes.
    for name,raw in baseline.items():
        if source_bytes(directory,name)!=raw:raise ValueError('client source changed before applying transforms: '+name)
    result,modes=overlay_result(spec,entries,identity,baseline)
    for name,raw in result.items():
        p=directory/portable(name)
        if raw is None:p.unlink()
        else:p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(int(modes[name],8)&0o777)


def collect(platform,unsigned):
    spec,directory=checkout(platform);entries=selected(spec,unsigned);identity=identity_definition(platform,unsigned)
    touched={e['path'] for e in entries}|(set(identity['files']) if identity else set())
    bases=baseline_definition(spec,entries,identity)
    others=set(filter(None,git(directory,'ls-files','--others','--exclude-standard','-z').decode().split('\0')))
    if not others<=touched:raise ValueError('untracked client source has no declared origin: '+repr(sorted(others-touched)))
    if others:git(directory,'add','--intent-to-add','--',*sorted(others))
    changed=set(filter(None,git(directory,'diff','--no-renames','--name-only','-z','HEAD').decode().split('\0')))
    if not touched<=changed<=touched|set(spec['versionMetadata']):raise ValueError('client source change inventory differs from declared transforms')
    baseline={name:original_bytes(directory,spec,name,bases[name]) for name in changed};check_baseline(baseline,bases)
    rows=[]
    for name in sorted(changed):
        raw=source_bytes(directory,name)
        rows.append({'path':name,'beforeSHA256':None if baseline[name] is None else sha(baseline[name]),
                     'afterSHA256':None if raw is None else sha(raw),'bytes':len(raw) if raw is not None else 0})
    if platform=='windows' and (os.environ.get('POLARIS_UNSIGNED_CLIENT')=='1')!=unsigned:
        raise ValueError('actual Windows unsigned flag conflicts with source receipt role')
    record={'schema':'polaris-client-source-v1','platform':platform,'repository':spec['repository'],'baseCommit':spec['commit'],'baseTree':spec['tree'],
            'coreSourceCommit':git(ROOT,'rev-parse','HEAD').decode().strip(),'overlayManifestSHA256':sha(MANIFEST.read_bytes()),'unsigned':unsigned,
            'sourceOverlayCount':len(touched),'identity':identity,'files':rows,
            'baseline':{name:None if raw is None else base64.b64encode(raw).decode() for name,raw in baseline.items()},
            'diff':git(directory,'diff','--no-ext-diff','--no-renames','--binary','--full-index','HEAD').decode()}
    record['diffSHA256']=sha(record['diff'].encode());validate(record,platform,record['coreSourceCommit'],unsigned);return record


def validate(record,platform,source,unsigned):
    spec=definition(platform);entries=selected(spec,unsigned);identity=identity_definition(platform,unsigned)
    touched={e['path'] for e in entries}|(set(identity['files']) if identity else set())
    for key,value in [('schema','polaris-client-source-v1'),('platform',platform),('repository',spec['repository']),('baseCommit',spec['commit']),('baseTree',spec['tree']),
                      ('coreSourceCommit',source),('overlayManifestSHA256',sha(MANIFEST.read_bytes())),('unsigned',unsigned),('sourceOverlayCount',len(touched)),('identity',identity)]:
        if type(record.get(key)) is not type(value) or record.get(key)!=value:raise ValueError('client source receipt identity mismatch: '+key)
    rows=record['files'];paths=[row['path'] for row in rows]
    if len(paths)!=len(set(paths)) or len(paths)>MAX_SOURCE_FILES or not touched<=set(paths)<=touched|set(spec['versionMetadata']) or set(record['baseline'])!=set(paths):
        raise ValueError('client source row/baseline inventory mismatch')
    encoded=[value for value in record['baseline'].values() if value is not None]
    if any(not isinstance(value,str) for value in encoded) or sum(len(value) for value in encoded)>4*((MAX_SOURCE_BYTES+2)//3)+4*len(encoded):
        raise ValueError('encoded client snapshot exceeds source budget')
    try:baseline={name:None if value is None else base64.b64decode(value,validate=True) for name,value in record['baseline'].items()}
    except (ValueError,TypeError) as error:raise ValueError('invalid client baseline encoding') from error
    bases=baseline_definition(spec,entries,identity);check_baseline(baseline,bases)
    if any(type(row.get('bytes')) is not int or row['bytes']<0 for row in rows) or sum(row['bytes'] for row in rows)>MAX_SOURCE_BYTES:
        raise ValueError('declared client source output exceeds budget')
    if not isinstance(record.get('diff'),str) or len(record['diff'].encode())>MAX_DIFF_BYTES:raise ValueError('client diff exceeds budget')
    if record.get('diffSHA256')!=sha(record['diff'].encode()):raise ValueError('client source diff digest mismatch')
    actual,actual_modes=apply_diff(baseline,{name:bases[name]['mode'] for name in paths},record['diff'],paths)
    expected,expected_modes=overlay_result(spec,entries,identity,baseline)
    for row in rows:
        name=row['path'];raw=actual[name]
        if (row.get('beforeSHA256'),row.get('afterSHA256'),row.get('bytes'))!=(None if baseline[name] is None else sha(baseline[name]),None if raw is None else sha(raw),0 if raw is None else len(raw)) or type(row.get('bytes')) is not int:
            raise ValueError('client diff and file row hashes/bytes are inconsistent')
        if actual_modes[name]!=expected_modes[name]:raise ValueError('client final mode differs from composed transforms: '+name)
        if name not in spec['versionMetadata'] and raw!=expected[name]:raise ValueError('client final source differs from composed transforms: '+name)


def record_signed(platform,directory):
    record={'schema':'polaris-client-source-evidence-v1','sourceCommit':git(ROOT,'rev-parse','HEAD').decode().strip(),
            'workflowRunId':os.environ['GITHUB_RUN_ID'],'workflowAttempt':os.environ['GITHUB_RUN_ATTEMPT'],'clientSource':collect(platform,False)}
    root=Path(directory);root.mkdir(exist_ok=True)
    (root/('polaris-candidate-manifest-client-source-'+os.environ['GITHUB_JOB']+'.json')).write_text(json.dumps(record,indent=2)+'\n', encoding='utf-8', newline='\n')

if __name__=='__main__':
    if sys.argv[1]=='apply':apply(sys.argv[2],unsigned='--unsigned' in sys.argv[3:])
    elif sys.argv[1]=='record-signed':record_signed(sys.argv[2],sys.argv[3])
    else:raise SystemExit('expected apply or record-signed')
