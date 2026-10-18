#!/usr/bin/env python3
"""Explicit draft/publication actions for a previously reviewed fixed asset manifest.

Never called by prepare. No cleanup, overwrite, device, build or upstream writes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request

REPO='polaris-arch/polaris-box'
TAG='polaris-box-v1.15.0-alpha.11-2'
SOURCE='a01da7a942b3a0dbbfdfda2bba5bd63d5bd9d932'
TITLE='Polaris-box desktop CLI 1.15.0-alpha.11-2'


def command(*args):
    return subprocess.check_output(args,text=True).strip()


def api(endpoint,*args):
    return json.loads(command('gh','api',endpoint,*args))


def file_identity(path):
    with path.open('rb') as stream: h=hashlib.file_digest(stream,'sha256').hexdigest()
    return {'name':path.name,'bytes':path.stat().st_size,'sha256':h}


def validate_manifest(path,expected_sha):
    data=path.read_bytes()
    if hashlib.sha256(data).hexdigest()!=expected_sha:raise ValueError('reviewed manifest hash mismatch')
    m=json.loads(data)
    if (m['repository'],m['tag'],m['tagTargetCommit'])!=(REPO,TAG,SOURCE):raise ValueError('release identity mismatch')
    names=[a['name'] for a in m['assets']]
    if len(names)!=10 or len(set(names))!=10 or any('/' in n or '\\' in n for n in names):raise ValueError('exact ten simple asset names required')
    for a in m['assets']:
        if file_identity(path.parent/a['name'])!=a:raise ValueError('local asset drift: '+a['name'])
    return m


def validate_remote_assets(release,manifest):
    expected={a['name']:a for a in manifest['assets']}
    if len(release['assets'])!=10 or {a['name'] for a in release['assets']}!=set(expected):raise ValueError('remote release asset set differs')
    for a in release['assets']:
        e=expected[a['name']]
        if a['size']!=e['bytes'] or a.get('digest')!='sha256:'+e['sha256']:raise ValueError('remote asset digest/size mismatch: '+a['name'])


def validate_tag(repo):
    output=command('git','-C',str(repo),'ls-remote','https://github.com/'+REPO+'.git','refs/tags/'+TAG,'refs/tags/'+TAG+'^{}')
    refs=dict((line.split()[1],line.split()[0]) for line in output.splitlines())
    if refs.get('refs/tags/'+TAG+'^{}')!=SOURCE:raise ValueError('remote annotated tag target mismatch')
    return refs['refs/tags/'+TAG]


def public_readback(release,manifest):
    validate_remote_assets(release,manifest)
    records=[]
    for a in manifest['assets']:
        url=f"https://github.com/{REPO}/releases/download/{TAG}/{a['name']}"
        h=hashlib.sha256();size=0
        request=urllib.request.Request(url,headers={'User-Agent':'polaris-box-public-readback'})
        # No credentials: prove stable public download availability.
        with urllib.request.urlopen(request,timeout=60) as response:
            while chunk:=response.read(1024*1024):
                size+=len(chunk)
                if size>a['bytes']:raise ValueError('public asset too large: '+a['name'])
                h.update(chunk)
        if size!=a['bytes'] or h.hexdigest()!=a['sha256']:raise ValueError('public asset hash/size mismatch: '+a['name'])
        records.append({**a,'url':url,'unauthenticatedReadback':True})
    return records


def find_draft_release(endpoint):
    # The by-tag REST endpoint returns published releases, not drafts.
    matches=[];page=1
    while True:
        releases=api(endpoint+f'?per_page=100&page={page}')
        matches.extend(release for release in releases if release['tag_name']==TAG)
        if len(releases)<100:break
        page+=1
    if len(matches)!=1:raise ValueError('exactly one release for proposed tag required')
    return matches[0]


def validate_empty_draft(release,notes,release_id=None):
    if release_id is not None and release['id']!=release_id:raise ValueError('draft release ID mismatch')
    if (release['tag_name']!=TAG or not release['draft'] or not release['prerelease']
            or release['name']!=TITLE or release['body']!=notes or release['assets']):
        raise ValueError('exact empty draft identity/notes required; preserve and inspect')


def execute(args):
    repo=args.repo.resolve()
    head=command('git','-C',str(repo),'rev-parse','HEAD')
    if head!=args.approved_head or command('git','-C',str(repo),'status','--porcelain'):raise ValueError('approved publication source HEAD must be exact and clean')
    manifest=validate_manifest(args.manifest,args.manifest_sha256)
    endpoint=f'repos/{REPO}/releases'
    if args.action in ('stage-draft','resume-empty-draft'):
        if args.action=='resume-empty-draft':
            if args.release_id is None or not args.expected_tag_object:raise ValueError('exact inspected release ID and tag object required')
            tag_object=validate_tag(repo)
            if tag_object!=args.expected_tag_object:raise ValueError('inspected tag object drift')
            release=find_draft_release(endpoint)
            by_id=api(endpoint+'/'+str(args.release_id))
            validate_empty_draft(release,(args.manifest.parent/'polaris-box-release-notes.md').read_text(),args.release_id)
            validate_empty_draft(by_id,(args.manifest.parent/'polaris-box-release-notes.md').read_text(),args.release_id)
        elif command('git','-C',str(repo),'ls-remote','https://github.com/'+REPO+'.git','refs/tags/'+TAG):raise ValueError('proposed tag already exists; preserve and inspect, never overwrite')
        remote=command('git','-C',str(repo),'remote','get-url','--push','polaris')
        if remote!='https://github.com/'+REPO+'.git':raise ValueError('polaris push remote mismatch')
        command('git','-C',str(repo),'cat-file','-e',SOURCE+'^{commit}')
        # Snapshot verified assets privately before any upload; no --clobber.
        with tempfile.TemporaryDirectory(prefix='polaris-publication-') as directory:
            snapshot=Path(directory)
            for a in manifest['assets']:
                target=snapshot/a['name'];shutil.copyfile(args.manifest.parent/a['name'],target)
                if file_identity(target)!=a:raise ValueError('upload snapshot differs')
            if args.action=='stage-draft':
                command('git','-C',str(repo),'tag','-a',TAG,SOURCE,'-m','Polaris desktop source a01 with six native distributions')
                command('git','-C',str(repo),'push','polaris','refs/tags/'+TAG+':refs/tags/'+TAG)
                tag_object=validate_tag(repo)
                command('gh','release','create',TAG,'--repo',REPO,'--verify-tag','--draft','--prerelease','--latest=false','--title',TITLE,'--notes-file',str(snapshot/'polaris-box-release-notes.md'))
            release=find_draft_release(endpoint)
            validate_empty_draft(release,(snapshot/'polaris-box-release-notes.md').read_text(),args.release_id if args.action=='resume-empty-draft' else None)
            for a in manifest['assets']:
                command('gh','release','upload',TAG,str(snapshot/a['name']),'--repo',REPO)
            release=api(endpoint+'/'+str(release['id']))
            validate_remote_assets(release,manifest)
            if not release['draft']:raise ValueError('release became public during draft preparation')
        result={'phase':'draft-staged','releaseId':release['id'],'tagObject':tag_object,'tagTargetCommit':SOURCE,'public':False,'manifestSha256':args.manifest_sha256}
    else:
        if args.release_id is None:raise ValueError('exact draft release ID required')
        release=api(endpoint+'/'+str(args.release_id))
        if release['tag_name']!=TAG or not release['prerelease']:raise ValueError('release tag/prerelease mismatch')
        tag_object=validate_tag(repo);validate_remote_assets(release,manifest)
        if args.action=='publish':
            if not release['draft']:raise ValueError('release already public; use verify-public for readback')
            release=api(endpoint+'/'+str(args.release_id),'-X','PATCH','-F','draft=false','-F','prerelease=true','-f','make_latest=false')
        if release['draft']:raise ValueError('cannot verify public availability of a draft')
        records=public_readback(release,manifest)
        result={'phase':'public-downloads-verified','releaseId':release['id'],'url':release['html_url'],'tagObject':tag_object,'tagTargetCommit':SOURCE,'manifestSha256':args.manifest_sha256,'assets':records,'oldReleaseCleanupPerformed':False}
    args.receipt.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['stage-draft','resume-empty-draft','publish','verify-public'])
    p.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument('--approved-head',required=True,help='Parent-reviewed exact source SHA; execution requires separate publication authorization')
    p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--manifest-sha256',required=True)
    p.add_argument('--release-id',type=int)
    p.add_argument('--expected-tag-object',help='Required for inspected empty-draft recovery; never recreate or overwrite a tag')
    p.add_argument('--receipt',type=Path,required=True)
    args=p.parse_args()
    if args.receipt.exists():raise ValueError('receipt already exists; preserve earlier evidence')
    try:
        execute(args)
    except Exception as error:
        args.receipt.write_text(json.dumps({'phase':'failed-or-partial','repository':REPO,'tag':TAG,
            'manifestSha256':args.manifest_sha256,'publicDownloadVerificationComplete':False,
            'error':str(error),'sideEffectsMustBeInspectedBeforeRetry':True,'cleanupPerformed':False},indent=2)+'\n')
        raise
