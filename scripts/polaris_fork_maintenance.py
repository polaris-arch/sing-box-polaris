#!/usr/bin/env python3
"""Read-only source/patch/baseline audit; never fetch, build, tag, sync or publish."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

CATALOG='release/polaris-fork-maintenance.json'
SHA=re.compile(r'[0-9a-f]{40}')

def require(ok,message):
    if not ok:raise ValueError(message)

def git(repo,*args):
    return subprocess.check_output(['git',*args],cwd=repo)

def safe_path(path):
    require(isinstance(path,str) and path and not path.startswith('/')
        and all(part not in ('','..','.') for part in path.split('/')) and '\\' not in path,
        'relative source path required')
    return path

def validate_catalog(value):
    require(value['schema']=='polaris-fork-maintenance-v1' and value['repository']=='polaris-arch/polaris-box'
        and value['upstreamRepository']=='SagerNet/sing-box','maintenance repository/schema differs')
    require(SHA.fullmatch(value['baselineCommit']) and SHA.fullmatch(value['reviewedRuntimeReference'])
        and SHA.fullmatch(value['previousReleasedBaseline']), 'fixed source SHAs required')
    features=value['features'];ids=[r['id'] for r in features]
    require(len(features)==15 and len(set(ids))==15 and ids.count('dial-side-dns-rules')==1
        and value['originalProductPatchCount']==14 and value['additionalDialSideDNS'] is True,'original14+DNS inventory differs')
    require(all(SHA.fullmatch(row['introducedCommit']) and row['paths'] for row in features),'feature origin/path required')
    paths={safe_path(path) for row in features for path in row['paths']}
    require(paths==set(value['runtimeFiles']),'runtime file coverage differs')
    for path,pin in value['runtimeFiles'].items():
        safe_path(path);require(SHA.fullmatch(pin['gitBlob']) and re.fullmatch('[0-9a-f]{64}',pin['sha256'])
            and type(pin['bytes']) is int and pin['bytes']>0,'runtime pin differs')
    return value

def parse_version(tag):
    match=re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)(?:-(alpha|beta|rc)\.(\d+))?',tag)
    require(match is not None,'unsupported upstream release version')
    major,minor,patch,stage,n=match.groups()
    return (int(major),int(minor),int(patch),{'alpha':0,'beta':1,'rc':2,None:3}[stage],int(n or 0))

def upstream_observation(value,catalog):
    require(value['forkRepository']['full_name']==catalog['repository'] and value['forkRepository']['id']==1407705262,
        'observed fork repository differs')
    require(isinstance(value['atUTC'],str) and value['atUTC'],'observation timestamp required')
    refs={k:value[k]['object']['sha'] for k in ['forkMain','forkTesting','upstreamTesting']}
    require(all(SHA.fullmatch(sha) for sha in refs.values()),'observed ref SHA differs')
    require(value['upstreamAlpha12']['object']['type']=='commit'
        and value['upstreamAlpha12']['object']['sha']==catalog['baselineCommit'],'fixed baseline tag observation differs')
    releases=[r for r in value['upstreamReleases'] if not r['draft'] and r['published_at']]
    ranked=[]
    for row in releases:
        try:version=parse_version(row['tag_name'])
        except ValueError:continue
        ranked.append((version,row['tag_name']))
    require(ranked,'supported upstream release observation required')
    baseline=parse_version(catalog['baselineTag']);latest=max(ranked)[1]
    return {'observedAtUTC':value['atUTC'],'refs':refs,'latestObservedRelease':latest,
        'newerObservedReleaseCount':sum(version>baseline for version,_ in ranked),
        'releaseCoverage':'only the supplied published API page; no claim beyond that page',
        'testingMirror':'aligned' if refs['forkTesting']==refs['upstreamTesting'] else 'not aligned; inspect divergence before any authorized ref write',
        'securityAdoption':'manual release/security advisory assessment required; no SLA or security verdict inferred',
        'refWritesPerformed':False}

def audit(repo,source=None,observation=None):
    actual=git(repo,'rev-parse','HEAD').decode().strip();source=source or actual
    require(SHA.fullmatch(source) and source==actual,'audit requires the exact checked-out HEAD')
    require(not git(repo,'status','--porcelain=v1','--untracked-files=all'),'clean source required')
    catalog=validate_catalog(json.loads(git(repo,'show',source+':'+CATALOG)))
    config=json.loads(git(repo,'show',source+':release/polaris-production-release.json'))
    require((config['upstreamTag'],config['upstreamCommit'])==(catalog['baselineTag'],catalog['baselineCommit']),
        'production baseline/catalog differs')
    for ancestor in [catalog['baselineCommit'],catalog['reviewedRuntimeReference'],*(row['introducedCommit'] for row in catalog['features'])]:
        subprocess.run(['git','merge-base','--is-ancestor',ancestor,source],cwd=repo,check=True,capture_output=True)
    delta=git(repo,'diff','--name-only',catalog['previousReleasedBaseline'],catalog['baselineCommit']).decode().splitlines()
    require(delta==catalog['upstreamDeltaExpected'],'upstream delta differs from reviewed retention basis')
    verified={};upstream={}
    for path,pin in catalog['runtimeFiles'].items():
        raw=git(repo,'show',source+':'+path);blob=git(repo,'rev-parse',source+':'+path).decode().strip()
        require(blob==pin['gitBlob'] and len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256'],
            'reviewed runtime changed; aggregate implementation/review and refresh catalog: '+path)
        verified[path]=pin
        found=subprocess.run(['git','cat-file','-e',catalog['baselineCommit']+':'+path],cwd=repo,capture_output=True)
        upstream[path]=git(repo,'rev-parse',catalog['baselineCommit']+':'+path).decode().strip() if found.returncode==0 else None
    rows=[{'id':row['id'],'feature':row['feature'],'role':row['role'],'paths':row['paths'],
        'sourceFilesVerified':True,'differentFromUpstream':[p for p in row['paths'] if upstream[p]!=verified[p]['gitBlob']],
        'retirementDecision':row['upstreamRetirement'],
        'upstreamBaselinePathChanges':[p for p in row['paths'] if p in delta]} for row in catalog['features']]
    return {'schema':'polaris-fork-maintenance-audit-v1','sourceCommit':source,
        'sourceTree':git(repo,'rev-parse',source+'^{tree}').decode().strip(),'baselineTag':catalog['baselineTag'],
        'baselineCommit':catalog['baselineCommit'],'actualUpstreamEndpointDelta':delta,'features':rows,'verifiedRuntimeFiles':len(verified),
        'upstreamObservation':upstream_observation(observation,catalog) if observation else 'not supplied; live upstream/mirror/lag not verified',
        'replayConflicts':'record actual per-path resolutions at an authorized baseline migration; not inferred from audit',
        'invalidatedReceipts':catalog['invalidatedReceipts'],'remoteWritesPerformed':False,'buildsPerformed':False,
        'acceptance':'source inventory only; independent review/runtime/platform/public/App gates remain separate'}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[1]);parser.add_argument('--source');parser.add_argument('--observation',type=Path)
    args=parser.parse_args();value=json.loads(args.observation.read_bytes()) if args.observation else None
    print(json.dumps(audit(args.repo,args.source,value),indent=2))
if __name__=='__main__':main()
