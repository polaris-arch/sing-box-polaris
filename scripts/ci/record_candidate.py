#!/usr/bin/env python3
"""Record actual candidate files; not a signed release or consumer acceptance receipt."""
import hashlib,json,os,subprocess,sys
from pathlib import Path

def git(*args):return subprocess.check_output(['git',*args],text=True).strip()
def main(directory):
 root=Path(directory)
 if not root.is_dir():raise SystemExit(f'missing artifact directory: {root}')
 files=[]
 for p in sorted(root.rglob('*')):
  if p.is_symlink():raise SystemExit(f'unexpected artifact symlink: {p}')
  if not p.is_file() or p.name.startswith('polaris-candidate-manifest-'):continue
  h=hashlib.sha256()
  with p.open('rb') as f:
   for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
  files.append({'path':p.relative_to(root).as_posix(),'bytes':p.stat().st_size,'sha256':h.hexdigest()})
 if not files:raise SystemExit('no candidate files')
 repo=os.environ['GITHUB_REPOSITORY'];rid=os.environ['GITHUB_REPOSITORY_ID']
 if repo!='polaris-arch/sing-box-polaris' or rid!='1421657509':raise SystemExit('candidate repository identity mismatch')
 job=os.environ['GITHUB_JOB']; suffix=os.environ.get('CANDIDATE_MATRIX_KEY','default')
 import re
 if not re.fullmatch('[A-Za-z0-9_.-]+',suffix):raise SystemExit('invalid artifact matrix key')
 record={'schema':'polaris-upstream-candidate-files-v1','repository':repo,'repositoryId':int(rid),'sourceCommit':git('rev-parse','HEAD'),'sourceTree':git('rev-parse','HEAD^{tree}'),'workflowRunId':os.environ['GITHUB_RUN_ID'],'workflowAttempt':os.environ['GITHUB_RUN_ATTEMPT'],'job':job,'matrixKey':suffix,'signatureState':'unsigned-candidate','releasePublication':False,'runtimeAcceptance':False,'files':files}
 from client_source import JOBS, collect
 if job in JOBS:record['clientSource']=collect(JOBS[job],True)
 (root/f'polaris-candidate-manifest-{job}-{suffix}.json').write_text(json.dumps(record,indent=2)+'\n')
if __name__=='__main__':main(sys.argv[1])
