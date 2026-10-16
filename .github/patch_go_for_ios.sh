#!/usr/bin/env bash
set -euo pipefail
# Keep only ARMv8.0 crypto features for supported A8/A9 devices. No atomics/SHA512.
# Validate exact source state; an existing filename alone is not a cache receipt.
export GOTOOLCHAIN=local
SOURCE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GOROOT="$(go env GOROOT)"
export SOURCE_ROOT GOROOT
python3 - <<'PY'
import hashlib,json,os,subprocess
from pathlib import Path
root=Path(os.environ['SOURCE_ROOT']);goroot=Path(os.environ['GOROOT'])
manifest=json.loads((root/'.github/go-toolchains.json').read_text());entry=manifest['iosCPU']
if subprocess.check_output(['go','env','GOVERSION'],text=True).strip()!='go'+manifest['version']:
    raise RuntimeError('Apple CPU patch requires exact source-owned Go version')
patch=root/entry['patch']
if hashlib.sha256(patch.read_bytes()).hexdigest()!=entry['patchSHA256']:
    raise RuntimeError('Apple CPU patch input hash mismatch')
def matches(expected):
    return all((hashlib.sha256((goroot/p).read_bytes()).hexdigest() if (goroot/p).is_file() else None)==h for p,h in expected.items())
if matches(entry['before']):
    subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(patch)],cwd=goroot,check=True)
if not matches(entry['after']):
    raise RuntimeError('Apple CPU source is partial, unexpected or corrupt')
print(json.dumps({'appleCPUSourceVerified':True,'goVersion':manifest['version'],'features':entry['features']}))
PY
CPU_FILES="$(GOOS=ios GOARCH=arm64 CGO_ENABLED=0 go list -f '{{.GoFiles}}' internal/cpu)"
echo "internal/cpu files for ios/arm64: $CPU_FILES"
case "$CPU_FILES" in
  *cpu_arm64_ios.go*) ;;
  *) echo 'Apple CPU patch is not effective' >&2; exit 1 ;;
esac
