#!/usr/bin/env python3
"""Collect one exact fork/local sing-tun source identity; never accept arbitrary replacements."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from polaris_go_environment import isolated_go_environment

MODULE = 'github.com/sagernet/sing-tun'
VERSION = 'v0.9.7-0.20261009022811-5c2edb183cc9'
REPLACEMENT = './third_party/sing-tun'
EXPECTED_REPLACEMENT_TREE = 'f3d3ebdbe6d7180d52388a5f3ba2214db4cffd6b'


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_replacements(modules, binding, repo):
    mains = [module for module in modules if module.get('Main')]
    if len(mains) != 1:
        raise ValueError('exactly one frozen main module required; external workspace is forbidden')
    main = mains[0]
    if main.get('Path') != 'github.com/sagernet/sing-box' or Path(main.get('Dir', '')).resolve() != repo.resolve() or Path(main.get('GoMod', '')).resolve() != (repo / 'go.mod').resolve():
        raise ValueError('main module Path/Dir/GoMod differs from the frozen repository')
    accepted = []
    for module in modules:
        replacement = module.get('Replace')
        if replacement is None:
            continue
        if (module.get('Path'), module.get('Version'), replacement.get('Path'), replacement.get('Version', '')) != (MODULE, VERSION, REPLACEMENT, ''):
            raise ValueError('unapproved replacement: ' + module.get('Path', ''))
        if Path(replacement['Dir']).resolve() != (repo / REPLACEMENT).resolve():
            raise ValueError('replacement directory does not resolve to the fixed source tree')
        accepted.append(module)
    if len(accepted) != 1:
        raise ValueError('exactly one approved local sing-tun replacement required')
    if binding['module'] != MODULE or binding['version'] != VERSION or binding['replacementPath'] != REPLACEMENT:
        raise ValueError('unapproved replacement binding')


def json_stream(text):
    decoder = json.JSONDecoder()
    values = []
    while text.strip():
        text = text.lstrip()
        value, count = decoder.raw_decode(text)
        values.append(value)
        text = text[count:]
    return values


def collect(repo, expected_head, go, module_list_output):
    head = git(repo, 'rev-parse', 'HEAD')
    if head != expected_head:
        raise ValueError('source HEAD differs from caller-frozen SHA')
    if git(repo, 'status', '--porcelain', '--untracked-files=all'):
        raise ValueError('source checkout is dirty')
    if git(repo, 'ls-files', '--others', '--', 'third_party/sing-tun'):
        raise ValueError('extra replacement source files, including ignored files')
    binding_path = repo / 'release/dependency-sources/sing-tun-replacement.json'
    binding = json.loads(binding_path.read_text())
    tree = git(repo, 'rev-parse', head + ':third_party/sing-tun')
    if tree != EXPECTED_REPLACEMENT_TREE or tree != binding['replacementTree']:
        raise ValueError('replacement full tree differs from approved binding')
    environment = isolated_go_environment()
    version = subprocess.check_output([str(go), 'env', 'GOVERSION'], cwd=repo, env=environment, text=True).strip()
    if version != 'go1.25.5':
        raise ValueError('this source fingerprint collector requires the approved Go1.25.5')
    # Run the real module resolver; a caller-supplied stale/forged module JSON
    # must not be accepted as current source evidence. Keep caches external.
    module_bytes = subprocess.check_output([str(go), 'list', '-mod=readonly', '-m', '-json', 'all'], cwd=repo, env=environment)
    modules = json_stream(module_bytes.decode())
    validate_replacements(modules, binding, repo)
    # Validate bytes and executable bits independently of status/index metadata.
    lines = subprocess.check_output(['git', '-C', str(repo), 'ls-tree', '-r', head, '--', 'third_party/sing-tun'], text=True).splitlines()
    for line in lines:
        identity, name = line.split('\t', 1)
        mode, kind, blob = identity.split()
        path = repo / name
        if kind != 'blob' or not path.is_file() or path.is_symlink():
            raise ValueError('replacement has non-regular source')
        actual = git(repo, 'hash-object', '--no-filters', str(path))
        if actual != blob or mode != ('100755' if path.stat().st_mode & 0o111 else '100644'):
            raise ValueError('replacement bytes/mode drift: ' + name)
    if len(lines) != binding['replacementFileCount'] or len(lines) != 256:
        raise ValueError('complete 256-file replacement snapshot required')
    module_list_output.write_bytes(module_bytes)
    # This schema is identical for all four future consuming kernels, but each
    # must carry its actual measured values. It does not relabel old a01/mobile.
    return {'schema': 'fork-source-fingerprint-v1', 'sourceCommit': head,
            'sourceTree': git(repo, 'rev-parse', head + '^{tree}'), 'sourceOverlay': 0,
            'goModSha256': digest(repo / 'go.mod'), 'goSumSha256': digest(repo / 'go.sum'),
            'replacement': {**binding, 'bindingSha256': digest(binding_path)},
            'moduleListSha256': hashlib.sha256(module_bytes).hexdigest(), 'replacementFilesVerified': len(lines),
            'goVersion': version, 'goExecutableSha256': digest(go),
            'isolatedGoSettings': {key: environment[key] for key in ('GOENV', 'GOWORK', 'GOFLAGS', 'GOTOOLCHAIN')},
            'scope': 'source identity only; no production kernel/platform/device acceptance'}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument('--expected-head', required=True)
    p.add_argument('--go', type=Path, required=True, help='Approved Go1.25.5 executable; use external private caches')
    p.add_argument('--module-list-output', type=Path, required=True, help='External output for fresh Go list -m -json all evidence')
    args = p.parse_args()
    print(json.dumps(collect(args.repo, args.expected_head, args.go, args.module_list_output), indent=2))
