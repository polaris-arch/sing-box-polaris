import io
import json
import copy
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from polaris_native_candidate import package
from polaris_native_distribution import encode, file_info, read_archive
import polaris_production_release as production

REPO = Path(__file__).resolve().parents[1]
HEAD = 'a' * 40
BUILD_ID = 'polaris.' + 'b' * 64


class ProductionTests(unittest.TestCase):
    def setUp(self):
        self.config = production.plan(REPO)

    def fingerprint(self):
        binding_path = REPO / 'release/dependency-sources/sing-tun-replacement.json'
        return {'schema': 'fork-source-fingerprint-v1', 'sourceCommit': HEAD,
            'sourceTree': 'c' * 40, 'sourceOverlay': 0, 'goVersion': 'go1.25.5',
            'goModSha256': production.sha((REPO / 'go.mod').read_bytes()),
            'goSumSha256': production.sha((REPO / 'go.sum').read_bytes()),
            'replacement': {**json.loads(binding_path.read_bytes()),
                            'bindingSha256': production.sha(binding_path.read_bytes())},
            'moduleListSha256': 'host-observation', 'goExecutableSha256': 'host-tool-observation',
            'replacementFilesVerified': 256,
            'isolatedGoSettings': {'GOENV': 'off', 'GOWORK': 'off', 'GOFLAGS': '', 'GOTOOLCHAIN': 'local'}}

    def test_windows_replacement_failure_stops_before_core_build_and_preserves_log(self):
        class BuilderReached(Exception):
            pass
        for failure in (True, False):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / 'source'
                (source / '.git').mkdir(parents=True)
                (source / 'release').mkdir()
                for name in ('DEFAULT_BUILD_TAGS_WINDOWS', 'LDFLAGS'):
                    shutil.copy2(REPO / 'release' / name, source / 'release' / name)
                output = Path(directory) / 'output'
                result = RuntimeError('actual vet failure') if failure else 'seven Windows tests passed'
                with patch.dict(production.os.environ, dict(os.environ), clear=True), \
                     patch.object(production, 'frozen_source', return_value=(self.config, 'c' * 40)), \
                     patch.object(production, 'verify_source'), \
                     patch.object(production, 'collect', return_value=self.fingerprint()), \
                     patch.object(production.shutil, 'which', return_value='/private/go'), \
                     patch.object(production, 'run', side_effect=result if failure else None,
                                  return_value=None if failure else result) as execute, \
                     patch.object(production, 'build_native', side_effect=BuilderReached) as builder:
                    expected = RuntimeError if failure else BuilderReached
                    with self.assertRaises(expected):
                        production.native(REPO, source, HEAD, 'windows/amd64', output)
                    self.assertEqual(builder.call_count, 0 if failure else 1)
                    command, cwd, environment = execute.call_args.args
                    self.assertEqual(command[-1], './...')
                    self.assertNotIn('-vet=off', command)
                    self.assertEqual(cwd, source / 'third_party/sing-tun')
                    self.assertEqual(environment['GOOS'], 'windows')
                    self.assertEqual(environment['CGO_ENABLED'], '0')
                    self.assertIn(str(result), (output / 'windows-replacement-regressions.log').read_text())

    def test_build_identity_is_portable_and_binds_source_version_tag_and_features(self):
        fp = self.fingerprint()
        tags = 'with_gvisor,with_quic'
        def identity(value=fp, version=self.config['version'], tag=self.config['tag'], flags=tags):
            return production.build_identity(value, 'linux/amd64', version, flags, tag)
        expected = identity()
        for directory in ['/tmp/checkout-a/mod-cache-a', 'C:/checkout-b/mod-cache-b']:
            observed = dict(fp, moduleListSha256=production.sha(directory.encode()),
                            goExecutableSha256=directory, scope=directory)
            self.assertEqual(identity(observed), expected)
            self.assertEqual(production.portable_source_identity(observed), production.portable_source_identity(fp))
        self.assertEqual(identity(flags='with_quic,with_gvisor'), expected)
        for key in ['sourceCommit', 'sourceTree', 'goModSha256', 'goSumSha256']:
            self.assertNotEqual(identity(dict(fp, **{key: 'changed'})), expected)
        changed = copy.deepcopy(fp)
        changed['replacement']['replacementTree'] = 'e' * 40
        self.assertNotEqual(identity(changed), expected)
        self.assertNotEqual(identity(version='other'), expected)
        self.assertNotEqual(identity(tag='vother'), expected)
        self.assertNotEqual(identity(flags='with_gvisor'), expected)
        facts = production.portable_source_identity(fp)['facts']
        self.assertEqual(set(facts), {'sourceCommit', 'sourceTree', 'sourceOverlay', 'goVersion',
                                     'goModSha256', 'goSumSha256', 'replacement'})
        self.assertEqual(production.portable_source_identity(fp)['fingerprint'],
                         production.sha(production.canonical(facts).encode()))

    def test_actual_clean_standalone_entry_without_bytecode_host_override(self):
        with tempfile.TemporaryDirectory(prefix='polaris-entry-proof-') as directory:
            source = Path(directory) / 'source'
            subprocess.run(['git', 'clone', '--local', '--no-hardlinks', str(REPO), str(source)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            for name in production.CHANGES:
                original = REPO / name
                if original.exists():
                    destination = source / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(original, destination)
            subprocess.run(['git', 'add', '--', *sorted(production.CHANGES)], cwd=source, check=True)
            subprocess.run(['git', '-c', 'user.name=Polaris entry test', '-c', 'user.email=entry-test@example.invalid',
                            'commit', '--allow-empty', '-m', 'Freeze temporary entry proof'], cwd=source,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
            environment = dict(os.environ)
            environment.pop('PYTHONDONTWRITEBYTECODE', None)
            for mode in ['plan', 'verify-source']:
                # Neither -B nor a pre-set bytecode environment protects this invocation.
                result = subprocess.run([sys.executable, 'scripts/polaris_production_release.py', mode,
                    '--expected-head', head], cwd=source, env=environment, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(list(source.rglob('__pycache__')))
            self.assertEqual(subprocess.check_output(['git', 'status', '--porcelain=v1', '--untracked-files=all'],
                                                     cwd=source), b'')

    def fixture(self, base, key='linux/amd64'):
        row = production.target(self.config, key)
        root = base / production.basename(self.config, key)
        root.mkdir()
        core = root / row['executable']
        core.write_bytes(b'inert-core-fixture')
        core.chmod(0o755)
        if row['sidecar']:
            (root / row['sidecar']).write_bytes(b'inert-library-fixture')
        (root / 'licenses').mkdir()
        (root / 'licenses/NOTICE').write_bytes((REPO / 'release/licenses/NOTICE').read_bytes())
        (root / 'provenance.json').write_bytes(b'{}')
        (root / 'SHA256SUMS').write_bytes(b'old checksum')
        archive = base / (root.name + row['suffix'])
        members = package(root, archive, key.split('/')[0])
        index, notice = production.material(REPO, self.config)
        module = next(d for d in index['modules'] if d['sourceBundleMember'])
        pins = json.loads((REPO / self.config['inputPinsPath']).read_bytes())
        smoke = {'os': key.split('/')[0], 'arch': key.split('/')[1], 'version': pins['cronetVersion'],
                 'gvisorCompiled': True, 'linkage': row['cronetLinkage'], 'go': 'go1.25.5'}
        preset = (REPO / 'release' / ('DEFAULT_BUILD_TAGS_WINDOWS' if key.startswith('windows/') else 'DEFAULT_BUILD_TAGS')).read_text().strip()
        tags = preset + (',with_purego' if key.startswith('linux/') else '')
        receipt = {'sourceCommit': HEAD, 'sourceTree': 'c' * 40,
                   'archive': {**file_info(archive), 'members': {n: production.sha(d) for n, d in members.items()}},
                   'archivePath': str(archive), 'payloadHashes': {row['executable']: production.sha(core.read_bytes())},
                   'tags': tags, 'nativeCronetSmoke': smoke,
                   'extractedNativeCronetSmoke': copy.deepcopy(smoke),
                   'coreNative': {'format': 'inert-fixture', 'signatureTrustValidated': False},
                   'cronetNative': {'format': 'inert-fixture', 'signatureTrustValidated': False},
                   'cronet': {'sha256': production.sha(b'inert-library-fixture')}}
        fp = self.fingerprint()
        bid = production.build_identity(fp, key, self.config['version'], tags, self.config['tag'])
        flags = ((REPO / 'release/LDFLAGS').read_text().strip()
                 + ' -s -w -X github.com/sagernet/sing-box/constant.Version=' + self.config['version']
                 + ' -buildid=' + bid)
        receipt.update(ldflags=flags, buildCommand=['go', 'build', '-buildvcs=true', '-mod=readonly',
            '-p', '1', '-trimpath', '-tags', tags, '-ldflags', flags, '-o', str(core), './cmd/sing-box'])
        graph = {'normalModules': [{k: module[k] for k in ('module', 'version', 'h1')}], 'settings': {'-tags': tags},
                 'prebuiltAcquisitionModules': []}
        return receipt, fp, graph

    def repack(self, base, key, mutate=None, version=None):
        receipt, fp, graph = self.fixture(base, key)
        if mutate:
            mutate(receipt, fp, graph)
        output = base / 'final'
        output.mkdir()
        return production.repackage(REPO, self.config, key, receipt, fp, graph,
            version or 'sing-box version ' + self.config['version'] + '\n', output), receipt

    def test_all_six_layouts_keep_actual_bytes_and_include_root_license(self):
        for row in self.config['desktop']:
            with self.subTest(target=row['target']), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                final, old = self.repack(base, row['target'])
                members = read_archive(base / 'final' / final['archive']['name'], final['archive'])
                root = production.basename(self.config, row['target'])
                self.assertEqual(members[root + '/LICENSE'][0], (REPO / 'LICENSE').read_bytes())
                self.assertEqual(members[root + '/' + row['executable']], (b'inert-core-fixture', 0o755))
                notice = members[root + '/NOTICE'][0]
                self.assertEqual(notice, members[root + '/licenses/NOTICE'][0])
                self.assertIn(HEAD.encode(), notice)
                self.assertIn(self.config['version'].encode(), notice)
                self.assertNotIn(b'/tree/a01da7a942b3a0dbbfdfda2bba5bd63d5bd9d932', notice)
                self.assertEqual(final['noticeIdentity']['sha256'], production.sha(notice))
                self.assertFalse(final['publicationEligible'])
                self.assertFalse(final['publicUploadPerformed'])
                self.assertEqual(final['archive']['name'], root + row['suffix'])
                self.assertEqual(final['sidecar'] is None, row['sidecar'] is None)

    def test_old_candidate_version_cannot_be_promoted_by_renaming(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'actual kernel version'):
            self.repack(Path(directory), 'linux/amd64', version='sing-box version 1.15.0-alpha.11.polaris.candidate-a01da7a9')

    def test_wrong_source_hash_library_and_capabilities_fail_before_output(self):
        mutations = [
            lambda r, f, g: r.update(sourceCommit='d' * 40),
            lambda r, f, g: r['payloadHashes'].update({'sing-box': '0' * 64}),
            lambda r, f, g: r['cronet'].update(sha256='0' * 64),
            lambda r, f, g: r.update(tags='with_naive_outbound'),
            lambda r, f, g: r['extractedNativeCronetSmoke'].update(arch='arm64'),
            lambda r, f, g: g['normalModules'].append({'module': 'new/unreviewed', 'version': 'v1.0.0', 'h1': 'h1:AAAA='}),
        ]
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                self.repack(Path(directory), 'linux/amd64', mutate=mutate)

    def test_member_digest_drift_and_missing_library_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            receipt, fp, graph = self.fixture(base)
            archive = Path(receipt['archivePath'])
            data = archive.read_bytes()
            archive.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
            with self.assertRaisesRegex(ValueError, 'fixed bytes/hash'):
                production.repackage(REPO, self.config, 'linux/amd64', receipt, fp, graph,
                    'sing-box version ' + self.config['version'], base)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            receipt, fp, graph = self.fixture(base)
            root = base / production.basename(self.config, 'linux/amd64')
            (root / 'libcronet.so').unlink()
            members = package(root, Path(receipt['archivePath']), 'linux')
            receipt['archive'] = {**file_info(Path(receipt['archivePath'])),
                                   'members': {n: production.sha(d) for n, d in members.items()}}
            with self.assertRaisesRegex(ValueError, 'sidecar absent'):
                production.repackage(REPO, self.config, 'linux/amd64', receipt, fp, graph,
                    'sing-box version ' + self.config['version'], base)

    def actual_info(self, key='linux/amd64'):
        os_name, arch = key.split('/')
        tags = (REPO / 'release' / ('DEFAULT_BUILD_TAGS_WINDOWS' if os_name == 'windows' else 'DEFAULT_BUILD_TAGS')).read_text().strip()
        if os_name == 'linux':
            tags += ',with_purego'
        return '\n'.join(['file: go1.25.5', '\tdep\tfilippo.io/edwards25519\tv1.2.0\th1:AAAA=',
            '\tdep\t' + production.MODULE + '\t' + production.VERSION,
            '\t=>\t' + production.REPLACEMENT + '\t(devel)',
            '\tbuild\tvcs.revision=' + HEAD, '\tbuild\tvcs.modified=false', '\tbuild\tGOOS=' + os_name,
            '\tbuild\tGOARCH=' + arch, '\tbuild\tCGO_ENABLED=' + ('1' if os_name == 'darwin' else '0'),
            '\tbuild\t-tags=' + tags, '\tbuild\t-trimpath=true'])

    def test_real_buildinfo_replacement_without_h1_is_supported(self):
        graph = production.build_info(self.actual_info(), HEAD, 'linux/amd64')
        self.assertEqual(graph['localReplacement']['module'], production.MODULE)
        self.assertEqual(len(graph['normalModules']), 1)

    def test_buildinfo_rejects_dirty_wrong_vcs_arch_cgo_and_replacement(self):
        for old, new in [('vcs.modified=false', 'vcs.modified=true'), (HEAD, 'd' * 40),
                         ('GOARCH=amd64', 'GOARCH=arm64'), ('CGO_ENABLED=0', 'CGO_ENABLED=1'),
                         (production.REPLACEMENT, '/tmp/external-replacement'), ('-trimpath=true', '-trimpath=false')]:
            with self.subTest(field=old), self.assertRaises(ValueError):
                production.build_info(self.actual_info().replace(old, new), HEAD, 'linux/amd64')

    def test_trimpath_buildinfo_omits_ldflags_on_all_production_targets(self):
        for row in self.config['desktop']:
            key = row['target']
            with self.subTest(target=key):
                info = self.actual_info(key)
                graph = production.build_info(info, HEAD, key)
                self.assertEqual(graph['settings']['-trimpath'], 'true')
                self.assertNotIn('-ldflags', graph['settings'])
                for wrong in [info.replace('\tbuild\t-trimpath=true', ''),
                              info + '\n\tbuild\t-ldflags=-buildid=' + BUILD_ID]:
                    with self.assertRaisesRegex(ValueError, 'trimpath BuildInfo differs'):
                        production.build_info(wrong, HEAD, key)

    def test_build_command_binds_frozen_tags_ldflags_buildid_and_destination(self):
        for row in self.config['desktop']:
            key = row['target']
            with self.subTest(target=key), tempfile.TemporaryDirectory() as directory:
                receipt, fp, unused = self.fixture(Path(directory), key)
                bid = production.build_identity(fp, key, self.config['version'], receipt['tags'], self.config['tag'])
                production.validate_build_command(REPO, self.config, receipt, key, bid)
                mutations = []
                for index, value in [(0, 'other-go'), (2, '-buildvcs=false'), (3, '-mod=mod'),
                                     (6, '-trimpath=false'), (8, 'with_quic'), (10, '-buildid=wrong'),
                                     (12, '/tmp/foreign/core'), (13, './other-command')]:
                    changed = copy.deepcopy(receipt)
                    changed['buildCommand'][index] = value
                    mutations.append(changed)
                for field in ['tags', 'ldflags']:
                    mutations.append({**receipt, field: 'changed'})
                mutations.append({**receipt, 'buildCommand': []})
                for changed in mutations:
                    with self.assertRaisesRegex(ValueError, 'build command'):
                        production.validate_build_command(REPO, self.config, changed, key, bid)
                with self.assertRaisesRegex(ValueError, 'build command'):
                    production.validate_build_command(REPO, self.config, receipt, key, 'wrong-measured-id')

    def test_real_go1255_trimpath_binary_records_settings_and_measured_buildid(self):
        go = Path(os.environ.get('POLARIS_TEST_GO', shutil.which('go') or '')).resolve()
        environment = production.isolated_go_environment()
        self.assertEqual(subprocess.check_output([str(go), 'env', 'GOVERSION'], env=environment,
                                                text=True).strip(), 'go1.25.5',
                         'Set POLARIS_TEST_GO to the approved Go1.25.5; do not change global Go.')
        with tempfile.TemporaryDirectory(prefix='polaris-real-trimpath-') as directory:
            root = Path(directory)
            source = root / 'source'
            source.mkdir()
            (source / 'go.mod').write_text('module example.invalid/polaris-trimpath\n\ngo 1.25.5\n')
            command_source = source / 'cmd/sing-box'
            command_source.mkdir(parents=True)
            (command_source / 'main.go').write_text('package main\nfunc main() {}\n')
            for args in [['git', 'init', '--quiet'], ['git', 'add', '--', 'go.mod', 'cmd/sing-box/main.go'],
                         ['git', '-c', 'user.name=Polaris trimpath test', '-c',
                          'user.email=trimpath-test@example.invalid', 'commit', '--quiet', '-m', 'Tiny actual Go regression']]:
                subprocess.run(args, cwd=source, check=True, capture_output=True)
            head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
            environment.update(GOMAXPROCS='2', CGO_ENABLED='0', GOOS='linux', GOARCH='amd64',
                GOAMD64='v1', GOMODCACHE=str(root / 'modules'),
                GOCACHE=os.environ.get('POLARIS_TEST_GO_CACHE', str(root / 'cache')))
            key = 'linux/amd64'
            tags = (REPO / 'release/DEFAULT_BUILD_TAGS').read_text().strip() + ',with_purego'
            bid = 'polaris-production-v1-' + 'b' * 64
            flags = ((REPO / 'release/LDFLAGS').read_text().strip()
                     + ' -s -w -X github.com/sagernet/sing-box/constant.Version=' + self.config['version']
                     + ' -buildid=' + bid)
            binary = root / production.basename(self.config, key) / 'sing-box'
            binary.parent.mkdir()
            command = ['go', 'build', '-buildvcs=true', '-mod=readonly', '-p', '1', '-trimpath',
                       '-tags', tags, '-ldflags', flags, '-o', str(binary), './cmd/sing-box']
            receipt = {'buildCommand': command, 'tags': tags, 'ldflags': flags}
            production.validate_build_command(REPO, self.config, receipt, key, bid)
            subprocess.run([str(go), *command[1:]], cwd=source, env=environment, check=True, capture_output=True)
            info = subprocess.check_output([str(go), 'version', '-m', str(binary)], env=environment, text=True)
            measured = subprocess.check_output([str(go), 'tool', 'buildid', str(binary)], env=environment, text=True).strip()
            self.assertEqual(measured, bid)
            settings = production.build_settings(info, head, key)
            self.assertEqual(settings['-trimpath'], 'true')
            self.assertNotIn('-ldflags', settings)
            self.assertNotIn('-ldflags=', info)
            with self.assertRaisesRegex(ValueError, 'build command'):
                production.validate_build_command(REPO, self.config, receipt, key, 'wrong-measured-id')
            print(json.dumps({'proof': 'real-Go1.25.5-tiny-trimpath-binary', 'goExecutable': str(go),
                'goExecutableSha256': production.digest(go), 'microSourceCommit': head, 'buildCommand': command,
                'binarySha256': production.digest(binary), 'actualBuildID': measured, 'actualBuildInfo': info,
                'scope': 'actual tiny Go regression; not production native/App/device acceptance'}))

    def test_binary_acquisition_modules_remain_separate_from_go_source_zips(self):
        info = self.actual_info() + '\n\tdep\tgithub.com/sagernet/cronet-go/lib/darwin_amd64\tv1.0.0\th1:BBBB='
        graph = production.build_info(info, HEAD, 'linux/amd64')
        self.assertEqual(len(graph['normalModules']), 1)
        self.assertEqual(len(graph['prebuiltAcquisitionModules']), 1)

    def test_native_header_rejects_foreign_or_truncated_binary(self):
        elf = bytearray(20)
        elf[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', elf, 18, 62)
        production.native_header(elf, 'linux/amd64')
        for key in ['linux/arm64', 'windows/amd64', 'darwin/amd64']:
            with self.subTest(key=key), self.assertRaises(ValueError):
                production.native_header(elf, key)

    def test_final_load_path_is_checked_but_relocation_is_allowed(self):
        expected = {'os': 'linux', 'version': '154', 'library': '/old/libcronet.so', 'sha256': 'a' * 64}
        actual = {**expected, 'library': '/new/libcronet.so'}
        production.validate_smoke(actual, expected, Path('/new/libcronet.so'))
        for wrong in [{**actual, 'sha256': 'b' * 64}, {**actual, 'library': '/foreign/libcronet.so'}]:
            with self.assertRaises(ValueError):
                production.validate_smoke(wrong, expected, Path('/new/libcronet.so'))

    def test_static_smoke_rejects_any_sidecar(self):
        with self.assertRaises(ValueError):
            production.validate_smoke({'library': '/tmp/x'}, {'library': '/tmp/x'})

    def test_assembly_rejects_partial_or_mixed_run_before_source_assembly(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            old = base / 'old.tar.gz'
            old.write_bytes(b'old')
            config = copy.deepcopy(self.config)
            config['reusedSource'] = file_info(old)
            inputs = base / 'inputs'
            inputs.mkdir()
            with patch.object(production, 'frozen_source', return_value=(config, 'c' * 40)):
                with self.assertRaisesRegex(ValueError, 'six-target'):
                    production.assemble(REPO, HEAD, inputs, base/'openwrt', base/'guests', base / 'out')

    def test_complete_same_run_desktop_assembly_preserves_pins_and_uses_public_sources(self):
        # Inert binary-shaped fixtures only: mocks return static Go metadata, never execute kernels.
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            inputs = base / 'inputs'
            inputs.mkdir()
            graphs, binary_keys, ids = {}, {}, {}
            for spec in self.config['desktop']:
                key = spec['target']
                platform = inputs / key.replace('/', '-')
                platform.mkdir()
                technical = platform / 'technical'
                technical.mkdir()
                receipt, fp, graph = self.fixture(technical, key)
                root = technical / production.basename(self.config, key)
                core = root / spec['executable']
                data = bytearray(128)
                os_name, arch = key.split('/')
                if os_name == 'linux':
                    data[:6] = b'\x7fELF\x02\x01'
                    struct.pack_into('<H', data, 18, 62 if arch == 'amd64' else 183)
                elif os_name == 'darwin':
                    data[:4] = b'\xcf\xfa\xed\xfe'
                    struct.pack_into('<I', data, 4, 0x1000007 if arch == 'amd64' else 0x100000c)
                else:
                    data[:2] = b'MZ'
                    struct.pack_into('<I', data, 60, 64)
                    data[64:68] = b'PE\0\0'
                    struct.pack_into('<H', data, 68, 0x8664 if arch == 'amd64' else 0xaa64)
                core.write_bytes(data)
                core.chmod(0o755)
                if spec['sidecar']:
                    (root / spec['sidecar']).write_bytes(data)
                    receipt['cronet']['sha256'] = production.sha(data)
                binary_keys[bytes(data)] = key
                members = package(root, Path(receipt['archivePath']), os_name)
                receipt['archive'] = {**file_info(Path(receipt['archivePath'])),
                                      'members': {n: production.sha(d) for n, d in members.items()}}
                receipt['payloadHashes'][spec['executable']] = production.sha(data)
                receipt.update(workflowCommit=HEAD, workflowRun='20', workflowAttempt='1')
                bid = production.build_identity(fp, key, self.config['version'], receipt['tags'], self.config['tag'])
                ids[key] = bid
                info = self.actual_info(key).replace('h1:AAAA=', graph['normalModules'][0]['h1']).replace(BUILD_ID, bid)
                graph = production.build_info(info, HEAD, key)
                graphs[key] = info
                out = platform / 'final'
                out.mkdir()
                final = production.repackage(REPO, self.config, key, receipt, fp, graph,
                    'sing-box version ' + self.config['version'] + '\n', out)
                final.update(buildID=bid, finalPackageCronetSmoke=receipt['nativeCronetSmoke'])
                if spec['sidecar']:
                    final['nativeCronetSmoke']['library'] = '/fixture/' + spec['sidecar']
                    final['finalPackageCronetSmoke'] = dict(final['nativeCronetSmoke'])
                # Keep the full real native upload layout including the same-name
                # technical archive; assembly must select the controlled final path.
                self.assertTrue(Path(receipt['archivePath']).exists())
                (out / 'production-receipt.json').write_bytes(encode(final))
            config = copy.deepcopy(self.config)
            def static_read(args, *unused):
                path = Path(args[-1])
                if args[:3] == ['go', 'version', '-m']:
                    return graphs[binary_keys[path.read_bytes()]]
                if args[:3] == ['go', 'tool', 'buildid']:
                    return ids[binary_keys[path.read_bytes()]]
                raise AssertionError('unexpected execution: ' + repr(args))
            with patch.object(production, 'frozen_source', return_value=(config, 'c' * 40)), \
                 patch.object(production, 'verify_source'), patch.object(production, 'run', side_effect=static_read), \
                 patch.object(production.subprocess, 'check_output', return_value=b'inert-new-source-tar'), \
                 patch('polaris_openwrt.validate_assembled_openwrt', return_value=[]), \
                 patch('polaris_public_sources.delivery', return_value={'method':'fixed-public-source-references'}), \
                 patch('polaris_public_sources.verify_public', return_value={'fixture':True}), \
                 patch.dict(production.os.environ, {'GITHUB_RUN_ID': '20', 'GITHUB_RUN_ATTEMPT': '1'}):
                result = production.assemble(REPO, HEAD, inputs, base/'ow',base/'guest', base / 'final')
                self.assertEqual(result['assetCount'], 8)
                index = json.loads((base / 'final/polaris-box-assets.json').read_bytes())
                self.assertEqual(len(index['platforms']), 6)
                self.assertFalse(index['publicationEligible'])
                self.assertTrue(all(value == 'pending' for value in index['gates'].values()))
                for line in (base / 'final/SHA256SUMS').read_text().splitlines():
                    expected, name = line.split('  ')
                    self.assertEqual(production.digest(base / 'final' / name), expected)
                # BuildInfo lacks ldflags, so verify the actual binary BuildID gate
                # still rejects a different measured ID during assembly.
                def wrong_buildid(args, *unused):
                    if args[:3] == ['go', 'tool', 'buildid']:
                        return 'wrong-measured-binary-id'
                    return static_read(args, *unused)
                with patch.object(production, 'run', side_effect=wrong_buildid):
                    with self.assertRaisesRegex(ValueError, 'actual packaged Go graph/BuildID differs'):
                        production.assemble(REPO, HEAD, inputs,base/'ow',base/'guest', base / 'wrong-buildid-output')
                self.assertNotIn('sourceAsset',index)
                self.assertEqual(index['sourceDelivery']['method'],'fixed-public-source-references')
                receipt_path = next(inputs.rglob('production-receipt.json'))
                mixed = json.loads(receipt_path.read_bytes())
                mixed['workflowAttempt'] = '2'
                receipt_path.write_bytes(encode(mixed))
                with self.assertRaisesRegex(ValueError, 'mixed source/run/attempt/version'):
                    production.assemble(REPO, HEAD, inputs,base/'ow',base/'guest', base / 'mixed-output')

    def test_historical_workflow_is_manual_no_publishing_and_does_not_retarget_lanes(self):
        workflow = (REPO / 'scripts/testdata/historical-workflows/polaris-production-release.yml').read_text()
        self.assertNotIn('max-parallel:', workflow)
        self.assertIn('needs: [plan, native-openwrt]', workflow)
        self.assertIn('needs: [plan, native, native-openwrt, openwrt-guests]', workflow)
        self.assertEqual(workflow.count('uses: ./.github/workflows/polaris-production-native.yml'), 2)
        runner = (REPO / 'scripts/testdata/historical-workflows/polaris-production-native.yml').read_text()
        self.assertIn('polaris_runner_resources.py', runner)
        self.assertIn('cancel-in-progress: false', workflow)
        self.assertIn('go-version: \'1.25.5\'', workflow)
        self.assertNotIn('contents: write', workflow)
        for operation in ('gh release', 'git push', '--clobber', 'git tag', 'push:'):
            self.assertNotIn(operation, workflow)
        self.assertIn("inputs.attest && github.ref == 'refs/heads/polaris-main'", workflow)
        self.assertEqual(json.loads((REPO / 'release/polaris-candidate-inputs.json').read_bytes())['sourceCommit'],
                         'a01da7a942b3a0dbbfdfda2bba5bd63d5bd9d932')
        self.assertEqual(json.loads((REPO / 'release/polaris-dns-candidate-inputs.json').read_bytes())['sourceCommit'],
                         'aafc521b745e0d1a8f50a6a3f41169433f1c2194')


if __name__ == '__main__':
    unittest.main()
