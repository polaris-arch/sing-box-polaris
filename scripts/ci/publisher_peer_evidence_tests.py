"""Offline exact QA admission tests. Synthetic fixtures never claim runtime success."""
import copy
import io
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

import github_release as p
import publisher_peer_evidence as e


class PeerEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.s, _ = e.load(p.ROOT)
        self.publisher = 'f' * 40
        self.env = mock.patch.dict(os.environ, GITHUB_SHA=self.publisher)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.make_fixture()

    @staticmethod
    def raw(value):
        return (json.dumps(value, indent=2) + '\n').encode()

    @staticmethod
    def zipped(files):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as z:
            for name, data in files.items():
                z.writestr(name, data)
        return stream.getvalue()

    def make_fixture(self):
        import test_github_release as old
        s = self.s
        index = old.GateTests().final_index()
        index.update(sourceCommit=e.SOURCE, sourceTree=s['sourceTree'], tagObject=s['tagObject'])
        index['producer'].update(workflowCommit=e.SOURCE, runId=s['runId'])
        self.carriers = {}
        for row in index['platforms']:
            row.update(sourceCommit=e.SOURCE, sourceTree=s['sourceTree'])
            row['archive'].update(bytes=1, sha256=e.digest(b'x'))
            self.carriers[row['archive']['name']] = b'x'
        linux = next(row for row in index['platforms'] if row['id'] == s['archive']['root'])
        linux.update(sidecar=s['identity']['sidecar'], finalPackageCronetSmoke={'status': 'passed', 'os': 'linux', 'arch': 'amd64', 'go': 'go1.27.2', 'gvisorCompiled': True, 'naiveOutbound': True, 'linkage': 'shared-purego', 'version': '154.0.8037.49', 'librarySha256': s['identity']['sidecar']['sha256'], 'coreSha256': linux['core']['sha256']}, tags='with_naive_outbound,with_quic,with_gvisor')
        original_row = copy.deepcopy(linux)
        original_row['archive'].pop('releaseName')
        self.row_raw = self.raw(original_row)
        s['archive'] = original_row['archive']
        s['identity'].update(coreSHA256=linux['core']['sha256'], nativeRowSHA256=e.digest(json.dumps(original_row, sort_keys=True).encode()), profile=linux['variant'])
        s['smokeRow'].update(bytes=len(self.row_raw), sha256=e.digest(self.row_raw))
        index['sourceArchive'].update(name='sing-box-polaris-source-' + e.SOURCE + '.tar.gz', bytes=1, sha256=e.digest(b's'))
        from native_release_index import distribution_materials
        index['distributionMaterials'] = distribution_materials(index, p.ROOT)
        self.index = index
        self.index_raw = self.raw(index)
        s['nativeIndexSHA256'] = e.digest(self.index_raw)
        self.r = {'schema': 'polaris-native-controlled-peer-v1', 'context': {
            'sourceCommit': e.SOURCE, 'sourceTree': s['sourceTree'], 'runId': s['runId'], 'runAttempt': 1, 'workflowCommit': e.SOURCE},
            'status': 'PASS', 'publicationEligible': False, 'identity': copy.deepcopy(s['identity']),
            'archive': copy.deepcopy(s['archive']), 'producerRowSHA256': s['smokeRow']['sha256'],
            'privateWorkspaceDeleted': True, 'privateOriginalConfigurationArchived': False,
            'descendantRetirement': {'remaining': [], 'forcedKill': False, 'retired': []}, 'cases': []}
        pid = 100
        for kind, mutation in e.CASES:
            c = {'kind': kind, 'mutation': mutation, 'status': 'PASS', 'continuationSafe': True, 'identityUncertain': False,
                 'fixturesJoined': True, 'rawConfigurationPubliclyRetained': False, 'privateFilesDeletedAtSuiteEnd': True,
                 'descendantRetirement': {'remaining': [], 'forcedKill': False, 'retired': []},
                 'portsReleased': [{'released': True}], 'cleanup': []}
            for _ in range(3):
                pid += 1
                c['cleanup'].append({'pid': pid, 'startIdentity': {'pid': pid, 'startTicks': pid},
                    'exitCode': 0, 'forcedKill': False, 'gracefulCleanupProven': True, 'exitBeforeTerminate': None,
                    'closeOperationFailure': None, 'resourceCloseErrors': [], 'remainingGroup': [], 'cleanupErrorLog': False,
                    'boundCoreSHA256': s['identity']['coreSHA256'], 'terminationActions': [{'signal': 'SIGTERM', 'pidfdBound': True,
                    'pid': pid, 'startTicks': pid, 'coreSHA256': s['identity']['coreSHA256']}]})
            self.r['cases'].append(c)
        self.downloads, self.runs, self.artifacts, self.scope = {}, {}, {}, {}
        for role, rid in [('all', str(s['runId'])), ('linux', '43'), ('docker', '44')]:
            workflow = s['workflow'] if role == 'all' else '.github/workflows/' + role + '.yml'
            self.runs[rid] = {'repository': {'id': p.RID}, 'head_repository': {'id': p.RID}, 'head_sha': e.SOURCE,
                'path': workflow, 'status': 'completed', 'conclusion': 'success', 'event': 'workflow_dispatch',
                'run_attempt': 1, 'run_started_at': '2026-10-25T05:00:00Z'}
            receipt = {'repository': p.REPO, 'repositoryId': p.RID, 'sourceCommit': e.SOURCE, 'runId': rid,
                'attempt': 1, 'version': p.VERSION, 'build': 'All', 'role': role, 'publishStores': False, 'publishRegistry': False}
            files = {'publisher-run-receipt': {'publisher-run-receipt.json': self.raw(receipt)}}
            if role == 'all':
                files.update({'binary-native-index': {'polaris-upstream-native-assets.json': self.index_raw, index['sourceArchive']['name']: b's'},
                    'binary-linux_amd64-purego': {s['archive']['name']: b'x'},
                    'binary-synthetic-remaining': {k: v for k, v in self.carriers.items() if k != s['archive']['name']},
                    s['smokeRow']['artifact']: {s['smokeRow']['path']: self.row_raw}})
                for flavor in ('other', 'other-legacy'):
                    files['binary-android-apks-' + flavor] = {'SFA-' + p.VERSION + '-version-metadata.json': b'{}'}
            self.scope[role] = {'workflow': workflow, 'requiredArtifacts': list(files), 'payloadRules': {
                name: [{'pattern': re.escape(n), 'count': 1} for n in rows if not n.startswith('native-row-')]
                for name, rows in files.items()}}
            self.artifacts[rid] = []
            for name, content in files.items():
                a = self.add_artifact(rid, name, content)
                if name == 'binary-linux_amd64-purego':
                    s['carrierArtifact'] = {k: a[k] for k in ('id', 'name', 'size_in_bytes', 'digest')}
        self.r['artifact'] = copy.deepcopy(s['carrierArtifact'])
        self.receipt_raw = self.raw(self.r)
        s['member'].update(bytes=len(self.receipt_raw), sha256=e.digest(self.receipt_raw))
        a = self.add_artifact(str(s['runId']), s['artifact']['name'], {'receipt.json': self.receipt_raw})
        s['artifact'] = {k: a[k] for k in ('id', 'name', 'size_in_bytes', 'digest')}
        (self.root / e.PATH).parent.mkdir(parents=True)
        self.save()

    def add_artifact(self, rid, name, files):
        data = self.zipped(files)
        ident = 500 + len(self.downloads)
        self.downloads[ident] = data
        a = {'id': ident, 'name': name, 'size_in_bytes': len(data), 'digest': 'sha256:' + e.digest(data), 'expired': False,
             'created_at': '2026-10-25T05:10:00Z', 'workflow_run': {'id': int(rid), 'head_sha': e.SOURCE,
             'repository_id': p.RID, 'head_repository_id': p.RID}}
        self.artifacts[rid].append(a)
        return a

    def save(self):
        (self.root / e.PATH).write_bytes(self.raw(self.s))
        self.policy = e.select(self.root, e.SOURCE, e.VERSION, 'v' + e.VERSION, self.s['sourceTree'], self.s['tagObject'])

    def measured(self):
        return {'bytes': self.s['member']['bytes'], 'sha256': self.s['member']['sha256']}

    def test_exact_selection_current_identity_and_no_wrong_run_fallback(self):
        self.assertIsNone(e.select(self.root, 'a' * 40, 'old', 'vold'))
        for source, version, tag in [('a' * 40, e.VERSION, 'v' + e.VERSION), (e.SOURCE, 'old', 'vold')]:
            with self.subTest(source=source), self.assertRaises(ValueError): e.select(self.root, source, version, tag)
        for run in ('other', str(self.s['runId'] + 1), None):
            with self.subTest(run=run), self.assertRaises(ValueError): e.scoped(self.scope, self.policy, {'all': run})
        scoped = e.scoped(self.scope, self.policy, {'all': str(self.s['runId'])})
        self.assertEqual(set(scoped['all']['requiredArtifacts']) - set(self.scope['all']['requiredArtifacts']), {self.s['artifact']['name']})
        self.assertNotIn(self.s['artifact']['name'], self.scope['all']['payloadRules'])

    def test_strict_json_and_selection_types(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"value":1e999}', b'{"value":-1e999}', b'[]x', b' ' * (e.JSON_LIMIT + 1)):
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError): e.strict_json(raw)
        for key, value in [('repositoryId', True), ('runAttempt', True), ('publicationEligible', True), ('extra', 'secret')]:
            changed = copy.deepcopy(self.s); changed[key] = value
            (self.root / e.PATH).write_bytes(self.raw(changed))
            with self.subTest(key=key), self.assertRaises(ValueError): e.load(self.root)

    def test_artifact_identity_and_members(self):
        a = self.artifacts[str(self.s['runId'])][-1]
        run = self.runs[str(self.s['runId'])]
        e.check_api(self.policy, 'all', run, a)
        for key, value in [('id', 1), ('name', a['name'] + '-extra'), ('digest', 'sha256:' + '0' * 64), ('size_in_bytes', 1), ('expired', True)]:
            with self.subTest(key=key), self.assertRaises(ValueError): e.check_api(self.policy, 'all', run, dict(a, **{key: value}))
        for altered in (dict(run, run_attempt=2), dict(run, run_attempt=True)):
            with self.assertRaises(ValueError): e.check_api(self.policy, 'all', altered, a)
        for role in ('linux', 'docker', 'signed'):
            with self.assertRaises(ValueError): e.check_api(self.policy, role, run, a)
        for names in (['receipt.json', 'extra'], ['folder/', 'receipt.json'], ['./receipt.json'], []):
            z = [zipfile.ZipInfo(name) for name in names]
            for item in z: item.file_size = self.s['member']['bytes']
            with self.subTest(names=names), self.assertRaises(ValueError): e.members(self.policy, z)

    def test_receipt_status_identity_cleanup_and_native_negatives(self):
        self.assertEqual(e.validate_receipt(self.policy, self.measured(), self.r), e.summary(self.policy))
        mutations = [lambda r: r.update(publicationEligible=True), lambda r: r.update(status='FAIL'),
            lambda r: r.update(diagnosticOnly=True), lambda r: r['context'].update(runAttempt=True),
            lambda r: r['context'].update(workflowCommit='a' * 40), lambda r: r['identity'].update(coreSHA256='0' * 64),
            lambda r: r['identity']['sidecar'].update(sha256='0' * 64), lambda r: r['identity']['profile'].update(linkage='static-cgo'),
            lambda r: r['artifact'].update(id=0), lambda r: r['archive'].update(bytes=2),
            lambda r: r['cases'].pop(), lambda r: r['cases'].append(copy.deepcopy(r['cases'][0])),
            lambda r: r['cases'][0].update(status='NOT_RUN'), lambda r: r['cases'][0].update(identityUncertain=True),
            lambda r: r['cases'][0].update(continuationSafe=False), lambda r: r.update(privateWorkspaceDeleted=False),
            lambda r: r['cases'][0]['cleanup'][0].update(forcedKill=True),
            lambda r: r['cases'][0]['cleanup'][0].update(exitCode=True),
            lambda r: r['cases'][0]['cleanup'][0].update(gracefulCleanupProven=False),
            lambda r: r['cases'][0]['cleanup'][0]['terminationActions'].clear(),
            lambda r: r['cases'][0]['portsReleased'][0].update(released=False)]
        for i, mutation in enumerate(mutations):
            r = copy.deepcopy(self.r); mutation(r)
            with self.subTest(mutation=i), self.assertRaises(ValueError): e.validate_receipt(self.policy, self.measured(), r)
        with self.assertRaises(ValueError): e.validate_receipt(self.policy, dict(self.measured(), sha256='0' * 64), self.r)

    def inventory(self):
        # Stub transport and synthetic package scope; Docker run 44 intentionally
        # has no real OCI images. Current OCI admission is exercised separately
        # by CurrentOCISelectionTests, never disabled in production. Exercise
        # actual bounded ZIP, JSON, receipt, final-index and peer cross-binding.
        def transport(path, destination, maximum, **_):
            data = self.downloads[int(path.split('/')[-2])]
            self.assertLessEqual(len(data), maximum)
            destination.write(data)
            return {'bytes': len(data), 'sha256': e.digest(data)}
        real_load = e.load
        with mock.patch.object(e, 'load', side_effect=lambda _: real_load(self.root)), \
             mock.patch.object(p, 'release_scope', return_value=self.scope), \
             mock.patch('oci_material_registry.supports_source', return_value=False), \
             mock.patch.object(p, 'api', side_effect=lambda path: self.runs[path.split('/')[-1]]), \
             mock.patch.object(p, 'pages', side_effect=lambda path, key: self.artifacts[path.split('/')[-2]]), \
             mock.patch.object(p, 'read_get', side_effect=transport), mock.patch.object(p, 'client_platform', return_value=None):
            return p.inventory({'all': str(self.s['runId']), 'linux': '43', 'docker': '44'}, e.SOURCE,
                self.root / 'work', self.s['sourceTree'], self.s['tagObject'], budget=p.ScratchBudget(self.root / 'work', reserve=0))

    def test_full_inventory_assemble_stream_excludes_peer(self):
        actual = self.inventory()
        self.assertEqual(actual['controlledPeerEvidence'], e.record(self.policy, self.publisher))
        reviewed = copy.deepcopy(actual); reviewed['reviewed'] = True
        real_load = e.load
        with mock.patch.object(e, 'load', side_effect=lambda _: real_load(self.root)):
            receipt = p.assemble(actual, reviewed, self.root / 'work', self.root / 'dist', self.root / 'audit', materialize=False)
            self.assertEqual(len(receipt['assets']), 45)
            self.assertNotIn('receipt.json', [f['releaseName'] for f in receipt['assets']])
            self.assertFalse((self.root / 'dist' / 'receipt.json').exists())
            peer_only = copy.deepcopy(actual)
            peer_only['runs']['all']['artifacts'] = {self.s['artifact']['name']: actual['runs']['all']['artifacts'][self.s['artifact']['name']]}
            peer_only['runs'] = {'all': peer_only['runs']['all']}
            with mock.patch.object(p, 'api', side_effect=AssertionError('nonpublic download')), \
                 mock.patch.object(p, 'artifact_archive', side_effect=AssertionError('nonpublic download')):
                self.assertEqual(list(p.public_asset_stream(peer_only, p.ScratchBudget(self.root / 'stream', reserve=0))), [])

    def test_cross_binding_and_publication_tampering_rejected(self):
        actual = self.inventory()
        real_load = e.load
        name = self.s['artifact']['name']
        for field, value in [('releaseName', 'leaked.json'), ('publicationDisposition', 'upstream-public-product'), ('controlledPeerEvidence', {})]:
            altered = copy.deepcopy(actual); altered['runs']['all']['artifacts'][name]['files']['receipt.json'][field] = value
            with self.subTest(field=field), mock.patch.object(e, 'load', side_effect=lambda _: real_load(self.root)), self.assertRaises(ValueError):
                list(p.public_asset_stream(altered, p.ScratchBudget(self.root / ('stream-' + field), reserve=0)))
            reviewed = copy.deepcopy(altered); reviewed['reviewed'] = True
            with mock.patch.object(e, 'load', side_effect=lambda _: real_load(self.root)), self.assertRaises(ValueError):
                p.assemble(actual, reviewed, self.root / 'work', self.root / ('bad-' + field), materialize=False)
        for field in ('nativeIndexSHA256', 'sourceTree'):
            altered = copy.deepcopy(actual); altered['controlledPeerEvidence']['evidence'][field] = '0' * 64
            with mock.patch.object(e, 'load', side_effect=lambda _: real_load(self.root)), self.assertRaises(ValueError):
                e.check_inventory(p.ROOT, altered, self.publisher)
        for kind in ('core', 'sidecar', 'variant', 'archive', 'extra'):
            index = copy.deepcopy(self.index); row = next(r for r in index['platforms'] if r['id'] == self.s['archive']['root'])
            if kind == 'extra': row['unexpected'] = True
            else: row[kind] = {}
            with self.subTest(kind=kind), self.assertRaises((ValueError, KeyError)):
                e.cross_bind(self.policy, index, self.s['nativeIndexSHA256'], actual['runs']['all'])

    def test_missing_extra_duplicate_artifact_fails_before_download(self):
        rows = self.artifacts[str(self.s['runId'])]
        original = copy.deepcopy(rows)
        for mode in ('missing', 'extra', 'duplicate-id'):
            rows[:] = copy.deepcopy(original)
            if mode == 'missing': rows.pop()
            elif mode == 'extra': rows.append(dict(rows[-1], name=rows[-1]['name'] + '-extra', id=900))
            else: rows[-1]['id'] = rows[0]['id']
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.inventory()

    def test_oci_ordinary_strict_gate_unchanged(self):
        import oci_material_registry
        self.assertTrue(oci_material_registry.supports_source(e.SOURCE))
        with mock.patch.object(p, 'validate_oci_material_reuse', side_effect=ValueError('actual OCI material drift')) as gate:
            with self.assertRaisesRegex(ValueError, 'actual OCI material drift'):
                p.measure_oci_materials(Path('not-executed'), 'oci-linux-loong64', e.SOURCE, '40164108947', 1)
            gate.assert_called_once_with(Path('not-executed'), 'oci-linux-loong64', e.SOURCE, '40164108947', 1)

    def test_origin_repository_and_attempt_fields_fail_closed(self):
        original = self.artifacts[str(self.s['runId'])][-1]
        run = self.runs[str(self.s['runId'])]
        for key, value in [('id', 42), ('head_sha', 'a' * 40), ('repository_id', 1), ('head_repository_id', 1)]:
            a = copy.deepcopy(original); a['workflow_run'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): e.check_api(self.policy, 'all', run, a)
        for tree, tag_object in [('a' * 40, self.s['tagObject']), (self.s['sourceTree'], 'b' * 40)]:
            with self.assertRaises(ValueError): e.select(self.root, e.SOURCE, e.VERSION, 'v' + e.VERSION, tree, tag_object)

    def test_exact_name_never_grants_prefix_or_foreign_role_mapping(self):
        name = self.s['artifact']['name']
        real_load = e.load
        with mock.patch.object(e, 'load', side_effect=lambda _: real_load(self.root)):
            self.assertEqual(p.publication('all', name, 'receipt.json', e.SOURCE), (None, e.DISPOSITION))
            for role, artifact, path, source in [('all', name + '-extra', 'receipt.json', e.SOURCE),
                ('linux', name, 'receipt.json', e.SOURCE), ('all', name, 'other.json', e.SOURCE),
                ('all', name, 'receipt.json', 'a' * 40)]:
                with self.subTest(role=role, artifact=artifact), self.assertRaises(ValueError):
                    p.publication(role, artifact, path, source)

    def test_zip_symlink_traversal_crc_and_duplicate_json_are_rejected(self):
        for name, mode in [('receipt.json', stat.S_IFLNK | 0o777), ('../receipt.json', stat.S_IFREG | 0o600)]:
            target = self.root / 'unsafe.zip'
            with zipfile.ZipFile(target, 'w') as z:
                info = zipfile.ZipInfo(name); info.external_attr = mode << 16
                z.writestr(info, b'private')
            with zipfile.ZipFile(target) as z, self.assertRaises(ValueError): p.safe_zip_members(z)
        target = self.root / 'json.zip'
        with zipfile.ZipFile(target, 'w') as z: z.writestr('receipt.json', b'{"x":1,"x":2}')
        with zipfile.ZipFile(target) as z, self.assertRaises(ValueError):
            p.measure_member(z, z.infolist()[0], json_limit=e.JSON_LIMIT, json_decoder=e.strict_json)
        raw = bytearray(target.read_bytes()); position = raw.index(b'{"x":1'); raw[position] ^= 1; target.write_bytes(raw)
        with zipfile.ZipFile(target) as z, self.assertRaises((ValueError, zipfile.BadZipFile)):
            p.measure_member(z, z.infolist()[0], json_limit=e.JSON_LIMIT, json_decoder=e.strict_json)

    def test_selection_regular_and_size_bounds(self):
        path = self.root / e.PATH
        path.unlink(); path.symlink_to(self.root / 'elsewhere')
        with self.assertRaises(ValueError): e.load(self.root)
        path.unlink(); path.write_bytes(b' ' * (e.JSON_LIMIT + 1))
        with self.assertRaises(ValueError): e.load(self.root)

    def test_inventory_record_and_smoke_carrier_changes_rejected(self):
        actual = self.inventory()
        for key in ('controlledPeerEvidence', 'sourceCommit', 'tagObject'):
            altered = copy.deepcopy(actual)
            if key == 'controlledPeerEvidence': altered.pop(key)
            else: altered[key] = 'a' * 40
            with self.subTest(key=key), self.assertRaises(ValueError): e.check_inventory(self.root, altered, self.publisher)
        entry = actual['runs']['all']
        for target, key, value in [(self.s['carrierArtifact']['name'], 'id', 0),
                (self.s['carrierArtifact']['name'], 'archiveSha256', 'sha256:' + '0' * 64)]:
            changed = copy.deepcopy(entry); changed['artifacts'][target][key] = value
            with self.assertRaises(ValueError): e.cross_bind(self.policy, self.index, self.s['nativeIndexSHA256'], changed)
        changed = copy.deepcopy(entry)
        changed['artifacts'][self.s['smokeRow']['artifact']]['files'][self.s['smokeRow']['path']]['sha256'] = '0' * 64
        with self.assertRaises(ValueError): e.cross_bind(self.policy, self.index, self.s['nativeIndexSHA256'], changed)

    def test_exact_set_rejects_missing_and_duplicate_names(self):
        scoped = e.scoped(self.scope, self.policy, {'all': str(self.s['runId'])})
        names = scoped['all']['requiredArtifacts']
        p.verify_artifact_names(names, names, 'all')
        for actual in [names[:-1], names + [names[-1]], names + [names[-1] + '-other']]:
            with self.assertRaises(ValueError): p.verify_artifact_names(actual, names, 'all')

    def test_current_identity_cannot_drop_selection_as_historical(self):
        for record in [dict(sourceCommit='a' * 40, version=e.VERSION, tag='v' + e.VERSION),
                       dict(sourceCommit='a' * 40, version='old', tag='v' + e.VERSION)]:
            record.update(sourceTree=self.s['sourceTree'], tagObject=self.s['tagObject'])
            with self.assertRaises(ValueError): e.check_inventory(self.root, record, self.publisher)


if __name__ == '__main__':
    unittest.main()
