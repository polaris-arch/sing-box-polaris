from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import github_read_transport as transport
import native_peer_metadata as metadata
import protocol_peer as peer


class NativePeerMetadataTests(unittest.TestCase):
    def context(self):
        return {'repository': metadata.REPO, 'repositoryId': metadata.RID, 'sourceCommit': 'a' * 40,
                'workflowCommit': 'a' * 40, 'runId': 123, 'runAttempt': 1, 'ref': 'refs/tags/v1.15.0-polaris-alpha.12.9',
                'sourceTree': 'c' * 40, 'version': '1.15.0-polaris-alpha.12.9',
                'tag': 'v1.15.0-polaris-alpha.12.9', 'producerRowSHA256': 'd' * 64}

    def run_document(self, context=None):
        c = context or self.context()
        return {'id': c['runId'], 'run_attempt': c['runAttempt'], 'head_sha': c['sourceCommit'],
                'run_started_at': '2026-01-01T00:00:00Z',
                'head_branch': c['ref'].split('/', 2)[2], 'event': 'workflow_dispatch', 'path': '.github/workflows/build.yml',
                'repository': {'id': metadata.RID, 'full_name': metadata.REPO},
                'head_repository': {'id': metadata.RID, 'full_name': metadata.REPO}}

    def artifact(self):
        c = self.context()
        return {'id': 31, 'name': metadata.ARTIFACT, 'digest': 'sha256:' + 'e' * 64,
                'size_in_bytes': 34607011, 'created_at': '2026-01-01T00:00:00Z',
                'expires_at': '2099-01-01T00:00:00Z', 'expired': False,
                'workflow_run': {'id': c['runId'], 'repository_id': metadata.RID, 'head_repository_id': metadata.RID,
                                 'head_sha': c['sourceCommit'], 'head_branch': c['ref'].split('/', 2)[2]}}

    def document(self):
        return {'schema': metadata.SCHEMA, 'context': self.context(), 'producerRun': self.run_document(), 'artifact': self.artifact()}

    def reader(self, responses, calls):
        def read(path, sink, limit, **kwargs):
            calls.append((path, limit, kwargs))
            response = responses.pop(0)
            if isinstance(response, Exception):
                raise response
            sink.write(json.dumps(response).encode())
            kwargs['record'](readAttempt=1, readStatus=200, readHeaders={}, readBytes=sink.tell(), readError=None, extraGETs=0)
        return read

    def test_authenticated_acquisition_and_offline_admission_keep_exact_identity(self):
        calls, records = [], []
        responses = [self.run_document(), {'total_count': 1, 'artifacts': [self.artifact()]}]
        with mock.patch.object(transport, 'read_get', side_effect=self.reader(responses, calls)):
            document = metadata.acquire(self.context(), records)
        self.assertEqual(document, self.document())
        self.assertEqual([x[0] for x in calls], [f'repos/{metadata.REPO}/actions/runs/123',
                         f'repos/{metadata.REPO}/actions/runs/123/artifacts?per_page=100&page=1'])
        for path, limit, options in calls:
            self.assertEqual(limit, 2 * 1024 * 1024)
            self.assertLessEqual(options['attempt_seconds'], 15)
            self.assertLessEqual(options['total_seconds'], 45)
            self.assertEqual(options['max_retry_wait'], 4)
            self.assertNotIn('token', options)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'admission.json'
            path.write_text(json.dumps(document))
            result = metadata.load(path, self.context())
        self.assertEqual(result['id'], 31)
        self.assertEqual([r['phase'] for r in records], ['producer_run_metadata', 'artifact_inventory'])

    def test_wrong_run_repo_attempt_source_and_native_row_bindings_reject(self):
        mutations = [('id', 124), ('run_attempt', 2), ('run_attempt', True), ('head_sha', 'b' * 40),
                     ('path', '.github/workflows/signed-release.yml'), ('event', 'push'),
                     ('head_branch', 'different'), ('repository', {'id': metadata.RID, 'full_name': 'other/repo'}),
                     ('head_repository', {'id': True, 'full_name': metadata.REPO})]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                run = self.run_document(); run[key] = value
                with self.assertRaises(ValueError): metadata.validate_run(run, self.context())
        for field in ('sourceTree', 'version', 'tag', 'producerRowSHA256', 'runAttempt', 'ref'):
            with self.subTest(context=field), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'admission.json'
                document = self.document(); document['context'][field] = 'changed'
                path.write_text(json.dumps(document))
                with self.assertRaises(ValueError): metadata.load(path, self.context())

    def test_expired_invalid_digest_missing_origin_and_wrong_artifact_are_rejected(self):
        for key, value in [('name', 'binary-linux_amd64'), ('id', True), ('size_in_bytes', 0), ('expired', True),
                           ('expired', 0), ('digest', ''), ('digest', 'sha256:' + 'a' * 63),
                           ('created_at', '2098-01-01T00:00:00Z'), ('expires_at', '2026-01-02T00:00:00Z'),
                           ('workflow_run', None)]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                metadata.validate_artifact(dict(self.artifact(), **{key: value}), self.context(), self.run_document()['run_started_at'],
                                           datetime(2026, 2, 1, tzinfo=timezone.utc))
        for key in ('id', 'repository_id', 'head_repository_id', 'head_sha', 'head_branch'):
            item = self.artifact(); item['workflow_run'][key] = 'wrong'
            with self.subTest(binding=key), self.assertRaises(ValueError):
                metadata.validate_artifact(item, self.context(), self.run_document()['run_started_at'])

    def test_current_attempt_rejects_previous_attempt_artifact_during_acquisition_and_load(self):
        # Synthetic same-run rerun fixture: run/source/ref/name remain identical.
        context = dict(self.context(), runAttempt=2)
        run = dict(self.run_document(context), run_started_at='2026-01-02T00:00:00Z')
        item = self.artifact()
        responses = [run, {'total_count': 1, 'artifacts': [item]}]
        with mock.patch.object(transport, 'read_get', side_effect=self.reader(responses, [])), \
             self.assertRaisesRegex(ValueError, 'predates current run attempt'):
            metadata.acquire(context, [])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'admission.json'
            document = dict(self.document(), context=context, producerRun=run)
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, 'predates current run attempt'):
                metadata.load(path, context)
            document['artifact']['created_at'] = run['run_started_at']
            path.write_text(json.dumps(document))
            self.assertEqual(metadata.load(path, context)['created_at'], run['run_started_at'])
        item['created_at'] = run['run_started_at']
        with mock.patch.object(transport, 'read_get', side_effect=self.reader([run, {'total_count': 1, 'artifacts': [item]}], [])):
            admitted = metadata.acquire(context, [])
        self.assertEqual(admitted['producerRun']['run_started_at'], run['run_started_at'])
        self.assertEqual(admitted['context']['runAttempt'], 2)

    def test_attempt_start_and_artifact_timestamp_shape_and_chronology_fail_closed(self):
        invalid = [None, True, 123, [], {}, '', '2026-01-01', '2026-01-01T00:00:00',
                   '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00.001Z', '2026-02-30T00:00:00Z']
        for value in invalid + ['2099-01-01T00:00:00Z']:
            with self.subTest(start=value), tempfile.TemporaryDirectory() as directory:
                run = dict(self.run_document(), run_started_at=value)
                with mock.patch.object(transport, 'read_get', side_effect=self.reader([run], [])), self.assertRaises(ValueError):
                    metadata.acquire(self.context(), [])
                path = Path(directory) / 'admission.json'
                path.write_text(json.dumps(dict(self.document(), producerRun=run)))
                with self.assertRaises(ValueError): metadata.load(path, self.context())
        for key in ('run_started_at',):
            run = self.run_document(); del run[key]
            with self.assertRaises(ValueError): metadata.validate_run(run, self.context())
        for field in ('created_at', 'expires_at'):
            for value in invalid:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    metadata.validate_artifact(dict(self.artifact(), **{field: value}), self.context(),
                                               self.run_document()['run_started_at'])

    def test_missing_duplicate_unstable_and_oversized_inventory_never_admit(self):
        for inventories in [[{'total_count': 0, 'artifacts': []}],
                            [{'total_count': 2, 'artifacts': [self.artifact(), dict(self.artifact(), id=32)]}],
                            [{'total_count': 2, 'artifacts': [self.artifact(), self.artifact()]}],
                            [{'total_count': 401, 'artifacts': []}],
                            [{'total_count': 2, 'artifacts': [self.artifact()]}]]:
            with self.subTest(inventories=inventories), mock.patch.object(transport, 'read_get', side_effect=self.reader([self.run_document()] + inventories, [])):
                with self.assertRaises(ValueError): metadata.acquire(self.context(), [])
        hundred = [dict(self.artifact(), id=i+1, name='other-' + str(i)) for i in range(100)]
        with mock.patch.object(transport, 'read_get', side_effect=self.reader([self.run_document(), {'total_count': 101, 'artifacts': hundred},
             {'total_count': 102, 'artifacts': [self.artifact()]}], [])), self.assertRaises(ValueError):
            metadata.acquire(self.context(), [])

    def test_page_and_whole_acquisition_budgets_are_finite(self):
        pages = [{'total_count': 400, 'artifacts': [dict(self.artifact(), id=page*100+i+1, name='other') for i in range(100)]}
                 for page in range(4)]
        calls = []
        with mock.patch.object(transport, 'read_get', side_effect=self.reader([self.run_document()] + pages, calls)), self.assertRaises(ValueError):
            metadata.acquire(self.context(), [])
        self.assertEqual(len(calls), 5)
        with mock.patch.object(metadata.time, 'monotonic', side_effect=[0, 121]), mock.patch.object(transport, 'read_get') as read:
            with self.assertRaises(ValueError): metadata.acquire(self.context(), [])
            read.assert_not_called()

    def test_arbitrary_or_unbound_json_and_symlink_are_not_fallback_admission(self):
        for document in [{}, {'status': 'PASS'}, dict(self.document(), fallback=True),
                         dict(self.document(), producerRun=dict(self.run_document(), extra='foreign'))]:
            with self.subTest(document=document), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'admission.json'; path.write_text(json.dumps(document))
                with self.assertRaises(ValueError): metadata.load(path, self.context())
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'target'; target.write_text(json.dumps(self.document()))
            link = Path(directory) / 'link'
            try: link.symlink_to(target)
            except OSError: self.skipTest('symlink unavailable')
            with self.assertRaises(ValueError): metadata.load(link, self.context())

    def test_api_failure_retains_safe_status_phase_context_and_all_not_run_cases(self):
        error = transport.ReadFailure('HTTP response', 403, {'x-github-request-id': 'safe'}, False)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'public'
            metadata.failure_receipt(output, self.context(), error, [{'phase': 'artifact_inventory', 'readStatus': 403}])
            receipt = json.loads((output / 'receipt.json').read_bytes())
        self.assertEqual(receipt['context'], self.context())
        self.assertEqual(receipt['transportFailure'], {'kind': 'HTTP response', 'status': 403, 'headers': {'x-github-request-id': 'safe'}})
        self.assertEqual(receipt['stage'], 'artifact_metadata_admission')
        self.assertFalse(receipt['publicationEligible']); self.assertEqual(receipt['status'], 'FAIL')
        self.assertEqual([(c['kind'], c['mutation']) for c in receipt['cases']], peer.case_matrix())
        self.assertTrue(all(c['status'] == 'NOT_RUN' for c in receipt['cases']))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'public'
            metadata.failure_receipt(output, {}, ValueError('PRIVATE_TOKEN_URL_CANARY'), [])
            self.assertNotIn('PRIVATE_TOKEN_URL_CANARY', (output / 'receipt.json').read_text())

    def test_execution_requires_admission_and_never_inherits_credentials(self):
        for name in ('GH_TOKEN', 'GITHUB_TOKEN'):
            with self.subTest(name=name), mock.patch.dict(peer.os.environ, {name: 'PRIVATE_TOKEN'}), \
                 self.assertRaisesRegex(ValueError, 'cannot inherit'):
                peer.run_suite(Path('unused'), Path('unused'))
        with self.assertRaisesRegex(ValueError, 'admission missing'):
            peer.artifact_metadata({}, None, Path('unused'))
        with mock.patch.object(metadata, 'actions_context', return_value=dict(self.context(), runAttempt=2)), self.assertRaises(ValueError):
            peer.artifact_metadata(self.context(), Path('unused'), Path('unused'))

    def test_native_row_bytes_source_version_and_profile_are_bound_before_admission(self):
        context = {key: value for key, value in self.context().items()
                   if key not in ('sourceTree', 'version', 'tag', 'producerRowSHA256')}
        row = {'sourceCommit': 'a' * 40, 'sourceTree': 'c' * 40, 'version': self.context()['version'],
               'tag': self.context()['tag'], 'target': 'linux/amd64', 'variant': {'linkage': 'shared-purego'}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / 'native-row-fixture.json'; path.write_text(json.dumps(row))
            with mock.patch.object(metadata.subprocess, 'check_output', return_value='c' * 40 + '\n'):
                bound = metadata.bind_row(root, context)
                self.assertEqual(bound['version'], row['version'])
                self.assertEqual(bound['producerRowSHA256'], metadata.hashlib.sha256(path.read_bytes()).hexdigest())
                for key, value in [('sourceCommit', 'b' * 40), ('sourceTree', 'b' * 40), ('version', 'testing'),
                                   ('tag', 'v1.15.0-polaris-alpha.12.8'), ('target', 'linux/arm64'),
                                   ('variant', {'linkage': 'static-cgo'})]:
                    path.write_text(json.dumps(dict(row, **{key: value})))
                    with self.subTest(key=key), self.assertRaises(ValueError): metadata.bind_row(root, context)

    def test_acquisition_step_requires_token_and_execution_failure_keeps_verified_context(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / 'public'
            argv = ['native_peer_metadata.py', '--native', str(root), '--output', str(root / 'admission.json'), '--failure-output', str(output)]
            with mock.patch.object(sys, 'argv', argv), mock.patch.object(metadata, 'actions_context', return_value=self.context()), \
                 mock.patch.object(metadata, 'bind_row', return_value=self.context()), mock.patch.dict(metadata.os.environ, {}, clear=True), \
                 mock.patch.object(metadata, 'acquire') as acquire, self.assertRaises(SystemExit):
                metadata.main()
            acquire.assert_not_called()
            receipt = json.loads((output / 'receipt.json').read_bytes())
            self.assertEqual(receipt['context'], self.context())
            self.assertEqual(receipt['status'], 'FAIL')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / 'public'
            argv = ['protocol_peer.py', str(root), '--admission', str(root / 'missing.json'), '--output', str(output)]
            with mock.patch.object(sys, 'argv', argv), mock.patch.object(peer, 'run_suite', side_effect=ValueError('PRIVATE_CANARY')), \
                 mock.patch.object(metadata, 'actions_context', return_value=self.context()), mock.patch.object(metadata, 'bind_row', return_value=self.context()), \
                 self.assertRaises(ValueError):
                peer.main()
            raw = (output / 'receipt.json').read_text(); receipt = json.loads(raw)
            self.assertNotIn('PRIVATE_CANARY', raw)
            self.assertEqual(receipt['context'], self.context())
            self.assertTrue(all(c['status'] == 'NOT_RUN' for c in receipt['cases']))

    def test_actions_context_rejects_other_workflow_repo_source_and_attempt(self):
        c = self.context()
        env = {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux', 'GITHUB_REPOSITORY': metadata.REPO,
               'GITHUB_REPOSITORY_ID': str(metadata.RID), 'GITHUB_EVENT_NAME': 'workflow_dispatch',
               'GITHUB_SHA': c['sourceCommit'], 'GITHUB_WORKFLOW_SHA': c['sourceCommit'],
               'GITHUB_RUN_ID': str(c['runId']), 'GITHUB_RUN_ATTEMPT': str(c['runAttempt']),
               'GITHUB_REF': c['ref'], 'GITHUB_WORKFLOW_REF': metadata.REPO + '/.github/workflows/build.yml@' + c['ref']}
        with mock.patch.object(metadata.subprocess, 'check_output', side_effect=[c['sourceCommit'] + '\n', '']):
            result = metadata.actions_context(env)
        self.assertEqual(result, {k: v for k, v in c.items() if k not in ('sourceTree', 'version', 'tag', 'producerRowSHA256')})
        for key, value in [('GITHUB_ACTIONS', 'false'), ('RUNNER_OS', 'Windows'), ('GITHUB_REPOSITORY_ID', '1'),
                           ('GITHUB_REPOSITORY', 'other/repo'), ('GITHUB_SHA', 'b' * 40), ('GITHUB_EVENT_NAME', 'push'),
                           ('GITHUB_RUN_ID', '0'), ('GITHUB_RUN_ATTEMPT', '0'), ('GITHUB_WORKFLOW_REF', 'other-workflow')]:
            with self.subTest(key=key), mock.patch.object(metadata.subprocess, 'check_output') as git, self.assertRaises(ValueError):
                metadata.actions_context(dict(env, **{key: value}))
            git.assert_not_called()


if __name__ == '__main__':
    unittest.main()
