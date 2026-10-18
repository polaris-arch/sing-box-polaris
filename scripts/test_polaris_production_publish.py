import copy
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import polaris_production_publish as publish
import polaris_production_release as production

REPO = Path(__file__).resolve().parents[1]
HEAD = 'a' * 40
TREE = 'b' * 40


class ProductionPublicationTests(unittest.TestCase):
    def inputs(self, base):
        config = production.plan(REPO)
        inputs = base / 'inputs'
        inputs.mkdir()
        platforms = []
        for row in config['desktop']:
            p = inputs / (production.basename(config, row['target']) + row['suffix'])
            p.write_bytes(b'inert-native-input-' + row['target'].encode())
            platforms.append({'target': row['target'], 'archive': publish.file_info(p)})
        openwrt=[]
        for arch in ['x86_64','aarch64_generic']:
            packages=[]
            for form in ['apk','ipk']:
                path=inputs/('polaris-box-'+config['version']+'-openwrt-'+arch+'.'+form)
                path.write_bytes(b'inert-package-'+arch.encode()+form.encode())
                packages.append({'format':form,'package':publish.file_info(path)})
            openwrt.append({'architecture':arch,'packages':packages})
        index = {'schema': 'polaris-production-assets-v1', 'repository': publish.REPOSITORY,
                 'version': config['version'], 'tag': config['tag'], 'tagObject': None,
                 'sourceCommit': HEAD, 'sourceTree': TREE, 'workflowRun': '20', 'workflowAttempt': '1',
                 'platforms': platforms, 'openwrtPlatforms':openwrt,
                 'sourceDelivery':{'method':'fixed-public-source-references','sourceAvailability':{'fixture':True}},
                 'gates': {'actualPublicDownloadConsumerAcceptance': 'pending'}}
        (inputs / 'polaris-box-assets.json').write_bytes(publish.encode(index))
        index_sha = publish.file_info(inputs / 'polaris-box-assets.json')['sha256']
        names = sorted(p.name for p in inputs.iterdir())
        (inputs / 'SHA256SUMS').write_text(''.join(publish.file_info(inputs / n)['sha256'] + '  ' + n + '\n' for n in names))
        approvals = base / 'raw-review.txt'
        approvals.write_text('Inert fixture only; never a real approval. Reviewed source '+HEAD+' and actual index '+index_sha+'.')
        return config, inputs, index_sha, approvals

    def prepare(self, base):
        config, inputs, index_sha, approvals = self.inputs(base)
        out = base / 'out'
        with patch.object(publish, 'frozen_source', return_value=(config, TREE)), \
             patch.object(publish, 'api', side_effect=AssertionError('no network during preparation')), \
             patch.object(publish, 'command', side_effect=AssertionError('no tag/Git writes during preparation')):
            result = publish.prepare(REPO, HEAD, inputs, index_sha, approvals, publish.sha(approvals.read_bytes()),
                                     out, '1791720000', 'Fixture reviewer', 'reviewer@example.invalid')
        manifest = out / 'publication-manifest.json'
        m = publish.validate_manifest(manifest, result['manifest']['sha256'], HEAD)
        return manifest, m

    def release(self, m, subset=None, draft=True):
        assets = m['assets'] if subset is None else subset
        return {'id': 19, 'tag_name': m['tag'], 'name': m['title'], 'body': m['notes'], 'prerelease': True,
                'draft': draft, 'assets': [{'name': a['name'], 'size': a['bytes'], 'digest': 'sha256:' + a['sha256'],
                                          'id': 100 + m['assets'].index(a),
                                          'browser_download_url': 'https://github.com/' + publish.REPOSITORY + '/releases/download/' + m['tag'] + '/' + a['name']}
                                          for a in assets]}

    def test_prepare_is_local_requires_actual_approvals_and_freezes_tag_object_and_twelve_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, m = self.prepare(Path(directory))
            self.assertEqual(len(m['assets']), 12)
            index = json.loads((manifest.parent / 'polaris-box-assets.json').read_bytes())
            self.assertEqual(index['tagObject'], m['tagObject'])
            self.assertEqual(index['gates']['actualPublicDownloadConsumerAcceptance'], 'pending')
            self.assertEqual(index['gates']['AppOwnerSignoff']['status'],'pending')
            self.assertNotIn('App owner acceptance',index['gates']['independentSourceReview']['status'])
            self.assertFalse(m['tagCreated'])
            self.assertFalse(m['publicUploadPerformed'])
            self.assertFalse(m['mobileAcceptance'])
            with self.assertRaisesRegex(ValueError, 'manifest hash'):
                publish.validate_manifest(manifest, '0' * 64, HEAD)
            asset = manifest.parent / m['assets'][0]['name']
            asset.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'local asset differs'):
                publish.validate_manifest(manifest, publish.sha(manifest.read_bytes()), HEAD)

    def test_same_length_archive_replacement_after_initial_check_is_rejected_before_manifest(self):
        # Exercise both native and corresponding-source inputs. A self-consistent
        # newly hashed output must never replace the reviewer-approved bytes.
        for replace_source in (False, True):
            with self.subTest(source=replace_source), tempfile.TemporaryDirectory() as directory:
                base = Path(directory);config, inputs, index_sha, approvals = self.inputs(base)
                initial = json.loads((inputs / 'polaris-box-assets.json').read_bytes())
                record = initial['openwrtPlatforms'][0]['packages'][0]['package'] if replace_source else initial['platforms'][0]['archive']
                changed = inputs / record['name'];original_copy = publish.shutil.copyfile
                mutated = False
                def copy_after_checked(src, dst):
                    nonlocal mutated
                    if Path(src) == changed:
                        data = changed.read_bytes()
                        changed.write_bytes(bytes([data[0] ^ 1]) + data[1:])
                        self.assertEqual(changed.stat().st_size, record['bytes'])
                        self.assertNotEqual(publish.file_info(changed)['sha256'], record['sha256'])
                        mutated = True
                    return original_copy(src, dst)
                with patch.object(publish, 'frozen_source', return_value=(config, TREE)), \
                     patch.object(publish.shutil, 'copyfile', side_effect=copy_after_checked), \
                     patch.object(publish, 'api', side_effect=AssertionError('local preparation only')), \
                     patch.object(publish, 'command', side_effect=AssertionError('no remote/tag writes')), \
                     self.assertRaisesRegex(ValueError, 'copied archive differs from reviewed input'):
                    publish.prepare(REPO, HEAD, inputs, index_sha, approvals, publish.sha(approvals.read_bytes()),
                                    base / 'out', '1791720000', 'Fixture', 'fixture@example.invalid')
                self.assertTrue(mutated)
                self.assertFalse((base / 'out' / 'publication-manifest.json').exists())
                self.assertFalse((base / 'out' / 'polaris-box-assets.json').exists())
                self.assertFalse((base / 'out' / 'SHA256SUMS').exists())

    def test_manifest_hash_and_parser_use_one_snapshot_despite_read_window_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, reviewed = self.prepare(Path(directory))
            frozen_raw = manifest.read_bytes();raw_read = Path.read_bytes;reads = []
            unreviewed = copy.deepcopy(reviewed);unreviewed['title'] = 'unapproved replacement title'
            def replace_after_read(path):
                raw = raw_read(path)
                if path == manifest:
                    reads.append(raw)
                    manifest.write_bytes(publish.encode(unreviewed))
                return raw
            with patch.object(Path, 'read_bytes', replace_after_read):
                actual = publish.validate_manifest(manifest, publish.sha(frozen_raw), HEAD)
            self.assertEqual(reads, [frozen_raw])
            self.assertEqual(actual, reviewed)
            self.assertNotEqual(actual['title'], unreviewed['title'])
            # The now-replaced file is rejected on the next independently invoked check.
            with self.assertRaisesRegex(ValueError, 'manifest hash'):
                publish.validate_manifest(manifest, publish.sha(frozen_raw), HEAD)

    def test_missing_review_or_new_index_blocks_before_any_output(self):
        for text in ['unbound review', HEAD+' mobile', '0'*40+' actual index']:
            with tempfile.TemporaryDirectory() as directory:
                base=Path(directory);config,inputs,index_sha,approvals=self.inputs(base)
                approvals.write_text(text)
                with patch.object(publish,'frozen_source',return_value=(config,TREE)), self.assertRaises(ValueError):
                    publish.prepare(REPO,HEAD,inputs,index_sha,approvals,publish.sha(approvals.read_bytes()),
                        base/'out','1791720000','Fixture','fixture@example.invalid')
                self.assertFalse((base/'out').exists())

    def test_tag_annotation_changes_for_source_version_or_tagger_epoch_and_rejects_injection(self):
        data = publish.annotation(HEAD, 'v1.2.3', '1791720000', 'Fixture', 'fixture@example.invalid')
        for changed in [publish.annotation('c' * 40, 'v1.2.3', '1791720000', 'Fixture', 'fixture@example.invalid'),
                        publish.annotation(HEAD, 'v1.2.4', '1791720000', 'Fixture', 'fixture@example.invalid'),
                        publish.annotation(HEAD, 'v1.2.3', '1791720001', 'Fixture', 'fixture@example.invalid')]:
            self.assertNotEqual(publish.tag_sha(changed), publish.tag_sha(data))
        with self.assertRaises(ValueError):
            publish.annotation(HEAD, 'v1.2.3', '1791720000', 'Bad\nname', 'fixture@example.invalid')

    def test_remote_assets_partial_resume_never_overwrites_and_rejects_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            _, m = self.prepare(Path(directory))
            release = self.release(m, m['assets'][:3])
            self.assertEqual(len(publish.validate_release(release, m, False, 19)), 9)
            with self.assertRaises(ValueError): publish.validate_release(release, m, True, 19)
            for change in [lambda r: r.update(id=20), lambda r: r.update(body='different'),
                           lambda r: r['assets'][0].update(digest='sha256:' + '0' * 64),
                           lambda r: r['assets'][0].update(id=0),
                           lambda r: r['assets'][0].update(browser_download_url='https://example.invalid/asset'),
                           lambda r: r['assets'].append(dict(r['assets'][0]))]:
                bad = copy.deepcopy(release);change(bad)
                with self.assertRaises(ValueError):publish.validate_release(bad, m, False, 19)

    def test_existing_wrong_tag_rejects_and_exact_tag_reads_only(self):
        with tempfile.TemporaryDirectory() as directory:
            _, m = self.prepare(Path(directory));tag = 'refs/tags/' + m['tag']
            good = m['tagObject'] + '\t' + tag + '\n' + HEAD + '\t' + tag + '^{}\n'
            with patch.object(publish, 'command', return_value=good):self.assertTrue(publish.remote_tag(REPO, m))
            with patch.object(publish, 'command', return_value=good.replace(HEAD, 'c' * 40)), self.assertRaises(ValueError):
                publish.remote_tag(REPO, m)

    def test_resume_uploads_only_missing_bytes_from_snapshot_and_does_not_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory);manifest, m = self.prepare(base);config = production.plan(REPO)
            args = SimpleNamespace(repo=REPO, expected_head=HEAD, manifest=manifest,
                manifest_sha256=publish.sha(manifest.read_bytes()), action='resume-draft', release_id=19)
            uploads = []
            calls = 0
            def fake_api(endpoint, payload=None):
                nonlocal calls
                self.assertIsNone(payload)
                if endpoint == 'repos/' + publish.REPOSITORY:return {'id': publish.REPOSITORY_ID}
                calls += 1
                if calls == 1:
                    # Source files can drift after snapshot without changing staged bytes.
                    (manifest.parent / m['assets'][-1]['name']).write_bytes(b'drift-after-freeze')
                    return self.release(m, m['assets'][:3])
                return self.release(m)
            def command(*args, **unused):
                self.assertEqual(args[:3], ('gh', 'release', 'upload'))
                path = Path(args[4]);uploads.append(path.name)
                self.assertIn(publish.file_info(path), m['assets'])
                self.assertNotIn('--clobber', args)
                return ''
            with patch.object(publish, 'frozen_source', return_value=(config, TREE)), \
                 patch.object(publish, 'remote_tag', return_value=True), patch.object(publish, 'api', side_effect=fake_api), \
                 patch.object(publish, 'command', side_effect=command), \
                 patch.object(publish, 'public_readback', side_effect=AssertionError('draft is not public')):
                result = publish.execute(args)
            self.assertEqual(len(uploads), 9)
            self.assertEqual(result['phase'], 'draft-staged')
            self.assertFalse(result['public'])

    def test_stage_creates_only_new_exact_tag_and_draft_then_reads_back_twelve_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); manifest, m = self.prepare(base);config = production.plan(REPO)
            args = SimpleNamespace(repo=REPO, expected_head=HEAD, manifest=manifest,
                manifest_sha256=publish.sha(manifest.read_bytes()), action='stage-draft', release_id=None)
            commands, uploads = [], []
            def fake_api(endpoint, payload=None):
                if endpoint == 'repos/' + publish.REPOSITORY:return {'id': publish.REPOSITORY_ID}
                if '?per_page=' in endpoint:return []
                if payload is not None:
                    self.assertTrue(payload['draft']);self.assertTrue(payload['prerelease'])
                    self.assertEqual(payload['make_latest'], 'false')
                    return self.release(m, [])
                return self.release(m)
            def command(*args, data=None):
                commands.append(args)
                if 'get-url' in args:return 'https://github.com/' + publish.REPOSITORY + '.git'
                if 'mktag' in args:
                    self.assertEqual(publish.tag_sha(data), m['tagObject']);return m['tagObject']
                if 'update-ref' in args:
                    self.assertEqual(args[-1], '0' * 40);return ''
                if args[:3] == ('gh', 'release', 'upload'):
                    uploads.append(publish.file_info(Path(args[4])));return ''
                if 'push' in args:
                    self.assertNotIn('--force', args);return ''
                raise AssertionError(args)
            with patch.object(publish, 'frozen_source', return_value=(config, TREE)), \
                 patch.object(publish, 'remote_tag', side_effect=[False, True]), \
                 patch.object(publish, 'api', side_effect=fake_api), patch.object(publish, 'command', side_effect=command):
                result = publish.execute(args)
            self.assertEqual(sorted(uploads, key=lambda x: x['name']), m['assets'])
            self.assertEqual(result['phase'], 'draft-staged')
            self.assertFalse(result['public'])
            self.assertTrue(any('mktag' in c for c in commands))
            self.assertFalse(any('PATCH' in c for c in commands))
            self.assertFalse(any('update-ref' in c for c in commands))
            self.assertTrue(any(c[-1] == m['tagObject']+':refs/tags/'+m['tag'] for c in commands))

    def test_publish_requires_full_inspected_draft_and_public_readback_does_not_assert_App_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory);manifest, m = self.prepare(base);config = production.plan(REPO)
            args = SimpleNamespace(repo=REPO, expected_head=HEAD, manifest=manifest,
                manifest_sha256=publish.sha(manifest.read_bytes()), action='publish', release_id=19)
            frozen_index = (manifest.parent / 'polaris-box-assets.json').read_bytes()
            published = False
            def fake_api(endpoint, payload=None):
                self.assertIsNone(payload)
                return {'id': publish.REPOSITORY_ID} if endpoint == 'repos/' + publish.REPOSITORY else self.release(m, draft=not published)
            def command(*args, **unused):
                nonlocal published
                published = True
                (manifest.parent / 'polaris-box-assets.json').write_bytes(b'changed-after-snapshot')
                self.assertIn('PATCH', args)
                payload=json.loads(Path(args[-1]).read_bytes())
                self.assertEqual(payload['tag_name'],m['tag']);self.assertEqual(payload['target_commitish'],HEAD)
                self.assertEqual(payload, {'tag_name':m['tag'],'target_commitish':m['sourceCommit'],
                                               'draft': False, 'prerelease': True, 'make_latest': 'false'})
                return json.dumps(self.release(m, draft=False))
            with patch.object(publish, 'frozen_source', return_value=(config, TREE)), \
                 patch.object(publish, 'remote_tag', return_value=True), patch.object(publish, 'api', side_effect=fake_api), \
                 patch.object(publish, 'command', side_effect=command), patch.object(publish, 'public_readback', return_value=m['assets']):
                result = publish.execute(args)
            self.assertTrue(result['public'])
            self.assertEqual(result['AppConsumerAcceptance'], 'pending')
            self.assertFalse(result['mobileAcceptance'])
            self.assertFalse(result['deviceAcceptance'])
            self.assertEqual(len(result['consumerContract']['platforms']), 4)
            self.assertTrue(all(a['assetId'] > 0 and a['releaseId'] == 19 for a in result['assets']))
            (manifest.parent / 'polaris-box-assets.json').write_bytes(frozen_index)
            with patch.object(publish, 'frozen_source', return_value=(config, TREE)), \
                 patch.object(publish, 'remote_tag', return_value=True), \
                 patch.object(publish, 'api', side_effect=lambda endpoint: {'id': publish.REPOSITORY_ID}
                              if endpoint == 'repos/' + publish.REPOSITORY else self.release(m, m['assets'][:3])), \
                 patch.object(publish, 'command', side_effect=AssertionError('must reject before publish')), self.assertRaises(ValueError):
                publish.execute(args)

    def test_published_state_survives_failed_anonymous_download_without_false_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory);manifest, m = self.prepare(base);config = production.plan(REPO)
            args = SimpleNamespace(repo=REPO, expected_head=HEAD, manifest=manifest,
                manifest_sha256=publish.sha(manifest.read_bytes()), action='readback', release_id=19,
                output=base / 'observed-public-state.json')
            with patch.object(publish, 'frozen_source', return_value=(config, TREE)), \
                 patch.object(publish, 'remote_tag', return_value=True), \
                 patch.object(publish, 'api', side_effect=lambda endpoint: {'id': publish.REPOSITORY_ID}
                              if endpoint == 'repos/' + publish.REPOSITORY else self.release(m, draft=False)), \
                 patch.object(publish, 'command', side_effect=AssertionError('no mutation during readback')), \
                 patch.object(publish, 'public_readback', side_effect=ValueError('download failed')), \
                 self.assertRaisesRegex(ValueError, 'download failed'):
                publish.execute(args)
            observed = json.loads(args.output.read_bytes())
            self.assertTrue(observed['public'])
            self.assertFalse(observed['anonymousReadback'])
            self.assertEqual(observed['phase'], 'public-awaiting-anonymous-readback')
            self.assertEqual(observed['AppConsumerAcceptance'], 'pending')
            self.assertFalse(observed['mobileAcceptance'])

    def test_public_readback_is_anonymous_and_rejects_size_or_hash_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, m = self.prepare(Path(directory))
            def download(request, timeout):
                self.assertNotIn('Authorization', request.headers)
                return io.BytesIO((manifest.parent / request.full_url.rsplit('/', 1)[1]).read_bytes())
            with patch.object(publish.urllib.request, 'urlopen', side_effect=download):
                self.assertEqual(len(publish.public_readback(m)), 12)
            with patch.object(publish.urllib.request, 'urlopen', return_value=io.BytesIO(b'changed')), self.assertRaises(ValueError):
                publish.public_readback(m)

    def test_bounded_draft_url_and_tag_drift_are_not_accepted_after_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest,m=self.prepare(Path(directory));draft=self.release(m);temp='untagged-b23d66d686ac1ee9af27'
            for a in draft['assets']:a['browser_download_url']=a['browser_download_url'].replace(m['tag'],temp)
            self.assertEqual(publish.validate_release(draft,m,True,19),set())
            with self.assertRaisesRegex(ValueError,'observed draft URL identity changed'):
                publish.validate_release(draft,m,True,19,'untagged-1234567890abcdef')
            draft['tag_name']=temp
            self.assertEqual(publish.validate_release(draft,m,True,19),set())
            for bad in [temp+'?extra=1','untagged-other','https://evil.invalid/x']:
                mutant=copy.deepcopy(draft);mutant['assets'][0]['browser_download_url']=mutant['assets'][0]['browser_download_url'].replace(temp,bad)
                with self.assertRaises(ValueError):publish.validate_release(mutant,m,True,19)
            mixed=copy.deepcopy(draft);mixed['assets'][0]['browser_download_url']=mixed['assets'][0]['browser_download_url'].replace(temp,'untagged-1234567890abcdef')
            with self.assertRaises(ValueError):publish.validate_release(mixed,m,True,19)
            draft['draft']=False
            with self.assertRaises(ValueError):publish.validate_release(draft,m,True,19)
    def test_app_owner_contract_evidence_is_separate_and_exactly_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);config,inputs,index_sha,review=self.inputs(base);app=base/'actual-app-record.txt'
            app.write_text('Inert App-owner contract fixture '+HEAD+' '+config['version']+' '+config['tag'])
            with patch.object(publish,'frozen_source',return_value=(config,TREE)):
                publish.prepare(REPO,HEAD,inputs,index_sha,review,publish.sha(review.read_bytes()),base/'out',
                    '1791720000','Fixture','fixture@example.invalid',app,publish.sha(app.read_bytes()))
            index=json.loads((base/'out/polaris-box-assets.json').read_bytes())
            self.assertEqual(index['gates']['AppOwnerSignoff']['status'],'recorded-App-owner-contract-review')
            self.assertEqual(index['gates']['AppOwnerSignoff']['text'],app.read_text())
            self.assertEqual(index['gates']['actualPublicDownloadConsumerAcceptance'],'pending')


if __name__ == '__main__':unittest.main()
