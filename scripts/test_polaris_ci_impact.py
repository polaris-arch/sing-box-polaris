import json
import re
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import polaris_ci_impact as impact

ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_WORKFLOWS = ROOT / 'scripts/testdata/historical-workflows'
BASE = 'a635e5345b0f44e716c20ddf95e5d2eba9db3159'
# Only stale.yml is still an immutable upstream workflow. The other five were
# migrated to owned, guarded workflows and are checked structurally below.
INHERITED_SHA256 = {'stale.yml': 'bc7400aff64735578e663d255ac576185dd35599d9e5711b907428af3be24e48'}
INHERITED = ('stale.yml',)
MIGRATED = {'build.yml', 'docker.yml', 'linux.yml', 'lint.yml', 'test.yml'}
SOURCE_OWNED = MIGRATED | {
    'polaris-selfcheck.yml', 'ci-contract.yml', 'g4-candidate.yml',
    'publish-container.yml', 'publish-github.yml', 'signed-linux.yml',
    'signed-release.yml', 'android-runtime-materials.yml',
}
WORKFLOWS = set(INHERITED) | SOURCE_OWNED


class ImpactTests(unittest.TestCase):
    def test_exact_allowlist_and_all_protected_negative_paths(self):
        guide = next(iter(impact.PROSE))
        def row(name, old='100644', new='100644', status='M'):
            return {'path': name, 'oldMode': old, 'newMode': new, 'status': status}
        self.assertTrue(impact.classify_changes([row(guide)]))
        self.assertFalse(impact.classify_changes([]))
        for path in impact.CI_ONLY:
            self.assertTrue(impact.classify_changes([row(path)]))
            self.assertFalse(impact.classify_changes([row(path, new='120000')]))
        for name in ('README.md', 'LICENSE', 'NOTICE', 'docs/configuration/dns/index.md',
            'docs/schema.json', 'docs/install.sh', 'release/POLARIS_ASSETS.md',
            'release/POLARIS_OPENWRT.md', 'release/licenses/license.md', 'release/NOTICE.md',
            'release/polaris-production-release.json', 'go.mod', 'go.sum',
            'third_party/sing-tun/go.sum',
            '.github/workflows/polaris-selfcheck.yml', 'unexpected.md', 'box.go'):
            with self.subTest(path=name):
                self.assertFalse(impact.classify_changes([row(guide), row(name)]))
        for mode in ('100755', '120000', '160000'):
            self.assertFalse(impact.classify_changes([row(guide, new=mode)]))
        self.assertFalse(impact.classify_changes([row(guide, status='T')]))

    def test_active_workflows_classifier_and_unknown_paths_always_keep_full(self):
        protected = ['scripts/polaris_ci_impact.py', 'scripts/polaris_runner_resources.py',
                     'scripts/ci/patch_test_packages.py', 'go.mod', 'go.sum', '.golangci.yml',
                     'release/DEFAULT_BUILD_TAGS', 'release/LDFLAGS',
                     'third_party/sing-tun/go.mod', 'third_party/metacubex-utls/go.sum',
                     'scripts/testdata/historical-workflows/unknown.yml',
                     'scripts/testdata/historical-workflows/unknown.go']
        protected += ['.github/workflows/' + name for name in WORKFLOWS]
        protected += ['.github/workflows/' + name for name in (
            'polaris-dns-native-candidate.yml', 'polaris-native-candidate.yml',
            'polaris-production-native.yml', 'polaris-production-release.yml')]
        for path in protected:
            for status, old, new in [('M', '100644', '100644'), ('A', '000000', '100644'), ('D', '100644', '000000')]:
                with self.subTest(path=path, status=status):
                    self.assertFalse(impact.classify_changes([
                        {'path': path, 'status': status, 'oldMode': old, 'newMode': new}]))

    def test_real_git_ci_changes_full_runtime_fallback_and_fixed_audits(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder)
            def git(*args):
                return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.PIPE).decode().strip()
            git('init', '-q'); git('config', 'user.name', 'fixture'); git('config', 'user.email', 'fixture@example.invalid')
            (repo / 'box.go').write_text('package box\n')
            legacy = '.github/workflows/polaris-production-native.yml'
            old = repo / legacy; old.parent.mkdir(parents=True); old.write_text('retired\n')
            git('add', '.'); git('commit', '-qm', 'base'); before = git('rev-parse', 'HEAD')
            for path in impact.CI_ONLY:
                p = repo / path; p.parent.mkdir(parents=True, exist_ok=True); p.write_text('contract fixture\n')
            git('add', '.'); git('commit', '-qm', 'ci'); head = git('rev-parse', 'HEAD')
            event = {'repository': {'full_name': 'polaris-arch/sing-box-polaris', 'id': 1421657509},
                     'before': before, 'after': head, 'deleted': False, 'forced': False}
            def run(event=event, kind='push', ref='refs/heads/polaris-main', head=head):
                return impact.classify(repo, event, kind, ref, head)
            self.assertFalse(run()['runFull'])
            for kind in ('workflow_dispatch', 'pull_request', 'merge_group', 'pull_request_target', 'schedule'):
                self.assertTrue(run(kind=kind)['runFull'])
            for ref in ('refs/tags/polaris-fixed', 'refs/heads/other'):
                self.assertTrue(run(ref=ref)['runFull'])
            for changes in ({'forced': True}, {'deleted': True}, {'before': '0' * 40}, {'after': 'a' * 40}):
                self.assertTrue(run(event={**event, **changes})['runFull'])
            for path in ('box.go', 'go.mod', 'release/DEFAULT_BUILD_TAGS', 'scripts/ci/patch_test_packages.py',
                         'third_party/sing-tun/go.sum', 'scripts/polaris_ci_impact.py',
                         '.github/workflows/test.yml', '.github/workflows/ci-contract.yml', 'unknown.file', legacy):
                p = repo / path; p.parent.mkdir(parents=True, exist_ok=True); p.write_text('runtime change\n')
                git('add', '.'); git('commit', '-qm', 'runtime'); tip = git('rev-parse', 'HEAD')
                self.assertTrue(run(event={**event, 'after': tip}, head=tip)['runFull'], path)
                git('reset', '--hard', head)
            old.unlink()
            git('add', '.'); git('commit', '-qm', 'retirement'); tip = git('rev-parse', 'HEAD')
            self.assertTrue(run(event={**event, 'after': tip}, head=tip)['runFull'])
            git('reset', '--hard', head)
            (repo / 'box.go').write_text('package box\n//go:embed scripts/*\n')
            git('add', '.'); git('commit', '-qm', 'embed'); base = git('rev-parse', 'HEAD')
            (repo / 'scripts/test_polaris_ci_impact.py').write_text('changed embedded input\n')
            git('add', '.'); git('commit', '-qm', 'embedded ci'); tip = git('rev-parse', 'HEAD')
            self.assertTrue(run(event={**event, 'before': base, 'after': tip}, head=tip)['runFull'])

    def test_raw_diff_control_unicode_and_malformed(self):
        sha = 'a' * 40
        raw = (':100644 100644 ' + sha + ' ' + sha + ' M\0' + next(iter(impact.PROSE)) + '\0').encode()
        self.assertTrue(impact.classify_changes(impact.parse_raw(raw)))
        for broken in (b'incomplete', raw[:-1], b':wrong\0name\0', b'X' * (impact.LIMIT + 1)):
            with self.assertRaises(ValueError):
                impact.parse_raw(broken)

    def test_real_git_doc_push_full_audits_and_embed_negative(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder)
            def git(*args):
                return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.PIPE).decode().strip()
            git('init', '-q'); git('config', 'user.name', 'fixture'); git('config', 'user.email', 'fixture@example.invalid')
            guide = repo / next(iter(impact.PROSE)); guide.parent.mkdir(); guide.write_text('pure instructions\n')
            (repo / 'box.go').write_text('package box\n')
            git('add', '.'); git('commit', '-qm', 'base'); before = git('rev-parse', 'HEAD')
            guide.write_text('revised instructions\n'); git('add', '.'); git('commit', '-qm', 'docs'); head = git('rev-parse', 'HEAD')
            event = {'repository': {'full_name': 'polaris-arch/sing-box-polaris', 'id': 1421657509}, 'before': before,
                     'after': head, 'deleted': False, 'forced': False}
            def run(event=event, name='push', ref='refs/heads/polaris-main', sha=head):
                return impact.classify(repo, event, name, ref, sha)
            self.assertFalse(run()['runFull'])
            for name, ref in [('workflow_dispatch', 'refs/heads/polaris-main'), ('push', 'refs/tags/polaris-fixed'),
                               ('pull_request', 'refs/pull/1/merge')]:
                self.assertTrue(run(name=name, ref=ref)['runFull'])
            for change in ({'forced': True}, {'deleted': True}, {'before': '0' * 40},
                           {'after': 'a' * 40}, {'repository': None}, {'repository': {'full_name': 'other/repo'}}):
                self.assertTrue(run(event={**event, **change})['runFull'])
            for repository in ({'full_name': 'polaris-arch/polaris-box', 'id': 1421657509},
                               {'full_name': 'SagerNet/sing-box', 'id': 1421657509},
                               {'full_name': 'polaris-arch/sing-box-polaris', 'id': 1},
                               {'full_name': 'polaris-arch/sing-box-polaris'}):
                self.assertTrue(run(event={**event, 'repository': repository})['runFull'])
            with patch.object(impact, 'git', side_effect=OSError('unavailable')):
                self.assertTrue(run()['runFull'])
            (repo / 'box.go').write_text('package box\n//go:embed all:release/*\n')
            git('add', '.'); git('commit', '-qm', 'embed'); before = git('rev-parse', 'HEAD')
            guide.write_text('still prose but now compiled input\n'); git('add', '.'); git('commit', '-qm', 'doc'); head = git('rev-parse', 'HEAD')
            self.assertTrue(impact.classify(repo, {**event, 'before': before, 'after': head}, 'push', 'refs/heads/polaris-main', head)['runFull'])

    def test_real_unicode_go_filename_and_go_character_classes_keep_full(self):
        for filename, pattern in [('诊断.go', 'release/*'), ('embed.go', '[!r]elease/*'),
                                  ('embed.go', '[^x]elease/*')]:
            with self.subTest(filename=filename, pattern=pattern), tempfile.TemporaryDirectory() as folder:
                repo=Path(folder)
                def git(*args):
                    return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.PIPE).decode().strip()
                git('init','-q');git('config','user.name','fixture');git('config','user.email','fixture@example.invalid')
                git('config','core.quotePath','true')
                guide=repo / next(iter(impact.PROSE));guide.parent.mkdir();guide.write_text('instructions')
                (repo / filename).write_text('package box\nimport _ "embed"\n//go:embed '+pattern+'\nvar guide string\n')
                git('add','.');git('commit','-qm','embedded');before=git('rev-parse','HEAD')
                guide.write_text('revised instructions');git('add','.');git('commit','-qm','only guide');head=git('rev-parse','HEAD')
                event={'repository':{'full_name':'polaris-arch/sing-box-polaris','id':1421657509},'before':before,'after':head,'deleted':False,'forced':False}
                self.assertTrue(impact.classify(repo,event,'push','refs/heads/polaris-main',head)['runFull'])

    def test_observed_shell_and_evidence_roots_and_shared_budget_wiring(self):
        for filename in WORKFLOWS - set(INHERITED):
            text=(ROOT / '.github/workflows' / filename).read_text()
            for job in re.split(r'(?=^  [a-z][a-z0-9_-]*:\n)',text,flags=re.M):
                steps=re.findall(r'^      - .*?(?=^      - |\Z)',job,re.M|re.S)
                wrappers=[step for step in steps if 'polaris-command-' in step]
                if not wrappers: continue
                self.assertIn('Start shared job clock',steps[0])
                self.assertIn('runner_bash=\"$BASH\"',steps[0])
                self.assertIn('cygpath -w \"$BASH\"',steps[0])
                self.assertIn("stream.write('POLARIS_RUNNER_BASH='",steps[0])
                for step in wrappers:
                    self.assertIn('-- \"$POLARIS_RUNNER_BASH\" --noprofile --norc -e -o pipefail',step)
                uploads=[(i,s) for i,s in enumerate(steps) if 'upload-artifact@' in s]
                caches=[(i,s) for i,s in enumerate(steps) if 'cache/save@' in s]
                for i,cache in caches:
                    primary=next(n for n,s in uploads if 'id: ci_evidence_upload' in s)
                    self.assertGreater(i,primary)
                    self.assertIn("steps.ci_evidence_upload.outcome == 'success'",cache)
                    self.assertIn('timeout-minutes: ${{ fromJSON(steps.',cache)
                for _,upload in uploads:
                    name=re.search(r'^          name: (.+)',upload,re.M)[1]
                    if name.startswith(('polaris-box-candidate-', 'polaris-box-dns-', 'polaris-box-openwrt-guest-')):
                        self.assertNotIn('/polaris-ci',upload)

    def test_complete_workflow_coverage_and_frozen_inherited_sources(self):
        self.assertEqual({p.name for p in (ROOT / '.github/workflows').glob('*.yml')}, WORKFLOWS)
        self.assertFalse(set(INHERITED) & SOURCE_OWNED)
        self.assertEqual(SOURCE_OWNED, WORKFLOWS - set(INHERITED))
        for name in INHERITED:
            self.assertEqual(hashlib.sha256((ROOT / '.github/workflows' / name).read_bytes()).hexdigest(), INHERITED_SHA256[name])
        # Retired producer lanes are fixtures, never current Actions entries.
        for name in ('polaris-production-release.yml', 'polaris-native-candidate.yml', 'polaris-dns-native-candidate.yml'):
            text = (HISTORICAL_WORKFLOWS / name).read_text()
            self.assertIn('  queue: max\n', text)
            self.assertIn('  cancel-in-progress: false\n', text)
        text = (ROOT / '.github/workflows/polaris-selfcheck.yml').read_text()
        self.assertNotIn('  queue: max', text)
        self.assertIn("format('audit-{0}', github.run_id)", text)
        self.assertIn("needs.classify.outputs.run_full == 'true'", text)
        for name, pin in [('polaris-native-candidate.yml', 'a01da7a942b3a0dbbfdfda2bba5bd63d5bd9d932'),
                          ('polaris-dns-native-candidate.yml', 'aafc521b745e0d1a8f50a6a3f41169433f1c2194')]:
            self.assertIn('ref: ' + pin, (HISTORICAL_WORKFLOWS / name).read_text())


    def assert_github_publisher_security(self, publisher):
        # Check the actual job fields, not a matching string in a comment/step.
        # Keep this stdlib-only: this contract runs before dependency setup.
        self.assertEqual(publisher.count('\njobs:\n'), 1)
        header, jobs_text = publisher.split('\njobs:\n')
        self.assertEqual(len(re.findall(r'^permissions:', header, re.M)), 1)
        self.assertEqual(re.findall(r'^permissions:\n((?:  [^\n]+\n)+)', header, re.M),
                         ['  contents: read\n'])
        jobs = re.findall(r'^  ([A-Za-z_][A-Za-z0-9_-]*):\n(.*?)(?=^  [A-Za-z_][A-Za-z0-9_-]*:\n|\Z)',
                          jobs_text, re.M | re.S)
        self.assertEqual([name for name, _ in jobs], ['validate', 'publish'])
        jobs = dict(jobs)

        def field(job, name, expected):
            self.assertEqual(re.findall(r'^    ' + re.escape(name) + r': ([^\n]+)$',
                                        jobs[job], re.M), [expected], (job, name))

        field('validate', 'if', "github.repository == 'polaris-arch/sing-box-polaris' && "
              "github.repository_id == '1421657509'")
        self.assertEqual(re.findall(r'^    continue-on-error:', jobs['validate'], re.M), [])
        field('publish', 'needs', 'validate')
        # All four explicit write modes share both the opt-in and environment.
        field('publish', 'if', "(inputs.mode == 'publish' || inputs.mode == 'reconcile' || "
              "inputs.mode == 'stage-replacement' || inputs.mode == 'replace') && "
              "vars.POLARIS_GITHUB_PUBLISH_ENABLED == 'true'")
        field('publish', 'environment', 'polaris-github-release')
        for name, contents in [('validate', 'read'), ('publish', 'write')]:
            self.assertEqual(len(re.findall(r'^    permissions:', jobs[name], re.M)), 1)
            self.assertEqual(re.findall(r'^    permissions:\n((?:      [^\n]+\n)+)',
                                        jobs[name], re.M),
                             [f'      contents: {contents}\n      actions: read\n'])
        self.assertIn('--inventory-sha256 "$INVENTORY_SHA256"', jobs['validate'])
        self.assertIn('--inventory-sha256 "$INVENTORY_SHA256"', jobs['publish'])

    def test_migrated_and_new_workflows_keep_owned_security_boundaries(self):
        def events(text):
            match = re.search(r"^(?:'on'|on):\n((?:[ \t].*\n|\n)+)", text, re.M)
            self.assertIsNotNone(match)
            return set(re.findall(r'^  ([a-z_]+):', match[1], re.M))
        for name in MIGRATED | {'ci-contract.yml', 'g4-candidate.yml', 'publish-github.yml',
                                'publish-container.yml', 'signed-linux.yml', 'signed-release.yml'}:
            with self.subTest(workflow=name):
                text = (ROOT / '.github/workflows' / name).read_text()
                self.assertIn('contents: read', text)
                if name in {'lint.yml', 'test.yml', 'ci-contract.yml'}:
                    self.assertEqual(events(text) - {'workflow_dispatch'}, {'push', 'pull_request'})
                    self.assertIn('- polaris-main', text)
                else:
                    self.assertEqual(events(text), {'workflow_dispatch'})
                if name in {'build.yml', 'linux.yml', 'docker.yml'}:
                    for forbidden in ('push.fury.io', 'ghr --replace', 'publish_testflight', 'push=true'):
                        self.assertNotIn(forbidden, text)
                if name in {'signed-release.yml', 'signed-linux.yml', 'publish-container.yml'}:
                    self.assertIn("github.repository == 'polaris-arch/sing-box-polaris'", text)
                    self.assertIn("vars.POLARIS_DISTRIBUTION_ENABLED == 'true'", text)
                    self.assertIn('environment: polaris-distribution', text)
        publisher = (ROOT / '.github/workflows/publish-github.yml').read_text()
        self.assert_github_publisher_security(publisher)
        # Negative fixtures must fail even though the original guard remains in
        # a comment. This prevents a future return to whole-file substring checks.
        gate = ("(inputs.mode == 'publish' || inputs.mode == 'reconcile' || "
                "inputs.mode == 'stage-replacement' || inputs.mode == 'replace') && "
                "vars.POLARIS_GITHUB_PUBLISH_ENABLED == 'true'")
        mutations = {
            'missing opt-in': (gate, gate.split(' && ')[0]),
            'opt-in OR bypass': (gate, gate.replace(' && ', ' || ')),
            'ungrouped modes': (gate, gate.replace('(', '').replace(')', '')),
            'read-only inventory promoted': (gate, gate.replace("'publish'", "'inventory'")),
            'unknown write mode': (gate, gate.replace(") &&", " || inputs.mode == 'unreviewed') &&")),
            'missing repository name': ("github.repository == 'polaris-arch/sing-box-polaris' && ", ''),
            'missing repository ID': (" && github.repository_id == '1421657509'", ''),
            'missing validation dependency': ('    needs: validate\n', ''),
            'ignored validation failure': ('  validate:\n', '  validate:\n    continue-on-error: true\n'),
            'wrong environment': ('    environment: polaris-github-release', '    environment: unprotected'),
            'elevated validation token': ('      contents: read\n', '      contents: write\n'),
            'elevated default token': ('  contents: read\n', '  contents: write\n'),
            'extra writer job': ('  publish:\n', '  unguarded:\n    permissions:\n      contents: write\n  publish:\n'),
            'uppercase writer job': ('  publish:\n', '  Writer:\n    permissions: write-all\n  publish:\n'),
            'underscore writer job': ('  publish:\n', '  _writer:\n    permissions: write-all\n  publish:\n'),
            'duplicate default scalar permissions': ('permissions:\n', 'permissions: write-all\npermissions:\n'),
            'duplicate job scalar permissions': ('    permissions:\n', '    permissions: write-all\n    permissions:\n'),
            'scalar default permissions': ('permissions:\n  contents: read\n', 'permissions: write-all\n'),
            'scalar job permissions': ('    permissions:\n      contents: read\n      actions: read\n', '    permissions: write-all\n'),
        }
        for label, (before, after) in mutations.items():
            with self.subTest(publisher_regression=label):
                self.assertIn(before, publisher)
                broken = publisher.replace(before, after, 1) + '\n# Original guard: ' + gate + '\n'
                with self.assertRaises(AssertionError):
                    self.assert_github_publisher_security(broken)

    def test_state_store_fixture_checkout_keeps_exact_revision_bytes(self):
        path = 'protocol/tailscale/testdata/synthetic-sealed-state.json'
        attributes = (ROOT / '.gitattributes').read_text().splitlines()
        self.assertIn('/' + path + ' text eol=lf', attributes)
        content = (ROOT / path).read_bytes()
        expected = json.loads((ROOT / 'protocol/tailscale/testdata/synthetic-sealed-state.expected.json').read_text())
        self.assertNotIn(b'\r', content)
        self.assertEqual(hashlib.sha256(content).hexdigest(), expected['stateFileRevision'])


if __name__ == '__main__':
    unittest.main()
