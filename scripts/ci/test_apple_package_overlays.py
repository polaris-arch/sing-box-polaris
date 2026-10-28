"""Exact source and real Git controls; never invoke Xcode or a package plugin."""
import copy
from contextlib import contextmanager, redirect_stderr
import errno
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

import apple_package_overlays as apple

ROOT = apple.ROOT
SOURCE = 'a' * 40


def make_git(directory):
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_AUTHOR_NAME='Synthetic fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid',
               GIT_COMMITTER_NAME='Synthetic fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid',
               GIT_AUTHOR_DATE='2000-01-01T00:00:00Z', GIT_COMMITTER_DATE='2000-01-01T00:00:00Z')
    for args in (['init', '-q'], ['add', '--all'], ['commit', '-q', '-m', 'Synthetic source fixture']):
        subprocess.run(['git', '-C', str(directory), *args], env=env, check=True)
    return (apple.git(directory, 'rev-parse', 'HEAD').decode().strip(),
            apple.git(directory, 'rev-parse', 'HEAD^{tree}').decode().strip())


@contextmanager
def fixture(symlink=None):
    spec = copy.deepcopy(apple.definition())
    with tempfile.TemporaryDirectory(prefix='apple-source-contract-') as temporary:
        root = Path(temporary)
        packages = root / 'SourcePackages'
        (packages / 'checkouts').mkdir(parents=True)
        pins = json.loads((ROOT / spec['client']['lockRecipe']).read_bytes())
        recipes = []
        for package in spec['packages']:
            original = (ROOT / package['originalRecipe']).read_bytes()
            directory = packages / 'checkouts' / package['identity']
            (directory / 'Sources').mkdir(parents=True)
            (directory / 'Package.swift').write_bytes(original)
            (directory / 'Sources/Runtime.swift').write_text('public let fixture = 1\n')
            (directory / '.gitignore').write_text('ignored.tmp\n')
            if symlink is not None:
                (directory/'Alias.swift').symlink_to(symlink)
            package['revision'], package['tree'] = make_git(directory)
            for pin in pins['pins']:
                if pin['identity'] == package['identity']:
                    pin['state']['revision'] = package['revision']
            path = root / package['originalRecipe']
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(original)
            recipes.append({'path': package['originalRecipe'], 'revision': package['revision'],
                            'bytes': len(original), 'sha256': apple.sha(original),
                            'sourceURL': package['repository'].replace('https://github.com/', 'https://raw.githubusercontent.com/') +
                            '/' + package['revision'] + '/Package.swift'})
        lock = (json.dumps(pins, indent=2) + '\n').encode()
        spec['client']['lockSHA256'] = apple.sha(lock)
        path = root / spec['client']['lockRecipe']
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(lock)
        directory = root / 'clients/apple'
        path = directory / spec['client']['lockfile']
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(lock)
        spec['client']['commit'], spec['client']['tree'] = make_git(directory)
        (root / 'release/ci').mkdir(parents=True)
        (root / apple.CONTRACT).write_text(json.dumps(spec, indent=2) + '\n')
        client = {key: spec['client'][key] for key in ('repository', 'commit', 'tree')}
        (root / 'release/ci/client-overlays.json').write_text(json.dumps({'platforms': {'apple': client}}))
        (root / 'release/dependency-sources/clients/runtime/recipe-index.json').write_text(json.dumps(recipes))
        yield root, packages, spec


class ApplePackageOverlayControls(unittest.TestCase):
    @contextmanager
    def readonly(self, directories=False):
        with fixture() as (root, packages, spec):
            paths = [packages / 'checkouts' / p['identity'] / 'Package.swift' for p in spec['packages']]
            before = [p.read_bytes() for p in paths]
            for path in paths:
                path.chmod(0o444)
                if directories:
                    path.parent.chmod(0o555)
            try:
                yield root, packages, spec, paths, before
            finally:
                for path in paths:
                    path.parent.chmod(0o755)
                    if path.exists() and not path.is_symlink():
                        path.chmod(0o644)

    def assert_restored(self, paths, before):
        self.assertEqual([p.read_bytes() for p in paths], before)
        self.assertEqual([stat.S_IMODE(p.stat().st_mode) for p in paths], [0o444, 0o444])

    def test_real_readonly_cold_files_and_directories_preserve_identity_and_modes(self):
        self.assertNotEqual(os.geteuid(), 0, 'readonly regression must run as an unprivileged user')
        with self.readonly(directories=True) as (root, packages, spec, paths, before):
            identities = [apple.file_identity(p.stat()) for p in paths]
            indexes = [(p.parent / '.git/index').read_bytes() for p in paths]
            runtimes = [(p.parent / 'Sources/Runtime.swift').read_bytes() for p in paths]
            with self.assertRaises(PermissionError):
                paths[0].write_bytes(before[0])  # Real regression: old apply's first operation fails.
            apple.apply(packages, root)
            apple.collect(SOURCE, packages, root)
            self.assertEqual([apple.file_identity(p.stat()) for p in paths], identities)
            self.assertEqual([(p.parent / '.git/index').read_bytes() for p in paths], indexes)
            self.assertEqual([(p.parent / 'Sources/Runtime.swift').read_bytes() for p in paths], runtimes)
            self.assertEqual([stat.S_IMODE(p.stat().st_mode) for p in paths], [0o444, 0o444])
            self.assertEqual([stat.S_IMODE(p.parent.stat().st_mode) for p in paths], [0o555, 0o555])
            with patch.object(apple.os, 'fchmod', side_effect=AssertionError('no chmod for exact overlay')), \
                 patch.object(apple, 'write_descriptor', side_effect=AssertionError('no rewrite for exact overlay')):
                apple.apply(packages, root)

    def test_second_write_open_failure_preflights_both_before_any_bytes_change(self):
        with self.readonly() as (root, packages, spec, paths, before):
            real_open = os.open
            opened = 0
            def deny_second(path, flags, *args, **kwargs):
                nonlocal opened
                if flags & os.O_RDWR:
                    opened += 1
                    if opened == 2:
                        raise PermissionError(errno.EACCES, 'synthetic second-file denial')
                return real_open(path, flags, *args, **kwargs)
            with patch.object(apple.os, 'open', side_effect=deny_second), \
                 patch.object(apple, 'write_descriptor') as writer:
                with self.assertRaises(PermissionError):
                    apple.apply(packages, root)
                writer.assert_not_called()
            self.assert_restored(paths, before)

    def test_partial_first_or_second_write_rolls_back_both_bytes_and_modes(self):
        for failing_write in (1, 2):
            with self.subTest(failing_write=failing_write), self.readonly() as (root, packages, spec, paths, before):
                real_write = apple.write_descriptor
                calls = 0
                def fail_after_partial(fd, raw):
                    nonlocal calls
                    calls += 1
                    if calls == failing_write:
                        os.lseek(fd, 0, os.SEEK_SET)
                        os.write(fd, raw[:-1])
                        os.ftruncate(fd, len(raw) - 1)
                        self.assertNotEqual(os.fstat(fd).st_size, len(before[failing_write - 1]))
                        raise OSError(errno.EIO, 'synthetic partial write')
                    real_write(fd, raw)
                with patch.object(apple, 'write_descriptor', side_effect=fail_after_partial):
                    with self.assertRaises(OSError):
                        apple.apply(packages, root)
                self.assert_restored(paths, before)
                apple.verify_actual(packages, False, root)

    def test_postwrite_verification_failure_rolls_back_after_readonly_modes_are_restored(self):
        with self.readonly() as (root, packages, spec, paths, before):
            verify = apple.verify_actual
            def fail_output(packages, output, root):
                result = verify(packages, output, root)
                if output:
                    self.assertEqual([stat.S_IMODE(p.stat().st_mode) for p in paths], [0o444, 0o444])
                    raise ValueError('synthetic final verification failure')
                return result
            with patch.object(apple, 'verify_actual', side_effect=fail_output):
                with self.assertRaisesRegex(ValueError, 'final verification'):
                    apple.apply(packages, root)
            self.assert_restored(paths, before)

    def test_failed_mode_restoration_is_fatal_and_diagnosed_not_a_success_receipt(self):
        with self.readonly() as (root, packages, spec, paths, before):
            real_chmod = os.fchmod
            def deny_restore(fd, mode):
                if mode == 0o444:
                    raise PermissionError(errno.EACCES, 'synthetic mode restoration denial')
                real_chmod(fd, mode)
            diagnostic = io.StringIO()
            with patch.object(apple.os, 'fchmod', side_effect=deny_restore), redirect_stderr(diagnostic):
                with self.assertRaisesRegex(RuntimeError, 'rollback incomplete'):
                    apple.apply(packages, root)
            self.assertEqual([p.read_bytes() for p in paths], before)
            self.assertEqual([stat.S_IMODE(p.stat().st_mode) for p in paths], [0o644, 0o644])
            self.assertIn('rollback-incomplete', diagnostic.getvalue())
            self.assertNotIn('verified-modes-restored', diagnostic.getvalue())
            with self.assertRaises(ValueError):
                apple.collect(SOURCE, packages, root)

    def test_owner_hardlink_protected_flags_and_special_mode_fail_without_writes(self):
        for case in ('owner', 'hardlink', 'flags', 'special-mode'):
            with self.subTest(case=case), self.readonly() as (root, packages, spec, paths, before):
                with patch.object(apple, 'write_descriptor') as writer, patch.object(apple.os, 'fchmod') as chmod:
                    if case == 'hardlink':
                        os.link(paths[0], root / 'outside-hardlink')
                    elif case == 'special-mode':
                        paths[0].chmod(0o444 | stat.S_ISUID)
                    if case == 'owner':
                        control = patch.object(apple.os, 'geteuid', return_value=os.geteuid() + 1)
                    else:
                        control = patch.object(apple, 'file_flags', return_value=stat.UF_IMMUTABLE if case == 'flags' else 0)
                    with control, self.assertRaises(ValueError):
                        apple.apply(packages, root)
                    writer.assert_not_called()
                    chmod.assert_not_called()
                self.assertEqual([p.read_bytes() for p in paths], before)

    def test_write_open_rejects_substituted_symlink_or_inode_and_restores_original_inode(self):
      for replacement in ('symlink', 'regular'):
        with self.subTest(replacement=replacement), self.readonly() as (root, packages, spec, paths, before):
            real_open = os.open
            moved = root / 'moved-original'
            outside = root / 'outside.swift'
            outside.write_bytes(b'not an allowed write target\n')
            switched = False
            def substitute(path, flags, *args, **kwargs):
                nonlocal switched
                if flags & os.O_RDWR and not switched:
                    switched = True
                    paths[0].rename(moved)
                    if replacement == 'symlink':
                        paths[0].symlink_to(outside)
                    else:
                        paths[0].write_bytes(outside.read_bytes())
                return real_open(path, flags, *args, **kwargs)
            with patch.object(apple.os, 'open', side_effect=substitute), self.assertRaises((OSError, ValueError)):
                apple.apply(packages, root)
            self.assertEqual(outside.read_bytes(), b'not an allowed write target\n')
            self.assertEqual(moved.read_bytes(), before[0])
            self.assertEqual(stat.S_IMODE(moved.stat().st_mode), 0o444)
            paths[0].unlink()
            moved.rename(paths[0])
            self.assert_restored(paths, before)

    def test_mixed_modes_and_before_archive_reset_are_reapplied_but_after_archive_reset_is_rejected(self):
        with fixture() as (root, packages, spec):
            paths = [packages / 'checkouts' / p['identity'] / 'Package.swift' for p in spec['packages']]
            paths[0].chmod(0o444)
            apple.apply(packages, root)
            self.assertEqual([stat.S_IMODE(p.stat().st_mode) for p in paths], [0o444, 0o644])
            # Real forced checkout stands in for a resolver refresh, not an Xcode archive.
            apple.git(paths[0].parent, 'checkout', '--force', spec['packages'][0]['revision'])
            paths[0].chmod(0o444)
            untouched = paths[1].stat().st_mtime_ns
            apple.apply(packages, root)
            self.assertEqual(paths[1].stat().st_mtime_ns, untouched)
            apple.collect(SOURCE, packages, root)
            apple.git(paths[0].parent, 'checkout', '--force', spec['packages'][0]['revision'])
            paths[0].chmod(0o444)
            reset = paths[0].read_bytes()
            with self.assertRaises(ValueError):
                apple.collect(SOURCE, packages, root)
            self.assertEqual(paths[0].read_bytes(), reset)
            self.assertEqual(stat.S_IMODE(paths[0].stat().st_mode), 0o444)

    def test_real_shared_object_store_cache_snapshot_restores_and_pruned_store_fails_closed(self):
        with fixture() as (root, packages, spec):
            repositories = packages / 'repositories'
            repositories.mkdir()
            for package in spec['packages']:
                directory = packages / 'checkouts' / package['identity']
                bare = repositories / (package['identity'] + '.git')
                subprocess.run(['git', 'clone', '--quiet', '--bare', str(directory), str(bare)], check=True)
                shutil.rmtree(directory)
                subprocess.run(['git', 'clone', '--quiet', '--shared', str(bare), str(directory)], check=True)
                self.assertEqual((directory / '.git/objects/info/alternates').read_text().strip(), str(bare / 'objects'))
                (directory / 'Package.swift').chmod(0o444)
            apple.apply(packages, root)
            cache = root / 'cache-snapshot'
            shutil.copytree(packages, cache)
            shutil.rmtree(packages)
            shutil.copytree(cache, packages)  # Same runtime path, including the complete shared object stores.
            with patch.object(apple.os, 'fchmod', side_effect=AssertionError('warm overlay must not chmod')), \
                 patch.object(apple, 'write_descriptor', side_effect=AssertionError('warm overlay must not write')):
                apple.apply(packages, root)
            apple.collect(SOURCE, packages, root)
            shutil.rmtree(repositories)
            with self.assertRaises(subprocess.CalledProcessError):
                apple.collect(SOURCE, packages, root)

    def test_diagnosis_is_fixed_scope_metadata_only_and_bounded(self):
        with self.readonly() as (root, packages, spec, paths, before):
            capture = io.StringIO()
            with patch.dict(os.environ, {'SYNTHETIC_SECRET': 'never-print-this-value'}), redirect_stderr(capture):
                apple.apply(packages, root)
            lines = capture.getvalue().splitlines()
            self.assertEqual(len(lines), 2)
            for line in lines:
                self.assertLessEqual(len(line), 8192 + len('apple-package-overlay: '))
                record = json.loads(line.removeprefix('apple-package-overlay: '))
                self.assertEqual(len(record['files']), 4)
                self.assertEqual({x['path'] for x in record['files']},
                                 {p['identity'] + suffix for p in spec['packages'] for suffix in ('/', '/Package.swift')})
                self.assertNotIn(str(root), line)
                self.assertNotIn('never-print-this-value', line)
                self.assertNotIn('plugins:', line)

    def test_even_pinned_symlinks_cannot_consume_unbound_external_or_git_data(self):
        for target in ('Sources/Runtime.swift','../../outside.swift','.git/config','/tmp/foreign.swift'):
            with self.subTest(target=target),fixture(symlink=target) as (root,packages,spec):
                if target=='Sources/Runtime.swift':
                    apple.apply(packages,root)
                    apple.collect(SOURCE,packages,root)
                else:
                    with self.assertRaisesRegex(ValueError,'symlink escapes pinned source'):
                        apple.apply(packages,root)

    def test_production_contract_is_fixed_original_source_and_only_four_lint_calls(self):
        spec = apple.definition()
        self.assertEqual({p['revision'] for p in spec['packages']},
                         {'0478fd4b8d45f191b6c400d2c7bf6cc648485593', 'd7ac3f11f22ec2e820187acce8f3a3fb7aa8ddec'})
        self.assertEqual(spec['plugin']['revision'], 'b384a67cf45d9989aed5aab23e226cbc7bc2cd54')
        for package in spec['packages']:
            before = (ROOT / package['originalRecipe']).read_bytes()
            after = apple.transformed(before, package)
            self.assertEqual([line for line in before.splitlines(True) if line not in after.splitlines(True)],
                             [apple.LINE, apple.LINE])
            self.assertEqual(before.count(b'plugins: ['), after.count(b'plugins: ['))
            self.assertIn(b'https://github.com/lukepistrol/SwiftLintPlugin', after)
            self.assertEqual((ROOT / package['originalRecipe']).read_bytes(), before)
        record = apple.expected_record(SOURCE)
        apple.validate(record, SOURCE)
        self.assertEqual(len(record['packages']), 2)

    def test_real_git_cold_apply_idempotence_collect_and_diff_replay(self):
        with fixture() as (root, packages, spec):
            originals = {p['identity']: (packages / 'checkouts' / p['identity'] / 'Package.swift').read_bytes()
                         for p in spec['packages']}
            with self.assertRaises(ValueError):
                apple.collect(SOURCE, packages, root)
            apple.apply(packages, root)
            apple.apply(packages, root)
            record = apple.collect(SOURCE, packages, root)
            apple.validate(record, SOURCE, root)
            for package in record['packages']:
                self.assertEqual(originals[package['identity']],
                                 (root / package['originalRecipe']).read_bytes())
                with tempfile.TemporaryDirectory(prefix='apple-diff-replay-') as td:
                    directory = Path(td)
                    (directory / 'Package.swift').write_bytes(originals[package['identity']])
                    subprocess.run(['git', 'apply', '--check', '-'], cwd=directory,
                                   input=package['diff'].encode(), check=True)
                    subprocess.run(['git', 'apply', '-'], cwd=directory,
                                   input=package['diff'].encode(), check=True)
                    self.assertEqual(apple.sha((directory / 'Package.swift').read_bytes()), package['afterSHA256'])

    def test_each_of_four_individually_restored_invocations_rejects(self):
        with fixture() as (root, packages, spec):
            apple.apply(packages, root)
            for package in spec['packages']:
                directory = packages / 'checkouts' / package['identity']
                original = (root / package['originalRecipe']).read_bytes()
                for keep in (0, 1):
                    index = -1
                    def retain(line):
                        nonlocal index
                        if line == apple.LINE:
                            index += 1
                            return index == keep
                        return True
                    wrong = b''.join(line for line in original.splitlines(True) if retain(line))
                    (directory / 'Package.swift').write_bytes(wrong)
                    with self.subTest(package=package['identity'], invocation=keep), self.assertRaises(ValueError):
                        apple.collect(SOURCE, packages, root)
                    (directory / 'Package.swift').write_bytes(apple.transformed(original, package))

    def test_both_worktrees_validate_before_either_is_written(self):
        with fixture() as (root, packages, spec):
            first, second = spec['packages']
            original = (packages / 'checkouts' / first['identity'] / 'Package.swift').read_bytes()
            (packages / 'checkouts' / second['identity'] / 'Sources/Runtime.swift').write_text('changed\n')
            with self.assertRaises(ValueError):
                apple.apply(packages, root)
            self.assertEqual((packages / 'checkouts' / first['identity'] / 'Package.swift').read_bytes(), original)

    def test_changed_runtime_source_even_assume_unchanged_and_ignored_extra_reject(self):
        with fixture() as (root, packages, spec):
            directory = packages / 'checkouts' / spec['packages'][0]['identity']
            path = directory / 'Sources/Runtime.swift'
            original = path.read_bytes()
            apple.git(directory, 'update-index', '--assume-unchanged', 'Sources/Runtime.swift')
            path.write_text('unreviewed source\n')
            with self.assertRaises(ValueError):
                apple.apply(packages, root)
            path.write_bytes(original)
            (directory / 'ignored.tmp').write_text('untracked even though ignored\n')
            with self.assertRaises(ValueError):
                apple.apply(packages, root)

    def test_cached_git_index_replacements_objects_and_environment_cannot_hide_extra_source(self):
        for case in ('staged-extra', 'replacement', 'object-tamper', 'environment'):
            with self.subTest(case=case), fixture() as (root, packages, spec):
                package=spec['packages'][0];directory=packages/'checkouts'/package['identity']
                path=directory/'Sources/Runtime.swift'
                if case=='staged-extra':
                    (directory/'Sources/Extra.swift').write_text('public let unreviewed = 1\n')
                    apple.git(directory,'add','Sources/Extra.swift')
                elif case in ('replacement','object-tamper'):
                    original_tree=apple.git(directory,'rev-parse','HEAD:Sources').decode().strip()
                    path.write_text('unreviewed runtime\n');apple.git(directory,'add','Sources/Runtime.swift')
                    changed_root=apple.git(directory,'write-tree').decode().strip()
                    changed_tree=apple.git(directory,'rev-parse',changed_root+':Sources').decode().strip()
                    if case=='replacement':
                        apple.git(directory,'replace',original_tree,changed_tree)
                    else:
                        content=apple.git(directory,'cat-file','tree',changed_tree)
                        loose=directory/'.git/objects'/original_tree[:2]/original_tree[2:]
                        loose.unlink()  # Git intentionally creates read-only loose objects.
                        loose.write_bytes(zlib.compress(b'tree '+str(len(content)).encode()+b'\0'+content))
                else:
                    # Foreign environment cannot redirect reads to another repo.
                    with patch.dict(os.environ,{'GIT_DIR':str(root/'clients/apple/.git'),
                                                'GIT_WORK_TREE':str(root/'clients/apple'),
                                                'GIT_INDEX_FILE':str(root/'missing-index')}):
                        apple.apply(packages,root)
                        apple.collect(SOURCE,packages,root)
                    continue
                with self.assertRaises(ValueError):apple.apply(packages,root)

    def test_actual_cli_uses_its_source_root_not_the_callers_working_directory(self):
        with fixture() as (root, packages, spec),tempfile.TemporaryDirectory() as cwd:
            script=root/'scripts/ci/apple_package_overlays.py'
            script.parent.mkdir(parents=True)
            script.write_bytes((ROOT/'scripts/ci/apple_package_overlays.py').read_bytes())
            for args in [('check-lock',),('apply','--source-packages',str(packages))]:
                subprocess.run([sys.executable,'-B',str(script),*args],cwd=cwd,check=True,capture_output=True)
            apple.collect(SOURCE,packages,root)
            (root/'clients/apple'/spec['client']['lockfile']).write_text('{}\n')
            result=subprocess.run([sys.executable,'-B',str(script),'check-lock'],cwd=cwd,capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn(b'Package.resolved changed',result.stderr)
    def test_wrong_pin_commit_tree_missing_package_symlink_or_source_mode_reject(self):
        cases = ['lock', 'commit', 'tree', 'missing', 'symlink', 'mode', 'manifest', 'case-collision']
        for case in cases:
            with self.subTest(case=case), fixture() as (root, packages, spec):
                package = spec['packages'][0]
                directory = packages / 'checkouts' / package['identity']
                if case == 'lock':
                    (root / 'clients/apple' / spec['client']['lockfile']).write_text('{}\n')
                elif case in ('commit', 'tree'):
                    policy = json.loads((root / apple.CONTRACT).read_text())
                    if case == 'commit':
                        # Commit mismatch reaches the real Git check, not merely the lock guard.
                        apple.git(directory, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                                  'commit', '--allow-empty', '-m', 'Different synthetic commit')
                    else:
                        policy['packages'][0]['tree'] = '0' * 40
                        (root / apple.CONTRACT).write_text(json.dumps(policy))
                elif case == 'missing':
                    shutil.rmtree(directory)
                elif case == 'symlink':
                    path = directory / 'Package.swift'
                    path.unlink()
                    path.symlink_to(root / package['originalRecipe'])
                elif case == 'mode':
                    (directory / 'Sources/Runtime.swift').chmod(0o755)
                elif case == 'manifest':
                    with (directory / 'Package.swift').open('ab') as stream:
                        stream.write(b'\n// drift\n')
                else:
                    (directory.parent / package['identity'].upper()).mkdir()
                with self.assertRaises(ValueError):
                    apple.apply(packages, root)

    def test_contract_and_recipe_edits_are_not_silently_accepted(self):
        for case in ['line', 'count', 'before', 'after', 'package', 'repository', 'recipe', 'lock-recipe']:
            with self.subTest(case=case), fixture() as (root, packages, spec):
                policy = json.loads((root / apple.CONTRACT).read_text())
                if case == 'line':
                    policy['removedLine'] = 'different\n'
                elif case == 'package':
                    policy['packages'].pop()
                elif case == 'recipe':
                    (root / policy['packages'][0]['originalRecipe']).write_text('changed\n')
                elif case == 'lock-recipe':
                    (root / policy['client']['lockRecipe']).write_text('{}\n')
                else:
                    key = {'count': 'removedInvocationLines', 'before': 'beforeSHA256',
                           'after': 'afterSHA256', 'repository': 'repository'}[case]
                    policy['packages'][0][key] = 1 if case == 'count' else 'wrong'
                (root / apple.CONTRACT).write_text(json.dumps(policy))
                with self.assertRaises(ValueError):
                    apple.apply(packages, root)

    def test_receipt_omission_duplicate_foreign_source_and_tampering_reject(self):
        with fixture() as (root, packages, spec):
            apple.apply(packages, root)
            record = apple.collect(SOURCE, packages, root)
            changes = [lambda r: r.update(coreSourceCommit='b' * 40),
                       lambda r: r.update(manifestSHA256='0' * 64),
                       lambda r: r.update(lockSHA256='0' * 64),
                       lambda r: r['packages'].pop(),
                       lambda r: r['packages'].append(r['packages'][0]),
                       lambda r: r['packages'][0].update(diff=''),
                       lambda r: r['packages'][0].update(afterSHA256='0' * 64),
                       lambda r: r['packages'][0].update(removedInvocationLines=True)]
            for index, change in enumerate(changes):
                wrong = copy.deepcopy(record)
                change(wrong)
                with self.subTest(case=index), self.assertRaises(ValueError):
                    apple.validate(wrong, SOURCE, root)
            with self.assertRaises(ValueError):
                apple.validate(None, SOURCE, root)
            # A later Xcode resolution resetting just one manifest is not an overlay receipt.
            package = spec['packages'][0]
            (packages / 'checkouts' / package['identity'] / 'Package.swift').write_bytes(
                (root / package['originalRecipe']).read_bytes())
            with self.assertRaises(ValueError):
                apple.collect(SOURCE, packages, root)


if __name__ == '__main__':
    unittest.main()
