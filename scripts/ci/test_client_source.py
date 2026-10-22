"""Consolidated source/unsigned/API controls. Private fixtures never publish."""
import base64
import copy
from contextlib import contextmanager, redirect_stderr
import difflib
import io
import json
import os
import shlex
from pathlib import Path
import subprocess
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock
import yaml

import client_source as client
import github_release as publisher
import apple_package_overlays as apple_packages
import test_apple_package_overlays as package_fixtures

REAL_ROOT=client.ROOT


class ClientPreflightControls(unittest.TestCase):
    @staticmethod
    def snapshot(root):
        return {p.relative_to(root).as_posix():(stat.S_IMODE(p.lstat().st_mode),p.lstat().st_mtime_ns,
                os.readlink(p) if p.is_symlink() else client.sha(p.read_bytes()))
                for p in root.rglob('*') if p.is_file() or p.is_symlink()}

    @contextmanager
    def actual(self,layout='ordinary'):
        # Real client gitlink, exact fixture transforms and actual nested package
        # collector. Only fixture identities/recipes differ from production pins.
        with package_fixtures.fixture() as (original,_,original_spec),tempfile.TemporaryDirectory(prefix='client preflight ') as temporary:
            root=Path(temporary);shutil.copytree(original,root,dirs_exist_ok=True)
            packages=root/'SourcePackages';spec=copy.deepcopy(original_spec);directory=root/'clients/apple'
            for name,value in [('source.txt','base\n'),('version.txt','v1\n'),('unrelated.txt','unchanged\n')]:
                (directory/name).write_text(value)
            spec['client']['commit'],spec['client']['tree']=package_fixtures.make_git(directory)
            (root/apple_packages.CONTRACT).write_text(json.dumps(spec))
            entries=[{'path':'source.txt','kind':'compatibility','beforeGitBlob':client.blob(b'base\n'),
                      'beforeSHA256':client.sha(b'base\n'),'afterSHA256':client.sha(b'changed\n'),
                      'beforeMode':'100644','edits':[{'old':'base\n','new':'changed\n','count':1}]},
                     {'path':'new.txt','kind':'unsigned','beforeGitBlob':None,'beforeSHA256':None,
                      'beforeMode':None,'content':'new source\n','afterSHA256':client.sha(b'new source\n')}]
            source_spec={key:spec['client'][key] for key in ('repository','commit','tree')}
            source_spec.update(path='clients/apple',files=entries,versionMetadata=['version.txt'],
                               baselineFiles={'version.txt':{'gitBlob':client.blob(b'v1\n'),'mode':'100644'}})
            manifest=root/'release/ci/client-overlays.json'
            manifest.write_text(json.dumps({'platforms':{'apple':source_spec}}))
            def git(*args):
                return subprocess.check_output(['git','-C',str(root),*args],stderr=subprocess.PIPE)
            git('init','-q');git('config','user.name','Private fixture');git('config','user.email','fixture@example.invalid')
            (root/'.gitmodules').write_text('[submodule "apple fixture"]\n\tpath = clients/apple\n\turl = https://fixture.invalid/apple.git\n')
            git('add','release','.gitmodules')
            git('update-index','--add','--cacheinfo','160000',source_spec['commit'],'clients/apple')
            git('commit','-qm','Private preflight source fixture')
            if layout!='ordinary':
                git('submodule','absorbgitdirs','clients/apple')
                self.assertTrue((directory/'.git').is_file())
            if layout=='gitfile-packed-alternate':
                client.git(directory,'gc','--prune=now')
                objects=Path(os.fsdecode(client.git(directory,'rev-parse','--path-format=absolute','--git-path','objects')).strip())
                alternate=root/'packed original objects';shutil.move(objects,alternate)
                (objects/'info').mkdir(parents=True);(objects/'info/alternates').write_text(str(alternate)+'\n')
                self.assertTrue(list((alternate/'pack').glob('*.pack')))
            if layout=='gitfile-split-index':
                client.git(directory,'config','core.splitIndex','true')
                client.git(directory,'update-index','--split-index')
            with mock.patch.multiple(client,ROOT=root,MANIFEST=manifest),mock.patch.dict(os.environ,{'RUNNER_TEMP':str(root)}):
                client.apply('apple',True)
                for package in spec['packages']:
                    (packages/'checkouts'/package['identity']/'Package.swift').chmod(0o444)
                with redirect_stderr(io.StringIO()):apple_packages.apply(packages,root)
                for name in ('source.txt','new.txt'):(directory/name).chmod(0o444)
                yield root,directory,packages,spec

    def test_preflight_real_gitfile_packed_alternate_cold_warm_and_no_writes(self):
        for layout in ('ordinary','gitfile','gitfile-packed-alternate'):
            with self.subTest(layout=layout),self.actual(layout) as (root,directory,packages,spec):
                original=self.snapshot(root)
                index=Path(os.fsdecode(client.git(directory,'rev-parse','--path-format=absolute','--git-path','index')).strip())
                index_before=(index.read_bytes(),index.stat().st_mtime_ns)
                empty='e69de29bb2d1d6434b8b29ae775ad8c2e48c5391'
                self.assertNotEqual(subprocess.run(['git','-C',str(directory),'cat-file','-e',empty],capture_output=True).returncode,0)
                git_env={key:value for key,value in os.environ.items() if key.startswith('GIT_')}
                actual_git=apple_packages.git;calls=[]
                def checked_git(*args):
                    self.assertEqual({key:value for key,value in os.environ.items() if key.startswith('GIT_')},git_env)
                    calls.append(args);return actual_git(*args)
                for _ in range(2):
                    with mock.patch.object(apple_packages,'git',side_effect=checked_git):summary=client.preflight('apple',True)
                    self.assertIn('2 client files; 2 package overlays',summary)
                    self.assertIn('not a build or producer receipt',summary)
                    self.assertEqual(self.snapshot(root),original)
                    self.assertEqual((index.read_bytes(),index.stat().st_mtime_ns),index_before)
                    self.assertFalse((root/'dist').exists())
                self.assertTrue(calls)
                self.assertNotEqual(subprocess.run(['git','-C',str(directory),'cat-file','-e',empty],capture_output=True).returncode,0)
                self.assertEqual(dict(os.environ).get('GIT_INDEX_FILE'),git_env.get('GIT_INDEX_FILE'))

    def test_split_index_is_rejected_without_freshening_and_fsmonitor_is_not_executed(self):
        with self.actual('gitfile-split-index') as (root,directory,_,_):
            before=self.snapshot(root)
            with self.assertRaisesRegex(ValueError,'split client Git index is unsupported'):
                client.preflight('apple',True)
            self.assertEqual(self.snapshot(root),before)
            self.assertEqual(json.loads(client.diagnose('apple',True)),{'diagnostic':'unavailable','errorType':'ValueError'})
            self.assertEqual(self.snapshot(root),before)
            self.assertFalse((root/'dist').exists())
        with self.actual('gitfile') as (root,directory,_,_):
            marker=root/'fsmonitor-invoked';hook=root/'fsmonitor-hook'
            hook.write_text('#!'+sys.executable+'\nfrom pathlib import Path\nimport sys\nPath('+repr(str(marker))+').write_text("invoked")\nsys.stdout.buffer.write(b"fixture-token\\0")\n')
            hook.chmod(0o755)
            client.git(directory,'config','core.fsmonitor',shlex.quote(str(hook)))
            client.git(directory,'config','core.fsmonitorHookVersion','2')
            # First prove this real hook executes without the scoped override.
            client.git(directory,'status','--porcelain');self.assertTrue(marker.exists());marker.unlink()
            before=self.snapshot(root)
            client.preflight('apple',True)
            self.assertFalse(marker.exists());self.assertEqual(self.snapshot(root),before)
            client.diagnose('apple',True)
            self.assertFalse(marker.exists());self.assertEqual(self.snapshot(root),before)

    def test_preflight_failures_preserve_source_live_index_objects_and_cleanup(self):
        for case in ('missing','extra-tracked','untracked','mode','lock','package-reset','package-source','package-object'):
            with self.subTest(case=case),self.actual('gitfile-packed-alternate') as (root,directory,packages,spec):
                if case=='missing':(directory/'source.txt').chmod(0o644);(directory/'source.txt').write_text('base\n')
                elif case=='extra-tracked':(directory/'unrelated.txt').write_text('unexpected\n')
                elif case=='untracked':(directory/'unexpected.txt').write_text('do not expose contents\n')
                elif case=='mode':(directory/'source.txt').chmod(0o755)
                elif case=='lock':(directory/client.APPLE_LOCK).write_text('{}\n')
                else:
                    package=spec['packages'][0];checkout=packages/'checkouts'/package['identity']
                    if case=='package-reset':
                        path=checkout/'Package.swift';path.chmod(0o644);path.write_bytes((root/package['originalRecipe']).read_bytes());path.chmod(0o444)
                    elif case=='package-source':(checkout/'Sources/Runtime.swift').write_text('unexpected runtime\n')
                    else:
                        oid=package['revision'];(checkout/'.git/objects'/oid[:2]/oid[2:]).unlink()
                before=self.snapshot(root);temporary_paths=[];original_temporary=tempfile.TemporaryDirectory
                def capture(*args,**kwargs):
                    result=original_temporary(*args,**kwargs);temporary_paths.append(Path(result.name));return result
                with mock.patch.object(client.tempfile,'TemporaryDirectory',side_effect=capture),self.assertRaises((ValueError,subprocess.CalledProcessError)):
                    client.preflight('apple',True)
                self.assertEqual(self.snapshot(root),before)
                self.assertTrue(temporary_paths);self.assertTrue(all(not p.exists() for p in temporary_paths))
                self.assertFalse((root/'dist').exists())
                self.assertFalse(list(root.rglob('polaris-candidate-manifest-*')))

    def test_post_index_change_hook_never_runs_and_existing_empty_blob_is_not_freshened(self):
        for packed in (False,True):
            with self.subTest(packed=packed),self.actual('gitfile') as (root,directory,_,_):
                hook=Path(os.fsdecode(client.git(directory,'rev-parse','--path-format=absolute','--git-path','hooks/post-index-change')).strip())
                hook.parent.mkdir(exist_ok=True);marker=root/'post-index-change-invoked'
                hook.write_text('#!/bin/sh\nprintf invoked > '+shlex.quote(str(marker))+'\n');hook.chmod(0o755)
                client.git(directory,'add','--intent-to-add','--','new.txt')
                self.assertTrue(marker.exists())  # Prove the hook is wired, not a mock.
                client.git(directory,'reset','--quiet','HEAD','--','new.txt');marker.unlink()
                empty=Path(os.fsdecode(client.git(directory,'rev-parse','--path-format=absolute','--git-path','objects/e6/9de29bb2d1d6434b8b29ae775ad8c2e48c5391')).strip())
                self.assertTrue(empty.is_file());os.utime(empty,ns=(1600000000000000000,1600000000000000000))
                if packed:
                    client.git(directory,'update-ref','refs/private-fixture-empty','e69de29bb2d1d6434b8b29ae775ad8c2e48c5391')
                    client.git(directory,'gc','--prune=now')
                    self.assertFalse(empty.exists())
                    packs=list((empty.parent.parent/'pack').glob('*.pack'));self.assertTrue(packs)
                    for path in packs:os.utime(path,ns=(1600000000000000000,1600000000000000000))
                before=self.snapshot(root)
                for _ in range(2):
                    client.preflight('apple',True)
                    self.assertFalse(marker.exists());self.assertEqual(self.snapshot(root),before)
                    client.diagnose('apple',True)
                    self.assertFalse(marker.exists());self.assertEqual(self.snapshot(root),before)

    def test_textconv_and_external_diff_are_disabled_without_modifying_configuration(self):
        for kind in ('textconv','external-diff'):
            with self.subTest(kind=kind),self.actual('gitfile') as (root,directory,_,_):
                marker=root/'conversion-invoked';script=root/'conversion script.py'
                script.write_text('from pathlib import Path\nimport sys\nPath('+repr(str(marker))+').write_text("invoked")\nif len(sys.argv)==2:sys.stdout.buffer.write(Path(sys.argv[1]).read_bytes())\n')
                command=shlex.quote(sys.executable)+' '+shlex.quote(str(script))
                attrs=Path(os.fsdecode(client.git(directory,'rev-parse','--path-format=absolute','--git-path','info/attributes')).strip())
                attrs.parent.mkdir(exist_ok=True);attrs.write_text('source.txt diff=fixture\n')
                client.git(directory,'config','diff.fixture.textconv' if kind=='textconv' else 'diff.external',command)
                client.git(directory,'diff','--binary','HEAD');self.assertTrue(marker.exists());marker.unlink()
                before=self.snapshot(root)
                client.preflight('apple',True)
                self.assertFalse(marker.exists());self.assertEqual(self.snapshot(root),before)
                client.diagnose('apple',True)
                self.assertFalse(marker.exists());self.assertEqual(self.snapshot(root),before)

    def test_failed_private_intent_to_add_restores_alternates_and_can_retry_without_live_writes(self):
        with self.actual('gitfile-packed-alternate') as (root,directory,_,_):
            before=self.snapshot(root);actual=subprocess.check_output;captured={}
            def locked_once(command,**kwargs):
                if 'add' in command and '--intent-to-add' in command and not captured:
                    env=kwargs['env'];index=Path(env['GIT_INDEX_FILE']);objects=Path(env['GIT_OBJECT_DIRECTORY'])
                    lock=Path(str(index)+'.lock');lock.write_bytes(b'private test lock')
                    captured.update(lock=lock,objects=objects)
                    self.assertFalse((objects/'info/alternates').exists())
                    self.assertEqual(env['GIT_ALTERNATE_OBJECT_DIRECTORIES'],'')
                return actual(command,**kwargs)
            with mock.patch.object(client.subprocess,'check_output',side_effect=locked_once),client.private_client_git(directory) as command:
                with self.assertRaises(subprocess.CalledProcessError):command(directory,'add','--intent-to-add','--','new.txt')
                self.assertTrue((captured['objects']/'info/alternates').is_file())
                self.assertFalse((captured['objects'].parent/'read-alternates').exists())
                captured['lock'].unlink()
                record=client.collect('apple',True,_client_git=command)
                self.assertEqual(record['sourceOverlayCount'],2)
            self.assertEqual(self.snapshot(root),before);self.assertFalse((root/'dist').exists())

    def test_active_clean_process_filters_rejected_before_execution_but_inactive_lfs_is_allowed(self):
        for driver in ('clean','process'):
            for location in ('info','global'):
                with self.subTest(driver=driver,location=location),self.actual('gitfile') as (root,directory,_,_):
                    marker=root/'filter-invoked';script=root/'filter script.py'
                    script.write_text('from pathlib import Path\nimport sys\nPath('+repr(str(marker))+').write_text("invoked")\n'+
                                      ('sys.stdout.buffer.write(sys.stdin.buffer.read())\n' if driver=='clean' else 'sys.exit(1)\n'))
                    command=shlex.quote(sys.executable)+' '+shlex.quote(str(script))
                    client.git(directory,'config','filter.fixture.'+driver,command)
                    client.git(directory,'config','filter.fixture.required','true')
                    if location=='info':
                        attrs=Path(os.fsdecode(client.git(directory,'rev-parse','--path-format=absolute','--git-path','info/attributes')).strip())
                    else:
                        attrs=root/'global attributes';client.git(directory,'config','core.attributesFile',str(attrs))
                    attrs.parent.mkdir(exist_ok=True);attrs.write_text('source.txt filter=fixture\n')
                    result=subprocess.run(['git','-C',str(directory),'diff','--name-only','HEAD'],capture_output=True)
                    self.assertTrue(marker.exists());marker.unlink()  # Real invocation, not a stubbed Git result.
                    self.assertEqual(result.returncode!=0,driver=='process')
                    before=self.snapshot(root)
                    with self.assertRaisesRegex(ValueError,'active client Git filters are unsupported'):
                        client.preflight('apple',True)
                    self.assertFalse(marker.exists());self.assertEqual(self.snapshot(root),before)
                    self.assertEqual(json.loads(client.diagnose('apple',True)),{'diagnostic':'unavailable','errorType':'ValueError'})
                    self.assertFalse(marker.exists());self.assertEqual(self.snapshot(root),before)
        with self.actual('gitfile') as (root,directory,_,_):
            # Like a globally installed LFS driver: no selected filter attribute.
            marker=root/'inactive-lfs-invoked';script=root/'inactive-lfs'
            script.write_text('#!/bin/sh\nprintf invoked > '+shlex.quote(str(marker))+'\nexit 1\n');script.chmod(0o755)
            for key in ('clean','process','smudge'):client.git(directory,'config','filter.lfs.'+key,shlex.quote(str(script)))
            client.git(directory,'config','filter.lfs.required','true')
            attrs=Path(os.fsdecode(client.git(directory,'rev-parse','--path-format=absolute','--git-path','info/attributes')).strip())
            for value in ('','source.txt -filter\n','source.txt !filter\n'):
                attrs.parent.mkdir(exist_ok=True);attrs.write_text(value);before=self.snapshot(root)
                client.preflight('apple',True)
                self.assertFalse(marker.exists());self.assertEqual(self.snapshot(root),before)
                client.diagnose('apple',True)
                self.assertFalse(marker.exists());self.assertEqual(self.snapshot(root),before)

    def test_diagnostics_are_bounded_escaped_read_only_and_distinguish_inventory(self):
        with self.actual() as (root,directory,_,_):
            (directory/'source.txt').chmod(0o644);(directory/'source.txt').write_text('base\n')
            (directory/'unrelated.txt').write_text('unexpected\n')
            (directory/'extra\ncontrol.txt').write_text('SECRET_SOURCE_SENTINEL')
            (directory/client.APPLE_LOCK).chmod(0o444)
            before=self.snapshot(root);text=client.diagnose('apple',True);data=json.loads(text)
            self.assertEqual(data['missingTouched']['paths'],['source.txt'])
            self.assertEqual(data['unexpectedChanged']['paths'],['unrelated.txt'])
            self.assertEqual(data['untracked']['count'],2)  # Declared new.txt is isolated intent-to-add.
            self.assertEqual(data['fixedAppleLock']['actualMode'],'0444')
            self.assertEqual(data['fixedAppleLock']['actualSHA256'],data['fixedAppleLock']['expectedSHA256'])
            self.assertNotIn('\n',text);self.assertNotIn('SECRET_SOURCE_SENTINEL',text)
            self.assertEqual(self.snapshot(root),before)
            many={str(i)+'\x1b\n'+('界'*500) for i in range(2000)}
            diagnostic=client.inventory_diagnostic(client.definition('apple'),directory,many,set(),many)
            self.assertLess(len(diagnostic.encode()),16384)
            self.assertNotIn('\x1b',diagnostic);self.assertNotIn('\n',diagnostic)
            self.assertEqual(json.loads(diagnostic)['missingTouched']['count'],2000)
            self.assertEqual(json.loads(diagnostic)['missingTouched']['omitted'],1992)
            lock=directory/client.APPLE_LOCK;lock.chmod(0o644);lock.unlink();lock.symlink_to(root/'secret-outside')
            (root/'secret-outside').write_text('SECRET_SOURCE_SENTINEL')
            self.assertEqual(client.fixed_lock_diagnostic(directory),{'status':'unsafe-or-unavailable'})
        with self.assertRaises(ValueError):client.preflight('apple',False)
        with self.assertRaises(ValueError):client.preflight('android',True)

    def test_final_candidate_receipt_still_requires_post_build_actual_collection(self):
        import record_candidate
        with self.actual() as (root,directory,_,_),mock.patch.dict(os.environ,{
                'GITHUB_REPOSITORY':'polaris-arch/sing-box-polaris','GITHUB_REPOSITORY_ID':'1421657509',
                'GITHUB_JOB':'build_apple_app_store','GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1',
                'CANDIDATE_MATRIX_KEY':'private-fixture'}):
            client.preflight('apple',True)
            self.assertFalse((root/'dist').exists())
            dist=root/'dist';dist.mkdir();(dist/'unsigned-fixture.xcarchive.tar').write_bytes(b'private test payload, not an archive')
            actual_git=lambda *args:client.git(root,*args).decode().strip()
            with mock.patch.object(record_candidate,'git',side_effect=actual_git):
                (directory/'unrelated.txt').write_text('post-build mutation\n')
                with self.assertRaisesRegex(ValueError,'inventory differs'):
                    record_candidate.main(dist)
                self.assertFalse(list(dist.glob('polaris-candidate-manifest-*')))
                (directory/'unrelated.txt').write_text('unchanged\n')
                record_candidate.main(dist)
            receipts=list(dist.glob('polaris-candidate-manifest-*'));self.assertEqual(len(receipts),1)
            value=json.loads(receipts[0].read_text());record=value['clientSource']
            self.assertEqual(record['schema'],'polaris-client-source-v1')
            self.assertEqual(record['sourceOverlayCount'],2)
            self.assertEqual(len(value['files']),1)
            self.assertEqual(set(record),{'schema','platform','repository','baseCommit','baseTree','coreSourceCommit',
                'overlayManifestSHA256','unsigned','sourceOverlayCount','identity','files','baseline','diff','diffSHA256','swiftPackageOverlays'})
            client.validate(record,'apple',record['coreSourceCommit'],True)
            # Final collect retains its existing allowed-new-source behavior.
            self.assertTrue(client.git(directory,'ls-files','--stage','--','new.txt'))
            self.assertEqual(subprocess.run(['git','-C',str(directory),'cat-file','-e','e69de29bb2d1d6434b8b29ae775ad8c2e48c5391'],capture_output=True).returncode,0)

    def test_original_package_graph_lock_mode_and_signed_overlay_contract_are_not_widened(self):
        spec=client.definition('apple');first={};last={}
        for entry in spec['files']:
            if entry['path'] in last:self.assertEqual(entry['beforeSHA256'],last[entry['path']])
            first.setdefault(entry['path'],entry['beforeSHA256']);last[entry['path']]=entry['afterSHA256']
        self.assertEqual(len(first),14)
        self.assertTrue(all(first[path]!=last[path] for path in first))
        self.assertEqual(spec['versionMetadata'],['sing-box.xcodeproj/project.pbxproj'])
        unsigned=[e for e in client.selected(spec,True) if e['path']=='Jailbreak/package.sh']
        signed=[e for e in client.selected(spec,False) if e['path']=='Jailbreak/package.sh']
        self.assertEqual(len(unsigned),3);self.assertEqual(len(signed),2)
        original=(REAL_ROOT/'scripts/ci/testdata/apple-e232aaf2/package.sh').read_bytes()
        signed_raw=original
        for entry in signed:signed_raw=client.edits(signed_raw,entry)
        self.assertEqual(client.sha(signed_raw),'24fc7314bcb1e412122af6313f7c70042d75240c6199ba36764fafa658c1ec85')
        self.assertNotIn(b'-disableAutomaticPackageResolution',signed_raw)


    def test_exact_jailbreak_arrays_reach_both_targets_plain_pipe_spaces_and_failures(self):
        spec=client.definition('apple')
        raw=(REAL_ROOT/'scripts/ci/testdata/apple-e232aaf2/package.sh').read_bytes()
        for entry in client.selected(spec,True):
            if entry['path']=='Jailbreak/package.sh':raw=client.edits(raw,entry)
        source=raw.decode()
        self.assertIn('XCODEBUILD_FLAGS=(-disableAutomaticPackageResolution)',source)
        self.assertIn('XCODEBUILD_FLAGS+=(-clonedSourcePackagesDirPath "$XCODEBUILD_CLONED_SOURCE_PACKAGES_DIR_PATH")',source)
        start=source.index('XCODEBUILD_FLAGS=')
        flags=source[start:source.index('\nfi',start)+3]
        functions=[]
        for name in ('build','build_daemon'):
            start=source.index(name+'() {')
            # Include the exact original xcbeautify/plain caller branch, not a
            # replacement invocation or exported xcodebuild interception.
            functions.append(source[start:source.index('\nfi',start)+3])
        fragment='\n'.join(['#!/bin/bash','set -euo pipefail',flags,*functions])+'\n'
        make=shutil.which('make');self.assertIsNotNone(make)
        with tempfile.TemporaryDirectory(prefix='jailbreak argv ') as temporary:
            root=Path(temporary);tools=root/'tools';tools.mkdir();(tools/'bash').symlink_to('/bin/bash')
            recorder=tools/'xcodebuild'
            recorder.write_text('#!'+sys.executable+'\nimport json,os,sys\nwith open(os.environ["ARGV_LOG"],"a") as f:f.write(json.dumps(sys.argv[1:])+"\\n")\nsys.exit(int(os.environ.get("TEST_EXIT","0")))\n')
            recorder.chmod(0o755)
            (root/'Jailbreak').mkdir();script=root/'Jailbreak/package.sh';script.write_text(fragment)
            # Exact two-line upstream target, no packaging/Apple tools run.
            (root/'Makefile').write_text('build_ios_deb:\n\tbash Jailbreak/package.sh\n')
            env=dict(os.environ,PATH=str(tools),ARGV_LOG=str(root/'argv.jsonl'),DERIVED_DATA='/fixture/Derived Data',
                     BASE_PACKAGE_IDENTIFIER='fixture.invalid',MARKETING_VERSION='1.15.0',
                     XCODEBUILD_FLAGS='-skipPackagePluginValidation -untrusted-environment-value')
            for pipe in (False,True):
                pretty=tools/'xcbeautify'
                if pipe:pretty.write_text('#!/bin/sh\nexec /bin/cat\n');pretty.chmod(0o755)
                for cloned in (False,True):
                    for failure in (False,True):
                        with self.subTest(pipe=pipe,cloned=cloned,failure=failure):
                            if cloned:env['XCODEBUILD_CLONED_SOURCE_PACKAGES_DIR_PATH']='/fixture/Source Packages'
                            else:env.pop('XCODEBUILD_CLONED_SOURCE_PACKAGES_DIR_PATH',None)
                            env['TEST_EXIT']='9' if failure else '0';log=Path(env['ARGV_LOG']);log.unlink(missing_ok=True)
                            result=subprocess.run([make,'--no-print-directory','-C',str(root),'build_ios_deb'],env=env,capture_output=True,text=True,timeout=10)
                            self.assertEqual(result.returncode!=0,failure)
                            argv=[json.loads(line) for line in log.read_text().splitlines()]
                            self.assertEqual(len(argv),1 if failure else 2)
                            self.assertEqual([args[args.index('-scheme')+1] for args in argv],['SFI'] if failure else ['SFI','JailbreakDaemon'])
                            for args in argv:
                                self.assertEqual(args.count('-disableAutomaticPackageResolution'),1)
                                self.assertEqual('-clonedSourcePackagesDirPath' in args,cloned)
                                if cloned:self.assertEqual(args[args.index('-clonedSourcePackagesDirPath')+1],'/fixture/Source Packages')
                                self.assertIn('CODE_SIGNING_ALLOWED=NO',args)
                                self.assertNotIn('-skipPackagePluginValidation',args)
                                self.assertNotIn('-untrusted-environment-value',args)
            # Demonstrate the append-vs-replace regression with real argv.
            script.write_text(fragment.replace('XCODEBUILD_FLAGS+=(','XCODEBUILD_FLAGS=('))
            env['TEST_EXIT']='0';log.unlink(missing_ok=True)
            result=subprocess.run([make,'--no-print-directory','-C',str(root),'build_ios_deb'],env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0)
            self.assertTrue(all('-disableAutomaticPackageResolution' not in json.loads(line) for line in log.read_text().splitlines()))

    def test_standalone_make_receives_the_complete_strict_unsigned_override(self):
        workflow=yaml.safe_load((REAL_ROOT/'.github/workflows/build.yml').read_text())
        for job in ('build_apple','build_apple_app_store'):
            step=next(s for s in workflow['jobs'][job]['steps'] if s.get('name')=='Build standalone packages')
            flags=step['env']['XCODEBUILD_FLAGS'].replace('${{ runner.temp }}','/fixture/Runner Temp')
            with self.subTest(job=job),tempfile.TemporaryDirectory(prefix='standalone argv ') as temporary:
                root=Path(temporary);tools=root/'tools';tools.mkdir();log=root/'argv.json'
                recorder=tools/'xcodebuild'
                recorder.write_text('#!'+sys.executable+'\nimport json,os,sys\nopen(os.environ["ARGV_LOG"],"w").write(json.dumps(sys.argv[1:]))\n')
                recorder.chmod(0o755)
                # Upstream archive argument expansion with its dangerous default
                # retained in the fixture: the workflow must override it fully.
                (root/'Makefile').write_text('XCODEBUILD_FLAGS ?= -skipPackagePluginValidation\narchive:\n\txcodebuild archive $(XCODEBUILD_FLAGS) -scheme SFM.System -configuration Release -archivePath build/SFM.System-universal.xcarchive\n')
                result=subprocess.run([shutil.which('make'),'--no-print-directory','-C',str(root),'archive'],
                    env=dict(os.environ,PATH=str(tools),ARGV_LOG=str(log),XCODEBUILD_FLAGS=flags),capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr);args=json.loads(log.read_text())
                self.assertEqual(args.count('-disableAutomaticPackageResolution'),1)
                self.assertEqual(args[args.index('-clonedSourcePackagesDirPath')+1],'/fixture/Runner Temp/SourcePackages')
                self.assertIn('CODE_SIGNING_ALLOWED=NO',args);self.assertIn('CODE_SIGNING_REQUIRED=NO',args)
                self.assertIn('CODE_SIGN_IDENTITY=',args);self.assertNotIn('-skipPackagePluginValidation',args)


def patch(before,after):
    result=[]
    for name in sorted(set(before)|set(after)):
        old,new=before.get(name),after.get(name)
        if old==new:continue
        result.append('diff --git a/'+name+' b/'+name+'\n')
        if old is None:result.append('new file mode 100644\n')
        if new is None:result.append('deleted file mode 100644\n')
        result.append('index '+('0'*40 if old is None else client.blob(old))+'..'+('0'*40 if new is None else client.blob(new))+(' 100644' if old is not None and new is not None else '')+'\n')
        result.extend(difflib.unified_diff(('' if old is None else old.decode()).splitlines(keepends=True),
                                         ('' if new is None else new.decode()).splitlines(keepends=True),
                                         fromfile='/dev/null' if old is None else 'a/'+name,
                                         tofile='/dev/null' if new is None else 'b/'+name))
    return ''.join(result)


class ClientSourceControls(unittest.TestCase):
    @contextmanager
    def fixture(self,platform='windows',unsigned=True,owned_mode='100644'):
        # Known original -> compatibility -> unsigned OR reviewed identity;
        # generated version metadata is a final, independently recorded stage.
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'release/ci').mkdir(parents=True)
            def entry(before,after,kind):
                return {'path':'source.txt','kind':kind,'beforeMode':'100644','beforeGitBlob':client.blob(before),
                        'beforeSHA256':client.sha(before),'afterSHA256':client.sha(after),
                        'edits':[{'old':before.decode(),'new':after.decode(),'count':1}]}
            spec={'path':'clients/fixture','repository':'fixture/client','commit':'b'*40,'tree':'c'*40,
                  'versionMetadata':['version.txt'],'baselineFiles':{'version.txt':{'gitBlob':client.blob(b'v1\n'),'mode':'100644'}},
                  'files':[entry(b'base\n',b'compat\n','compatibility'),entry(b'compat\n',b'unsigned\n','unsigned')]}
            policy=root/'release/ci/client-overlays.json';policy.write_text(json.dumps({'platforms':{platform:spec}}))
            baseline={'source.txt':b'base\n','version.txt':b'v1\n'}
            desired={'source.txt':b'unsigned\n' if unsigned else b'owned\n','version.txt':b'v2\n'}
            if not unsigned:
                # Test-only public identity file is explicitly new/untracked.
                baseline['owned.txt']=None;desired['owned.txt']=b'public owned identity\n'
                identity_before={'source.txt':b'compat\n','owned.txt':None}
                identity_after={name:desired[name] for name in identity_before}
                raw=patch(identity_before,identity_after).replace('new file mode 100644','new file mode '+owned_mode).encode();path=root/'release/ci/private-fixture.patch';path.write_bytes(raw)
                files={name:{'baseGitBlob':None if baseline[name] is None else client.blob(baseline[name]),
                             'beforeSHA256':None if identity_before[name] is None else client.sha(identity_before[name]),
                             'afterSHA256':client.sha(identity_after[name]),'bytes':len(identity_after[name]),
                             'beforeMode':None if identity_before[name] is None else '100644',
                             'afterMode':owned_mode if name=='owned.txt' else '100644'} for name in identity_before}
                key='desktop' if platform in ('windows','linux') else platform
                config={'repository':'polaris-arch/sing-box-polaris','repositoryId':1421657509,'reviewed':True,
                        'clientIdentityPatches':{key:{'path':'release/ci/private-fixture.patch','sha256':client.sha(raw),'clientCommit':'b'*40,'files':files}}}
                (root/'release/ci/owned-distribution.json').write_text(json.dumps(config))
            with mock.patch.multiple(client,ROOT=root,MANIFEST=policy):
                identity=client.identity_definition(platform,unsigned)
                touched={e['path'] for e in client.selected(spec,unsigned)}|(set(identity['files']) if identity else set())
                diff=patch(baseline,desired)
                if not unsigned:diff=diff.replace('new file mode 100644','new file mode '+owned_mode)
                record={'schema':'polaris-client-source-v1','platform':platform,'repository':spec['repository'],'baseCommit':'b'*40,'baseTree':'c'*40,
                        'coreSourceCommit':'a'*40,'overlayManifestSHA256':client.sha(policy.read_bytes()),'unsigned':unsigned,'sourceOverlayCount':len(touched),
                        'identity':identity,'baseline':{name:None if raw is None else base64.b64encode(raw).decode() for name,raw in baseline.items()},
                        'files':[{'path':name,'beforeSHA256':None if baseline[name] is None else client.sha(baseline[name]),
                                  'afterSHA256':client.sha(raw),'bytes':len(raw)} for name,raw in sorted(desired.items())],
                        'diff':diff,'diffSHA256':client.sha(diff.encode())}
                if platform=='apple' and unsigned:
                    # Test-only client identity; retain actual dependency recipes
                    # and exercise the real nested source validator, not a mock.
                    package_spec=copy.deepcopy(apple_packages.definition())
                    package_spec['client'].update({k:spec[k] for k in ('repository','commit','tree')})
                    paths=[package_spec['client']['lockRecipe'],
                           'release/dependency-sources/clients/runtime/recipe-index.json']
                    paths += [p['originalRecipe'] for p in package_spec['packages']]
                    for name in paths:
                        target=root/name;target.parent.mkdir(parents=True,exist_ok=True)
                        target.write_bytes((REAL_ROOT/name).read_bytes())
                    (root/apple_packages.CONTRACT).write_text(json.dumps(package_spec))
                    record['swiftPackageOverlays']=apple_packages.expected_record('a'*40,root)
                yield record

    def check(self,record):
        client.validate(record,record['platform'],'a'*40,record['unsigned'])

    def test_actual_diff_replays_compatibility_unsigned_identity_new_file_and_metadata(self):
        for platform in ['windows','linux','android','apple']:
            for unsigned in [True,False]:
                with self.subTest(platform=platform,unsigned=unsigned),self.fixture(platform,unsigned) as record:
                    self.check(record)
                    artifact='signed-apple-store-ios' if not unsigned and platform=='apple' else {
                        'windows':'binary-windows-client-x64','linux':'binary-linux-client-x64',
                        'android':'binary-android-apks-other','apple':'unsigned-apple-ios-archive'}[platform]
                    self.assertEqual(publisher.validate_client_source({'clientSource':record},artifact,'all' if unsigned else 'signed','a'*40),record)
                    with self.assertRaises(ValueError):publisher.validate_client_source({},artifact,'all' if unsigned else 'signed','a'*40)

    def test_identity_source_tree_mode_config_and_count_are_not_interchangeable(self):
        with self.fixture(unsigned=False) as record:
            for key,bad in [('baseCommit','d'*40),('baseTree','e'*40),('coreSourceCommit','f'*40),('overlayManifestSHA256','0'*64),
                            ('sourceOverlayCount',0),('unsigned',True),('identity',None),('diffSHA256','0'*64)]:
                value=copy.deepcopy(record);value[key]=bad
                with self.subTest(key=key),self.assertRaises(ValueError):self.check(value)

    def test_unsigned_apple_package_evidence_is_mandatory_through_producer_consumer(self):
        with self.fixture('apple',True) as record:
            for mutate in [lambda r:r.pop('swiftPackageOverlays'),
                           lambda r:r['swiftPackageOverlays'].update(coreSourceCommit='d'*40),
                           lambda r:r['swiftPackageOverlays']['packages'][0].update(diff='')]:
                bad=copy.deepcopy(record);mutate(bad)
                with self.assertRaises(ValueError):
                    publisher.validate_client_source({'clientSource':bad},'unsigned-apple-macos-archive','all','a'*40)
        for platform,unsigned in [('android',True),('apple',False)]:
            with self.fixture(platform,unsigned) as record:
                record['swiftPackageOverlays']={}
                with self.assertRaisesRegex(ValueError,'unexpected unsigned Apple'):
                    self.check(record)

    def test_diff_rows_and_original_baseline_are_verified_beyond_a_self_digest(self):
        with self.fixture() as record:
            mutations=[lambda d:d['files'][0].update(afterSHA256='0'*64),lambda d:d['files'][0].update(bytes=1),
                       lambda d:d['files'].pop(),lambda d:d['files'].append(d['files'][0]),
                       lambda d:d['baseline'].update({'source.txt':base64.b64encode(b'forged\n').decode()}),
                       lambda d:d['diff'].replace('+unsigned','+other')]
            for i,change in enumerate(mutations):
                value=copy.deepcopy(record)
                if i==5:value['diff']=change(value)
                else:change(value)
                value['diffSHA256']=client.sha(value['diff'].encode())
                with self.subTest(case=i),self.assertRaises(ValueError):self.check(value)

    def test_owned_patch_requires_inventory_exact_intermediate_bytes_and_raw_patch(self):
        with self.fixture(unsigned=False) as record:
            cfg=client.ROOT/'release/ci/owned-distribution.json';original=cfg.read_text()
            for kind in ['unreviewed','missing-files','wrong-stage','wrong-patch']:
                config=json.loads(original);entry=config['clientIdentityPatches']['desktop']
                if kind=='unreviewed':config['reviewed']=False
                elif kind=='missing-files':entry.pop('files')
                elif kind=='wrong-stage':entry['files']['source.txt']['beforeSHA256']=client.sha(b'base\n')
                else:entry['sha256']='0'*64
                cfg.write_text(json.dumps(config))
                value=copy.deepcopy(record)
                if kind=='wrong-stage':value['identity']=client.identity_definition('windows',False)
                with self.subTest(kind=kind),self.assertRaises(ValueError):self.check(value)
            cfg.write_text(original)

    def test_new_untracked_source_must_have_explicit_origin_not_a_permitted_name_only(self):
        with self.fixture() as record:
            value=copy.deepcopy(record);value['baseline']['surprise.kt']=None
            value['files'].append({'path':'surprise.kt','beforeSHA256':None,'afterSHA256':client.sha(b'new\n'),'bytes':4})
            value['diff']+=patch({'surprise.kt':None},{'surprise.kt':b'new\n'});value['diffSHA256']=client.sha(value['diff'].encode())
            with self.assertRaises(ValueError):self.check(value)
        with self.fixture(unsigned=False) as record:
            # New owned.txt is validated by its reviewed patch and cannot be
            # relabeled as an old baseline or replaced by arbitrary new bytes.
            value=copy.deepcopy(record);value['baseline']['owned.txt']=base64.b64encode(b'planted\n').decode()
            with self.assertRaises(ValueError):self.check(value)

    def test_source_resource_and_portable_path_boundaries(self):
        with self.fixture() as record:
            value=copy.deepcopy(record);value['baseline']['source.txt']='e'*(2*client.MAX_SOURCE_BYTES)
            with self.assertRaises(ValueError):self.check(value)
            value=copy.deepcopy(record);value['diff']='x'*(client.MAX_DIFF_BYTES+1)
            with self.assertRaises(ValueError):self.check(value)
        for name in ['../escape','/absolute','a\\b','.git/config','CON','trailing.']:
            with self.subTest(path=name),self.assertRaises(ValueError):client.portable(name)

    def test_crlf_is_rejected_instead_of_normalizing_a_wrong_blob(self):
        raw=b'raw baseline\n';entry={'path':'fixture','beforeGitBlob':client.blob(raw),'beforeSHA256':client.sha(raw),
             'afterSHA256':client.sha(b'changed\n'),'edits':[{'old':'raw baseline','new':'changed','count':1}]}
        self.assertEqual(client.edits(raw,entry),b'changed\n')
        with self.assertRaises(ValueError):client.edits(raw.replace(b'\n',b'\r\n'),entry)
        bad=copy.deepcopy(entry);bad['edits'][0]['count']=2
        with self.assertRaises(ValueError):client.edits(raw,bad)

    def test_final_modes_are_bound_for_transforms_identity_and_version_metadata(self):
        for unsigned in [True,False]:
            with self.fixture(unsigned=unsigned) as record:
                for name in ['source.txt','version.txt']+([] if unsigned else ['owned.txt']):
                    value=copy.deepcopy(record)
                    marker='diff --git a/'+name+' b/'+name+'\n'
                    if name=='owned.txt':
                        before=marker+'new file mode 100644\n'
                        after=marker+'new file mode 100755\n'
                    else:
                        # Git index contains the Git blob, not the SHA256 row identity.
                        body=value['diff'].split(marker,1)[1].split('\n',1)[0]
                        self.assertTrue(body.startswith('index ') and body.endswith(' 100644'))
                        before=marker+body+'\n';after=marker+'old mode 100644\nnew mode 100755\n'+body.removesuffix(' 100644')+'\n'
                    self.assertEqual(value['diff'].count(before),1)
                    value['diff']=value['diff'].replace(before,after,1);value['diffSHA256']=client.sha(value['diff'].encode())
                    with self.subTest(unsigned=unsigned,path=name),self.assertRaisesRegex(ValueError,'final mode'):
                        self.check(value)
        # An explicitly reviewed executable new identity file is allowed.
        with self.fixture(unsigned=False,owned_mode='100755') as record:self.check(record)

    def test_windows_unsigned_flag_covers_builder_and_nested_payloads_signed_stays_strict(self):
        spec=client.definition('windows');entries=[e for e in spec['files'] if e['kind']=='unsigned']
        self.assertEqual(spec['commit'],'50f503849148dd73fa4f4bc231119acf5b2f3d7a')
        self.assertEqual({e['path'] for e in entries},{'scripts/package.ts','scripts/afterPack.cjs'})
        self.assertTrue(all(e['kind']=='branding' for e in client.selected(spec,False)))  # Signed retains strict signing, with reviewed display names.
        result={}
        original={}
        for entry in entries:
            raw=(REAL_ROOT/'scripts/ci/testdata/desktop-50f50384'/Path(entry['path']).name).read_bytes()
            original[entry['path']]=raw.decode()
            for brand in spec['files']:
                if brand['path']==entry['path'] and brand['kind']=='branding':raw=client.edits(raw,brand)
            self.assertEqual(client.blob(raw),entry['beforeGitBlob'])
            self.assertEqual(client.sha(raw),entry['beforeSHA256'])
            result[entry['path']]=client.edits(raw,entry).decode()
        package=result['scripts/package.ts'];nested=result['scripts/afterPack.cjs']
        for fragment in ['unsignedWindowsPackage ? undefined : readWindowsSigningConfiguration()',
                         'forceCodeSigning: !unsignedWindowsPackage','signExecutable: unsignedWindowsPackage ? false : undefined']:
            self.assertIn(fragment,package)
        self.assertNotIn('signAndEditExecutable:',package)  # Keep resources and afterSign integrity/fuses.
        strict='const signed = await context.packager.signIf(executablePath);\n    if (!signed) {\n      throw new Error(`failed to sign ${relativePath.join("/")}`);'
        self.assertIn(strict,original['scripts/afterPack.cjs'])
        self.assertIn(strict,nested)  # Check the full patched source, including unchanged signed checks.
        for fragment in ['process.env.POLARIS_UNSIGNED_CLIENT === "1"','fs.statSync(executablePath).isFile()',
                         'continue; // Explicit unsigned candidate']:
            self.assertIn(fragment,nested)
        workflow=yaml.safe_load((REAL_ROOT/'.github/workflows/build.yml').read_text())
        steps=workflow['jobs']['build_windows_client']['steps'];first=next(s for s in steps if s.get('name')=='Checkout desktop client')
        self.assertIn('-c core.autocrlf=false -c core.eol=lf submodule update',first['run'])
        build=next(s for s in steps if s.get('name')=='Build')
        self.assertEqual(build['env']['POLARIS_UNSIGNED_CLIENT'],'1')
        overlay=next(s for s in steps if 'unsigned_clients.py windows' in s.get('run',''))
        self.assertIn('unsigned_clients.py windows\nif ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }',overlay['run'])
        signed=yaml.safe_load((REAL_ROOT/'.github/workflows/signed-release.yml').read_text())
        self.assertNotIn('POLARIS_UNSIGNED_CLIENT',json.dumps(signed))

    def test_android_min_api_guard_and_jvm_negative_controls_are_in_existing_producers(self):
        entries=client.definition('android')['files'];text='\n'.join(e.get('content','') or '\n'.join(c['new'] for c in e.get('edits',[])) for e in entries)
        for fragment in ['Build.VERSION.SDK_INT < Build.VERSION_CODES.M','@DoNotInline','@RequiresApi(Build.VERSION_CODES.M)',
                         'if (sdk < 23)','listOf(21, 22)','listOf(23, 24, 35)','SecurityException','resolve = { null }']:
            self.assertIn(fragment,text)
        for filename in ['build.yml','signed-release.yml']:
            workflow=yaml.safe_load((REAL_ROOT/'.github/workflows'/filename).read_text());steps=workflow['jobs']['build_android']['steps']
            build=next(s for s in steps if './gradlew --build-cache --parallel' in s.get('run',''))
            self.assertIn('testOtherLegacyReleaseUnitTest',build['run']);self.assertIn('testOtherReleaseUnitTest',build['run'])
            self.assertEqual([m['variant'] for m in workflow['jobs']['build_android']['strategy']['matrix']['include']],['other','other-legacy'])

    def test_signed_identity_entry_owns_composition_before_version_update(self):
        workflow=yaml.safe_load((REAL_ROOT/'.github/workflows/signed-release.yml').read_text())
        for name in ['build_android','publish_android','build_windows_client','build_linux_client','build_apple','build_apple_app_store']:
            steps=workflow['jobs'][name]['steps'];identities=[i for i,s in enumerate(steps) if 'owned_distribution.py apply' in s.get('run','')]
            self.assertEqual(len(identities),1,name)
            self.assertFalse(any('client_source.py apply' in s.get('run','') for s in steps),name)
            builds=[i for i,s in enumerate(steps) if './gradlew' in s.get('run','') or 'xcodebuild archive' in s.get('run','') or 'package:win' in s.get('run','')]
            if builds:self.assertLess(identities[0],min(builds))


    def test_android_stable_ndk_matches_both_client_layers_and_producers(self):
        spec=client.definition('android')
        raw=(REAL_ROOT/'release/dependency-sources/clients/runtime/recipes/sing-box-for-android/app/build.gradle.kts').read_bytes()
        for entry in [e for e in spec['files'] if e['path']=='app/build.gradle.kts']:
            raw=client.edits(raw,entry)
            self.assertIn(b'ndkVersion = "30.0.16248370"',raw)
            self.assertNotIn(b'ndkVersion = "28.0.13004108"',raw)
        properties=(REAL_ROOT/'scripts/ci/testdata/android-ae93152f/gradle.properties').read_bytes()
        entry=next(e for e in spec['files'] if e['path']=='gradle.properties')
        self.assertIn(b'ndkVersion=30.0.16248370\n',client.edits(properties,entry))
        for filename in ['build.yml','signed-release.yml']:
            workflow=yaml.safe_load((REAL_ROOT/'.github/workflows'/filename).read_text())
            for job in workflow['jobs'].values():
                for step in job.get('steps',[]):
                    if step.get('uses','').startswith('nttld/setup-ndk@'):
                        self.assertEqual(step['with']['ndk-version'],'r30')
                        self.assertTrue(step['with']['link-to-sdk'])
                    if step.get('name')=='Build Android':
                        self.assertEqual(step['env']['ANDROID_NDK_HOME'],'${{ steps.setup-ndk.outputs.ndk-path }}')
        workflow=yaml.safe_load((REAL_ROOT/'.github/workflows/polaris-selfcheck.yml').read_text())
        self.assertEqual(workflow['env']['NDK_ROOT'],'android-ndk-r30')
        self.assertEqual(workflow['env']['NDK_SHA256'],'753611f410d002cfcd3f3dc2ef49aad532089d3180b436c060a90bf0fcb64df2')
        self.assertEqual(workflow['env']['NDK_URL'],'https://dl.google.com/android/repository/android-ndk-r30-linux.zip')

    def test_android_release_unit_tests_are_enabled_in_the_complete_pinned_properties(self):
        spec=client.definition('android')
        entry=next(e for e in spec['files'] if e['path']=='gradle.properties')
        raw=(REAL_ROOT/'scripts/ci/testdata/android-ae93152f/gradle.properties').read_bytes()
        self.assertEqual(client.blob(raw),entry['beforeGitBlob'])
        self.assertEqual(client.sha(raw),entry['beforeSHA256'])
        self.assertEqual(entry['beforeMode'],'100644')
        self.assertEqual(entry['kind'],'compatibility')
        text=client.edits(raw,entry).decode()
        flag='android.onlyEnableUnitTestForTheTestedBuildType'
        self.assertEqual([line for line in text.splitlines() if line.startswith(flag+'=')],[flag+'=false'])
        for unsigned in [True,False]:
            self.assertIn(entry,client.selected(spec,unsigned))
        for replacement in [flag+'=true','']:
            bad=copy.deepcopy(entry)
            bad['edits'][0]['new']=bad['edits'][0]['new'].replace(flag+'=false',replacement)
            with self.subTest(replacement=replacement),self.assertRaisesRegex(ValueError,'result identity'):
                client.edits(raw,bad)
        # The adjoining producer/API controls still require both release tasks
        # and their real API21/22 rejection inputs.

    def test_jailbreak_full_package_and_numeric_marketing_versions_use_complete_source(self):
        spec=client.definition('apple')
        entries=[e for e in spec['files'] if e['path']=='Jailbreak/package.sh'];entry=entries[0]
        raw=(REAL_ROOT/'scripts/ci/testdata/apple-e232aaf2/package.sh').read_bytes()
        self.assertEqual(client.blob(raw),entry['beforeGitBlob'])
        self.assertEqual(client.sha(raw),entry['beforeSHA256'])
        self.assertEqual(entry['beforeMode'],'100755')
        self.assertEqual(entry['kind'],'branding')
        for transform in entries:raw=client.edits(raw,transform)
        script=raw.decode()
        self.assertNotRegex(script,r'(?m)^VERSION=')
        self.assertIn('MARKETING_VERSION="$MARKETING_VERSION"',script)
        self.assertIn('Set :CFBundleShortVersionString $MARKETING_VERSION',script)
        self.assertIn('Version: $DEB_VERSION\n',script)
        self.assertNotIn('Version: $MARKETING_VERSION',script)
        self.assertIn('SFI-${PACKAGE_VERSION}-${architecture}.deb',script)
        for unsigned in [True,False]:
            self.assertIn(entry,client.selected(spec,unsigned))
        # Only pure version assignments and the variable prologue of build_deb
        # are taken from the full patched source. No Xcode, ldid or dpkg runs.
        self.assertIn('python3 "$POLARIS_SOURCE_ROOT/scripts/ci/polaris_version.py" "$PACKAGE_VERSION"',script)
        self.assertNotIn('[[ "$PACKAGE_VERSION" =~',script)
        capture=script[:script.index('\nneed()')]
        start=script.index('# Apple bundle marketing')
        marketing=script[start:script.index('\necho "Packaging',start)]
        debian=script[script.index('TILDE="~"'):script.index('\nbuild_deb() {')]
        prologue=script[script.index('build_deb() {'):script.index('\n\trm -rf "$deb_root"')]
        finish='\n\tprintf "%s\\n" "$PACKAGE_VERSION" "$MARKETING_VERSION" "$DEB_VERSION" "$deb_out"\n}\nbuild_deb /var/jb iphoneos-arm64\nbuild_deb "" iphoneos-arm64e\n'
        fragment='\n'.join([capture,marketing,debian,prologue])+finish
        def evaluate(version,marketing_version,include_helper=True):
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp);directory=root/'clients/apple'
                (directory/'sing-box.xcodeproj').mkdir(parents=True)
                (directory/'sing-box.xcodeproj/project.pbxproj').write_text(
                    'MARKETING_VERSION = '+marketing_version+';\n'
                    'PRODUCT_BUNDLE_IDENTIFIER = "$(BASE_PACKAGE_IDENTIFIER).standalone";\n')
                script_path=directory/'Jailbreak/package.sh';script_path.parent.mkdir()
                script_path.write_text(fragment)
                if include_helper:
                    helper=root/'scripts/ci/polaris_version.py';helper.parent.mkdir(parents=True)
                    helper.write_bytes((REAL_ROOT/'scripts/ci/polaris_version.py').read_bytes())
                unrelated=root/'unrelated-working-directory';unrelated.mkdir()
                env=dict(os.environ,PRODUCT_NAME='sing-box')
                if version is None:env.pop('VERSION',None)
                else:env['VERSION']=version
                result=subprocess.run(['bash',str(script_path)],cwd=unrelated,env=env,capture_output=True,text=True,timeout=10)
                return result,str(directory)
        contract=json.loads((REAL_ROOT/'scripts/ci/testdata/polaris-versions.json').read_text())
        versions=contract['valid']+['2.0.0-polaris-beta.0']
        for version in versions:
            marketing_version=version.split('-')[0];deb_version=version.replace('-','~')
            with self.subTest(version=version):
                result,temp=evaluate(version,marketing_version)
                self.assertEqual(result.returncode,0,result.stderr)
                expected=[]
                for arch in ['iphoneos-arm64','iphoneos-arm64e']:
                    expected += [version,marketing_version,deb_version,temp+'/build/jailbreak/SFI-'+version+'-'+arch+'.deb']
                self.assertEqual(result.stdout.splitlines(),expected)
        for version in [None,*contract['invalid']]:
            with self.subTest(invalid_package=version):
                result,_=evaluate(version,'1.15.0')
                self.assertNotEqual(result.returncode,0)
                self.assertIn('VERSION',result.stderr)
        result,_=evaluate('1.15.0-polaris-alpha.12.1','1.15.0',include_helper=False)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('VERSION',result.stderr)
        for marketing_version in ['','1.16.0','1.15.0-alpha.12']:
            with self.subTest(invalid_marketing=marketing_version):
                result,_=evaluate('1.15.0-polaris-alpha.12',marketing_version)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('version',result.stderr.lower())
        for filename in ['build.yml','signed-release.yml']:
            workflow=yaml.safe_load((REAL_ROOT/'.github/workflows'/filename).read_text())
            for job in ['build_apple','build_apple_app_store']:
                steps=workflow['jobs'][job]['steps']
                version=next(step for step in steps if step.get('name')=='Set tag')
                package=next(step for step in steps if step.get('name')=='Build jailbreak package')
                self.assertIn('echo "VERSION=${{ needs.calculate_version.outputs.version }}"',version['run'])
                self.assertIn('make -C clients/apple build_ios_deb',package['run'])
                for arch in ['iphoneos-arm64','iphoneos-arm64e']:
                    self.assertIn('SFI-${VERSION}-'+arch+'.deb',package['run'])
