import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile
from unittest.mock import patch, Mock
import polaris_openwrt as ow

REPO=Path(__file__).resolve().parents[1]

class OpenWrtTests(unittest.TestCase):
    def test_scope_and_linker_contract_preserve_generic_capabilities(self):
        config=ow.plan(REPO)
        self.assertEqual(config['clangInput']['revision'],'llvmorg-24-init-3796-g20e97c4b-27')
        self.assertEqual(config['clangInput']['sha256'],'968195fa0b49958e066695df2c7c985d169a20fa06eedb8fcef900a6030edcb0')
        self.assertEqual({r['architecture'] for r in config['targets']},{'x86_64','aarch64_generic'})
        self.assertEqual(len(config['guestInputs']),4)
        self.assertFalse(config['publicationEligible']);self.assertFalse(config['realDeviceAcceptance'])
        self.assertEqual(config['package']['provides'],[])

    def test_payload_preserves_binary_mode_and_has_disabled_safe_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);core=root/'core';core.write_bytes(b'inert-core')
            inventory=ow.payload(REPO,ow.plan(REPO),core,root/'payload',{'fixture':True})
            p=root/'payload';self.assertEqual((p/'usr/bin/sing-box').read_bytes(),b'inert-core')
            self.assertEqual(inventory['usr/bin/sing-box']['mode'],0o755)
            self.assertIn("option enabled '0'",(p/'etc/config/sing-box').read_text())
            self.assertEqual(json.loads((p/'etc/sing-box/config.json').read_bytes())['inbounds'],[])
            self.assertFalse(list(p.rglob('*.so')))
            for name in ['MUSL-COPYRIGHT.txt','GCC-RUNTIME-LIBRARY-EXCEPTION-3.1.txt','GPL-3.0.txt']:
                self.assertTrue((p/'usr/share/licenses/polaris-box'/name).is_file())

    def test_actual_shell_lifecycle_preserves_preexisting_and_removed_configuration(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'etc/config').mkdir(parents=True);(root/'etc/sing-box').mkdir()
            uci=root/'etc/config/sing-box';cfg=root/'etc/sing-box/config.json';uci.write_bytes(b'user uci\n');cfg.write_bytes(b'user configuration\n')
            env=dict(os.environ,IPKG_INSTROOT=str(root))
            def shell(name,*args):subprocess.run(['sh',str(REPO/'release/openwrt'/name),*args],env=env,check=True)
            shell('preinst');uci.write_bytes(b'package default');cfg.write_bytes(b'package default');shell('postinst')
            self.assertEqual(uci.read_bytes(),b'user uci\n');self.assertEqual(cfg.read_bytes(),b'user configuration\n')
            shell('prerm','remove');uci.unlink();cfg.unlink();shell('postrm','remove')
            self.assertEqual(uci.read_bytes(),b'user uci\n');self.assertEqual(cfg.read_bytes(),b'user configuration\n')
            # Manager-retained/new user paths are never overwritten by remove recovery.
            cfg.write_bytes(b'new user config');shell('postrm','remove');self.assertEqual(cfg.read_bytes(),b'new user config')

    def test_upgrade_never_disables_or_creates_removal_backup(self):
        with tempfile.TemporaryDirectory() as d:
            env=dict(os.environ,IPKG_INSTROOT=d)
            for script in ['prerm','postrm']:
                subprocess.run(['sh',str(REPO/'release/openwrt'/script),'upgrade'],env=env,check=True)
            self.assertFalse((Path(d)/'etc/polaris-box/retained-config').exists())

    def test_foreign_elf_or_dynamic_dependency_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            core=Path(d)/'core';core.write_bytes(b'not ELF')
            with self.assertRaises(ValueError):ow.check_static(core,'x86_64')
            data=bytearray(64);data[:6]=b'\x7fELF\x02\x01';data[18:20]=(62).to_bytes(2,'little');core.write_bytes(data)
            with patch.object(ow,'run',return_value=' INTERP NEEDED GLIBC_2.39'):
                with self.assertRaisesRegex(ValueError,'interpreter/glibc'):ow.check_static(core,'x86_64')
            with self.assertRaises(ValueError):ow.check_static(core,'aarch64_generic')

    def test_partial_guest_inventory_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);inputs=root/'inputs';inputs.mkdir();guests=root/'guests';guests.mkdir()
            with self.assertRaisesRegex(ValueError,'two OpenWrt'):ow.validate_assembled_openwrt(REPO,'a'*40,'b'*40,inputs,guests,root/'out','20','1')


class OwnershipRegressionTests(unittest.TestCase):
    def ipk(self,root,bad_section=None):
        import io,tarfile
        path=root/'fixture.ipk'
        with tarfile.open(path,'w:gz') as outer:
            for section in ['control.tar.gz','data.tar.gz']:
                buffer=io.BytesIO()
                with tarfile.open(fileobj=buffer,mode='w:gz') as inner:
                    entry=tarfile.TarInfo('control' if section.startswith('control') else './usr/bin/sing-box')
                    entry.uid=1001 if section==bad_section else 0;entry.gid=0;entry.size=4;inner.addfile(entry,io.BytesIO(b'test'))
                raw=buffer.getvalue();entry=tarfile.TarInfo(section);entry.uid=entry.gid=0;entry.size=len(raw);outer.addfile(entry,io.BytesIO(raw))
        return path
    def test_all_payload_and_control_archive_members_must_be_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            self.assertEqual(len(ow.archive_ownership(self.ipk(root),'ipk')['members']),4)
            for section in ['control.tar.gz','data.tar.gz']:
                with self.subTest(section=section),self.assertRaisesRegex(ValueError,'root:root'):
                    ow.archive_ownership(self.ipk(root,section),'ipk')
    def test_apk_all_directory_and_file_acl_owners_are_checked(self):
        with patch.object(ow,'run',return_value=json.dumps({'paths':[{'name':'usr','acl':{'mode':493,'user':'root','group':'root'},'files':[{'name':'bin','acl':{'mode':493,'user':'1001','group':'root'}}]}]})):
            with self.assertRaisesRegex(ValueError,'root:root'):ow.archive_ownership(Path('inert.apk'),'apk',Path('/inert/apk'))
    def test_packaging_command_explicitly_sets_virtual_root_ownership(self):
        with patch.object(ow.shutil,'which',return_value='/usr/bin/fakeroot'), patch.object(ow,'fakeroot_library',return_value=Path('/fixed/libfakeroot.so')):
            args=ow.root_owned_command(Path('/private payload'),['sh','/fixed/sdk/ipkg-build','/private payload','/out'])
            self.assertEqual(args[:5],['fakeroot','-l','/fixed/libfakeroot.so','sh','-ec'])
            self.assertIn('chown -hR 0:0 "$1"',args[5])
            self.assertEqual(args[7],'/private payload')


class APKNativeOwnerRegressionTests(unittest.TestCase):
    def test_actual_staging_identity_maps_to_root_account_names(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(ow.os,'getuid',return_value=1001), patch.object(ow.os,'getgid',return_value=1002):
            root=ow.apk_owner_root(Path(directory)/'identities')
            self.assertEqual((root/'etc/passwd').read_text(),'root:x:1001:1002:root:/root:/bin/false\n')
            self.assertEqual((root/'etc/group').read_text(),'root:x:1002:\n')
    def test_sdk_loader_never_inherits_host_glibc_preloads(self):
        original={'LD_PRELOAD':'/host/libfakeroot.so','LD_LIBRARY_PATH':'/host/glibc', 'SOURCE_DATE_EPOCH':'0'}
        self.assertEqual(ow.apk_native_environment(original),{'SOURCE_DATE_EPOCH':'0'})
        self.assertIn('LD_PRELOAD',original)
    def test_actual_root_account_names_pass_directory_and_file_ownership_audit(self):
        acl={'mode':493,'user':'root','group':'root'}
        with patch.object(ow,'run',return_value=json.dumps({'paths':[{'name':'usr/bin','acl':acl,'files':[{'name':'sing-box','acl':acl}]}]})):
            result=ow.archive_ownership(Path('inert.apk'),'apk',Path('/inert/apk'))
        self.assertEqual(set(result['members']),{'usr/bin','usr/bin/sing-box'})
        self.assertTrue(all(x['uid']==x['gid']==0 for x in result['members'].values()))


class PortableOwnerRegressionTests(unittest.TestCase):
    def inspect(self,row,exit_code=0):
        import polaris_openwrt_guest as guest,shlex
        stub='ls() { printf "%s\\n" '+shlex.quote(row)+'; return '+str(exit_code)+'; }; '
        return subprocess.run(['sh','-c',stub+'set -eu; '+guest.ownership_command([Path('/safe path'),Path('/second')])],capture_output=True)
    def test_all_root_numeric_entries_pass_without_stat(self):
        result=self.inspect('-rw-r--r-- 1 0 0 7 Jan 1 00:00 safe path')
        self.assertEqual(result.returncode,0);self.assertEqual(len(result.stdout.splitlines()),2)
    def test_nonroot_uid_or_gid_is_not_hidden_by_later_entry(self):
        for uid,gid in [(1001,0),(0,1001)]:
            with self.subTest(uid=uid,gid=gid):
                result=self.inspect(f'-rw-r--r-- 1 {uid} {gid} 7 Jan 1 00:00 safe path')
                self.assertNotEqual(result.returncode,0);self.assertEqual(len(result.stdout.splitlines()),1)
    def test_missing_utility_and_incomplete_numeric_row_fail_closed(self):
        self.assertNotEqual(self.inspect('',127).returncode,0)
        self.assertNotEqual(self.inspect('incomplete').returncode,0)


class NaiveNamespaceRegressionTests(unittest.TestCase):
    def test_certificate_and_client_sni_use_same_nonlocalhost_private_name(self):
        import polaris_naive_loopback as fixture
        self.assertEqual(fixture.FIXTURE_SERVER_NAME,'polaris-naive.test')
        self.assertNotEqual(fixture.FIXTURE_SERVER_NAME,'localhost')
        for phase in ['wrong','trusted']:
            config=fixture.client_config(Path('/inert'),phase,1080,443)
            tls=config['outbounds'][0]['tls'];args=fixture.certificate_command(Path('/inert'),phase)
            self.assertEqual(tls['server_name'],fixture.FIXTURE_SERVER_NAME)
            self.assertIn('subjectAltName=DNS:'+tls['server_name'],args)
            self.assertIn('/CN='+tls['server_name'],args)
            self.assertNotIn('insecure',tls);self.assertFalse(config['outbounds'][0]['quic'])
    def test_ready_pid_is_bound_to_exact_phase_config_not_old_listener(self):
        import polaris_naive_loopback as fixture
        state={'sing-box':{'instances':{'old':{'running':True,'pid':20,'command':['core','-c','/tmp/wrong.json']},
            'new':{'running':True,'pid':21,'command':['core','-c','/tmp/trusted.json']},
            'malformed':{'running':True,'pid':True,'command':'/tmp/trusted.json'}}}}
        self.assertEqual(fixture.matching_phase_pids(state,'/tmp/trusted.json'),{21})
        self.assertEqual(fixture.matching_phase_pids(state,'/tmp/missing.json'),set())
    def test_matching_path_elsewhere_in_command_does_not_bind_config(self):
        import polaris_naive_loopback as fixture
        state={'sing-box':{'instances':{'other':{'running':True,'pid':21,'command':['core','--unrelated','/tmp/trusted.json']}}}}
        self.assertEqual(fixture.matching_phase_pids(state,'/tmp/trusted.json'),set())
    def test_listener_is_exact_numeric_port_and_rejects_other_ports(self):
        import polaris_naive_loopback as fixture
        self.assertTrue(fixture.tcp_listener(b'tcp 0 0 :::1080 :::* LISTEN\n',1080))
        self.assertTrue(fixture.tcp_listener(b'tcp 0 0 0.0.0.0:1080 0.0.0.0:* LISTEN\n',1080))
        self.assertFalse(fixture.tcp_listener(b'tcp 0 0 0.0.0.0:11080 0.0.0.0:* LISTEN\n',1080))
        self.assertFalse(fixture.tcp_listener(b'utility failure\n',1080))
    def test_cleanup_failure_does_not_leave_other_owned_processes_or_target(self):
        import polaris_naive_loopback as fixture
        first=Mock();first.poll.return_value=None;first.terminate.side_effect=OSError('fixture process failure')
        second=Mock();second.poll.return_value=None
        log=Mock();target=Mock()
        self.assertEqual(fixture.cleanup_processes([second,first],[log],target),['fixture process failure'])
        first.wait.assert_called_once_with(timeout=5);second.terminate.assert_called_once();second.wait.assert_called_once_with(timeout=5)
        log.close.assert_called_once();target.shutdown.assert_called_once();target.server_close.assert_called_once()
    def test_wrong_ca_requires_specific_certificate_error_not_general_502(self):
        import polaris_naive_loopback as fixture
        for message in ['cert authority invalid','proxy certificate invalid','ERR_CERT_AUTHORITY_INVALID']:
            self.assertTrue(fixture.certificate_rejection(message))
        for message in ['HTTP502 Bad Gateway','connection refused','name not resolved','network timeout','']:
            self.assertFalse(fixture.certificate_rejection(message))


class TUNFixtureRegressionTests(unittest.TestCase):
    def test_linux_interface_byte_limit_and_actual_config_name(self):
        import polaris_openwrt_guest as guest
        config=guest.fixture_tun_config();name=config['inbounds'][0]['interface_name']
        self.assertEqual(name,guest.TUN_INTERFACE_NAME);self.assertLess(len(name.encode()),16)
        self.assertEqual(guest.fixture_tun_config('x'*15)['inbounds'][0]['interface_name'],'x'*15)
        for invalid in ['polaris-test-tun','x'*16,'界'*6,'','bad/name','bad name','bad\x00name']:
            with self.subTest(name=invalid),self.assertRaises(ValueError):guest.fixture_tun_config(invalid)
        self.assertEqual(config['inbounds'][0]['stack'],'gvisor');self.assertFalse(config['inbounds'][0]['auto_route'])
    def test_failed_process_is_bound_to_exact_config_and_remains_a_failure(self):
        import polaris_openwrt_guest as guest
        state={'sing-box':{'instances':{'one':{'running':False,'exit_code':1,'command':['core','run','-c','/etc/sing-box/config.json']}}}}
        self.assertEqual(guest.phase_exit_failure(state,'/etc/sing-box/config.json'),1)
        self.assertIsNone(guest.phase_exit_failure(state,'/tmp/client.json'))
        state['sing-box']['instances']['one']['running']=True
        self.assertIsNone(guest.phase_exit_failure(state,'/etc/sing-box/config.json'))


class GuestProtocolRegressionTests(unittest.TestCase):
    def test_ssh_warning_is_not_part_of_version_or_json_stdout(self):
        import polaris_openwrt_guest as guest
        result=subprocess.CompletedProcess([],0,stdout=b'sing-box version 1.15.0-alpha.12\n',stderr=b'Warning: Permanently added fixture host\n')
        with patch.object(guest.subprocess,'run',return_value=result) as run:
            actual=guest.ssh_command(['ssh','private-fixture'],'sing-box version')
        self.assertEqual(guest.checked_stdout(actual,'version').splitlines()[0],b'sing-box version 1.15.0-alpha.12')
        self.assertEqual(run.call_args.kwargs['stderr'],subprocess.PIPE)
        self.assertTrue(run.call_args.args[0][-1].startswith('set -eu; '))
    def test_fail_fast_shell_cannot_hide_earlier_owner_or_ca_failure(self):
        result=subprocess.run(['sh','-c','set -eu; false; printf masked-success'],capture_output=True)
        self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
    def test_actual_old_prerm_new_preinst_postinst_order_restores_active_service(self):
        import shlex
        with tempfile.TemporaryDirectory(prefix='polaris-upgrade-order-') as directory:
            root=Path(directory);(root/'etc/config').mkdir(parents=True);(root/'etc/sing-box').mkdir()
            (root/'etc/config/sing-box').write_text('user enabled configuration');(root/'etc/sing-box/config.json').write_text('user JSON')
            state=root/'running';state.touch();calls=root/'calls';service=root/'service'
            service.write_text('#!/bin/sh\ncase "$1" in\n running) test -f '+shlex.quote(str(state))+';;\n stop) printf "stop\n" >> '+shlex.quote(str(calls))+'; rm -f '+shlex.quote(str(state))+';;\n start) printf "start\n" >> '+shlex.quote(str(calls))+'; touch '+shlex.quote(str(state))+';;\nesac\n');service.chmod(0o755)
            for name,args in [('prerm',['upgrade']),('preinst',['upgrade']),('postinst',['configure'])]:
                body=(REPO/'release/openwrt'/name).read_text().replace('/etc/init.d/sing-box',str(service)).replace('$root/etc/',str(root)+'/etc/')
                script=root/name;script.write_text(body)
                subprocess.run(['sh',script,*args],env=dict(os.environ,IPKG_INSTROOT=''),check=True)
            self.assertTrue(state.exists());self.assertEqual(calls.read_text().splitlines(),['stop','start'])
            self.assertEqual((root/'etc/config/sing-box').read_text(),'user enabled configuration')
            self.assertEqual((root/'etc/sing-box/config.json').read_text(),'user JSON')



class GuestArtifactLayoutTests(unittest.TestCase):
    def test_actual_zip_path_projection_retains_exact_four_same_run_receipts(self):
        # upload-artifact uses the least common ancestor of its search roots;
        # archive real files relative to that root, then download/extract into
        # four artifact-name directories and call the production join helper.
        import polaris_openwrt as producer
        source='a'*40;tree='b'*40;run='1234';attempt='2'
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);downloads=root/'downloads';downloads.mkdir()
            for arch in producer.ARCHITECTURES:
                for form in ('ipk','apk'):
                    temp=root/(arch+'-'+form);guest=temp/'openwrt-guest';guest.mkdir(parents=True)
                    receipt={'schema':'polaris-openwrt-guest-receipt-v1','sourceCommit':source,'sourceTree':tree,
                             'workflowCommit':source,'workflowRun':run,'workflowAttempt':attempt,
                             'architecture':arch,'format':form}
                    (guest/'guest-receipt.json').write_text(json.dumps(receipt))
                    (guest/'guest.log').write_text('original guest log')
                    (temp/'polaris-ci').mkdir();(temp/'polaris-ci/observation.json').write_text('{}')
                    selected=[guest/'guest-receipt.json',guest/'guest.log']
                    common=Path(os.path.commonpath([str(p.parent) for p in selected]))
                    archive=temp/'actual.zip'
                    with zipfile.ZipFile(archive,'w') as z:
                        for p in selected:z.write(p,p.relative_to(common))
                    with zipfile.ZipFile(archive) as z:z.extractall(downloads/(arch+'-'+form))
            rows=producer.read_same_run_guest_receipts(downloads,source,tree,run,attempt)
            self.assertEqual(len(rows),4)
            for wrong in [(source,tree,'1235',attempt),(source,tree,run,'1'),('c'*40,tree,run,attempt),
                          (source,'c'*40,run,attempt)]:
                with self.assertRaises(ValueError):producer.read_same_run_guest_receipts(downloads,*wrong)
            # Former sibling observation input lifts common root and breaks
            # real extraction; the production loader must reject that layout.
            bad=root/'wrong-root';bad.mkdir()
            for p in downloads.iterdir():
                temp=root/p.name
                selected=[temp/'openwrt-guest/guest-receipt.json',temp/'openwrt-guest/guest.log',temp/'polaris-ci/observation.json']
                common=Path(os.path.commonpath([str(file.parent) for file in selected]))
                archive=temp/'bad-projection.zip'
                with zipfile.ZipFile(archive,'w') as z:
                    for file in selected:z.write(file,file.relative_to(common))
                with zipfile.ZipFile(archive) as z:z.extractall(bad/p.name)
            with self.assertRaises(ValueError):producer.read_same_run_guest_receipts(bad,source,tree,run,attempt)

if __name__=='__main__':unittest.main()
