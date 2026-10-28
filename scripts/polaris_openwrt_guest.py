#!/usr/bin/env python3
"""Whole-batch isolated OpenWrt VM package/lifecycle/Naive/gVisor gates. No devices."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import signal
import shlex
import socket
import subprocess
import sys
import time
import urllib.request
sys.dont_write_bytecode = True
from polaris_openwrt import plan, require, run
from polaris_native_distribution import encode, file_info
from polaris_go_environment import verify_source
from polaris_naive_loopback import main as naive_loopback, matching_phase_pids

TUN_INTERFACE_NAME='polaris-gv0'

def fixture_tun_config(name=TUN_INTERFACE_NAME):
    # Linux IFNAMSIZ includes the trailing NUL, so the name has at most15 bytes.
    require(isinstance(name,str) and 0<len(name.encode())<16
            and not any(c in name for c in '\x00/ :\t\n'), 'invalid fixture TUN interface name')
    return {'log':{'level':'debug','output':'/tmp/polaris-gvisor.log'},
        'inbounds':[{'type':'tun','tag':'actual-gvisor','interface_name':name,
            'address':['172.31.99.1/30'],'auto_route':False,'stack':'gvisor'}],
        'outbounds':[{'type':'direct'}],
        'route':{'rules':[{'ip_cidr':['198.18.0.1/32'],'action':'route-options',
            'override_address':'127.0.0.1','override_port':18081}]}}

def phase_exit_failure(state,config_path):
    for entry in state.get('sing-box',{}).get('instances',{}).values():
        command=entry.get('command',[])
        if isinstance(command,list) and any(command[i:i+2]==['-c',config_path] for i in range(len(command)-1)):
            if entry.get('running') is False and type(entry.get('exit_code')) is int and entry['exit_code']!=0:
                return entry['exit_code']
    return None

def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

def fetch(pin,path):
    require(not path.exists(),'preserve guest input')
    with urllib.request.urlopen(pin['url'],timeout=90) as source,path.open('xb') as output:
        while data:=source.read(1024*1024):output.write(data)
    require(file_info(path)['sha256']==pin['sha256'],'official guest image hash differs')
    return {'url':pin['url'],**file_info(path)}

def ssh_command(ssh,command,data=None,timeout=300):
    return subprocess.run([*ssh,'set -eu; '+command],input=data,
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)

def checked_stdout(result,command,expected_exit=0):
    require(result.returncode==expected_exit,'guest operation failed: '+command+'\n'
        +result.stdout.decode(errors='replace')+'\n'+result.stderr.decode(errors='replace'))
    return result.stdout

def ownership_command(paths):
    require(paths and all(Path(path).is_absolute() for path in paths),'absolute installed ownership paths required')
    # Base OpenWrt has ls, but not necessarily stat. -l/-d/-n yields one
    # entry per path with numeric UID/GID, without listing directory contents.
    # Disable glob expansion when splitting the diagnostic row into fields.
    names=' '.join(shlex.quote(str(path)) for path in paths)
    return ('set -f; for owner_path in '+names+'; do '
            'owner_row=$(LC_ALL=C ls -ldn -- "$owner_path"); '
            'printf "%s\\n" "$owner_row"; set -- $owner_row; '
            'test "$#" -ge 4; test "$3:$4" = 0:0; done')

def validate(repo,expected,architecture,form,inputs,output):
    verify_source(repo,expected);config=plan(repo)
    require(not output.exists() and not output.resolve().is_relative_to(repo.resolve()),'fresh external guest output required')
    output.mkdir(parents=True);work=output/'work';work.mkdir()
    receipt=json.loads((inputs/'openwrt-receipt.json').read_bytes());core=inputs/'sing-box'
    core.chmod(0o755)  # Artifact transport drops executable mode; package ELF bytes remain pinned.
    require(receipt['sourceCommit']==expected and receipt['workflowCommit']==expected
        and receipt['architecture']==architecture and str(receipt['workflowRun'])==os.environ['GITHUB_RUN_ID']
        and str(receipt['workflowAttempt'])==os.environ['GITHUB_RUN_ATTEMPT'] and file_info(core)==receipt['core'], 'same-source/run actual core required')
    package=next(r for r in receipt['packages'] if r['format']==form)['package']
    files={'candidate':inputs/'packages'/package['name'], 'upgrade':inputs/'test-inputs'/('private-upgrade.'+form),
           'conflict':inputs/'test-inputs'/('private-conflict.'+form)}
    require(file_info(files['candidate'])==package,'candidate package bytes differ')
    for role in ['upgrade','conflict']:
        require(file_info(files[role])==receipt['privateGuestFixtures'][role+'-'+form], 'same-run private package fixture differs')
    release=config['formats'][form]['sdkRelease']
    pin=next(p for p in config['guestInputs'] if p['release']==release and p['architecture']==architecture)
    observed={role:fetch(pin[role],work/(role+'.gz' if role=='rootfs' else role+'.bin')) for role in ['rootfs','kernel']}
    disk=work/'guest-root.img'
    with gzip.open(work/'rootfs.gz','rb') as source,disk.open('xb') as destination:
        while chunk:=source.read(1024*1024):destination.write(chunk)
    with disk.open('r+b') as f:f.truncate(1024*1024*1024)
    run(['resize2fs',disk])
    key=work/'fixture-ssh-key';run(['ssh-keygen','-q','-t','ed25519','-N','','-f',key])
    network=work/'network';network.write_text("config interface 'loopback'\n option device 'lo'\n option proto 'static'\n option ipaddr '127.0.0.1'\n option netmask '255.0.0.0'\nconfig interface 'wan'\n option device 'eth0'\n option proto 'dhcp'\n")
    firewall=work/'firewall';firewall.write_text("config defaults\n option input 'ACCEPT'\n option output 'ACCEPT'\n option forward 'REJECT'\nconfig zone\n option name 'wan'\n list network 'wan'\n option input 'ACCEPT'\n option output 'ACCEPT'\n option forward 'REJECT'\n")
    for cmd in ['mkdir /etc/dropbear',f'write "{key}.pub" /etc/dropbear/authorized_keys','rm /etc/config/network',
                f'write "{network}" /etc/config/network','rm /etc/config/firewall',f'write "{firewall}" /etc/config/firewall']:
        run(['debugfs','-w','-R',cmd,disk])
    ssh_port,proxy_port=port(),port();cpu=pin['cpu']
    qemu='qemu-system-x86_64' if architecture=='x86_64' else 'qemu-system-aarch64'
    import shutil
    qemu_path=Path(shutil.which(qemu)).resolve()
    args=[qemu_path,'-accel','tcg','-cpu',cpu,'-smp','2','-m','1536','-nographic','-no-reboot',
        '-kernel',work/'kernel.bin','-append','root=/dev/vda rw rootwait console='+('ttyS0' if architecture=='x86_64' else 'ttyAMA0'),
        '-drive',f'file={disk},format=raw,if=virtio','-netdev',f'user,id=validation,hostfwd=tcp:127.0.0.1:{ssh_port}-:22,hostfwd=tcp:127.0.0.1:{proxy_port}-:1080',
        '-device','virtio-net-pci,netdev=validation']
    if architecture!='x86_64':args+=['-machine','virt']
    ssh=['ssh','-i',str(key),'-p',str(ssh_port),'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null',
         '-o','BatchMode=yes','-o','ConnectTimeout=3','root@127.0.0.1']
    checks={k:False for k in ['install','upgradeConfigurationPreserved','removeConfigurationPreserved','packageConflict',
        'procd','caBundle','naiveTLSH2','wrongCARejected','gvisorTUN','staticNoSidecar','genericCPU']}
    event_log=(output/'guest-actions.log').open('w');vm_log=(output/'guest-console.log').open('wb');process=None
    def execute(command, data=None, expected_exit=0):
        result=ssh_command(ssh,command,data)
        event_log.write('COMMAND '+command+'\nSTDOUT\n'+result.stdout.decode(errors='replace')+'\nSTDERR (SSH/remote diagnostics; not protocol stdout)\n'+result.stderr.decode(errors='replace')+'\nEXIT '+str(result.returncode)+'\n');event_log.flush()
        return checked_stdout(result,command,expected_exit)
    def upload(path,name):execute('cat > /tmp/'+name,data=path.read_bytes())
    def manager(action,filename=None,allow_failure=False):
        suffix=' /tmp/'+filename if filename else ' polaris-box'
        command=('opkg '+action if form=='ipk' else 'apk --allow-untrusted '+({'install':'add','remove':'del'}.get(action,action)))+suffix
        if allow_failure:
            result=subprocess.run([*ssh,command],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=300)
            event_log.write('NEGATIVE '+command+'\n'+result.stdout.decode(errors='replace')+'\nEXIT '+str(result.returncode)+'\n');event_log.flush()
            require(result.returncode!=0,'package conflict did not reject candidate');return
        return execute(command)
    def config_pins():
        return execute('sha256sum /etc/config/sing-box /etc/sing-box/config.json').decode()
    try:
        process=subprocess.Popen([str(x) for x in args],stdout=vm_log,stderr=subprocess.STDOUT,start_new_session=True)
        for _ in range(240):
            if process.poll() is not None:raise RuntimeError('guest exited before SSH')
            result=subprocess.run([*ssh,'true'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
            if result.returncode==0:break
            time.sleep(1)
        else:raise TimeoutError('OpenWrt SSH did not start')
        require(release.encode() in execute('cat /etc/openwrt_release'),'actual guest release differs')
        from datetime import datetime,timezone
        execute("date -u -s '"+datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')+"'")
        repository_attempts=[]
        # Bounded APK/IPK I/O preparation retries stay inside this one whole-batch run.
        # Every failure is logged; no index/dependency checks are weakened.
        for attempt in range(1,4):
            try:
                execute('opkg update' if form=='ipk' else 'apk update')
                repository_attempts.append({'attempt':attempt,'status':'all required indexes available'});break
            except ValueError as error:
                repository_attempts.append({'attempt':attempt,'status':'preparation failed','error':str(error)})
                (output/'REPOSITORY-PREPARATION.json').write_bytes(encode(repository_attempts))
                if attempt==3:raise
                execute('date -u; ip route')
                time.sleep(5*attempt)
        (output/'REPOSITORY-PREPARATION.json').write_bytes(encode(repository_attempts))
        execute(('opkg install ' if form=='ipk' else 'apk add ')+' '.join(config['dependencies']))
        execute('test -s /etc/ssl/certs/ca-certificates.crt; test -c /dev/net/tun');checks['caBundle']=True
        # Test-only controlled HTTP fixture from the same official guest feed.
        execute('opkg install uhttpd' if form=='ipk' else 'apk add uhttpd')
        http_fixture=execute('uhttpd -h 2>&1 || test -x /usr/sbin/uhttpd; sha256sum /usr/sbin/uhttpd').decode()
        for role,path in files.items():upload(path,role+'.'+form)
        manager('install','conflict.'+form)
        before=execute('sha256sum /usr/bin/sing-box')
        manager('install','candidate.'+form,allow_failure=True)
        require(execute('sha256sum /usr/bin/sing-box')==before,'conflict failure overwrote old binary')
        execute('opkg remove sing-box' if form=='ipk' else 'apk del sing-box');checks['packageConflict']=True
        # Pre-existing configuration belongs to the user even before first install.
        execute("mkdir -p /etc/sing-box /etc/config; printf '%s\\n' \"config sing-box 'main'\" \" option enabled '0'\" \" option conffile '/etc/sing-box/config.json'\" > /etc/config/sing-box; printf '%s\\n' '{\"log\":{\"level\":\"debug\"},\"inbounds\":[],\"outbounds\":[{\"type\":\"direct\"}]}' > /etc/sing-box/config.json")
        initial=config_pins();manager('install','candidate.'+form)
        require(config_pins()==initial,'initial install overwrote pre-existing user configuration')
        execute('test "$(uci get sing-box.main.enabled)" = 0; test ! -e /etc/rc.d/S99sing-box')
        expected_files=next(r for r in receipt['packages'] if r['format']==form)['payloadInventory']
        installed_paths={Path('/'+name) for name in expected_files}
        if form=='apk':
            installed_paths.update(Path('/lib/apk/packages')/name for name in
                ['polaris-box.conffiles','polaris-box.conffiles_static','polaris-box.list'])
        # Check all installed files and their directories, including shared parents.
        installed_paths.update(parent for path in list(installed_paths) for parent in path.parents)
        execute(ownership_command(sorted(installed_paths)))
        require(receipt['core']['sha256'].encode() in execute('sha256sum /usr/bin/sing-box'),'installed core differs')
        actual_version=execute('sing-box version').decode()
        require(actual_version.splitlines()[0]=='sing-box version '+config['version'],'installed version differs')
        smoke=json.loads(execute('sing-box tools cronet --expected-version '+config['cronetVersion']))
        require(smoke['linkage']=='static-cgo' and smoke['gvisorCompiled'] is True,'actual guest static Cronet/gvisor differs')
        execute('test ! -e /usr/lib/libcronet.so; '+ownership_command([Path('/usr/bin/sing-box')])+'; sing-box check -c /etc/sing-box/config.json');checks['install']=True;checks['staticNoSidecar']=True;checks['genericCPU']=True
        execute('uci set sing-box.main.enabled=1; uci commit sing-box; /etc/init.d/sing-box start');time.sleep(2)
        active_before=json.loads(execute("ubus call service list '{\"name\":\"sing-box\"}'"))
        require(any(x.get('running') is True for x in active_before.get('sing-box',{}).get('instances',{}).values()),'pre-upgrade service failed')
        initial=config_pins();manager('install','upgrade.'+form);time.sleep(2)
        active_after=json.loads(execute("ubus call service list '{\"name\":\"sing-box\"}'"))
        old_pids={x.get('pid') for x in active_before['sing-box']['instances'].values() if x.get('running')}
        new_pids={x.get('pid') for x in active_after.get('sing-box',{}).get('instances',{}).values() if x.get('running')}
        require(new_pids and not old_pids & new_pids,'upgrade did not restart previously active procd service')
        require(config_pins()==initial,'upgrade overwrote modified user configuration');checks['upgradeConfigurationPreserved']=True
        manager('remove')
        require(config_pins()==initial,'removal lost user configuration');checks['removeConfigurationPreserved']=True
        manager('install','candidate.'+form)
        require(config_pins()==initial,'reinstall overwrote retained user configuration')
        user_runner=[] if architecture=='x86_64' else ['qemu-aarch64','-cpu','cortex-a53']
        naive_loopback(core,output/'naive-tls-h2',user_runner,{'ssh':ssh,'proxyPort':proxy_port})
        naive=json.loads((output/'naive-tls-h2/RECEIPT.json').read_bytes())
        require(naive['actualOpenWrtGuestClient'] and naive['caBundleUsed'] and naive['responses']['trusted']['accepted']
            and not naive['responses']['wrong']['accepted'],'actual guest Naive TLS-H2/CA controls failed')
        checks['naiveTLSH2']=True;checks['wrongCARejected']=True
        tun_config=fixture_tun_config();tun_name=tun_config['inbounds'][0]['interface_name']
        (output/'gvisor-config-observation.json').write_bytes(encode(tun_config))
        execute('cat > /etc/sing-box/config.json',data=json.dumps(tun_config).encode())
        execute("mkdir -p /tmp/polaris-www; printf '%s' actual-gvisor-tun-response > /tmp/polaris-www/token; "
                "uhttpd -f -p 127.0.0.1:18081 -h /tmp/polaris-www >/tmp/httpd.log 2>&1 & "
                "http_pid=$!; printf '%s\\n' \"$http_pid\" > /tmp/polaris-http.pid; "
                "for attempt in 1 2 3 4 5 6 7 8 9 10; do "
                "if ! kill -0 \"$http_pid\"; then cat /tmp/httpd.log; exit 1; fi; "
                "if response=$(wget -T 2 -qO- http://127.0.0.1:18081/token 2>/tmp/http-probe.log) "
                "&& [ \"$response\" = actual-gvisor-tun-response ]; then exit 0; fi; sleep 1; done; "
                "cat /tmp/httpd.log /tmp/http-probe.log; exit 1")
        execute('uci set sing-box.main.enabled=1; uci set sing-box.main.conffile=/etc/sing-box/config.json; uci commit sing-box; /etc/init.d/sing-box start')
        deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            procd=json.loads(execute("ubus call service list '{\"name\":\"sing-box\"}'"))
            (output/'gvisor-procd-observation.json').write_bytes(encode(procd))
            failure=phase_exit_failure(procd,'/etc/sing-box/config.json')
            if failure is not None:raise RuntimeError('exact gvisor phase exited '+str(failure)+'; see procd/runtime/syslog diagnostics')
            probe=ssh_command(ssh,'ip link show '+shlex.quote(tun_name),timeout=10)
            event_log.write('TUN READINESS\n'+probe.stdout.decode(errors='replace')+probe.stderr.decode(errors='replace')+'\nEXIT '+str(probe.returncode)+'\n');event_log.flush()
            if len(matching_phase_pids(procd,'/etc/sing-box/config.json'))==1 and probe.returncode==0:break
            time.sleep(.2)
        else:raise TimeoutError('exact gvisor procd/config/TUN phase did not become ready')
        checks['procd']=True
        execute('ip route add 198.18.0.1/32 dev '+shlex.quote(tun_name))
        require(b'actual-gvisor-tun-response' in execute('wget -T 15 -qO- http://198.18.0.1:18081/token'),'actual gvisor TUN request failed');checks['gvisorTUN']=True
        require(receipt['core']['sha256'].encode() in execute('sha256sum /usr/bin/sing-box'),'running core identity changed')
        (output/'procd-observation.json').write_bytes(encode(procd));(output/'cronet-observation.json').write_bytes(encode(smoke))
        record={'schema':'polaris-openwrt-guest-receipt-v1','status':'passed','sourceCommit':expected,'sourceTree':receipt['sourceTree'],
            'architecture':architecture,'format':form,'release':release,'package':package,'core':receipt['core'],'checks':checks,'actualVersionOutput':actual_version,
            'repositoryPreparation':repository_attempts,'testOnlyHTTPFixture':{'source':'official same-release guest feed uhttpd','observation':http_fixture},'guestInputs':observed,'qemu':{'command':[str(x) for x in args],'binary':file_info(qemu_path),'version':run([qemu_path,'--version']).splitlines()[0],
                'cpu':cpu,'memoryMiB':1536,'cpus':2,'network':'user-mode; SSH/proxy forwards bound only to127.0.0.1; no TAP/host routes'},
            'workflowCommit':os.environ['GITHUB_SHA'],'workflowRun':os.environ['GITHUB_RUN_ID'],'workflowAttempt':os.environ['GITHUB_RUN_ATTEMPT'],
            'scope':'actual isolated official OpenWrt guest kernel/package manager/procd/CA/Naive TLS-H2/gvisor TUN on measured generic CPU profile',
            'genericCPURestriction':'measured qemu64 or cortex-a53 only; no claim for all physical CPUs/boards','realDeviceAcceptance':False,'signatureTrustValidated':False}
        (output/'guest-receipt.json').write_bytes(encode(record));verify_source(repo,expected);return record
    except BaseException as error:
        (output/'GUEST-FAILURE.json').write_bytes(encode({'sourceCommit':expected,'architecture':architecture,'format':form,
            'checks':checks,'error':str(error),'status':'failed','realDeviceAcceptance':False}));raise
    finally:
        try:
            try:
                if process and process.poll() is None:
                    diagnostics=[('cat /tmp/polaris-gvisor.log','gvisor-runtime.log'),
                        ('cat /tmp/httpd.log','gvisor-httpd.log'),('cat /tmp/http-probe.log','gvisor-http-probe.log'),
                        ('logread','gvisor-syslog.log'),('ip link; ip route','gvisor-links-routes.log'),
                        ('cat /etc/sing-box/config.json','gvisor-actual-config.log')]
                    for command,local in diagnostics:
                        try:
                            diagnostic=ssh_command(ssh,command,timeout=10)
                            (output/local).write_bytes(diagnostic.stdout)
                            (output/(local+'.stderr.log')).write_bytes(diagnostic.stderr)
                            event_log.write('DIAGNOSTIC '+command+' EXIT '+str(diagnostic.returncode)+'\n');event_log.flush()
                        except (OSError,subprocess.SubprocessError) as error:(output/(local+'.capture-error.log')).write_text(str(error)+'\n')
            finally:
                if process and process.poll() is None:
                    try:os.killpg(process.pid,signal.SIGTERM)
                    except ProcessLookupError:pass
                    try:process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        try:os.killpg(process.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                        process.wait(timeout=10)
        finally:event_log.close();vm_log.close()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[1]);p.add_argument('--expected-head',required=True)
    p.add_argument('--architecture',required=True);p.add_argument('--format',required=True);p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    signal.signal(signal.SIGTERM,lambda *_: (_ for _ in ()).throw(KeyboardInterrupt('CI canceled')))
    print(json.dumps(validate(a.repo,a.expected_head,a.architecture,a.format,a.inputs,a.output),indent=2))
if __name__=='__main__':main()
