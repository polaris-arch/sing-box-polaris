#!/usr/bin/env python3
"""Real isolated TLS/H2 Naive exchange with positive and wrong-CA controls."""
from pathlib import Path
import argparse,hashlib,http.server,json,os,shlex,socket,subprocess,threading,time,sys

FIXTURE_SERVER_NAME='polaris-naive.test'

def certificate_command(output,name):
    # Chromium resolves localhost internally before the wrapper DNS redirect.
    # A private test SNI reaches that redirect and stays inside the fixture.
    return ['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(output/(name+'.key')),
            '-out',str(output/(name+'.crt')),'-days','1','-subj','/CN='+FIXTURE_SERVER_NAME,
            '-addext','subjectAltName=DNS:'+FIXTURE_SERVER_NAME,'-addext','basicConstraints=critical,CA:TRUE']

def client_config(output,name,proxy_port,server_port):
    return {'log':{'level':'trace'},'inbounds':[{'type':'mixed','listen':'127.0.0.1','listen_port':proxy_port}],
            'outbounds':[{'type':'naive','tag':'measured-static-cronet','server':'127.0.0.1','server_port':server_port,
                'username':'polaris-test','password':'temporary-loopback-only','quic':False,
                'tls':{'enabled':True,'server_name':FIXTURE_SERVER_NAME,'certificate_path':str(output/(name+'.crt'))}}]}

def matching_phase_pids(state,config_path):
    return {entry['pid'] for entry in state.get('sing-box',{}).get('instances',{}).values()
            if entry.get('running') is True and type(entry.get('pid')) is int
            and entry['pid']>0 and isinstance(entry.get('command'),list)
            and any(entry['command'][i:i+2]==['-c',config_path] for i in range(len(entry['command'])-1))}

def tcp_listener(output,port):
    return any(len(fields)>=4 and fields[3].rsplit(':',1)[-1]==str(port)
               for fields in (line.split() for line in output.decode(errors='replace').splitlines()))

def cleanup_processes(processes,logs,target):
    errors=[]
    for process in reversed(processes):
        try:
            if process.poll() is None:process.terminate()
        except (OSError,subprocess.SubprocessError) as error:errors.append(str(error))
        try:
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        except (OSError,subprocess.SubprocessError) as error:errors.append(str(error))
    for log in logs:
        try:log.close()
        except OSError as error:errors.append(str(error))
    try:target.shutdown()
    except OSError as error:errors.append(str(error))
    finally:
        try:target.server_close()
        except OSError as error:errors.append(str(error))
    return errors

def certificate_rejection(log):
    text=log.lower()
    return any(marker in text for marker in ['err_cert_authority_invalid','cert authority invalid',
                                             'err_proxy_certificate_invalid','proxy certificate invalid'])

def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def request(proxy,target):
    with socket.create_connection(('127.0.0.1',proxy),timeout=3) as s:
        s.settimeout(12);s.sendall(f'GET http://127.0.0.1:{target}/polaris-naive-h2 HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\nConnection: close\r\n\r\n'.encode());out=b''
        while True:
            b=s.recv(65536)
            if not b:break
            out+=b
        return out

def main(core,output,runner=None,guest=None):
    output.mkdir(parents=True,exist_ok=False);token=b'polaris-actual-static-cronet-naive-tls-h2';counts=[]
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            counts.append(self.path);self.send_response(200);self.send_header('Content-Length',str(len(token)));self.end_headers();self.wfile.write(token)
        def log_message(self,*a):pass
    target=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=target.serve_forever,daemon=True).start();tp=target.server_port;np=port();processes=[];logs=[]
    phase_states={};results={};started_phases=[]
    def cert(name):subprocess.run(certificate_command(output,name),capture_output=True,check=True)
    def guest_call(command,data=None,check=True):
        try:result=subprocess.run([*guest['ssh'],'set -eu; '+command],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
        except subprocess.TimeoutExpired as error:
            with (output/'guest-fixture-actions.log').open('a') as log:
                log.write('COMMAND '+command+'\nTIMEOUT\n'+str(error)+'\n')
            raise
        with (output/'guest-fixture-actions.log').open('a') as log:
            log.write('COMMAND '+command+'\nSTDOUT\n'+result.stdout.decode(errors='replace')+'\nSTDERR\n'
                      +result.stderr.decode(errors='replace')+'\nEXIT '+str(result.returncode)+'\n')
        if check and result.returncode!=0:raise RuntimeError('guest fixture command failed: '+command+'\n'+result.stderr.decode(errors='replace'))
        return result
    def guest_state():
        return json.loads(guest_call('ubus call service list '+shlex.quote('{"name":"sing-box"}')).stdout)
    def capture_client(phase):
        result=guest_call('cat '+shlex.quote('/tmp/polaris-client-'+phase+'.log'),check=False)
        (output/('client-'+phase+'.log')).write_bytes(result.stdout)
        return result.stdout.decode(errors='replace')
    def start(name,config,listen):
        if guest and name.startswith('client-'):
            phase=name.removeprefix('client-');started_phases.append(phase)
            config_path='/tmp/polaris-fixture-client-'+phase+'.json'
            config['log']['output']='/tmp/polaris-client-'+phase+'.log'
            config['inbounds'][0].update(listen='0.0.0.0',listen_port=1080)
            config['outbounds'][0]['server']='10.0.2.2'
            ca=guest_call('cat /etc/ssl/certs/ca-certificates.crt').stdout
            bundle=ca+b'\n'+(output/(phase+'.crt')).read_bytes()
            ca_path='/tmp/polaris-fixture-ca-'+phase+'.pem'
            guest_call('cat > '+shlex.quote(ca_path),data=bundle)
            config['outbounds'][0]['tls']['certificate_path']=ca_path
            (output/(name+'.json')).write_text(json.dumps(config,indent=2)+'\n')
            guest_call('cat > '+shlex.quote(config_path),data=json.dumps(config).encode())
            before=guest_state();old_pids={x.get('pid') for x in before.get('sing-box',{}).get('instances',{}).values() if x.get('running')}
            guest_call('set -eu; /etc/init.d/sing-box stop; command -v netstat >/dev/null')
            deadline=time.monotonic()+90
            while time.monotonic()<deadline:
                state=guest_state()
                running=any(x.get('running') for x in state.get('sing-box',{}).get('instances',{}).values())
                listener=tcp_listener(guest_call('netstat -lnt').stdout,1080)
                if not running and not listener:break
                time.sleep(.1)
            else:raise TimeoutError(name+' previous guest phase did not stop')
            guest_call('set -eu; uci set sing-box.main.enabled=1; uci set sing-box.main.conffile='+shlex.quote(config_path)+'; uci commit sing-box; /etc/init.d/sing-box start')
            deadline=time.monotonic()+90
            while time.monotonic()<deadline:
                state=guest_state();pids=matching_phase_pids(state,config_path)
                listener=tcp_listener(guest_call('netstat -lnt').stdout,1080)
                if len(pids)==1 and not old_pids&pids and listener:
                    phase_states[phase]={'procd':state,'configPath':config_path,'pids':sorted(pids),'oldPids':sorted(p for p in old_pids if type(p) is int)}
                    (output/(phase+'-procd.json')).write_text(json.dumps(phase_states[phase],indent=2)+'\n');return
                time.sleep(.1)
            capture_client(phase);raise TimeoutError(name+' exact guest phase not ready')
        p=output/(name+'.json');p.write_text(json.dumps(config));f=(output/(name+'.log')).open('wb');logs.append(f);proc=subprocess.Popen([*list(runner or []),str(core),'run','-c',str(p)],stdout=f,stderr=subprocess.STDOUT,env={k:v for k,v in os.environ.items() if k not in ['LD_PRELOAD','LD_LIBRARY_PATH']});processes.append(proc)
        for _ in range(200):
            if proc.poll() is not None:raise RuntimeError(f'{name} exited {proc.returncode}: '+(output/(name+'.log')).read_text())
            try:
                with socket.create_connection(('127.0.0.1',listen),timeout=.1):return
            except OSError:time.sleep(.05)
        raise TimeoutError(name)
    try:
        cert('trusted');cert('wrong')
        start('naive-server',{'log':{'level':'trace'},'inbounds':[{'type':'naive','tag':'verified-h2-in','listen':'127.0.0.1','listen_port':np,'network':'tcp','users':[{'username':'polaris-test','password':'temporary-loopback-only'}],'tls':{'enabled':True,'certificate_path':str(output/'trusted.crt'),'key_path':str(output/'trusted.key'),'alpn':['h2']}}],'outbounds':[{'type':'direct'}]},np)
        for name in ['wrong','trusted']:
            cp=guest['proxyPort'] if guest else port();start('client-'+name,client_config(output,name,cp,np),cp)
            try:response=request(cp,tp)
            except (OSError,TimeoutError) as e:response=str(e).encode()
            (output/(name+'-response.bin')).write_bytes(response);results[name]={'accepted':b'200 OK' in response and token in response,'bytes':len(response),'sha256':hashlib.sha256(response).hexdigest()}
            client_log=capture_client(name) if guest else (output/('client-'+name+'.log')).read_text(errors='replace')
            if name=='wrong':
                assert results[name]['accepted'] is False and not counts,'untrusted TLS reached target'
                assert certificate_rejection(client_log),'wrong CA did not produce a certificate verification error'
            else:assert results[name]['accepted'] is True and counts==['/polaris-naive-h2'],'actual TLS-H2 Naive request failed'
        receipt={'schema':'polaris-naive-loopback-validation-v1','core':{'bytes':core.stat().st_size,'sha256':hashlib.sha256(core.read_bytes()).hexdigest()},'transport':'TCP TLS; server ALPN only h2; client QUIC=false; fixed static Cronet Naive','certificateVerification':'wrong CA rejected; matching CA accepted; insecure never enabled','responses':results,'targetPaths':counts,'fixtureServerName':FIXTURE_SERVER_NAME,'guestPhases':phase_states,'realDeviceAcceptance':False,'externalNetwork':False,'runner':list(runner or []),'actualOpenWrtGuestClient':bool(guest),'caBundleUsed':bool(guest),'certificates':{name:{'bytes':(output/(name+'.crt')).stat().st_size,'sha256':hashlib.sha256((output/(name+'.crt')).read_bytes()).hexdigest()} for name in ['wrong','trusted']}}
    except BaseException as error:
        (output/'FAILURE.json').write_text(json.dumps({'status':'failed','error':str(error),'fixtureServerName':FIXTURE_SERVER_NAME,'responses':results,'targetPaths':counts,'guestPhases':phase_states,'actualClientTCPRouteObserved':False,'realDeviceAcceptance':False},indent=2)+'\n');raise
    finally:
        original_error=sys.exc_info()[0] is not None;cleanup_errors=[]
        try:
            if guest:
                for phase in started_phases:
                    try:capture_client(phase)
                    except (OSError,subprocess.SubprocessError,RuntimeError) as error:
                        cleanup_errors.append('capture '+phase+': '+str(error))
                try:guest_call('/etc/init.d/sing-box stop')
                except (OSError,subprocess.SubprocessError,RuntimeError) as error:cleanup_errors.append(str(error))
        finally:cleanup_errors.extend(cleanup_processes(processes,logs,target))
        if cleanup_errors:
            (output/'CLEANUP-FAILURE.json').write_text(json.dumps({'errors':cleanup_errors,'originalFailurePreserved':original_error},indent=2)+'\n')
            if not original_error:raise RuntimeError('fixture cleanup failed: '+'; '.join(cleanup_errors))
    (output/'RECEIPT.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--core',type=Path,required=True);a.add_argument('--output',type=Path,required=True);a.add_argument('--runner',nargs='*',default=[]);o=a.parse_args();main(o.core.resolve(),o.output.resolve(),o.runner)
