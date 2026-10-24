"""Private controlled-peer runner. Never publishes or accepts user node URLs."""
import argparse
import contextlib
import ctypes
import concurrent.futures
import shutil
import sys
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import secrets
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request
from protocol_peer_diagnostic import event, safe_log_observation, safe_to_continue


SUITE_DEADLINE = None


class IdentityFailure(RuntimeError):
    """Failure to prove exact executing or archived native identity; suite STOP."""


def verify_case_product(binary,row):
    try:
        for field in ('core','sidecar'):
            fact=row[field];file=binary.parent/fact['member']
            if (file.is_symlink() or not file.is_file() or file.stat().st_size!=fact['bytes']
                    or digest(file.read_bytes())!=fact['sha256']):
                raise IdentityFailure('native executable or sidecar bytes changed before case')
    except IdentityFailure:raise
    except Exception:raise IdentityFailure('native executable or sidecar identity unavailable before case') from None


def remaining(limit):
    if SUITE_DEADLINE is None: return limit
    value = min(limit, SUITE_DEADLINE - time.monotonic())
    if value <= 0: raise TimeoutError('controlled peer suite deadline exceeded')
    return value


def digest(data):
    return hashlib.sha256(data).hexdigest()


def core_environment(directory):
    # Do not inherit repository tokens, proxy settings or dynamic-loader injection.
    return {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(directory),
            'TMPDIR': str(directory), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}


def private_write(path, data):
    data = data if isinstance(data, bytes) else data.encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
    return {'sha256': digest(data), 'bytes': len(data)}


def send_exact(sock, payload, events=None, stage='socket.send'):
    fact=event(events,stage,requestedBytes=len(payload),completedBytes=0,status='RUNNING')
    try:
        while fact['completedBytes']<len(payload):
            count=sock.send(memoryview(payload)[fact['completedBytes']:])
            if count<=0: raise EOFError('socket closed during exact write')
            fact['completedBytes']+=count
        fact['status']='PASS'
    except Exception as error:
        fact.update(status='FAIL',errorType=type(error).__name__)
        raise


def exact_read(sock, size, deadline=None, events=None, stage='socket.receive'):
    deadline = time.monotonic() + remaining(8) if deadline is None else deadline
    result = bytearray()
    fact=event(events,stage,requestedBytes=size,completedBytes=0,status='RUNNING')
    try:
        while len(result) < size:
            left = min(remaining(8), deadline - time.monotonic())
            if left <= 0: raise TimeoutError('exact payload read deadline exceeded')
            sock.settimeout(left)
            part = sock.recv(size - len(result))
            if not part: raise EOFError('peer closed before exact response')
            result.extend(part);fact['completedBytes']=len(result)
        fact['status']='PASS'
    except Exception as error:
        fact.update(status='FAIL',errorType=type(error).__name__,partialSHA256=digest(result))
        raise
    return bytes(result)


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Echo:
    def __init__(self, udp=False):
        self.udp = udp
        self.stop = threading.Event()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        try:
            self.socket.bind(('127.0.0.1', 0))
            self.socket.settimeout(.2)
            self.port = self.socket.getsockname()[1]
            self.received = 0
            self.accepted = 0
            self.errors = []
            self.lock = threading.Lock()
            self.children = []
            self.connections = []
            if not udp:
                self.socket.listen(8)
            self.thread = threading.Thread(target=self.serve)
            self.thread.start()
        except BaseException:
            self.socket.close()
            raise

    def add(self, size):
        with self.lock:
            self.received += size

    def serve_connection(self, conn):
        conn.settimeout(.2)
        try:
            while not self.stop.is_set():
                try:
                    data = conn.recv(65536)
                except socket.timeout:
                    continue
                if not data:
                    return
                self.add(len(data))
                conn.sendall(data)
        except (ConnectionResetError, BrokenPipeError):
            pass  # A closed application stream is an expected terminal event.
        except Exception as error:
            if not self.stop.is_set():
                self.errors.append(type(error).__name__)
        finally:
            conn.close()

    def serve(self):
        while not self.stop.is_set():
            try:
                if self.udp:
                    data, addr = self.socket.recvfrom(65535)
                    if addr[0] != '127.0.0.1':
                        raise ValueError('non-loopback echo peer')
                    self.add(len(data))
                    self.socket.sendto(data, addr)
                else:
                    conn, addr = self.socket.accept()
                    if addr[0] != '127.0.0.1':
                        conn.close()
                        raise ValueError('non-loopback echo peer')
                    self.accepted += 1
                    self.connections.append(conn)
                    thread = threading.Thread(target=self.serve_connection, args=(conn,))
                    self.children.append(thread)
                    thread.start()
            except socket.timeout:
                pass
            except Exception as error:
                if not self.stop.is_set():
                    self.errors.append(type(error).__name__)
                    self.stop.set()

    def close(self):
        self.stop.set()
        self.socket.close()
        for conn in self.connections:
            with contextlib.suppress(OSError):
                conn.shutdown(socket.SHUT_RDWR)
        self.thread.join(3)
        for child in self.children:
            child.join(3)
        if self.errors or self.thread.is_alive() or any(t.is_alive() for t in self.children):
            raise RuntimeError('echo thread did not join')


class UDPRelay:
    """Loopback-only datagram observation without packet privileges or decryption."""
    def __init__(self, target):
        self.front = None
        self.back = None
        try:
            self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.front.bind(('127.0.0.1', 0))
            self.port = self.front.getsockname()[1]
            self.back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.back.bind(('127.0.0.1', 0))
            self.back.connect(('127.0.0.1', target))
            self.client = None
            self.counts = [0, 0]
            self.errors = []
            self.stop = threading.Event()
            self.thread = threading.Thread(target=self.serve)
            self.thread.start()
        except BaseException:
            for sock in (self.front, self.back):
                if sock is not None: sock.close()
            raise

    def serve(self):
        with selectors.DefaultSelector() as selector:
            selector.register(self.front, selectors.EVENT_READ, 0)
            selector.register(self.back, selectors.EVENT_READ, 1)
            while not self.stop.is_set():
                for key, _ in selector.select(.1):
                    try:
                        data, addr = key.fileobj.recvfrom(65535)
                        if addr[0] != '127.0.0.1':
                            raise ValueError('non-loopback relay peer')
                        self.counts[key.data] += 1
                        if key.data == 0:
                            if self.client not in (None, addr):
                                raise ValueError('unexpected second QUIC client')
                            self.client = addr
                            self.back.send(data)
                        elif self.client:
                            self.front.sendto(data, self.client)
                    except Exception as err:
                        self.errors.append(type(err).__name__)
                        self.stop.set()
                        return

    def close(self):
        self.stop.set()
        self.thread.join(3)
        self.front.close()
        self.back.close()
        if self.thread.is_alive() or self.errors:
            raise RuntimeError('UDP observer cleanup or transport failed')


def process_group_members(group):
    # Linux /proc verifies descendants in our new, private process group.
    if not Path('/proc').is_dir():
        raise RuntimeError('this initial runner requires Linux /proc cleanup proof')
    found = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
            if int(fields[2]) == group:
                found.append(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return found


class CoreProcess:
    def __init__(self, binary, config, directory, name, expected_hash, events=None):
        self.events=events
        self.role=name
        self.source_root=Path(__file__).resolve().parents[2]
        event(events,name+'.process.spawn')
        self.log_path = directory / (name + '.private.log')
        self.config_path = directory / (name + '.private.json')
        self.config_fact = private_write(self.config_path, json.dumps(config, separators=(',', ':')))
        self.log = os.fdopen(os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')
        env = core_environment(directory)
        try:
            self.process = subprocess.Popen([str(binary), '--disable-color', 'run', '-c', str(self.config_path)],
                                            cwd=binary.parent, env=env, stdout=self.log, stderr=subprocess.STDOUT,
                                            start_new_session=True)
        except BaseException:
            self.log.close()
            raise
        self.pid = self.process.pid
        self.pidfd = None
        self.start_identity = None
        self.stopped = False
        self.cleanup = None
        try:
            self.pidfd = os.pidfd_open(self.pid)
            self.start_identity = process_identity(self.pid)
            actual = Path(f'/proc/{self.pid}/exe').read_bytes()
            if digest(actual) != expected_hash:
                raise RuntimeError('actual process ELF hash differs')
            self.bound_sha256 = expected_hash
            event(events,name+'.process.identity',pid=self.pid,startTicks=self.start_identity['startTicks'],coreSHA256=expected_hash)
        except Exception as primary:
            try: self.close()
            except Exception as secondary: primary.add_note('startup cleanup also failed: ' + type(secondary).__name__)
            finally: self.log.close()
            raise

    def wait_tcp(self, port):
        fact=event(self.events,self.role+'.readiness.tcp',status='RUNNING')
        end = time.monotonic() + remaining(10)
        while time.monotonic() < end:
            if self.process.poll() is not None:
                raise RuntimeError('core exited during readiness')
            try:
                with socket.create_connection(('127.0.0.1', port), .2):
                    fact['status']='PASS'
                    return
            except OSError:
                time.sleep(.05)
        raise TimeoutError('loopback listener not ready')

    def wait_udp(self, port):
        fact=event(self.events,self.role+'.readiness.udp',status='RUNNING')
        end = time.monotonic() + remaining(10)
        expected = '0100007F:' + format(port, '04X')
        while time.monotonic() < end:
            if self.process.poll() is not None: raise RuntimeError('peer exited before UDP readiness')
            inodes = set()
            for path in Path(f'/proc/{self.pid}/fd').iterdir():
                try: target = os.readlink(path)
                except FileNotFoundError: continue
                matched = re.fullmatch(r'socket:\[(\d+)\]', target)
                if matched: inodes.add(matched[1])
            for line in Path(f'/proc/{self.pid}/net/udp').read_text().splitlines()[1:]:
                fields = line.split()
                if fields[1] == expected and fields[9] in inodes:
                    fact['status']='PASS';return
            time.sleep(.05)
        raise TimeoutError('exact peer-owned UDP socket not ready')

    def wait_assigned(self):
        fact=event(self.events,self.role+'.readiness.assigned',status='RUNNING')
        end = time.monotonic() + remaining(10)
        while time.monotonic() < end:
            if self.process.poll() is not None: raise RuntimeError('MASQUE client exited before readiness')
            if re.search(r'assigned 198\.18\.0\.[0-9]+/', self.log_path.read_text(errors='replace')):
                fact['status']='PASS';return
            time.sleep(.05)
        raise TimeoutError('MASQUE assignment readiness not observed')


    def close(self):
        if self.stopped:
            return self.cleanup
        forced = False
        pre_terminate=self.process.poll()
        actions=[]
        event(self.events,self.role+'.process.close.begin',pid=self.pid,exitBeforeTerminate=pre_terminate)
        if pre_terminate is None:
            current_identity = process_identity(self.pid)
            if self.start_identity is None:
                # Still our unreaped Popen child in its newly created group.
                if current_identity['pgrp'] != self.pid or current_identity['session'] != self.pid:
                    raise RuntimeError('new child group identity unavailable; no signal sent')
                self.start_identity = current_identity
            if current_identity != self.start_identity:
                raise RuntimeError('owned process identity changed; no signal sent')
            if self.pidfd is None: raise RuntimeError('owned child pidfd unavailable; deferred to exact subreaper cleanup')
            signal.pidfd_send_signal(self.pidfd, signal.SIGTERM)
            actions.append(event(self.events,self.role+'.process.signal',signal='SIGTERM',pidfdBound=True))
            try:
                self.process.wait(15)
            except subprocess.TimeoutExpired:
                forced = True
                signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
                actions.append(event(self.events,self.role+'.process.signal',signal='SIGKILL',pidfdBound=True))
                self.process.wait(5)
        self.log.close()
        if self.pidfd is not None:
            os.close(self.pidfd)
            self.pidfd = None
        remaining = process_group_members(self.pid)
        raw = self.log_path.read_bytes()
        close_error = any(s in raw.lower() for s in [b'did not closed properly', b'close timeout', b'close timed out', b'panic:', b'fatal'])
        self.cleanup = {'role':self.role,'pid': self.pid, 'startIdentity': self.start_identity, 'exitCode': self.process.returncode, 'forcedKill': forced,
                        'boundCoreSHA256':getattr(self,'bound_sha256',None),
                        'exitBeforeTerminate':pre_terminate,'terminationActions':actions,
                        'safeLog':safe_log_observation(raw,self.source_root),
                        'remainingGroup': remaining, 'cleanupErrorLog': close_error,
                        'privateLogSHA256': digest(raw), 'privateLogBytes': len(raw)}
        self.stopped = True
        event(self.events,self.role+'.process.close.observed',exitCode=self.process.returncode,forcedKill=forced,cleanupErrorLog=close_error)
        if forced or remaining or close_error or self.process.returncode != 0:
            raise RuntimeError('core graceful cleanup not proven')
        return self.cleanup


def process_snapshot():
    result = {}
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal(): continue
        try:
            fields = (entry/'stat').read_text().rsplit(')', 1)[1].split()
            result[int(entry.name)] = {'pid':int(entry.name), 'ppid':int(fields[1]),
                'startTicks':int(fields[19]), 'state':fields[0]}
        except (FileNotFoundError, ProcessLookupError): pass
    return result


def descendant_rows(snapshot, parent):
    owned = {parent}; result = {}
    while True:
        new = {pid:row for pid,row in snapshot.items() if row['ppid'] in owned and pid not in owned}
        if not new: return result
        result.update(new); owned.update(new)


def drain_owned_children():
    """Only this runner's actual descendants/adopted orphans; signal exact pidfds."""
    root = os.getpid(); handles = {}; records = []; forced = False
    deadline = time.monotonic()+15; final_deadline = deadline+5
    try:
        while True:
            # All original Popen owners have already been waited by each case.
            while True:
                try:
                    pid, _ = os.waitpid(-1, os.WNOHANG)
                    if pid == 0: break
                except ChildProcessError: break
            rows = descendant_rows(process_snapshot(), root)
            if not rows: return {'remaining': [], 'forcedKill':forced, 'retired':records}
            for pid, row in rows.items():
                key = (pid, row['startTicks'])
                if key not in handles:
                    try: fd = os.pidfd_open(pid)
                    except ProcessLookupError: continue
                    current = process_snapshot()
                    now_owned = descendant_rows(current, root)
                    if pid not in now_owned or now_owned[pid]['startTicks'] != row['startTicks']:
                        os.close(fd)
                        raise RuntimeError('descendant identity changed; unknown process not signaled')
                    handles[key] = fd
                    records.append({'pid':pid,'startTicks':row['startTicks'],'source':'own-descendant-or-subreaper-adoption'})
                    try: signal.pidfd_send_signal(fd, signal.SIGTERM)
                    except ProcessLookupError: pass
                if time.monotonic() >= deadline:
                    forced = True
                    try: signal.pidfd_send_signal(handles[key], signal.SIGKILL)
                    except ProcessLookupError: pass
            if time.monotonic() >= final_deadline:
                raise RuntimeError('owned descendant retirement deadline exceeded')
            time.sleep(.05)
    finally:
        for fd in handles.values(): os.close(fd)


@contextlib.contextmanager
def owned_child_scope(receipt):
    if descendant_rows(process_snapshot(), os.getpid()):
        raise RuntimeError('runner already has unknown children; ownership scope rejected')
    library = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    if library.prctl(37, ctypes.byref(previous), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'cannot read process child-subreaper state')
    if library.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'cannot set process-only child-subreaper state')
    primary = None
    try:
        yield
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup_error = None
        try:
            observed = drain_owned_children(); receipt['descendantRetirement'] = observed
            if observed['retired'] or observed['forcedKill']:
                cleanup_error = RuntimeError('core left descendants; recovered but graceful cleanup failed')
        except Exception as error:
            cleanup_error = error
            receipt['descendantRetirement'] = {'status':'UNKNOWN','errorType':type(error).__name__}
        if library.prctl(36, previous.value, 0, 0, 0) != 0:
            cleanup_error = OSError(ctypes.get_errno(), 'cannot restore process-only subreaper state')
        if cleanup_error is not None:
            receipt['status'] = 'FAIL'
            if primary is not None: primary.add_note('owned descendant cleanup also failed: '+type(cleanup_error).__name__)
            else: raise cleanup_error


def process_identity(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return {'pid': pid, 'pgrp': int(fields[2]), 'session': int(fields[3]), 'startTicks': int(fields[19])}


def certificate(directory, name):
    """One-day private CA and CA-signed controlled.invalid leaf; never install trust."""
    ca_key, ca = directory/(name+'-ca.key'), directory/(name+'-ca.pem')
    key, csr, cert = directory/(name+'.key'), directory/(name+'.csr'), directory/(name+'.pem')
    ext = directory/(name+'.ext')
    private_write(ext, 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:controlled.invalid,IP:127.0.0.1\n')
    commands = [
        ['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-sha256',
         '-subj','/CN=Controlled Peer Temporary CA','-addext','basicConstraints=critical,CA:TRUE',
         '-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',str(ca_key),'-out',str(ca)],
        ['openssl','req','-new','-newkey','rsa:2048','-nodes','-sha256','-subj','/CN=controlled.invalid',
         '-keyout',str(key),'-out',str(csr)],
        ['openssl','x509','-req','-in',str(csr),'-CA',str(ca),'-CAkey',str(ca_key),
         '-set_serial',str(secrets.randbits(128) or 1),'-days','1','-sha256','-extfile',str(ext),'-out',str(cert)]]
    for command in commands:
        if subprocess.run(command,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=remaining(25)).returncode:
            raise RuntimeError('temporary test certificate generation failed')
    for path in (ca_key,ca,key,csr,cert): path.chmod(0o600)
    return ca.read_text(), cert.read_text(), key.read_text()


def configs(kind, peer_port, client_peer_port, mixed_port, ca, cert, key, password, echo_ports, mutation=None):
    server_tls = {'enabled':True,'certificate':[cert],'key':[key],'alpn':['h2' if kind=='naive-h2' else 'h3']}
    client_tls = {'enabled':True,'server_name':'wrong.invalid' if mutation=='wrong-sni' else 'controlled.invalid','certificate':[ca]}
    username='controlled-peer'
    auth = {'username':username,'password':password}
    peer = {'log':{'level':'debug'},'outbounds':[{'type':'direct','tag':'echo-only'}],
            'route':{'rules':[{'inbound':['peer'],'ip_cidr':['127.0.0.1/32'],'port':echo_ports,'action':'route','outbound':'echo-only'},{'action':'reject'}]}}
    client = {'log':{'level':'debug'},'inbounds':[{'type':'mixed','tag':'mixed-test','listen':'127.0.0.1','listen_port':mixed_port}],
              'route':{'rules':[{'inbound':['mixed-test'],'ip_cidr':['127.0.0.1/32' if kind.startswith('naive') else '198.18.0.1/32'],'port':echo_ports,'action':'route','outbound':'controlled-peer'},{'action':'reject'}]}}
    common={'tag':'controlled-peer','server':'127.0.0.1','server_port':client_peer_port,
            'username':username,'password':password if mutation!='wrong-auth' else password+'-wrong','tls':client_tls,
            'connect_timeout':'5s'}
    if kind.startswith('naive'):
        peer['inbounds']=[{'type':'naive','tag':'peer','listen':'127.0.0.1','listen_port':peer_port,
                         'network':'tcp' if kind=='naive-h2' else 'udp','users':[auth],'tls':server_tls}]
        client['outbounds']=[dict(common,type='naive',quic=kind=='naive-h3')]
    else:
        peer['endpoints']=[{'type':'masque-server','tag':'peer','listen':'127.0.0.1','listen_port':peer_port,
            'system':False,'mtu':1280,'path':'/controlled-ip/','address':['198.18.0.1/24'],'advertise_routes':['198.18.0.1/32'],
            'version':[3],'users':[auth],'tls':server_tls}]
        client['endpoints']=[dict(common,type='masque-client',system=False,mtu=1280,version=3,
            path='/wrong-ip/' if mutation=='wrong-path' else '/controlled-ip/',
            disable_version_fallback=True,on_demand=kind.endswith('on-demand'))]
    for config in (peer, client):
        config['dns'] = {'servers':[{'type':'hosts','tag':'test-hosts','predefined':{'controlled.invalid':['127.0.0.1']}}], 'final':'test-hosts'}
    return peer,client


def socks_connect(port, target, destination_port, events=None, label='client'):
    event(events,label+'.socks.tcp_connect')
    conn=socket.create_connection(('127.0.0.1',port),remaining(5))
    conn.settimeout(remaining(8))
    deadline = time.monotonic() + remaining(8)
    try:
        send_exact(conn,b'\x05\x01\x00',events,label+'.socks.greeting.send')
        if exact_read(conn,2,deadline,events,label+'.socks.greeting.receive')!=b'\x05\x00':raise ValueError('SOCKS auth mode differs')
        send_exact(conn,b'\x05\x01\x00\x01'+socket.inet_aton(target)+struct.pack('!H',destination_port),events,label+'.socks.connect.send')
        reply=exact_read(conn,4,deadline,events,label+'.socks.connect.response')
        event(events,label+'.socks.connect.status',version=reply[0],replyCode=reply[1],addressType=reply[3])
        if reply[0]!=5 or reply[1]!=0:raise ConnectionError('SOCKS controlled-peer connection rejected')
        if reply[3]==1:exact_read(conn,6,deadline,events,label+'.socks.connect.address')
        elif reply[3]==4:exact_read(conn,18,deadline,events,label+'.socks.connect.address')
        elif reply[3]==3:exact_read(conn,exact_read(conn,1,deadline,events,label+'.socks.connect.address_length')[0]+2,deadline,events,label+'.socks.connect.address')
        else:raise ValueError('unknown SOCKS address')
        return conn
    except BaseException:
        conn.close();raise


def identity(binary, row, expected_source, expected_hash, diagnostic=False):
    if row['schema']!='polaris-upstream-native-receipt-v1' or row['sourceCommit']!=expected_source:
        raise ValueError('producer source mismatch')
    if row['core']['sha256']!=expected_hash or digest(binary.read_bytes())!=expected_hash:
        raise ValueError('approved core bytes differ')
    if row['target']!='linux/amd64' or not diagnostic and row['finalPackageCronetSmoke']['status']!='passed':
        raise ValueError('requires already smoked Linux native producer row')
    if not {'with_naive_outbound','with_quic','with_gvisor'} <= set(row['tags'].split(',')):
        raise ValueError('not the required complete native profile')
    if row['variant']['linkage']=='shared-purego':
        side=binary.parent/row['sidecar']['member']
        if digest(side.read_bytes())!=row['sidecar']['sha256']:raise ValueError('Cronet sidecar bytes differ')
    elif row['variant']['linkage']!='static-cgo':
        raise ValueError('unknown native linkage')
    version=subprocess.check_output([str(binary),'version'],text=True,timeout=15,cwd=binary.parent,env=core_environment(binary.parent))
    if 'Revision: '+expected_source not in version or 'sing-box version '+row['version']+'\n' not in version:
        raise ValueError('actual executable identity differs')
    return {'source':expected_source,'version':row['version'],'coreSHA256':expected_hash,
            'nativeRowSHA256':digest(json.dumps(row,sort_keys=True).encode()),'profile':row['variant'],
            'sidecar':row['sidecar'],'runtimeVersionOutputSHA256':digest(version.encode())}


def socks_udp(port, events=None, label='client'):
    event(events,label+'.udp_associate.tcp_connect')
    control = socket.create_connection(('127.0.0.1', port), remaining(5))
    control.settimeout(remaining(8))
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1', 0)); udp.settimeout(remaining(8))
    try:
        send_exact(control,b'\x05\x01\x00',events,label+'.udp_associate.greeting.send')
        if exact_read(control,2,events=events,stage=label+'.udp_associate.greeting.receive') != b'\x05\x00': raise ValueError('SOCKS UDP auth differs')
        send_exact(control,b'\x05\x03\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', udp.getsockname()[1]),events,label+'.udp_associate.request.send')
        reply = exact_read(control,4,events=events,stage=label+'.udp_associate.response')
        event(events,label+'.udp_associate.status',version=reply[0],replyCode=reply[1],addressType=reply[3])
        if reply != b'\x05\x00\x00\x01': raise ValueError('SOCKS UDP association is not loopback IPv4')
        address = socket.inet_ntoa(exact_read(control,4,events=events,stage=label+'.udp_associate.address'))
        target_port = struct.unpack('!H',exact_read(control,2,events=events,stage=label+'.udp_associate.port'))[0]
        if address not in ('0.0.0.0', '127.0.0.1') or not target_port: raise ValueError('SOCKS UDP relay escaped loopback')
        udp.connect(('127.0.0.1', target_port))
        return control, udp
    except BaseException:
        control.close(); udp.close(); raise


def tcp_exchange(mixed, target, port, sizes=(1, 4096, 131071), keep=False, events=None, label='client', facts=None):
    facts = [] if facts is None else facts
    conn = socks_connect(mixed,target,port,events,label)
    succeeded = False
    deadline = time.monotonic() + remaining(20)
    try:
        for size in sizes:
            payload = secrets.token_bytes(size)
            fact={'bytes':size,'sentSHA256':digest(payload),'status':'RUNNING'};facts.append(fact)
            send_exact(conn,payload,events,label+'.tcp.payload.send')
            received = exact_read(conn,size,deadline,events,label+'.tcp.payload.receive')
            if payload != received: raise RuntimeError('TCP echoed payload bytes differ')
            fact.update(receivedSHA256=digest(received),status='PASS')
        succeeded = True
        return facts, conn if keep else None
    finally:
        if not keep or not succeeded: conn.close()


def udp_exchange(mixed,target,port,events=None,label='client',facts=None):
    facts=[] if facts is None else facts
    control, udp = socks_udp(mixed,events,label)
    try:
        header = b'\x00\x00\x00\x01' + socket.inet_aton(target) + struct.pack('!H', port)
        for size in (1, 64, 1200):
            payload = secrets.token_bytes(size)
            fact={'bytes':size,'sentSHA256':digest(payload),'status':'RUNNING'};facts.append(fact)
            sent=udp.send(header + payload)
            event(events,label+'.udp.payload.send',requestedBytes=len(header)+size,completedBytes=sent)
            if sent!=len(header)+size: raise RuntimeError('UDP fixture datagram write was truncated')
            receive=event(events,label+'.udp.payload.receive',status='RUNNING')
            try:response = udp.recv(65535)
            except Exception as error:
                receive.update(status='FAIL',errorType=type(error).__name__);raise
            receive.update(status='RECEIVED',completedBytes=len(response),sha256=digest(response))
            if response != header + payload: raise RuntimeError('UDP address, boundary or payload differs')
            fact.update(receivedSHA256=digest(response[len(header):]),datagramBoundary=True,status='PASS')
            receive['status']='PASS'
        return facts
    finally:
        udp.close(); control.close()


def _bound_library(process, binary, row):
    if process.process.poll() is not None or process_identity(process.pid) != process.start_identity:
        raise RuntimeError('actual core identity no longer live')
    if digest(Path(f'/proc/{process.pid}/exe').read_bytes()) != row['core']['sha256']:
        raise RuntimeError('actual executing ELF changed')
    if row['variant']['linkage'] != 'shared-purego':
        return {'linkage': 'static-cgo', 'coreSHA256': row['core']['sha256']}
    side = (binary.parent / row['sidecar']['member']).resolve(strict=True)
    info = side.stat()
    expected = (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
    matched = []
    for line in Path(f'/proc/{process.pid}/maps').read_text().splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6 or fields[5] != str(side): continue
        major, minor = (int(x, 16) for x in fields[3].split(':'))
        if (major, minor, int(fields[4])) != expected: raise RuntimeError('mapped Cronet file identity differs')
        matched.append(fields[1])
    if not matched or not any('x' in mode for mode in matched): raise RuntimeError('actual native Cronet mapping not proven')
    if digest(side.read_bytes()) != row['sidecar']['sha256']: raise RuntimeError('mapped Cronet source bytes changed')
    return {'linkage': 'shared-purego', 'pid':process.pid, 'startIdentity':process.start_identity, 'sha256': row['sidecar']['sha256'], 'device': list(expected[:2]), 'inode': expected[2], 'mappedExecutable': True}


def bound_library(process,binary,row):
    try:return _bound_library(process,binary,row)
    except Exception:raise IdentityFailure('actual native executable or Cronet mapping identity not proven') from None


def assert_port_released(port, udp=False):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as sock:
        if not udp: sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', port))
        if not udp: sock.listen(1)
    return {'port': port, 'protocol': 'udp' if udp else 'tcp', 'released': True}


def retire_old_stream(conn,events=None):
    nonce = secrets.token_bytes(32)
    try:
        conn.settimeout(remaining(2))
        send_exact(conn,nonce,events,'healthy.retired_stream.send')
        fact=event(events,'healthy.retired_stream.receive',status='RUNNING')
        retired = conn.recv(32) == b''
        fact['status']='CLOSED' if retired else 'UNEXPECTED_PAYLOAD'
    except (socket.timeout, TimeoutError):
        raise RuntimeError('retired stream close is unknown after timeout')
    except (ConnectionResetError, BrokenPipeError):
        retired = True
        event(events,'healthy.retired_stream.closed_reset')
    finally:
        conn.close()
    if not retired: raise RuntimeError('retired stream returned a new payload')
    return {'nonceSHA256':digest(nonce),'transportClosed':True}


def negative_evidence(kind, mutation, client_raw, peer_raw):
    patterns = {
        'wrong-auth': r'authorization failed|authentication required|status: 407|407 Proxy Authentication',
        'wrong-ca': r'ERR_CERT_AUTHORITY_INVALID|cert authority invalid|certificate signed by unknown authority|unknown certificate authority',
        'wrong-sni': r'ERR_CERT_COMMON_NAME_INVALID|cert common name invalid|certificate is valid for controlled\.invalid(?:, 127\.0\.0\.1)?, not wrong\.invalid',
        'wrong-path': r'unexpected path: /wrong-ip/|unexpected status: 404',
    }
    if mutation == 'wrong-auth' and kind.startswith('masque'):
        patterns['wrong-auth'] = r'authentication failed: (?:username=|missing or malformed)|unexpected status: 401'
    for role, raw in (('client', client_raw), ('peer', peer_raw)):
        raw = raw if isinstance(raw, bytes) else raw.encode()
        matched = re.search(patterns[mutation].encode(), raw, re.I)
        if matched:
            fragment = matched.group().decode('ascii', errors='replace')
            if len(fragment) > 256: raise RuntimeError('rejection evidence fragment exceeded bound')
            return {'category':mutation, 'specificRejectionObserved':True, 'logRole':role,
                    'privateRawLogSHA256':digest(raw), 'privateRawLogBytes':len(raw), 'byteOffset':matched.start(),
                    'matchedAllowlistedFragment':fragment, 'matcher':patterns[mutation]}
    raise RuntimeError('negative lacks actual peer TLS/auth/path rejection evidence')


def config_check(binary, config_path, directory, name, records=None):
    record={'role':name,'configurationSHA256':digest(config_path.read_bytes()),'configurationBytes':config_path.stat().st_size,'status':'RUNNING'}
    if records is not None: records.append(record)
    result = subprocess.run([str(binary), 'check', '-c', str(config_path)], cwd=binary.parent,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=remaining(20), env=core_environment(directory))
    fact = private_write(directory / (name + '-check.private.log'), result.stdout)
    record.update(exitCode=result.returncode,status='PASS' if result.returncode==0 else 'FAIL',privateLog=fact)
    if result.returncode != 0: raise RuntimeError('generated controlled configuration failed actual core check')
    return fact


def run_case(binary, row, root, kind, mutation=None):
    directory = Path(tempfile.mkdtemp(prefix=kind+'-', dir=root)); directory.chmod(0o700)
    echo = None; udp_echo = None
    relay = None; processes = []; old_connection = None; reserved_tcp = None
    result = {'kind': kind, 'mutation': mutation, 'status': 'RUNNING', 'cleanup': [],
              'expectedCoreSHA256':row['core']['sha256'],
              'events':[], 'configurationChecks':[], 'fixturesJoined':False, 'identityUncertain':False,
              'rawConfigurationPubliclyRetained': False, 'privateFilesDeletedAtSuiteEnd': True}
    events=result['events']
    primary = None
    peer_port = None; mixed_ports = []
    try:
        identity_event=event(events,'case.native_identity.verify',status='RUNNING')
        verify_case_product(binary,row)
        identity_event['status']='PASS'
        event(events,'case.certificate')
        ca, cert, key = certificate(directory, 'controlled.invalid')
        password = secrets.token_hex(24)
        if descendant_rows(process_snapshot(),os.getpid()):
            result['identityUncertain']=True
            raise RuntimeError('unexpected children before isolated case')
        event(events,'case.fixtures.start')
        echo = Echo()
        udp_echo = Echo(udp=True)
        peer_port = free_port(socket.SOCK_STREAM if kind == 'naive-h2' else socket.SOCK_DGRAM)
        if kind != 'naive-h2':
            # Hold the TCP port without listen: no TCP/H2 server can satisfy fallback.
            reserved_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            relay = UDPRelay(peer_port)
            reserved_tcp.bind(('127.0.0.1', relay.port))
        peer_cfg, _ = configs(kind, peer_port, relay.port if relay else peer_port, 1, ca, cert, key,
                              password, [echo.port, udp_echo.port])
        config_file = directory / 'peer-check.private.json'; private_write(config_file, json.dumps(peer_cfg))
        event(events,'peer.configuration.check')
        result['peerCheck'] = config_check(binary,config_file,directory,'peer',result['configurationChecks'])
        try: peer = CoreProcess(binary,peer_cfg,directory,'peer',row['core']['sha256'],events)
        except Exception:
            result['identityUncertain']=True;raise
        processes.append(peer)
        if kind == 'naive-h2': peer.wait_tcp(peer_port)
        else: peer.wait_udp(peer_port)
        def start_client(label, alter=None):
            mixed = free_port(); mixed_ports.append(mixed)
            _, cfg = configs(kind, peer_port, relay.port if relay else peer_port, mixed, ca, cert, key,
                             password, [echo.port, udp_echo.port], alter)
            if alter == 'wrong-ca':
                wrong_ca, _, _ = certificate(directory, label + '-wrong-ca')
                (cfg.get('outbounds') or cfg['endpoints'])[0]['tls']['certificate'] = [wrong_ca]
            path = directory / (label + '-check.private.json'); private_write(path, json.dumps(cfg))
            event(events,label+'.configuration.check')
            config_check(binary,path,directory,label,result['configurationChecks'])
            try: proc = CoreProcess(binary,cfg,directory,label,row['core']['sha256'],events)
            except Exception:
                result['identityUncertain']=True;raise
            processes.append(proc)
            proc.wait_tcp(mixed)
            if kind.startswith('masque') and alter is None: proc.wait_assigned()
            return proc, mixed
        target = '127.0.0.1' if kind.startswith('naive') else '198.18.0.1'
        healthy, mixed = start_client('healthy')
        result['healthyTCP']=[]
        _, old_connection = tcp_exchange(mixed,target,echo.port,keep=True,events=events,label='healthy',facts=result['healthyTCP'])
        if kind.startswith('naive'):
            library_event=event(events,'healthy.native_identity.verify',status='RUNNING')
            result['loadedNativeLibrary'] = bound_library(healthy, binary, row)
            library_event['status']='PASS'
            protocol = 'h2' if kind == 'naive-h2' else 'h3'
            pairs = re.findall(r'response received, protocol: ([^,\s]+), status: (\d+)', healthy.log_path.read_text(errors='replace'))
            if not any(status == '200' and (name == protocol or protocol == 'h3' and name.startswith('h3-')) for name, status in pairs):
                raise RuntimeError('actual successful negotiated Naive protocol not proven')
            result['negotiatedProtocolAndStatus'] = [list(x) for x in pairs]
        if relay and not all(relay.counts): raise RuntimeError('actual two-way QUIC carrier missing')
        if not mutation:
            result['concurrentTCP']=[[],[]]
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(tcp_exchange,mixed,target,echo.port,(16384,),False,events,'concurrent'+str(i),result['concurrentTCP'][i]) for i in range(2)]
                for future in futures: future.result(timeout=20)
            if kind.startswith('masque'):
                result['applicationUDP']=[]
                udp_exchange(mixed,target,udp_echo.port,events,'healthy',result['applicationUDP'])
        healthy.close()
        before = echo.received
        retired = retire_old_stream(old_connection,events); old_connection = None
        time.sleep(.2)
        if echo.received != before: raise RuntimeError('retired process old stream still carried new payload')
        result['oldStreamRetired'] = dict(retired, noNewEchoBytes=True)
        # Relay supports one exact current QUIC source; retire and recreate observer before new client.
        if relay:
            result['firstCarrierDatagrams'] = relay.counts[:]
            relay.close(); reserved_tcp.close()
            relay = UDPRelay(peer_port)
            reserved_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            reserved_tcp.bind(('127.0.0.1', relay.port))
        client, mixed = start_client('negative' if mutation else 'reconnected', mutation)
        baseline = (echo.accepted, echo.received, udp_echo.received)
        if mutation:
            failed = False
            result['negativeAttemptTCP']=[]
            try: tcp_exchange(mixed,target,echo.port,(32,),events=events,label='negative',facts=result['negativeAttemptTCP'])
            except (OSError, EOFError, TimeoutError): failed = True
            time.sleep(.25)
            if not failed or (echo.accepted, echo.received, udp_echo.received) != baseline:
                raise RuntimeError('negative reached echo or did not reject')
            result['negative'] = negative_evidence(kind, mutation, client.log_path.read_bytes(), peer.log_path.read_bytes())
            result['negative'].update({'tcpAcceptDelta': 0, 'tcpByteDelta': 0, 'udpNegativeAttempted': False})
            if kind.startswith('masque'):
                control, udp = socks_udp(mixed,events,'negative')
                nonce = secrets.token_bytes(48)
                header = b'\x00\x00\x00\x01' + socket.inet_aton(target) + struct.pack('!H', udp_echo.port)
                try:
                    udp.settimeout(remaining(2)); count=udp.send(header+nonce)
                    event(events,'negative.udp.payload.send',requestedBytes=len(header)+len(nonce),completedBytes=count)
                    if count!=len(header)+len(nonce): raise RuntimeError('negative UDP nonce truncated')
                    try:
                        udp.recv(65535)
                        raise RuntimeError('negative MASQUE UDP unexpectedly returned a payload')
                    except socket.timeout:
                        event(events,'negative.udp.no_payload_timeout') # NOT a transport-close claim.
                finally:
                    udp.close(); control.close()
                result['negative'].update({'udpNegativeAttempted':True,'udpNonceSHA256':digest(nonce)})
            client.close()
            time.sleep(.2)
            if (echo.accepted, echo.received, udp_echo.received) != baseline:
                raise RuntimeError('negative late fallback reached echo before complete retirement')
            result['negative']['afterCompleteClientRetirementZeroEchoDelta'] = True
        else:
            result['freshProcessTCP']=[]
            tcp_exchange(mixed,target,echo.port,(4096,),events=events,label='reconnected',facts=result['freshProcessTCP'])
        if echo.errors or udp_echo.errors: raise RuntimeError('echo worker failed')
        result['status'] = 'PASS'
    except Exception as error:
        primary = error
        if isinstance(error,IdentityFailure):
            result['identityUncertain']=True
            for item in events:
                if item['stage'].endswith('native_identity.verify') and item.get('status')=='RUNNING':
                    item.update(status='FAIL',errorType='IdentityFailure')
        from protocol_peer_diagnostic import safe_exception
        result.update(status='FAIL',errorType=type(error).__name__,error=safe_exception(error),
                      failedOperationStages=[e['stage'] for e in events if e.get('status')=='FAIL'],
                      observedStageAtException=events[-1]['stage'] if events else 'case.setup',
                      observedStageIsUniqueRootCause=False)
    finally:
        result['configs']=[{'role':proc.role,'pid':proc.pid,'startIdentity':proc.start_identity,**proc.config_fact} for proc in processes]
        result['carrierDatagrams']=relay.counts[:] if relay else None
        result['echoCounters']={'tcpAccepted':echo.accepted if echo else 0,'tcpReceivedBytes':echo.received if echo else 0,
                                'udpReceivedBytes':udp_echo.received if udp_echo else 0}
        for item in events:
            if item.get('status')=='RUNNING':item['status']='INCOMPLETE_AT_CASE_RETIREMENT'
        for key in ('healthyTCP','applicationUDP','freshProcessTCP','negativeAttemptTCP'):
            for fact in result.get(key,[]):
                if fact.get('status')=='RUNNING':fact['status']='INCOMPLETE_AT_CASE_RETIREMENT'
        for connection in result.get('concurrentTCP',[]):
            for fact in connection:
                if fact.get('status')=='RUNNING':fact['status']='INCOMPLETE_AT_CASE_RETIREMENT'
        if old_connection: old_connection.close()
        errors = []
        for proc in reversed(processes):
            try: proc.close()
            except Exception as error:
                from protocol_peer_diagnostic import safe_exception
                errors.append(type(error).__name__+': '+safe_exception(error))
            result['cleanup'].append(proc.cleanup)
        try:
            result['descendantRetirement'] = drain_owned_children()
            if result['descendantRetirement']['retired'] or result['descendantRetirement']['forcedKill']:
                errors.append('owned descendants required recovery; graceful cleanup failed')
        except Exception as error:
            errors.append('owned descendant cleanup unknown: ' + type(error).__name__)
        for fixture in (relay, echo, udp_echo):
            if fixture:
                try: fixture.close()
                except Exception as error:
                    from protocol_peer_diagnostic import safe_exception
                    errors.append(type(error).__name__+': '+safe_exception(error))
        result['fixturesJoined']=not errors
        result['echoCountersAfterRetirement']={'tcpAccepted':echo.accepted if echo else 0,
            'tcpReceivedBytes':echo.received if echo else 0,'udpReceivedBytes':udp_echo.received if udp_echo else 0}
        result['carrierDatagramsAfterRetirement']=relay.counts[:] if relay else None
        if reserved_tcp: reserved_tcp.close()
        ports = [(port, False) for port in mixed_ports]
        if echo: ports.append((echo.port, False))
        if udp_echo: ports.append((udp_echo.port, True))
        if relay: ports.append((relay.port, True))
        if peer_port: ports.append((peer_port, kind != 'naive-h2'))
        try: result['portsReleased'] = [assert_port_released(port, udp) for port, udp in ports]
        except OSError: errors.append('owned listening port not released')
        if errors:
            result['status'] = 'FAIL'; result['cleanupErrors'] = errors
        result['privateLogs']=[{'name':path.name,**safe_log_observation(path.read_bytes(),Path(__file__).resolve().parents[2])} for path in directory.glob('*.private.log')]
        result['continuationSafe']=safe_to_continue(result)
    return result

def validate_linux_dispatch(env=os.environ):
    """A new exact-source native build, never a reuse of the old diagnostic carrier."""
    if env.get('GITHUB_ACTIONS') != 'true' or env.get('RUNNER_OS') != 'Linux':
        raise ValueError('Linux peer build requires its existing Actions environment')
    if env.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' or env.get('PEER_BUILD') != 'NativePeerLinux':
        raise ValueError('Linux peer build requires its explicit manual selector')
    if env.get('PEER_EVIDENCE_MODE') != 'staging' or env.get('PEER_SOURCE_GENERATE_ONLY') != 'false':
        raise ValueError('Linux peer build cannot select final evidence or source generation')
    if env.get('PEER_VERSION') != '1.15.0-polaris-alpha.12.3':
        raise ValueError('Linux peer build version differs')
    if env.get('GITHUB_REPOSITORY') != 'polaris-arch/sing-box-polaris' or env.get('GITHUB_REPOSITORY_ID') != '1421657509':
        raise ValueError('Linux peer build repository differs')


def verify_same_run_context(root, row, diagnostic=False):
    from native_release_index import identity as source_identity
    commit, tree = source_identity()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Linux':
        raise ValueError('controlled native peer execution requires the existing Linux Actions job')
    if os.geteuid() == 0 or sys.platform != 'linux': raise ValueError('controlled peer execution must be nonroot Linux')
    if os.environ.get('GITHUB_SHA') != commit:
        raise ValueError('actual runner checkout differs from run')
    if diagnostic:
        from protocol_peer_diagnostic import verify_runner_bridge, PRODUCER
        runner=verify_runner_bridge(root)
        product_commit,product_tree=PRODUCER['commit'],PRODUCER['tree']
    else:
        product_commit,product_tree=commit,tree
    if row['sourceCommit'] != product_commit or row['sourceTree'] != product_tree:
        raise ValueError('same-run exact checkout and native producer source differ')
    if os.environ.get('GITHUB_WORKFLOW_SHA') != commit:
        raise ValueError('runner implementation is not exact same-source workflow')
    if not re.fullmatch(r'[1-9][0-9]*', os.environ.get('GITHUB_RUN_ID', '')) or not re.fullmatch(r'[1-9][0-9]*', os.environ.get('GITHUB_RUN_ATTEMPT', '')):
        raise ValueError('run/attempt identity missing')
    if row['target'] != 'linux/amd64' or row['variant']['linkage'] != 'shared-purego':
        raise ValueError('initial peer matrix accepts only actual existing Linux amd64 native smoke profile')
    if row['goVersion'] != 'go' + (root/'release/GO_VERSION').read_text().strip(): raise ValueError('producer Go pin differs')
    modules = row['sourceIdentity']
    for name, field in [('go.mod', 'goModSha256'), ('go.sum', 'goSumSha256')]:
        if digest((root/name).read_bytes()) != modules[field]: raise ValueError('producer source module bytes differ')
    replacements = modules['replacements']
    if len(replacements) != 10 or len({x['path'] for x in replacements}) != 10:
        raise ValueError('complete ten-vendor closure missing')
    declared = re.findall(r'^replace (\S+) => (\./third_party/[A-Za-z0-9_-]+)$', (root/'go.mod').read_text(), re.M)
    if len(declared) != 10 or len(set(declared)) != 10 or {(x['module'],x['path']) for x in replacements} != set(declared):
        raise ValueError('native module-to-path closure differs from source go.mod')
    for item in replacements:
        path = item['path']
        if not re.fullmatch(r'\./third_party/[A-Za-z0-9_-]+', path): raise ValueError('non-source-owned replacement')
        expected = subprocess.check_output(['git', 'rev-parse', 'HEAD:'+path[2:]], cwd=root, text=True).strip()
        if item['tree'] != expected: raise ValueError('native producer vendor tree differs')
    if diagnostic:
        return {'sourceCommit':product_commit,'sourceTree':product_tree,'runId':PRODUCER['run'],
                'runAttempt':PRODUCER['attempt'],'workflowCommit':product_commit,
                'runner':runner,'reusedProduct':True,'diagnosticOnly':True}
    return {'sourceCommit': commit, 'sourceTree': tree, 'runId': int(os.environ['GITHUB_RUN_ID']),
            'runAttempt': int(os.environ['GITHUB_RUN_ATTEMPT']), 'workflowCommit': os.environ['GITHUB_WORKFLOW_SHA']}


def artifact_metadata(context):
    # Public metadata of this exact repository/run; no additional token permission.
    name = 'binary-linux_amd64-purego'
    matches = []
    for page in range(1, 5):
        endpoint = f"repos/polaris-arch/sing-box-polaris/actions/runs/{context['runId']}/artifacts?per_page=100&page={page}"
        request = urllib.request.Request('https://api.github.com/' + endpoint, headers={'Accept':'application/vnd.github+json','User-Agent':'polaris-controlled-peer'})
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024: raise ValueError('artifact metadata exceeds bounded response')
        result = json.loads(raw)
        matches.extend(x for x in result['artifacts'] if x['name'] == name)
        if len(result['artifacts']) < 100: break
    else: raise ValueError('artifact inventory exceeded bounded pages')
    if len(matches) != 1: raise ValueError('same-run Linux artifact is not unique')
    item = matches[0]
    if item.get('expired') or not re.fullmatch(r'sha256:[0-9a-f]{64}', item.get('digest','')):
        raise ValueError('same-run artifact has no current immutable digest')
    binding = item.get('workflow_run')
    if binding and (binding.get('id') != context['runId'] or binding.get('head_sha') != context['sourceCommit']):
        raise ValueError('artifact API producer source differs')
    return {key:item[key] for key in ('id','name','digest','size_in_bytes','created_at','expires_at')}


def validate_executable_members(row, members):
    names = []
    for kind in ('core', 'sidecar'):
        fact = row.get(kind)
        if not isinstance(fact, dict): raise ValueError('native executable/sidecar fact missing')
        name = fact.get('member')
        if not isinstance(name, str) or name not in members or Path(name).name != name or name in names:
            raise ValueError('native executable member is not a distinct archived basename')
        if fact.get('bytes') != len(members[name]) or fact.get('sha256') != digest(members[name]):
            raise ValueError('native executable member raw bytes differ')
        names.append(name)
    if names != ['sing-box', 'libcronet.so']:
        raise ValueError('Linux native smoke selected executable names differ')


def case_matrix():
    return [(kind,mutation) for kind in ('naive-h2','naive-h3','masque-h3','masque-h3-on-demand')
            for mutation in ((None,) if kind.endswith('on-demand') else
                (None,'wrong-auth','wrong-ca','wrong-sni') if kind.startswith('naive') else
                (None,'wrong-auth','wrong-ca','wrong-sni','wrong-path'))]


def execute_cases(receipt, execute, deadline):
    blocked=None
    for kind,mutation in case_matrix():
        if blocked:
            receipt['cases'].append({'kind':kind,'mutation':mutation,'status':'NOT_RUN',
                'reason':'blocked_by_cleanup_or_identity','blockedByCase':blocked})
            continue
        if time.monotonic()>=deadline:
            receipt['cases'].append({'kind':kind,'mutation':mutation,'status':'NOT_RUN','reason':'bounded_suite_budget_exhausted'})
            continue
        try: result=execute(kind,mutation)
        except Exception as error:
            from protocol_peer_diagnostic import safe_exception
            result={'kind':kind,'mutation':mutation,'status':'FAIL','identityUncertain':True,
                'errorType':type(error).__name__,'error':safe_exception(error),'continuationSafe':False}
        receipt['cases'].append(result)
        if not safe_to_continue(result):
            result['status']='FAIL'
            blocked={'kind':kind,'mutation':mutation,'index':len(receipt['cases'])-1}


def run_suite(directory, output, diagnostic=False):
    from native_release_index import read_archive, smoke_temp_directory
    root = Path(__file__).resolve().parents[2]
    rows = list(directory.glob('native-row-*.json'))
    if len(rows) != 1: raise ValueError('requires one exact same-run native row')
    row_raw = rows[0].read_bytes(); row = json.loads(row_raw)
    context = verify_same_run_context(root,row,diagnostic)
    if diagnostic:
        from protocol_peer_diagnostic import verify_product_row,validate_zip,PRODUCER
        verify_product_row(row,row_raw)
        validate_zip((directory/'original-artifact.zip').read_bytes())
        acquisition=json.loads((directory/'diagnostic-acquisition.json').read_bytes())
        if acquisition.get('producer')!=PRODUCER or acquisition.get('runner')!=context['runner']:
            raise ValueError('diagnostic artifact acquisition dual identity differs')
        actual_artifact=acquisition['artifact']
    else: actual_artifact=artifact_metadata(context)
    archive = directory/row['archive']['name']
    if archive.parent != directory or digest(archive.read_bytes()) != row['archive']['sha256']:
        raise ValueError('same-run final archive identity differs')
    archive_root, members = read_archive(archive)
    if archive_root != row['archive']['root'] or {archive_root+'/'+name:digest(raw) for name,raw in members.items()} != row['archive']['members']:
        raise ValueError('same-run final archive exact members differ')
    validate_executable_members(row, members)
    output.mkdir(parents=True, exist_ok=False)
    receipt = {'schema':'polaris-native-controlled-peer-v1', 'context':context,
               'producerRowSHA256':digest(row_raw), 'archive':row['archive'],
               'artifact':actual_artifact,
               'outerArtifactDigestObservation':('independently hashed exact original artifact ZIP and inner members' if diagnostic else 'API metadata and same-run download action; independently verified inner archive/member hashes'),
               'status':'RUNNING', 'cases':[], 'publicationEligible':False,
               'coverage':'Linux native peer process-level IPv4; not App GUI, in-process HOT, IPv6 or other platforms',
               'privateOriginalConfigurationArchived':False}
    if diagnostic:
        receipt.update(diagnosticOnly=True,reusedProduct=True,producer=PRODUCER,runner=context['runner'],
                       originalProducerRowImmutable=True,originalProducerRowSHA256=digest(row_raw))
    global SUITE_DEADLINE
    started = time.monotonic()
    SUITE_DEADLINE = started + 480
    old_umask = os.umask(0o077)
    try:
        openssl = shutil.which('openssl')
        if not openssl: raise RuntimeError('existing runner OpenSSL is required; no dependency installation')
        receipt['certificateTool'] = {'sha256':digest(Path(openssl).read_bytes()),
            'version':subprocess.check_output([openssl,'version'],text=True,timeout=10).strip()}
        with smoke_temp_directory() as td:
            work = Path(td); work.chmod(0o700)
            with owned_child_scope(receipt):
                for name, raw in members.items(): private_write(work/name, raw)
                binary = work/row['core']['member']; binary.chmod(0o700)
                receipt['identity'] = identity(binary,row,context['sourceCommit'],row['core']['sha256'],diagnostic)
                if diagnostic:
                    from tls_fingerprint_probe import validate, producer_module_identities
                    capability_raw=subprocess.check_output([str(binary),'tools','tls-fingerprints'],cwd=work,timeout=30,env=core_environment(work))
                    document=json.loads(capability_raw)
                    validate(document,source=row['sourceCommit'],version=row['version'],go_version=row['goVersion'],
                             target=row['target'],expected_modules=producer_module_identities(row['buildGraph']))
                    receipt['nativeTLSCapabilityObservation']={'sha256':digest(capability_raw),'bytes':len(capability_raw),
                        'profileIDs':[profile['id'] for profile in document['profiles']],'sourceValidated':True,
                        'networkHandshakeValidated':False}
                pins = json.loads((root/'release/polaris-candidate-inputs.json').read_bytes())
                observed = json.loads(subprocess.check_output([str(binary),'tools','cronet','--expected-version',pins['cronetVersion'],
                    '--library',str(work/row['sidecar']['member']),'--sha256',row['sidecar']['sha256']],cwd=work,text=True,timeout=30,env=core_environment(work)))
                if observed.get('version') != pins['cronetVersion'] or observed.get('sha256') != row['sidecar']['sha256'] or observed.get('gvisorCompiled') is not True:
                    raise ValueError('actual final native Cronet library smoke differs')
                receipt['nativeCronetObservation'] = observed
                execute_cases(receipt,lambda kind,mutation:run_case(binary,row,work,kind,mutation),started+480)
                if digest(binary.read_bytes()) != row['core']['sha256'] or digest((work/row['sidecar']['member']).read_bytes()) != row['sidecar']['sha256']:
                    raise ValueError('native bytes changed during peer execution')
        receipt['privateWorkspaceDeleted'] = not Path(td).exists()
        if not receipt['privateWorkspaceDeleted']: raise RuntimeError('private key/config workspace was not deleted')
        expected = 14
        receipt['status'] = 'PASS' if len(receipt['cases']) == expected and all(case['status']=='PASS' for case in receipt['cases']) else 'FAIL'
    except Exception as error:
        from protocol_peer_diagnostic import safe_exception
        receipt.update(status='FAIL',errorType=type(error).__name__,error=safe_exception(error))
    finally:
        if rows[0].read_bytes()!=row_raw:
            receipt.update(status='FAIL',originalProducerRowImmutable=False,error='original native row changed during QA')
        completed={(case['kind'],case.get('mutation')) for case in receipt['cases']}
        for kind,mutation in case_matrix():
            if (kind,mutation) not in completed:
                receipt['cases'].append({'kind':kind,'mutation':mutation,'status':'NOT_RUN','reason':'suite_preflight_or_safety_failure'})
        SUITE_DEADLINE = None
        os.umask(old_umask)
        receipt['elapsedSeconds'] = time.monotonic()-started
        (output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    if receipt['status'] != 'PASS': raise RuntimeError('controlled native peer matrix failed; sanitized receipt retained')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path,nargs='?')
    parser.add_argument('--output',type=Path)
    action=parser.add_mutually_exclusive_group()
    action.add_argument('--diagnostic',action='store_true')
    action.add_argument('--fetch-diagnostic',action='store_true')
    action.add_argument('--validate-diagnostic-dispatch',action='store_true')
    action.add_argument('--validate-linux-dispatch',action='store_true')
    args = parser.parse_args()
    output=args.output.resolve() if args.output else None
    stage='native_execution_preflight'
    try:
        if args.validate_linux_dispatch:
            if args.directory is not None:parser.error('dispatch validation has no native directory')
            stage='dispatch_preflight'
            validate_linux_dispatch();return
        if args.validate_diagnostic_dispatch:
            if args.directory is not None:parser.error('dispatch validation has no native directory')
            stage='dispatch_preflight'
            from protocol_peer_diagnostic import validate_dispatch
            validate_dispatch();return
        if args.fetch_diagnostic:
            if args.directory is None or output is None:
                parser.error('fixed fetch needs native directory and failure receipt output')
            stage='artifact_acquisition'
            from protocol_peer_diagnostic import fetch_diagnostic
            fetch_diagnostic(args.directory.resolve(),Path(__file__).resolve().parents[2]);return
        if args.directory is None or output is None:parser.error('peer execution needs native directory and receipt output')
        run_suite(args.directory.resolve(strict=True),output,args.diagnostic)
    except Exception as error:
        if output is not None and not (output/'receipt.json').exists():
            output.mkdir(parents=True, exist_ok=True)
            from protocol_peer_diagnostic import safe_exception
            (output/'receipt.json').write_text(json.dumps({'schema':'polaris-native-controlled-peer-v1','status':'FAIL',
                'stage':stage,'errorType':type(error).__name__,'error':safe_exception(error),'publicationEligible':False,
                'cases':[{'kind':kind,'mutation':mutation,'status':'NOT_RUN','reason':stage+'_failed'} for kind,mutation in case_matrix()]},indent=2)+'\n')
        raise


if __name__ == '__main__':
    try: main()
    except Exception as error:
        from protocol_peer_diagnostic import safe_exception
        print(type(error).__name__+': '+safe_exception(error),file=sys.stderr)
        raise SystemExit(1) from None
