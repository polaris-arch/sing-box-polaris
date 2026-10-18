#!/usr/bin/env python3
"""Pinned OpenWrt musl core and package producer; never publishes or touches devices."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import urllib.request
sys.dont_write_bytecode = True
from polaris_native_distribution import encode, file_info
from polaris_production_release import require, sha

CONFIG = 'release/polaris-openwrt-inputs.json'
ARCHITECTURES = {'x86_64': ('amd64', 62, 'GOAMD64', 'v1', '-Os -march=x86-64'),
                 'aarch64_generic': ('arm64', 183, 'GOARM64', 'v8.0', '-Os -march=armv8-a')}

def run(command, cwd=None, env=None):
    process = subprocess.run([str(x) for x in command], cwd=cwd, env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if process.returncode:
        raise RuntimeError(f'command failed ({process.returncode}): {command}\n{process.stdout}')
    return process.stdout

def plan(repo):
    value = json.loads((repo / CONFIG).read_bytes())
    require(value['schema'] == 'polaris-openwrt-release-plan-v1'
            and value['repository'] == 'polaris-arch/polaris-box'
            and value['version'] == '1.15.0-alpha.12' and value['tag'] == 'v' + value['version'], 'wrong OpenWrt identity')
    require({r['architecture'] for r in value['targets']} == set(ARCHITECTURES)
            and len(value['targets']) == 2, 'exact two generic OpenWrt architectures required')
    require(value['requiredTags'] == ['with_gvisor', 'with_naive_outbound', 'with_musl']
            and value['forbiddenTags'] == ['with_purego'] and value['go'] == '1.25.5', 'wrong capabilities/toolchain')
    require(value['dependencies'] == ['ca-bundle', 'kmod-inet-diag', 'kmod-tun', 'firewall4', 'kmod-nft-queue'], 'dependency contract differs')
    require(value['package']['name'] == 'polaris-box' and value['package']['conflicts'] == ['sing-box']
            and value['package']['provides'] == [] and not value['package']['autostartOnInstall'], 'unsafe replacement/autostart policy')
    return value

def sdk_input(config, key):
    rows = [r for r in config['sdkInputs'] if r['key'] == key]
    require(len(rows) == 1, 'unknown SDK')
    return rows[0]

def acquire_sdk(config, key, cache):
    pin = sdk_input(config, key)
    downloads = cache / 'downloads'
    downloads.mkdir(parents=True, exist_ok=True)
    archive = downloads / pin['file']
    if not archive.exists():
        partial = downloads / (pin['file'] + '.partial')
        require(not partial.exists(), 'preserve interrupted SDK input for inspection')
        with urllib.request.urlopen(pin['url'], timeout=90) as response, partial.open('xb') as stream:
            shutil.copyfileobj(response, stream)
        require(file_info(partial)['sha256'] == pin['sha256'], 'SDK hash differs')
        partial.rename(archive)
    require(file_info(archive)['sha256'] == pin['sha256'], 'cached SDK hash differs')
    slot = cache / 'sdks' / key
    slot.mkdir(parents=True, exist_ok=True)
    root_name = pin['file'].removesuffix('.tar.zst')
    root = slot / root_name
    stamp = slot / 'POLARIS-SDK-VERIFIED.json'
    if not stamp.exists():
        require(not root.exists(), 'existing SDK needs a verified producer stamp; preserve it')
        skipped, names = [], set()
        # Python3.12 has no zstd tar decoder. Stream the fixed archive once.
        process = subprocess.Popen(['zstd', '-dc', archive], stdout=subprocess.PIPE)
        try:
            with tarfile.open(fileobj=process.stdout, mode='r|') as reader:
                for member in reader:
                    require(member.name not in names and member.name.split('/')[0] == root_name,
                            'duplicate/foreign SDK member')
                    names.add(member.name)
                    if member.issym() and member.linkname.startswith('/'):
                        require(member.name.startswith(root_name + '/staging_dir/host/bin/'), 'external SDK link')
                        skipped.append({'member': member.name, 'target': member.linkname})
                        continue
                    reader.extract(member, slot, filter='data')
            require(process.wait() == 0, 'SDK decompression failed')
        finally:
            if process.poll() is None:
                process.terminate(); process.wait()
        stamp.write_bytes(encode({'input': pin, 'archive': file_info(archive), 'root': str(root),
                                 'skippedBuildHostAbsoluteLinks': skipped}))
    actual = json.loads(stamp.read_bytes())
    require(actual['input'] == pin and actual['archive'] == file_info(archive)
            and actual['root'] == str(root), 'SDK stamp differs')
    compilers = list((root / 'staging_dir').glob('toolchain-*/bin/' + pin['compiler']))
    require(len(compilers) == 1 and compilers[0].is_file() and compilers[0].resolve().is_relative_to(root.resolve()), 'unique regular cross compiler required')
    compiler = compilers[0]
    require(run([compiler, '-dumpmachine']).strip() == ('aarch64' if key == 'ipk-arm64' else 'x86_64')
            + '-openwrt-linux-musl', 'compiler target differs')
    return {'input': pin, 'root': str(root), 'compilerPath': str(compiler),
            'compilerSha256': file_info(compiler)['sha256'], 'compilerVersion': run([compiler, '--version']).splitlines()[0],
            'compilerTriple': run([compiler, '-dumpmachine']).strip()}

def check_static(core, architecture):
    header = core.read_bytes()[:64]
    require(header[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', header, 18)[0]
            == ARCHITECTURES[architecture][1], 'wrong OpenWrt ELF architecture')
    segments = run(['readelf', '-l', core]); dynamic = run(['readelf', '-d', core]); versions = run(['readelf', '-V', core])
    require('INTERP' not in segments and 'NEEDED' not in dynamic and 'GLIBC_' not in versions,
            'OpenWrt core requires an interpreter/glibc/dynamic library')
    return {'header': run(['readelf', '-h', core]), 'segments': segments, 'dynamic': dynamic,
            'versionReferences': versions, 'staticNoInterpreterOrDynamicDependencies': True}

def payload(repo, config, core, destination, source_reference):
    require(not destination.exists(), 'fresh payload required')
    destination.mkdir(parents=True)
    def add(name, data, mode=0o644):
        p = destination / name;p.parent.mkdir(parents=True, exist_ok=True);p.write_bytes(data);p.chmod(mode)
    add('usr/bin/sing-box', core.read_bytes(), 0o755)
    for source, name, mode in [('sing-box.init', 'etc/init.d/sing-box', 0o755),
        ('sing-box.uci', 'etc/config/sing-box', 0o644), ('config.json', 'etc/sing-box/config.json', 0o644)]:
        add(name, (repo / 'release/openwrt' / source).read_bytes(), mode)
    add('lib/upgrade/keep.d/polaris-box', b'/etc/config/sing-box\n/etc/sing-box/\n/etc/polaris-box/retained-config/\n')
    add('usr/share/licenses/polaris-box/LICENSE', (repo / 'LICENSE').read_bytes())
    add('usr/share/licenses/polaris-box/SOURCE-INDEX.json', encode(source_reference))
    for name in ['GCC-RUNTIME-LIBRARY-EXCEPTION-3.1.txt', 'MUSL-COPYRIGHT.txt', 'GPL-3.0.txt']:
        add('usr/share/licenses/polaris-box/' + name, (repo / 'release/licenses' / name).read_bytes())
    add('usr/share/licenses/polaris-box/NOTICE-SUPERSET.txt',
        (repo / 'release/desktop-source-candidate/DESKTOP-SOURCE-NOTICE-SUPERSET.txt').read_bytes())
    add('usr/share/licenses/polaris-box/OPENWRT-INPUTS.json', (repo / CONFIG).read_bytes())
    add('usr/share/doc/polaris-box/OPENWRT.md', (repo / 'release/POLARIS_OPENWRT.md').read_bytes())
    # This payload intentionally has no dynamic Cronet/OpenSSL sidecar.
    require(not list(destination.rglob('*.so')), 'unexpected dynamic library payload')
    return {str(p.relative_to(destination)): {**file_info(p), 'mode': p.stat().st_mode & 0o777}
            for p in sorted(destination.rglob('*')) if p.is_file()}

def fakeroot_library():
    # The SDK APK wrapper uses its own loader --library-path. An absolute
    # preload survives that wrapper instead of silently losing fakeroot.
    libraries=list(Path('/usr/lib').glob('*/libfakeroot/libfakeroot-sysv.so'))
    require(len(libraries)==1,'exact Ubuntu packaging fakeroot library required')
    return libraries[0].resolve()

def root_owned_command(root,command):
    require(shutil.which('fakeroot'), 'explicit fakeroot packaging tool required')
    # Only virtual ownership is changed, in this bounded staging tree. argv is
    # passed without shell interpolation; symlink targets are never followed.
    return ['fakeroot','-l',str(fakeroot_library()),'sh','-ec','chown -hR 0:0 "$1"; shift; exec "$@"',
            'polaris-root-owned-archive',str(root),*[str(x) for x in command]]

def apk_owner_root(directory):
    # APK archives store account names. Map this private staging UID/GID to
    # root:root with the SDK's native --root identity database; the guest's
    # root account resolves these names to numeric 0:0 on installation.
    (directory/'etc').mkdir(parents=True)
    (directory/'etc/passwd').write_text(f'root:x:{os.getuid()}:{os.getgid()}:root:/root:/bin/false\n')
    (directory/'etc/group').write_text(f'root:x:{os.getgid()}:\n')
    return directory

def apk_native_environment(environment):
    # The SDK wrapper supplies its matching loader/libraries and runas.so.
    # A host fakeroot preload has a different GLIBC ABI and must not enter it.
    result=dict(environment)
    for key in ['LD_PRELOAD','LD_LIBRARY_PATH']:result.pop(key,None)
    return result

def archive_ownership(path,form,apk=None):
    owners={}
    if form=='ipk':
        with tarfile.open(path,'r:gz') as outer:
            for member in outer:
                require(member.uid==0 and member.gid==0,'IPK outer member is not root:root')
                owners['outer/'+member.name]={'uid':member.uid,'gid':member.gid}
                if member.name.removeprefix('./') in ['control.tar.gz','data.tar.gz']:
                    require(member.isfile(),'regular IPK inner archive required')
                    stream=outer.extractfile(member)
                    with tarfile.open(fileobj=stream,mode='r|gz') as inner:
                        for entry in inner:
                            require(entry.uid==0 and entry.gid==0,'IPK payload/control member is not root:root: '+entry.name)
                            owners[member.name+'/'+entry.name]={'uid':entry.uid,'gid':entry.gid,'mode':entry.mode}
    else:
        dump=json.loads(run([apk,'adbdump','--format','json',path],env=apk_native_environment(os.environ)))
        require(isinstance(dump.get('paths'),list) and dump['paths'],'complete APK path metadata required')
        for directory in dump['paths']:
            items=[(directory.get('name',''),directory)]
            items += [(directory.get('name','')+'/'+item['name'],item) for item in directory.get('files',[])]
            for name,item in items:
                acl=item.get('acl',{})
                require(acl.get('user') in ['root','0'] and acl.get('group') in ['root','0'],
                        'APK directory/file is not explicit root:root: '+name)
                require(name not in owners,'duplicate APK ownership path')
                owners[name]={'uid':0,'gid':0,'user':acl['user'],'group':acl['group'],'mode':acl['mode']}
    require(owners,'package ownership inventory missing')
    return {'policy':'all archived payload/control filesystem entries root:root (0:0)', 'members':owners}

def package(repo, config, core, architecture, form, sdk, work, output, source_reference):
    require(architecture in ARCHITECTURES and form in ('apk', 'ipk'), 'unsupported package target')
    require(not output.exists(), 'preserve existing package')
    root = work / (architecture + '-' + form)
    inventory = payload(repo, config, core, root, source_reference)
    version = config['formats'][form]['packageVersion']
    deps = config['dependencies']
    sdkroot = Path(sdk['root'])
    env = dict(os.environ, SOURCE_DATE_EPOCH='0', LC_ALL='C')
    if form == 'ipk':
        control = root / 'CONTROL';control.mkdir()
        text = (f'Package: polaris-box\nVersion: {version}\nArchitecture: {architecture}\n'
                'Maintainer: Polaris maintainers\nLicense: GPL-3.0-or-later\n'
                'Section: net\nPriority: optional\nConflicts: sing-box\n'
                'Depends: ' + ', '.join(deps) + '\nDescription: Polaris-box musl static proxy platform\n')
        (control / 'control').write_text(text)
        (control / 'conffiles').write_text('\n'.join(config['package']['configs']) + '\n')
        for name in ('preinst', 'postinst', 'prerm', 'postrm'):
            shutil.copyfile(repo / 'release/openwrt' / name, control / name);(control / name).chmod(0o755)
        generated = work / (architecture + '-ipk-generated');generated.mkdir()
        command = ['sh', sdkroot / 'scripts/ipkg-build', root, generated]
        command=root_owned_command(root,command)
        log = run(command, env=env)
        files = list(generated.glob('*.ipk'));require(len(files) == 1, 'IPK builder inventory differs')
        shutil.copyfile(files[0], output)
    else:
        metadata = root / 'lib/apk/packages';metadata.mkdir(parents=True)
        (metadata / 'polaris-box.conffiles').write_text('\n'.join(config['package']['configs']) + '\n')
        (metadata / 'polaris-box.conffiles_static').write_text(''.join(
            f'{name} {sha((root / name.lstrip("/")).read_bytes())}\n' for name in config['package']['configs']))
        (metadata / 'polaris-box.list').write_text(''.join('/' + name + '\n' for name in sorted(inventory)))
        owner_root = apk_owner_root(work / (architecture + '-apk-owners'))
        command = [sdkroot / 'staging_dir/host/bin/apk', '--root', owner_root, 'mkpkg',
            '--info', 'name:polaris-box', '--info', 'version:' + version,
            '--info', 'description:Polaris-box musl static proxy platform', '--info', 'arch:' + architecture,
            '--info', 'license:GPL-3.0-or-later', '--info', 'origin:polaris-box',
            '--info', 'url:https://github.com/polaris-arch/polaris-box',
            '--info', 'depends:' + ' '.join([*deps, '!sing-box']),
            '--script', 'pre-install:' + str(repo / 'release/openwrt/preinst'),
            '--script', 'post-install:' + str(repo / 'release/openwrt/postinst'),
            '--script', 'pre-upgrade:' + str(repo / 'release/openwrt/preinst'),
            '--script', 'post-upgrade:' + str(repo / 'release/openwrt/postinst'),
            '--script', 'pre-deinstall:' + str(repo / 'release/openwrt/prerm'),
            '--script', 'post-deinstall:' + str(repo / 'release/openwrt/postrm'),
            '--files', root, '--output', output]
        log = run(command, env=apk_native_environment(env))
    (work / (architecture + '-' + form + '-packager.log')).write_text(log)
    return {'architecture': architecture, 'format': form, 'packageVersion': version,
            'package': file_info(output), 'core': file_info(core), 'payloadInventory': inventory,
            'archiveOwnership':archive_ownership(output,form,sdkroot/'staging_dir/host/bin/apk' if form=='apk' else None),
            'command': [str(x) for x in command], 'sdk': sdk, 'dependencies': deps,
            'conflictPolicy': 'sing-box cannot coexist; back up configuration and remove it before explicit migration',
            'autostartOnInstall': False, 'signatureTrustValidated': False,
            'packageManagerLifecycle': 'pending actual isolated roots', 'realDeviceAcceptance': False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['plan', 'sdk', 'check-static', 'package', 'native'])
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--cache', type=Path);parser.add_argument('--sdk-key')
    parser.add_argument('--core', type=Path);parser.add_argument('--architecture')
    parser.add_argument('--format');parser.add_argument('--work', type=Path);parser.add_argument('--output', type=Path)
    parser.add_argument('--source-reference', type=Path)
    parser.add_argument('--source', type=Path);parser.add_argument('--expected-head')
    args = parser.parse_args();config = plan(args.repo)
    if args.mode == 'plan':result = config
    elif args.mode == 'sdk':result = acquire_sdk(config, args.sdk_key, args.cache)
    elif args.mode == 'check-static':result = check_static(args.core, args.architecture)
    elif args.mode == 'native':
        require(all([args.source,args.expected_head,args.architecture,args.cache,args.output]),'native inputs missing')
        result=core_build(args.repo,args.source,args.expected_head,args.architecture,args.cache,args.output)
    else:
        require(all([args.core, args.architecture, args.format, args.cache, args.work, args.output, args.source_reference]), 'package inputs missing')
        check_static(args.core, args.architecture)
        sdk = acquire_sdk(config, 'apk-host' if args.format == 'apk' else 'ipk-x64', args.cache)
        result = package(args.repo, config, args.core, args.architecture, args.format, sdk,
                         args.work, args.output, json.loads(args.source_reference.read_bytes()))
    print(json.dumps(result, indent=2))

def acquire_clang(config, cache):
    pin = config['clangInput'];downloads = cache / 'downloads';downloads.mkdir(parents=True, exist_ok=True)
    archive = downloads / pin['url'].rsplit('/', 1)[1]
    if not archive.exists():
        with urllib.request.urlopen(pin['url'], timeout=90) as response, archive.open('xb') as output:
            shutil.copyfileobj(response, output)
    require(file_info(archive)['sha256'] == pin['sha256'] and archive.stat().st_size == pin['bytes'], 'fixed upstream Clang archive differs')
    root = cache / 'upstream-clang';stamp = cache / 'upstream-clang-verified.json'
    if not stamp.exists():
        require(not root.exists(), 'preserve unstamped Clang extraction')
        root.mkdir()
        with tarfile.open(archive, 'r:xz') as reader:
            names = set()
            for member in reader:
                require(member.name not in names, 'duplicate toolchain member');names.add(member.name)
                reader.extract(member, root, filter='data')
        stamp.write_bytes(encode({'input': pin, 'archive': file_info(archive)}))
    require(json.loads(stamp.read_bytes()) == {'input': pin, 'archive': file_info(archive)}, 'Clang stamp differs')
    executables = {}
    for name in ['clang', 'clang++', 'ld.lld']:
        path = root / 'bin' / name
        require(path.is_file() and path.resolve().is_relative_to(root.resolve()), 'toolchain executable escapes fixed archive')
        executables[name] = {'path': str(path), 'sha256': file_info(path)['sha256'],
                             'version': run([path, '--version']).splitlines()[0]}
    return {'input': pin, 'executables': executables, 'root': str(root)}

def platform_identity(repo,fp,architecture):
    from polaris_production_release import portable_source_identity
    config=plan(repo)
    row=next(r for r in config['targets'] if r['architecture']==architecture)
    goarch,machine,isa_name,isa,flags=ARCHITECTURES[architecture]
    triple=('x86_64' if goarch=='amd64' else 'aarch64')+'-openwrt-linux-musl'
    tags=(repo/'release/DEFAULT_BUILD_TAGS').read_text().strip()+',with_musl'
    return {'sourceIdentity': portable_source_identity(fp), 'version': config['version'], 'tag': config['tag'],
        'architecture': architecture, 'goarch': goarch, 'CGO_ENABLED':'1', isa_name:isa, 'tags':sorted(tags.split(',')),
        'planSha256':sha((repo/CONFIG).read_bytes()),'sdkInput':sdk_input(config,row['compilerSdk']),'clangInput':config['clangInput'],
        'cronetModule':row['cronetModule'],'cronetModuleSum':row['cronetModuleSum'],'cronetSha256':row['cronetSha256'],
        'CC': 'pinned Clang --target='+triple+' --sysroot=<fixed SDK toolchain> --gcc-toolchain=<fixed SDK toolchain>',
        'CXX': 'pinned Clang++ with identical target/sysroot/gcc-toolchain','CFLAGS':flags,'LDFLAGS':'-fuse-ld=lld -static --rtlib=libgcc'}

def provider_identity(repo,expected):
    files=[CONFIG,'scripts/polaris_openwrt.py','scripts/polaris_openwrt_guest.py','scripts/polaris_naive_loopback.py',
        'scripts/polaris_public_sources.py','release/polaris-public-source-inputs.json',
        *['release/openwrt/'+n for n in ['config.json','sing-box.uci','sing-box.init','preinst','postinst','prerm','postrm']]]
    return {'contract':'polaris-openwrt-release-v1','sourceCommit':expected,'files':{n:sha((repo/n).read_bytes()) for n in files}}

def core_build(repo, source, expected, architecture, cache, output):
    from polaris_go_environment import isolated_go_environment, verify_source
    from polaris_source_fingerprint import collect
    from polaris_production_release import frozen_source, build_info, portable_source_identity
    from polaris_public_sources import delivery
    from polaris_dns_identity import canonical
    import shlex
    config = plan(repo);production, tree = frozen_source(source, expected);verify_source(repo, expected)
    require((source / '.git').is_dir() and not output.exists(), 'fresh external native source/output required')
    require(not output.resolve().is_relative_to(source.resolve()), 'outputs cannot modify source')
    output.mkdir(parents=True);go = Path(shutil.which('go')).resolve()
    row = next(r for r in config['targets'] if r['architecture'] == architecture)
    sdk = acquire_sdk(config, row['compilerSdk'], cache);clang = acquire_clang(config, cache)
    toolroot = Path(sdk['compilerPath']).parent.parent
    goarch, machine, isa_name, isa, flags = ARCHITECTURES[architecture]
    triple = ('x86_64' if goarch == 'amd64' else 'aarch64') + '-openwrt-linux-musl'
    env = isolated_go_environment();env.update(GOOS='linux', GOARCH=goarch, CGO_ENABLED='1',
        GOMAXPROCS='2', GOEXPERIMENT='', GOAMD64='v1', GOARM64='v8.0', STAGING_DIR=str(Path(sdk['root'])/'staging_dir'))
    for name in ['CGO_CPPFLAGS', 'CGO_FFLAGS', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'LD_PRELOAD', 'LD_LIBRARY_PATH']:
        env.pop(name, None)
    for name, compiler in [('CC', 'clang'), ('CXX', 'clang++')]:
        env[name] = shlex.join([clang['executables'][compiler]['path'], '--target=' + triple,
            '--sysroot=' + str(toolroot), '--gcc-toolchain=' + str(toolroot)])
    env.update(CGO_CFLAGS=flags, CGO_CXXFLAGS=flags, CGO_LDFLAGS='-fuse-ld=lld -static --rtlib=libgcc')
    require(run([go, 'env', 'GOVERSION'], env=env).strip() == 'go1.25.5', 'exact Go1.25.5 required')
    os.environ.update(env)  # Collector observes the same process-local, private cache environment.
    fp = collect(source, expected, go, output / 'module-list.json')
    module = json.loads(run([go, 'mod', 'download', '-json', row['cronetModule']+'@'+config['cronetModuleVersion']], source, env))
    library = Path(module['Dir'])/'libcronet.a'
    require(module['Sum'] == row['cronetModuleSum'] and library.stat().st_size == row['cronetBytes']
            and file_info(library)['sha256'] == row['cronetSha256'], 'actual prebuilt static Cronet differs')
    tags = (source/'release/DEFAULT_BUILD_TAGS').read_text().strip()+',with_musl'
    require(set(config['requiredTags']) <= set(tags.split(',')) and not set(config['forbiddenTags']) & set(tags.split(',')), 'wrong complete musl preset')
    identity=platform_identity(source,fp,architecture)
    fingerprint = sha(canonical(identity).encode());bid='polaris-openwrt-v1-'+fingerprint
    ldflags = (source/'release/LDFLAGS').read_text().strip()+' -s -w -linkmode=external -extldflags=-static -buildid='+bid+' -X github.com/sagernet/sing-box/constant.Version='+config['version']
    core = output/'sing-box';command=[go,'build','-buildvcs=true','-mod=readonly','-p','1','-trimpath','-tags',tags,'-ldflags',ldflags,'-o',core,'./cmd/sing-box']
    (output/'BUILD-INPUT.json').write_bytes(encode({'sourceCommit':expected,'sourceTree':tree,'command':[str(x) for x in command],
        'env':{k:env[k] for k in ['CC','CXX','CGO_CFLAGS','CGO_CXXFLAGS','CGO_LDFLAGS','GOOS','GOARCH','GOAMD64','GOARM64','CGO_ENABLED','STAGING_DIR']},'sdk':sdk,'clang':clang,'goExecutableSha256':file_info(go)['sha256']}))
    build_env=dict(env,GOMAXPROCS=os.environ.get('POLARIS_COMPILE_GOMAXPROCS',env['GOMAXPROCS']))
    try:log=run(command,source,build_env)
    except RuntimeError as error:(output/'build.log').write_text(str(error)+'\n');raise
    (output/'build.log').write_text(log);elf=check_static(core,architecture)
    info=run([go,'version','-m',core]);graph=build_info(info,expected,'linux/'+goarch,expected_cgo='1')
    require(graph['settings'][isa_name] == isa and set(graph['settings']['-tags'].strip('"').split(',')) == set(tags.split(',')), 'actual core ISA/tags differ')
    require(run([go,'tool','buildid',core]).strip() == bid, 'actual OpenWrt BuildID differs')
    tests=[go,'test','-mod=readonly','-p','1','-parallel','2','-count=1','-v','-tags',tags,
           '-ldflags',(source/'release/LDFLAGS').read_text().strip()+' -linkmode=external -extldflags=-static']
    if architecture=='aarch64_generic':tests+=['-exec','qemu-aarch64 -cpu cortex-a53']
    tests+=['./common/dialer','./dns','./option','./dns/transport/local/systemconfig']
    try:test_log=run(tests,source,env)
    except RuntimeError as error:(output/'musl-dns-regressions.log').write_text(str(error)+'\n');raise
    (output/'musl-dns-regressions.log').write_text(test_log)
    source_ref=delivery(source,production,expected,tree,[graph]);(output/'SOURCE-INDEX.json').write_bytes(encode(source_ref))
    package_output=output/'packages';package_output.mkdir();receipts=[]
    apk_sdk=acquire_sdk(config,'apk-host',cache)
    for form in ['ipk','apk']:
        work=output/('work-'+form);work.mkdir()
        path=package_output/('polaris-box-'+config['version']+'-openwrt-'+architecture+'.'+form)
        receipts.append(package(source,config,core,architecture,form,apk_sdk if form=='apk' else sdk,work,path,source_ref))
    # All package byte inventories remain bound to the unchanged measured ELF.
    fixtures=private_guest_fixtures(source,config,core,architecture,sdk,apk_sdk,output/'test-inputs',source_ref)
    provider=provider_identity(source,expected)
    receipt={'schema':'polaris-openwrt-native-receipt-v1','sourceCommit':expected,'sourceTree':tree,'sourceFingerprint':fp,
        'version':config['version'],'tag':config['tag'],'architecture':architecture,'goarch':goarch,
        'platformIdentity':identity,'platformInputFingerprint':fingerprint,'providerIdentity':provider,
        'providerFingerprint':sha(canonical(provider).encode()),'buildID':bid,'buildInfo':info,'buildGraph':graph,
        'buildCommand':[str(x) for x in command],'dnsRegressionCommand':[str(x) for x in tests],'dnsRegressionLogSha256':sha(test_log.encode()),'ldflags':ldflags,'tags':tags,'elf':elf,'core':file_info(core),
        'cronet':{'module':row['cronetModule'],'version':config['cronetModuleVersion'],'h1':module['Sum'],**file_info(library)},
        'compiler':clang,'sdk':sdk,'packages':receipts,'workflowCommit':os.environ['GITHUB_SHA'],
        'workflowRun':os.environ['GITHUB_RUN_ID'],'workflowAttempt':os.environ['GITHUB_RUN_ATTEMPT'],
        'privateGuestFixtures':fixtures,'signatureTrustValidated':False,'guestValidation':'pending same-run four guest receipts',
        'publicationEligible':False,'realDeviceAcceptance':False}
    verify_source(source,expected);verify_source(repo,expected)
    (output/'openwrt-receipt.json').write_bytes(encode(receipt))
    return receipt


def read_same_run_guest_receipts(guests, expected, tree, run_id, attempt):
    """Artifact roots must retain one-level receipt layout and exact four identities."""
    rows = [json.loads(p.read_bytes()) for p in sorted(guests.glob('*/guest-receipt.json'))]
    keys = {(r['architecture'], r['format']) for r in rows}
    require(len(rows) == 4 and keys == {(a, f) for a in ARCHITECTURES for f in ['ipk', 'apk']},
            'exact four actual guest receipts required')
    for row in rows:
        require(row['schema'] == 'polaris-openwrt-guest-receipt-v1' and row['sourceCommit'] == expected
                and row['sourceTree'] == tree and row['workflowCommit'] == expected
                and str(row['workflowRun']) == str(run_id) and str(row['workflowAttempt']) == str(attempt),
                'mixed guest source/tree/run/attempt')
    return rows


def validate_assembled_openwrt(repo, expected, tree, inputs, guests, output, run_id, attempt):
    from polaris_production_release import build_info, verify_fingerprint
    from polaris_dns_identity import canonical
    config = plan(repo)
    paths = sorted(inputs.glob('*/openwrt-receipt.json'))
    rows = [json.loads(p.read_bytes()) for p in paths]
    require(len(rows) == 2 and {r['architecture'] for r in rows} == set(ARCHITECTURES), 'exact two OpenWrt core receipts required')
    guest_rows = read_same_run_guest_receipts(guests, expected, tree, run_id, attempt)
    for path, row in zip(paths,rows):
        require(row['schema'] == 'polaris-openwrt-native-receipt-v1' and row['sourceCommit'] == expected
            and row['sourceTree'] == tree and row['version'] == config['version'] and row['tag'] == config['tag']
            and row['workflowCommit'] == expected and str(row['workflowRun']) == run_id
            and str(row['workflowAttempt']) == attempt, 'mixed OpenWrt source/version/run')
        verify_fingerprint(repo,row['sourceFingerprint'],expected,tree)
        core=path.parent/'sing-box';require(file_info(core) == row['core'], 'actual OpenWrt core differs')
        check_static(core,row['architecture'])
        require(build_info(run(['go','version','-m',core]),expected,'linux/'+row['goarch'],expected_cgo='1') == row['buildGraph'], 'actual OpenWrt graph differs')
        require(run(['go','tool','buildid',core]).strip() == row['buildID'] == 'polaris-openwrt-v1-'+row['platformInputFingerprint'], 'actual OpenWrt BuildID differs')
        require(sha(canonical(row['platformIdentity']).encode()) == row['platformInputFingerprint']
                and sha(canonical(row['providerIdentity']).encode()) == row['providerFingerprint'], 'OpenWrt normalized identity differs')
        require(row['providerIdentity'] == provider_identity(repo,expected), 'OpenWrt provider file map differs')
        wanted=platform_identity(repo,row['sourceFingerprint'],row['architecture'])
        require(row['platformIdentity']==wanted, 'OpenWrt source/platform input facts differ')
        require(row['sdk']['input']==sdk_input(config,next(t for t in config['targets'] if t['architecture']==row['architecture'])['compilerSdk'])
                and row['compiler']['input']==config['clangInput'], 'OpenWrt SDK/Clang source-owned inputs differ')
        tags=(repo/'release/DEFAULT_BUILD_TAGS').read_text().strip()+',with_musl'
        flags=(repo/'release/LDFLAGS').read_text().strip()+' -s -w -linkmode=external -extldflags=-static -buildid='+row['buildID']+' -X github.com/sagernet/sing-box/constant.Version='+config['version']
        command=row['buildCommand']
        require(len(command)==14 and command[1:12]==['build','-buildvcs=true','-mod=readonly','-p','1','-trimpath','-tags',tags,'-ldflags',flags,'-o']
            and command[12].replace('\\','/').endswith('/sing-box') and command[13]=='./cmd/sing-box'
            and row['tags']==tags and row['ldflags']==flags,'OpenWrt actual complete build command differs')
        target=next(t for t in config['targets'] if t['architecture'] == row['architecture'])
        require(row['cronet']['module'] == target['cronetModule'] and row['cronet']['h1'] == target['cronetModuleSum']
                and row['cronet']['sha256'] == target['cronetSha256'] and row['cronet']['bytes'] == target['cronetBytes'], 'OpenWrt Cronet pin differs')
        require(len(row['packages']) == 2 and {p['format'] for p in row['packages']} == {'ipk','apk'}, 'OpenWrt package inventory differs')
        validation=[]
        for record in row['packages']:
            name='polaris-box-'+config['version']+'-openwrt-'+row['architecture']+'.'+record['format']
            require(record['package']['name'] == name and record['core'] == row['core'], 'package/core identity differs')
            package_file=path.parent/'packages'/name
            require(file_info(package_file) == record['package'] and record['payloadInventory']['usr/bin/sing-box']['sha256'] == row['core']['sha256'], 'actual package/core bytes differ')
            ownership=record.get('archiveOwnership',{}).get('members',{})
            require(ownership and all(entry.get('uid')==0 and entry.get('gid')==0 for entry in ownership.values()),
                    'actual package root ownership evidence missing/different')
            if record['format']=='ipk':
                require(archive_ownership(package_file,'ipk')==record['archiveOwnership'],'actual IPK ownership differs')
            guest=next(g for g in guest_rows if (g['architecture'],g['format'])==(row['architecture'],record['format']))
            require(guest['schema'] == 'polaris-openwrt-guest-receipt-v1' and guest['sourceCommit'] == expected
                and guest['sourceTree'] == tree and guest['workflowCommit'] == expected
                and str(guest['workflowRun']) == run_id and str(guest['workflowAttempt']) == attempt
                and guest['package'] == record['package'] and guest['core'] == row['core']
                and guest['status'] == 'passed' and guest['realDeviceAcceptance'] is False, 'mixed/incomplete actual guest receipt')
            required=['install','upgradeConfigurationPreserved','removeConfigurationPreserved','packageConflict',
                      'procd','caBundle','naiveTLSH2','wrongCARejected','gvisorTUN','staticNoSidecar','genericCPU']
            require(set(guest['checks']) == set(required) and all(guest['checks'][k] is True for k in required), 'required guest behavior failed/missing')
            shutil.copyfile(package_file,output/name);require(file_info(output/name)==record['package'],'copied package drift')
            validation.append(guest)
        row['guestValidation']=validation
    return rows


def private_guest_fixtures(repo, config, core, architecture, sdk, apk_sdk, output, source_ref):
    """Same-run package-manager controls, never part of the public asset inventory."""
    import copy
    output.mkdir();records={}
    for form in ['ipk','apk']:
        work=output/('upgrade-'+form);work.mkdir();upgrade=copy.deepcopy(config)
        upgrade['formats'][form]['packageVersion']=config['formats'][form]['packageVersion'].rsplit('-',1)[0]+('-r2' if form=='apk' else '-2')
        path=output/('private-upgrade.'+form)
        package(repo,upgrade,core,architecture,form,apk_sdk if form=='apk' else sdk,work,path,source_ref)
        records['upgrade-'+form]=file_info(path)
        root=output/('conflict-root-'+form);(root/'usr/bin').mkdir(parents=True)
        (root/'usr/bin/sing-box').write_bytes(b'private sing-box conflict fixture; never executable product\n')
        destination=output/('private-conflict.'+form)
        if form=='ipk':
            control=root/'CONTROL';control.mkdir();(control/'control').write_text('Package: sing-box\nVersion: 0.0.1-1\nArchitecture: '+architecture+'\nMaintainer: fixture\nDescription: private package conflict fixture\n')
            generated=output/'conflict-generated';generated.mkdir()
            run(root_owned_command(root,['sh',Path(sdk['root'])/'scripts/ipkg-build',root,generated]),env=dict(os.environ,SOURCE_DATE_EPOCH='0'))
            files=list(generated.glob('*.ipk'));require(len(files)==1,'private conflict inventory differs');shutil.copyfile(files[0],destination)
        else:
            owners=apk_owner_root(output/('conflict-owners-'+form))
            command=[Path(apk_sdk['root'])/'staging_dir/host/bin/apk','--root',owners,'mkpkg',
                '--info','name:sing-box','--info','version:0.0.1-r1','--info','arch:'+architecture,
                '--info','description:private package conflict fixture','--info','license:GPL-3.0-or-later','--files',root,'--output',destination]
            run(command,env=apk_native_environment(os.environ))
        archive_ownership(destination,form,Path(apk_sdk['root'])/'staging_dir/host/bin/apk' if form=='apk' else None)
        records['conflict-'+form]=file_info(destination)
    return records

if __name__ == '__main__':main()
