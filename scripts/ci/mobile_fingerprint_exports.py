"""Read actual gomobile package exports; no device or loaded-library claim."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile


APPLE_DECLARATION = re.compile(r'FOUNDATION_EXPORT\s+NSString\s*\*\s*_Nonnull\s+LibboxTLSFingerprintCapabilities\s*\(\s*NSError\s*\*\s*_Nullable\s*\*\s*_Nullable\s+error\s*\)\s*;')
JAVA_DECLARATION = re.compile(r'public static native java\.lang\.String tlsFingerprintCapabilities\(\) throws java\.lang\.Exception;')
ABI = {'386': 'x86', 'amd64': 'x86_64', 'arm': 'armeabi-v7a', 'arm64': 'arm64-v8a'}


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''): h.update(chunk)
    return h.hexdigest()


def apple(root):
    frameworks = sorted(Path(root).rglob('Libbox.framework'))
    if not frameworks: raise ValueError('generated Libbox.framework slice inventory is empty')
    rows = []
    for framework in frameworks:
        declarations = []
        for header in sorted((framework / 'Headers').rglob('*.h')):
            declarations += [m.group() for m in APPLE_DECLARATION.finditer(header.read_text())]
        if len(declarations) != 1: raise ValueError('exact capability header declaration missing/duplicated: ' + str(framework))
        binary = framework / 'Libbox'
        symbols = subprocess.check_output(['xcrun', 'nm', '-gU', str(binary)], text=True)
        if not re.search(r'\b_LibboxTLSFingerprintCapabilities$', symbols, re.M):
            raise ValueError('capability function not linked in actual Apple library: ' + str(binary))
        row = {'framework': str(framework), 'librarySHA256': digest(binary), 'declaration': declarations[0],
               'staticExportObserved': True}
        rows.append(row)
    return rows


def android(paths, arch):
    rows = []
    for path in paths:
        path = Path(path)
        with tempfile.TemporaryDirectory(prefix='tls-mobile-exports-') as temporary, zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)) or names.count('classes.jar') != 1: raise ValueError('AAR member ambiguity')
            info = archive.getinfo('classes.jar')
            if info.file_size > 32 * 1024**2: raise ValueError('classes.jar exceeds symbol-inspection budget')
            jar = Path(temporary) / 'classes.jar';jar.write_bytes(archive.read(info))
            declarations = subprocess.check_output(['javap', '-classpath', str(jar), 'io.nekohasekai.libbox.Libbox'], text=True)
            match = JAVA_DECLARATION.search(declarations)
            if not match: raise ValueError('actual AAR capability Java declaration missing')
            libs = [name for name in names if name.startswith('jni/') and name.endswith('/libbox.so')]
            expected = 'jni/' + ABI[arch] + '/libbox.so'
            if libs != [expected]: raise ValueError('AAR ABI inventory differs from original matrix: ' + repr(libs))
            info = archive.getinfo(expected)
            if info.file_size > 512 * 1024**2: raise ValueError('JNI member exceeds package inspection budget')
            h = hashlib.sha256()
            with archive.open(info) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''): h.update(block)
            rows.append({'archive': str(path), 'sha256': digest(path), 'declaration': match.group(),
                         'jniMember': expected, 'jniBytes': info.file_size, 'jniSHA256': h.hexdigest(),
                         'loadedJNIValidated': False})
    return rows


def main():
    p = argparse.ArgumentParser();p.add_argument('mode', choices=['apple', 'android']);p.add_argument('paths', nargs='+');p.add_argument('--arch');a = p.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true': raise RuntimeError('mobile package observations run on CI only')
    if a.mode == 'apple':
        if len(a.paths) != 1: raise ValueError('one generated XCFramework root required')
        rows = apple(a.paths[0])
    else:
        if a.arch not in ABI: raise ValueError('explicit original Android matrix ABI required')
        rows = android(a.paths, a.arch)
    print('MOBILE_TLS_FINGERPRINT_EXPORTS ' + json.dumps({'rows': rows, 'deviceRuntimeValidated': False}, sort_keys=True))


if __name__ == '__main__': main()
