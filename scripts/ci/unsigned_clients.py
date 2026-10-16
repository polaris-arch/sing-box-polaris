#!/usr/bin/env python3
"""Narrow, pinned build-only overlays. Never changes gitlinks or publishes products."""
import hashlib
import sys
from pathlib import Path

def overlay(path, blob, edits):
    p=Path(path); raw=p.read_bytes()
    actual=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    if actual != blob:
        raise SystemExit(f'Unsigned overlay source mismatch: {path}: {actual}, expected {blob}')
    text=raw.decode()
    for old,new,count in edits:
        if text.count(old)!=count:
            raise SystemExit(f'Unsigned overlay anchor mismatch: {path}: {old!r}')
        text=text.replace(old,new)
    p.write_text(text)

def main(mode):
    if mode=='android':
        overlay('clients/android/app/build.gradle.kts','85b78694cff9584ac23001ac92fa77b083030283',[
            ('signingConfig = signingConfigs.getByName("release")','signingConfig = null // unsigned CI candidate; not installable release identity',2)])
    elif mode=='windows':
        overlay('clients/desktop/scripts/package.ts','3b322c70581f02f12015010ba07c866d62eaa368',[
            ('signingConfiguration: WindowsSigningConfiguration,','signingConfiguration: WindowsSigningConfiguration | undefined,',1),
            ('const signingConfiguration = readWindowsSigningConfiguration();','const signingConfiguration = undefined; // unsigned CI candidate',1),
            ('signtoolOptions: {\n            certificateFile: signingConfiguration.certificateFile,\n            certificatePassword: signingConfiguration.certificatePassword,\n          },','signAndEditExecutable: signingConfiguration ? undefined : false,\n          signtoolOptions: signingConfiguration ? {\n            certificateFile: signingConfiguration.certificateFile,\n            certificatePassword: signingConfiguration.certificatePassword,\n          } : undefined,',1)])
    elif mode=='apple':
        overlay('clients/apple/Makefile','274323492752448d66f96edffe6374f518ae1782',[
            ('xcodebuild -exportArchive -archivePath build/SFM.System-universal.xcarchive -exportOptionsPlist SFM.System/Export.plist -exportPath build/SFM.System-universal','mkdir -p build/SFM.System-universal\n\tditto build/SFM.System-universal.xcarchive/Products/Applications/SFM.app build/SFM.System-universal/SFM.app',1)])
        overlay('clients/apple/SFM.System/package_from_universal.sh','d1c2f8cdbcbf964933330f1846dff86e8e7cb4b4',[
            ('\t\t--sign "$INSTALLER_SIGN_IDENTITY" \\\n','',1),
            ('\tpkgutil --check-signature "build/SFM-$label.pkg" > /dev/null','\t# Unsigned candidate: no release signature is asserted.',1),
            ('\tresign "build/SFM.System-$arch-thin/SFM.app"','\t# Unsigned candidate: do not sign thinned app.',1)])
    else: raise SystemExit('expected android, windows or apple')
if __name__=='__main__':main(sys.argv[1])
