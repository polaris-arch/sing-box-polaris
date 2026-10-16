"""Inspect legacy binary minimum-OS headers, not old-OS runtime compatibility."""
import struct


def minimum_version(data, osname):
    if osname == 'windows':
        if len(data) < 64 or data[:2] != b'MZ': raise ValueError('legacy Windows core is not PE')
        offset = struct.unpack_from('<I',data,60)[0]
        if offset+24+52 > len(data) or data[offset:offset+4] != b'PE\0\0': raise ValueError('truncated legacy PE header')
        optional = offset+24
        if struct.unpack_from('<H',data,optional)[0] not in (0x10b,0x20b): raise ValueError('unknown PE optional-header layout')
        os_version = struct.unpack_from('<HH',data,optional+40)
        subsystem = struct.unpack_from('<HH',data,optional+48)
        if os_version > (6,1) or subsystem > (6,1): raise ValueError('legacy Windows header requires a system newer than Windows 7')
        return {'osVersion':list(os_version),'subsystemVersion':list(subsystem)}
    if osname != 'darwin': raise ValueError('unexpected legacy platform')
    if data[:4] == b'\xcf\xfa\xed\xfe': endian='<';header=32
    elif data[:4] == b'\xce\xfa\xed\xfe': endian='<';header=28
    elif data[:4] == b'\xfe\xed\xfa\xcf': endian='>';header=32
    elif data[:4] == b'\xfe\xed\xfa\xce': endian='>';header=28
    else: raise ValueError('legacy macOS core is not a thin Mach-O')
    if len(data) < header: raise ValueError('truncated Mach-O header')
    count,size = struct.unpack_from(endian+'II',data,16)
    end = header+size
    if count > 4096 or end > len(data): raise ValueError('Mach-O load-command budget/layout invalid')
    versions=[];offset=header
    for _ in range(count):
        if offset+8 > end: raise ValueError('truncated Mach-O command')
        command,length=struct.unpack_from(endian+'II',data,offset)
        if length < 8 or offset+length > end: raise ValueError('invalid Mach-O command length')
        value=None
        if command == 0x24:
            if length < 16: raise ValueError('short macOS minimum-version command')
            value=struct.unpack_from(endian+'I',data,offset+8)[0]
        if command == 0x32:
            if length < 24: raise ValueError('short build-version command')
            platform,value=struct.unpack_from(endian+'II',data,offset+8)
            if platform != 1: raise ValueError('legacy macOS command names another Apple platform')
        if value is not None: versions.append((value>>16,(value>>8)&255,value&255))
        offset+=length
    if offset != end or len(versions) != 1: raise ValueError('missing/ambiguous macOS minimum-version command')
    if versions[0] > (10,13,0): raise ValueError('legacy macOS header requires a system newer than 10.13')
    return {'minimumMacOS':list(versions[0])}
