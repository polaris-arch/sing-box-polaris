import struct
import unittest
from legacy_binary_version import minimum_version


class LegacyHeaderControls(unittest.TestCase):
    def pe(self,version):
        data=bytearray(512);data[:2]=b'MZ';struct.pack_into('<I',data,60,64);data[64:68]=b'PE\0\0'
        struct.pack_into('<H',data,88,0x20b);struct.pack_into('<HH',data,88+40,*version);struct.pack_into('<HH',data,88+48,*version)
        return data
    def macho(self,version):
        data=bytearray(48);data[:4]=b'\xcf\xfa\xed\xfe';struct.pack_into('<II',data,16,1,16)
        struct.pack_into('<IIII',data,32,0x24,16,version,0);return data
    def test_original_legacy_minimums_are_observed(self):
        self.assertEqual(minimum_version(self.pe((6,1)),'windows')['osVersion'],[6,1])
        self.assertEqual(minimum_version(self.macho(10<<16|13<<8),'darwin')['minimumMacOS'],[10,13,0])
    def test_newer_or_truncated_legacy_header_is_rejected(self):
        self.assertRaises(ValueError,minimum_version,self.pe((6,2)),'windows')
        self.assertRaises(ValueError,minimum_version,self.macho(10<<16|14<<8),'darwin')
        self.assertRaises(ValueError,minimum_version,self.pe((6,1))[:70],'windows')
        self.assertRaises(ValueError,minimum_version,self.macho(10<<16|13<<8)[:40],'darwin')
        bad=self.macho(10<<16|13<<8);struct.pack_into('<I',bad,36,0)
        self.assertRaises(ValueError,minimum_version,bad,'darwin')
