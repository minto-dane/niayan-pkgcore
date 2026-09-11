#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Check the Ada-emitted test archives and wrap them as script-free DEB fixtures."""
import argparse
import base64
from decimal import Decimal, localcontext
import hashlib
import io
import json
from pathlib import Path
import struct
import tarfile

from make_deb_control_fixtures import member, tar

CLOCKS = {
    'normal': [(-42, 123456789), (123, 456), (-1, 1), (0, 42)],
    'full-range': [(-(2**63), 0), (-(2**63), 1), (2**63-1, 999999999), (-1, 999999999)],
}
XATTRS = {b'user.binary': b'\0\xff\x7f', b'user.empty': b'', b'user.raw-\xff': b'x',
          b'user.long-'+b'\xff'*200: b'large-key'}
ACL = 'user::rwx,user:42:r--,group::r--,mask::r--,other::---'


def raw(text):
    return text.encode('utf-8', 'surrogateescape')


def object_bytes(store, digest):
    assert len(digest) == 64 and all(c in '0123456789abcdef' for c in digest)
    path = store/'objects'/digest[:2]/digest[2:]
    assert path.is_file() and not path.is_symlink() and path.stat().st_size <= 196608
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest
    return data


def native_check(name, directory, stores, expected):
    lines = (directory/(name+'.native.log')).read_text().splitlines()
    assert any(line.startswith('PASS assertions=') for line in lines)
    fields = {}
    for line in lines:
        key, _, value = line.partition(' ')
        if key in {'ORIGINAL', 'TAR', 'COUNT', 'PATH', 'ATTR', 'CONTENT', 'XATTR', 'ACL', 'MTIME', 'ATIME', 'CTIME', 'BTIME'}:
            assert key not in fields, key
            fields[key] = value.strip()
    assert fields['ORIGINAL'] == hashlib.sha256((directory/(name+'.deb')).read_bytes()).hexdigest()
    assert fields['TAR'] == hashlib.sha256((directory/(name+'.tar')).read_bytes()).hexdigest()
    assert fields['COUNT'] == '1' and fields['PATH'] == b'etc/raw-\xff.conf'.hex()
    attrs = fields['ATTR'].split()
    assert attrs[0] == 'REGULAR'
    assert list(map(int, attrs[1:])) == [0o6740, 4294967294, 1234, 0, 0, 3, 3, 1, 64 if name == 'normal' else 0, 0]
    assert fields['CONTENT'] == hashlib.sha256(b'abc').hexdigest()
    for key, (sec, ns) in zip(['MTIME', 'ATIME', 'CTIME', 'BTIME'], expected):
        parts = fields[key].split()
        assert parts == ['TRUE', str(sec), str(ns)], (name, key, parts)
    values = XATTRS if name == 'normal' else {}
    xattrs = struct.pack('>H', len(values)) + b''.join(struct.pack('>HI', len(k), len(v))+k+v for k, v in sorted(values.items()))
    assert fields['XATTR'] == hashlib.sha256(xattrs).hexdigest(), name
    acl = object_bytes(stores/(name+'-store'), fields['ACL'])
    count, = struct.unpack_from('>H', acl); offset = 2; entries = set()
    for _ in range(count):
        kind, perm, tag, who, length = struct.unpack_from('>IIIIH', acl, offset); offset += 18
        label = acl[offset:offset+length]; offset += length
        assert label in ({b'', b'42'} if tag == 10001 and who == 42 else {b''})
        entries.add((kind, perm, tag, who))
    assert offset == len(acl) and count == len(entries)
    want = {(256, 7, 10002, 2**32-1), (256, 4, 10004, 2**32-1), (256, 0, 10006, 2**32-1),
            (256, 4, 10001, 42), (256, 4, 10005, 2**32-1)} if name == 'normal' else set()
    assert entries == want, (name, entries)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--native-stores', type=Path)
    args = parser.parse_args(); results = []
    for name, clocks in CLOCKS.items():
        data = (args.directory/(name+'.tar')).read_bytes()
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:', encoding='utf-8', errors='surrogateescape') as archive:
            members = archive.getmembers(); assert len(members) == 1
            item = members[0]
            assert item.isreg() and raw(item.name) == b'etc/raw-\xff.conf'
            assert (item.mode, item.uid, item.gid, item.size) == (0o6740, 4294967294, 1234, 3)
            assert archive.extractfile(item).read() == b'abc'
            pax = item.pax_headers; assert pax['hdrcharset'] == 'BINARY'
            with localcontext() as context:
                context.prec = 50
                for key, (sec, ns) in zip(['mtime', 'atime', 'ctime', 'LIBARCHIVE.creationtime'], clocks):
                    assert Decimal(pax[key]) == Decimal(sec) + Decimal(ns)/Decimal(1000000000), (name, key)
            if name == 'normal':
                assert base64.b64decode(pax['LIBARCHIVE.xattr.user.binary']) == b'\0\xff\x7f'
                assert pax['LIBARCHIVE.xattr.user.empty'] == '' and pax['LIBARCHIVE.xattr.user.raw-%FF'] == 'eA'
                assert base64.b64decode(pax['LIBARCHIVE.xattr.user.long-'+'%FF'*200]) == b'large-key'
                assert pax['SCHILY.acl.access'] == ACL and pax['SCHILY.fflags'] == 'nodump'
        control = b'Package: generated-configuration\nVersion: 1\nArchitecture: all\nMaintainer: Fixture <fixture@example.invalid>\nDescription: codec fixture\n'
        metadata = tar([('./control', control, tarfile.REGTYPE, '')])
        deb = b'!<arch>\n'+member('debian-binary', b'2.0\n')+member('control.tar', metadata)+member('data.tar', data)
        target = args.directory/(name+'.deb')
        if args.native_stores:
            assert target.read_bytes() == deb
            native_check(name, args.directory, args.native_stores, clocks)
        else:
            target.write_bytes(deb)
        results.append({'name': name, 'tar_sha256': hashlib.sha256(data).hexdigest(), 'deb_sha256': hashlib.sha256(deb).hexdigest(),
                        'independent_python_read': 'pass', 'native_payload_read': 'pass' if args.native_stores else 'not-run'})
    print(json.dumps({'result': 'pass', 'files': results, 'filesystem_attribute_application': False}, indent=2))


if __name__ == '__main__':
    main()
