#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Deterministic tar observations. No fixture is extracted or executed."""
import argparse
import hashlib
import io
import json
import tarfile
from pathlib import Path
from make_deb_data_fixtures import deb

DEST = Path(__file__).resolve().parent / 'fixtures/deb-payload'

def entry(name, data=b'', kind=tarfile.REGTYPE, link='', **attrs):
    item = tarfile.TarInfo(name)
    item.type, item.linkname, item.size = kind, link, len(data)
    item.mode, item.mtime, item.uid, item.gid = 0o644, 1700000000, 123, 456
    item.uname, item.gname = 'fixture-user', 'fixture-group'
    for key, value in attrs.items():
        setattr(item, key, value)
    return item, data

def archive(entries, fmt=tarfile.USTAR_FORMAT, **options):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=fmt, **options) as stream:
        for item, data in entries:
            stream.addfile(item, io.BytesIO(data))
    return buf.getvalue()

def fixtures():
    entries = [entry('./', kind=tarfile.DIRTYPE, mode=0o755),
               entry('./usr/', kind=tarfile.DIRTYPE, mode=0o2755),
               entry('./usr/a', b'payload\x00\xff\n', mode=0o6751),
               entry('./empty'),
               entry('./forward', kind=tarfile.LNKTYPE, link='./chain'),
               entry('./chain', kind=tarfile.LNKTYPE, link='./usr/a'),
               entry('./usr/sym', kind=tarfile.SYMTYPE, link='../empty', mode=0o777),
               entry('./absolute', kind=tarfile.SYMTYPE, link='/usr/a', mode=0o777),
               entry('./dangling', kind=tarfile.SYMTYPE, link='missing', mode=0o777),
               entry('./device', kind=tarfile.CHRTYPE, devmajor=1, devminor=3),
               entry('./block', kind=tarfile.BLKTYPE, devmajor=8, devminor=1),
               entry('./pipe', kind=tarfile.FIFOTYPE),
               entry('./tmp/', kind=tarfile.DIRTYPE, mode=0o1777)]
    yield 'basic', archive(entries), True
    yield 'empty', archive([]), True
    longname = 'usr/' + 'a' * 150 + '/' + 'b' * 150
    for fmt, name in [(tarfile.GNU_FORMAT, 'gnu'), (tarfile.PAX_FORMAT, 'pax')]:
        yield name, archive([entry(longname, b'long'), entry('link', kind=tarfile.SYMTYPE, link='/' + longname)], fmt), True
    yield 'unicode', archive([entry('資料/更新.txt', b'utf8')], tarfile.PAX_FORMAT), True
    yield 'multilingual', archive([entry('العربية/日本語-e\u0301-😀', b'text'), entry('name with space\nand newline', b'bytes'),
        entry('link-e\u0301', kind=tarfile.SYMTYPE, link='العربية/日本語-e\u0301-😀', uname='e\u0301-user', gname='e\u0301-group'),
        entry('distinct-e\u0301', b'one'), entry('distinct-é', b'two')], tarfile.PAX_FORMAT), True
    yield 'gnu-numeric', archive([entry('numeric', b'n', uid=4294967295, gid=4294967294, mtime=-1)], tarfile.GNU_FORMAT), True
    yield 'flags', archive([entry('flags', pax_headers={'SCHILY.fflags': 'nodump'})], tarfile.PAX_FORMAT), True
    yield 'attributes', archive([entry('attr', b'attributes', mode=0o4750, pax_headers={
        'uid': '4294967295', 'gid': '4294967294', 'mtime': '1700000000.123456789',
        'atime': '1700000001.000000007', 'ctime': '1700000002.42',
        'LIBARCHIVE.creationtime': '1700000003.75',
        'SCHILY.xattr.user.demo': 'test', 'SCHILY.xattr.security.capability': '\x01\x00\x02',
        'SCHILY.acl.access': 'user::rwx,user:42:r--,group::r--,mask::r--,other::---',
    })], tarfile.PAX_FORMAT), True
    yield 'negative-clock', archive([entry('before-epoch', pax_headers={'mtime': '-1.25'})], tarfile.PAX_FORMAT), True
    yield 'negative-zero', archive([entry('before-epoch', pax_headers={'mtime': '-0.000000001', 'atime': '0.123456789000'})], tarfile.PAX_FORMAT), True
    yield 'global', archive([entry('global', b'g')], tarfile.PAX_FORMAT, pax_headers={'uid': '42', 'uname': 'global-user'}), False
    invalid = {
        'duplicate': [entry('a'), entry('./a')],
        'ancestor': [entry('a/b'), entry('a', kind=tarfile.SYMTYPE, link='elsewhere')],
        'parent': [entry('../a')], 'absolute-path': [entry('/a')],
        'dot-component': [entry('a/./b')], 'empty-component': [entry('a//b')],
        'escape-link': [entry('a', kind=tarfile.SYMTYPE, link='../outside')],
        'missing-hardlink': [entry('a', kind=tarfile.LNKTYPE, link='missing')],
        'cycle': [entry('a', kind=tarfile.LNKTYPE, link='b'), entry('b', kind=tarfile.LNKTYPE, link='a')],
        'hardlink-directory': [entry('a', kind=tarfile.LNKTYPE, link='d'), entry('d', kind=tarfile.DIRTYPE)],
    }
    for name, items in invalid.items():
        yield name, archive(items), False
    for name, headers in {
        'unknown-pax': {'vendor.unknown': 'x'},
        'sparse-pax': {'GNU.sparse.size': '100'},
        'clock-precision': {'mtime': '1.0000000001'},
        'uid-overflow': {'uid': '4294967296'},
        'unknown-flags': {'SCHILY.fflags': 'unknown-flag'},
        'invalid-acl': {'SCHILY.acl.access': 'invalid'},
        'empty-pax-name': {'uname': ''},
        'too-many-xattrs': {'SCHILY.xattr.user.' + str(i): 'v' for i in range(65)},
    }.items():
        yield name, archive([entry('a', pax_headers=headers)], tarfile.PAX_FORMAT), False
    raw = archive([entry('a', b'abc')])
    changed = bytearray(raw); changed[0] ^= 1
    yield 'checksum', bytes(changed), False
    changed = bytearray(raw); changed[515] = 1
    yield 'padding', bytes(changed), False
    changed = bytearray(raw); changed[-1] = 1
    yield 'trailing', bytes(changed), False
    yield 'one-terminator', raw[:1536], False
    yield 'no-terminator', raw[:1024], False
    yield 'truncated', raw[:-1], False
    yield 'orphan-local', archive([entry('a', pax_headers={'path': 'b'})], tarfile.PAX_FORMAT)[:1024] + bytes(1024), False
    pax = archive([entry('a', pax_headers={'path': 'b'})], tarfile.PAX_FORMAT)
    yield 'repeated-local', pax[:1024] + pax, False
    changed = bytearray(archive([entry('first'), entry('second')]))
    changed[512+108:512+116] = b'0001junk'
    changed[512+148:512+156] = b'        '
    changed[512+148:512+156] = ('%06o\0 ' % sum(changed[512:1024])).encode()
    yield 'numeric-tail', bytes(changed), False
    yield 'duplicate-pax', archive([entry('PaxHeader', b'10 path=a\n10 path=b\n', kind=tarfile.XHDTYPE), entry('file')]), False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--write', action='store_true'); mode.add_argument('--check', action='store_true')
    args = parser.parse_args(); manifest = []
    if args.write: DEST.mkdir(parents=True, exist_ok=True)
    for name, raw, accepted in fixtures():
        encoded = deb(raw, '')
        name += '.deb'; path = DEST / name
        if args.write: path.write_bytes(encoded)
        elif path.read_bytes() != encoded: raise SystemExit('fixture differs: ' + name)
        manifest.append(dict(filename=name, sha256=hashlib.sha256(encoded).hexdigest(), size=len(encoded), accepted=accepted))
    encoded = (json.dumps(manifest, indent=2) + '\n').encode()
    if args.write: (DEST / 'manifest.json').write_bytes(encoded)
    elif (DEST / 'manifest.json').read_bytes() != encoded: raise SystemExit('fixture manifest differs')
    print('Payload fixtures:', len(manifest), 'written' if args.write else 'match')
