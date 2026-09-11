#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Compare generated entries with retained observations/originals; export small VM inputs."""
import argparse
import base64
from decimal import Decimal, localcontext
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import tarfile
from urllib.parse import unquote_to_bytes

from check_tar_output import object_bytes, raw
from compare_root_archive import members
from make_deb_control_fixtures import member, tar

ZERO = '0' * 64
CLOCKS = ('mtime', 'atime', 'ctime', 'LIBARCHIVE.creationtime')
LOCAL_CLEAR = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40 | 0x80 | 0x4000 | 0x8000 | 0x10000 | 0x20000 | 0x800000 | 0x20000000


def observation(data):
    assert data[:8] == b'NIACOBS1'
    pos = 8

    def number():
        nonlocal pos
        value, = struct.unpack_from('<Q', data, pos); pos += 8
        return value

    def blob():
        nonlocal pos
        length = number(); value = data[pos:pos+length]; pos += length
        assert len(value) == length
        return value

    def node():
        values = [number() for _ in range(7)]
        return dict(zip(('mount', 'major', 'minor', 'inode', 'mode', 'uid', 'gid'), values, strict=True))

    def clock():
        sec = number(); ns = number()
        if sec >= 2**63:
            sec -= 2**64
        assert 0 <= ns < 10**9
        return sec * 10**9 + ns

    path = blob(); observer = [number(), number()]
    tag = number()
    while tag == 2:
        node(); tag = number()
    assert tag == 1
    fields = node()
    fields.update(path=path, observer=observer, links=number(), size=number(), attributes=number(), mask=number())
    accessed, modified, changed = clock(), clock(), clock()
    created = clock() if number() else None
    fields.update(clocks=[modified, accessed, changed, created], flags=number())
    xattrs = {}
    for _ in range(number()):
        name, value = blob(), blob()
        assert name not in xattrs
        xattrs[name] = value
    fields.update(xattrs=xattrs, content=data[pos:pos+32].hex()); pos += 32
    assert pos == len(data)
    return fields


def acl(data):
    assert data[:4] == struct.pack('<I', 2) and (len(data)-4) % 8 == 0
    tags = {1: 'user', 2: 'user', 4: 'group', 8: 'group', 16: 'mask', 32: 'other'}
    result = []
    for offset in range(4, len(data), 8):
        tag, perm, identity = struct.unpack_from('<HHI', data, offset)
        bits = ''.join(c if perm & bit else '-' for c, bit in zip('rwx', (4, 2, 1), strict=True))
        result.append(f"{tags[tag]}:{identity if tag in (2, 8) else ''}:{bits}")
    return ','.join(result)


def native_check(directory, name, expected):
    lines = (directory/(name+'.native.log')).read_text().splitlines()
    assert any(line.startswith('PASS assertions=') for line in lines)
    fields = {line.split(' ', 1)[0]: line.split(' ', 1)[1].strip() for line in lines if ' ' in line}
    assert fields['COUNT'] == '1' and fields['PATH'] == expected['path_hex']
    attrs = fields['ATTR'].split()
    assert attrs[0] == 'REGULAR'
    assert list(map(int, attrs[1:])) == [expected[k] for k in ('mode', 'uid', 'gid')] + [0, 0, expected['size'], expected['size'], 1, *expected['flags']]
    assert fields['CONTENT'] == expected['content']
    for key, value in zip(('MTIME', 'ATIME', 'CTIME', 'BTIME'), expected['clocks'], strict=True):
        tokens = fields[key].split()
        assert tokens[0] == ('TRUE' if value is not None else 'FALSE')
        if value is not None:
            assert int(tokens[1])*10**9+int(tokens[2]) == value
    store = directory/(name+'-store')
    xattrs = {bytes.fromhex(k): bytes.fromhex(v) for k, v in expected['xattrs'].items()}
    wire = struct.pack('>H', len(xattrs)) + b''.join(struct.pack('>HI', len(k), len(v))+k+v for k, v in sorted(xattrs.items()))
    assert object_bytes(store, fields['XATTR']) == wire
    wire = object_bytes(store, fields['ACL']); count, = struct.unpack_from('>H', wire); pos = 2; got = set()
    for _ in range(count):
        kind, perm, tag, who, length = struct.unpack_from('>IIIIH', wire, pos); pos += 18
        label = wire[pos:pos+length]; pos += length
        assert label in (b'', str(who).encode())
        got.add((kind, perm, tag, who))
    want = set()
    for item in expected['acl'].split(','):
        label, who, bits = item.split(':')
        tag = {'user': 10001 if who else 10002, 'group': 10003 if who else 10004, 'mask': 10005, 'other': 10006}[label]
        perm = sum(bit for c, bit in zip(bits, (4, 2, 1), strict=True) if c != '-')
        want.add((256, perm, tag, int(who) if who else 2**32-1))
    assert got == want and pos == len(wire) and count == len(want)
    assert fields['ORIGINAL'] == hashlib.sha256((directory/(name+'.deb')).read_bytes()).hexdigest()
    assert fields['TAR'] == expected['archive']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('native', 'cas', 'output'):
        parser.add_argument('--'+name, required=True, type=Path)
    parser.add_argument('--native-roundtrip', action='store_true')
    parser.add_argument('--driver', type=Path)
    args = parser.parse_args()
    args.output.mkdir(exist_ok=True)
    lines = args.native.read_text().splitlines()
    assert any(line.startswith('PASS assertions=') for line in lines)
    entries = [line.split()[1:] for line in lines if line.startswith('ENTRY ')]
    assert [row[0] for row in entries] == ['local', 'backup', 'vendor', 'override']
    results = []
    for name, address, source, override, prefix, content in entries:
        data = object_bytes(args.cas, address)
        header = object_bytes(args.cas, prefix)
        assert data.startswith(header) and len(header) % 512 == 0
        if name in ('local', 'backup'):
            fields = observation(object_bytes(args.cas, source))
            expected_content = b'content'
            assert fields['content'] == content and fields['links'] == 1
            assert fields['flags'] & ~0x80000 == 0 and fields['attributes'] == 0
            clocks = fields['clocks']; mode, uid, gid = (fields[k] for k in ('mode', 'uid', 'gid'))
            values = fields['xattrs'].copy(); access_acl = acl(values.pop(b'system.posix_acl_access'))
            path = fields['path'][1:] if name == 'local' else b'backup-\xff'
            flags = [0, LOCAL_CLEAR]
        else:
            original = members(object_bytes(args.cas, source))['data.tar']
            with tarfile.open(fileobj=io.BytesIO(original), mode='r:') as vendor:
                item = vendor.getmember('./dir/file'); expected_content = vendor.extractfile(item).read()
                mode, uid, gid = item.mode, item.uid, item.gid
                clocks = [int(Decimal(item.pax_headers[key])*10**9) for key in CLOCKS]
                access_acl = item.pax_headers['SCHILY.acl.access']
                values = {raw(key.removeprefix('SCHILY.xattr.')): raw(value) for key, value in item.pax_headers.items() if key.startswith('SCHILY.xattr.')}
                assert item.pax_headers['SCHILY.fflags'] == 'nodump'
            path = b'vendor'; flags = [64, 0]
            if name == 'override':
                fields = observation(object_bytes(args.cas, override))
                assert fields['path'] == b'/dir/file' and fields['content'] == hashlib.sha256(b'edited').hexdigest()
                mode, uid, gid = (fields[k] for k in ('mode', 'uid', 'gid'))
                assert mode & 0o7777 == 0o600
                access_acl = access_acl.replace('mask::r--', 'mask::---')
                path = b'renamed-vendor'
        mode &= 0o7777
        assert override == ZERO if name != 'override' else override != ZERO
        assert content == hashlib.sha256(expected_content).hexdigest()
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:', encoding='utf-8', errors='surrogateescape') as generated:
            all_items = generated.getmembers(); assert len(all_items) == 1
            item = all_items[0]; pax = item.pax_headers
            assert item.isreg() and raw(item.name) == path
            assert (item.mode, item.uid, item.gid, item.size) == (mode, uid, gid, len(expected_content))
            assert generated.extractfile(item).read() == expected_content
            assert data == header + expected_content + bytes((-len(expected_content)) % 512 + 1024)
            assert pax['hdrcharset'] == 'BINARY' and pax['SCHILY.acl.access'] == access_acl
            got = {unquote_to_bytes(key.removeprefix('LIBARCHIVE.xattr.')): base64.b64decode(value+'='*((-len(value))%4), validate=True)
                   for key, value in pax.items() if key.startswith('LIBARCHIVE.xattr.')}
            assert got == values
            with localcontext() as context:
                context.prec = 50
                for key, value in zip(CLOCKS, clocks, strict=True):
                    assert key not in pax if value is None else Decimal(pax[key])*10**9 == value
        control = b'Package: configured-entry\nVersion: 1\nArchitecture: all\nMaintainer: Fixture <fixture@example.invalid>\nDescription: retained attribute fixture\n'
        deb = b'!<arch>\n'+member('debian-binary', b'2.0\n')+member('control.tar', tar([('./control', control, tarfile.REGTYPE, '')]))+member('data.tar', data)
        root = tarfile.TarInfo('./'); root.type = tarfile.DIRTYPE; root.mode = 0o755; root.mtime = 0
        root_data = root.tobuf(format=tarfile.USTAR_FORMAT)+data
        for suffix, value in (('.tar', data), ('.deb', deb), ('.root.tar', root_data)):
            target = args.output/(name+suffix)
            if args.native_roundtrip:
                assert target.read_bytes() == value
            else:
                target.write_bytes(value)
        result = dict(name=name, archive=address, root_archive=hashlib.sha256(root_data).hexdigest(), source=source, override=override,
                      prefix=prefix, content=content, path_hex=path.hex(), mode=mode, uid=uid, gid=gid, size=len(expected_content),
                      clocks=clocks, xattrs={k.hex(): v.hex() for k, v in values.items()}, acl=access_acl, flags=flags)
        if args.driver:
            store = args.output/(name+'-store'); store.mkdir(mode=0o700, exist_ok=False)
            with (args.output/(name+'.native.log')).open('w') as log:
                subprocess.run([str(args.driver.resolve()), str(store.resolve()), str(args.output.resolve()), name+'.deb'],
                               stdout=log, stderr=subprocess.STDOUT, check=True, timeout=60)
        if args.native_roundtrip or args.driver:
            native_check(args.output, name, result)
        results.append(result)
    report = dict(result='pass', cases=results, native_payload_read=bool(args.native_roundtrip or args.driver), filesystem_application=False)
    (args.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print('PASS four retained-source configuration entries' + (' and native payload roundtrip' if args.native_roundtrip or args.driver else ''))


if __name__ == '__main__':
    main()
