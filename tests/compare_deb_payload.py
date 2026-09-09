#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only independent tar/CAS oracle for the native payload observation probe."""
import argparse
from decimal import Decimal, ROUND_FLOOR
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile

ZERO = '0' * 64
EMPTY = b'\0\0'

def digest(stream):
    h = hashlib.sha256(); size = 0
    while data := stream.read(65536):
        h.update(data); size += len(data)
    return h.hexdigest(), size

def clock(value):
    value = Decimal(str(value)); seconds = int(value.to_integral_value(rounding=ROUND_FLOOR))
    return ['TRUE', seconds, int((value - seconds) * 10**9)]

def canonical(name, directory=False):
    if name in ('.', './') and directory: return ''
    if name.startswith('./'): name = name[2:]
    return name.rstrip('/') if directory else name

def observe(log):
    result = {'entries': []}; item = result
    for line in log.read_text().splitlines():
        key, _, value = line.partition(' '); value = value.strip()
        if key == 'PASS': continue
        if key == 'ENTRY':
            item = {'index': int(value)}; result['entries'].append(item)
        elif key in ('PATH', 'LINK', 'UNAME', 'GNAME'): item[key] = bytes.fromhex(value).decode('utf-8', 'surrogateescape')
        elif key == 'ATTR':
            fields = value.split(); item[key] = [fields[0], *map(int, fields[1:])]
        elif key in ('MTIME', 'ATIME', 'CTIME', 'BTIME'):
            fields = value.split(); item[key] = [fields[0], *map(int, fields[1:])]
        else: item[key] = value
    assert len(result['entries']) == int(result['COUNT'])
    return result

def cas_bytes(cas, value):
    return (cas / 'objects' / value[:2] / value[2:]).read_bytes()

def xattrs(headers):
    items = sorted((k.removeprefix('SCHILY.xattr.').encode(), v.encode('utf-8', 'surrogateescape')) for k, v in headers.items() if k.startswith('SCHILY.xattr.'))
    return struct.pack('>H', len(items)) + b''.join(struct.pack('>HI', len(k), len(v)) + k + v for k, v in items)

def acl(headers):
    # This independent oracle supports the POSIX access/default text used by
    # these fixtures. Other ACL families require an additional oracle.
    items = []; base = {}; named = []
    for key, typ in [('SCHILY.acl.access', 0x100), ('SCHILY.acl.default', 0x200)]:
        if key not in headers: continue
        for record in headers[key].split(','):
            kind, qualifier, perms = record.split(':')
            perm = sum(bit for char, bit in [('r', 4), ('w', 2), ('x', 1)] if char in perms)
            tag = {'user': 10001 if qualifier else 10002, 'group': 10003 if qualifier else 10004, 'mask': 10005, 'other': 10006}[kind]
            item = (typ, perm, tag, int(qualifier) if qualifier else 0xffffffff, qualifier.encode())
            if typ == 0x100 and not qualifier and kind in ('user', 'group', 'other'): base[kind] = item
            else: named.append(item)
    if base:
        items.extend(base[k] for k in ('user', 'group', 'other'))
    items.extend(named)
    return struct.pack('>H', len(items)) + b''.join(struct.pack('>IIIIH', t, p, tag, q, len(n)) + n for t, p, tag, q, n in items)

def compare(source, native, cas):
    observed = observe(native)
    with source.open('rb') as stream: original, size = digest(stream)
    assert observed['ORIGINAL'] == original
    with tempfile.TemporaryFile() as raw:
        subprocess.run(['dpkg-deb', '--fsys-tarfile', str(source)], stdout=raw, check=True, timeout=120)
        raw.seek(0); tar_hash, tar_size = digest(raw)
        assert tar_hash == observed['TAR']; raw.seek(0)
        with tarfile.open(fileobj=raw, mode='r:') as tar:
            expected = []
            for i, entry in enumerate(tar, 1):
                kind = {tarfile.REGTYPE: 'REGULAR', tarfile.AREGTYPE: 'REGULAR', tarfile.CONTTYPE: 'REGULAR', tarfile.DIRTYPE: 'DIRECTORY', tarfile.SYMTYPE: 'SYMBOLIC_LINK', tarfile.LNKTYPE: 'HARD_LINK', tarfile.CHRTYPE: 'CHARACTER_DEVICE', tarfile.BLKTYPE: 'BLOCK_DEVICE', tarfile.FIFOTYPE: 'FIFO'}[entry.type]
                name = canonical(entry.name, entry.isdir()); link = canonical(entry.linkname) if entry.islnk() else entry.linkname
                mode = entry.mode
                if 'SCHILY.acl.access' in entry.pax_headers:
                    for item in entry.pax_headers['SCHILY.acl.access'].split(','):
                        k, q, text = item.split(':')
                        if not q and k in ('user', 'group', 'other'):
                            shift = {'user': 6, 'group': 3, 'other': 0}[k]; perm = sum(n for c,n in [('r',4),('w',2),('x',1)] if c in text)
                            mode = (mode & ~(7 << shift)) | (perm << shift)
                content, content_size, inode = ZERO, 0, 0
                if entry.isreg():
                    with tar.extractfile(entry) as stream: content, content_size = digest(stream)
                    inode = i
                elif entry.issym():
                    value = link.encode('utf-8', 'surrogateescape'); content = hashlib.sha256(value).hexdigest(); content_size = len(value)
                clocks = {'MTIME': clock(entry.pax_headers.get('mtime', entry.mtime))}
                for key, field in [('atime', 'ATIME'), ('ctime', 'CTIME'), ('LIBARCHIVE.creationtime', 'BTIME')]:
                    clocks[field] = clock(entry.pax_headers[key]) if key in entry.pax_headers else ['FALSE', 0, 0]
                raw.seek(entry.offset); header = raw.read(512)
                if header[257:265] == b'ustar  \0':
                    for field, offset in [('ATIME', 345), ('CTIME', 357)]:
                        if header[offset:offset+12].strip(b'\0 '): clocks[field] = clock(int(header[offset:offset+12].strip(b'\0 '), 8))
                expected.append(dict(index=i, PATH=name, LINK=link, UNAME=entry.uname, GNAME=entry.gname,
                    ATTR=[kind,mode,entry.uid,entry.gid,entry.devmajor,entry.devminor,entry.size,content_size,inode,64 if entry.pax_headers.get('SCHILY.fflags') == 'nodump' else 0,0],
                    CONTENT=content, XATTR=hashlib.sha256(xattrs(entry.pax_headers)).hexdigest(), ACL=hashlib.sha256(acl(entry.pax_headers)).hexdigest(), **clocks))
            by_name = {e['PATH']: e for e in expected}
            for entry in expected:
                if entry['ATTR'][0] == 'HARD_LINK':
                    target = by_name[entry['LINK']]; seen = {entry['PATH']}
                    while target['ATTR'][0] == 'HARD_LINK':
                        assert target['PATH'] not in seen; seen.add(target['PATH']); target = by_name[target['LINK']]
                    assert target['ATTR'][0] == 'REGULAR'; entry['CONTENT'] = target['CONTENT']; entry['ATTR'][7:9] = target['ATTR'][7:9]
            assert len(expected) == len(observed['entries'])
            for exp, got in zip(expected, observed['entries']):
                assert exp == got, (source.name, exp, got)
            # All CAS hashes are checked independently, including empty xattrs,
            # normalized ACL blobs, symlink text and hardlink-shared content.
            objects = {original: size, tar_hash: tar_size}
            for entry in expected:
                for key in ['XATTR','ACL']: objects[entry[key]] = None
                if entry['CONTENT'] != ZERO: objects[entry['CONTENT']] = entry['ATTR'][7]
            for value, size in objects.items():
                with (cas/'objects'/value[:2]/value[2:]).open('rb') as stream: actual, n = digest(stream)
                assert actual == value and (size is None or size == n)
    return dict(filename=source.name, original=original, tar=tar_hash, entries=len(expected), tar_bytes=tar_size, cas_objects=len(objects), result='pass')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--media', type=Path, required=True); parser.add_argument('--probes', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rows=[]
    for log in sorted(args.probes.glob('*.deb.log')):
        source=args.media/log.name.removesuffix('.log'); cas=args.probes/(source.name+'.cas')
        rows.append(compare(source,log,cas)); print(source.name,rows[-1]['entries'],flush=True)
    assert rows
    args.output.write_text(json.dumps(dict(result='pass',scope='read-only native payload versus Python tarfile, dpkg-deb and complete CAS objects; no extraction or execution',files=rows),indent=2)+'\n')
