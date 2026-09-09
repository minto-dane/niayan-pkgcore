#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regenerate small synthetic DEBs; uses upstream compressors, never installs."""
import argparse
import ctypes
import gzip
import hashlib
import io
import json
import lzma
from pathlib import Path
import tarfile

DEST = Path(__file__).resolve().parent / 'fixtures/deb-control'
CONTROL = b'Package: fixture\nVersion: 1:2.0-1\nArchitecture: all\nMaintainer: Fixture <fixture@example.invalid>\nDescription: fixture only\n continuation\nX-Preserved: opaque\n'
SCRIPT = b'#!/bin/sh\nexit 97\n'

def tar(entries, *, fmt=tarfile.USTAR_FORMAT, pax=None):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=fmt) as archive:
        for name, data, kind, target in entries:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            entry.linkname = target
            entry.size = len(data)
            entry.uid = 1001
            entry.gid = 1002
            entry.uname = 'fixture-user'
            entry.gname = 'fixture-group'
            entry.mtime = 1788739200
            entry.mode = 0o755 if kind == tarfile.DIRTYPE or name == './postinst' else 0o640
            if pax:
                entry.pax_headers = pax
            archive.addfile(entry, io.BytesIO(data))
    return out.getvalue()

def zstd(raw):
    lib = ctypes.CDLL('libzstd.so.1')
    lib.ZSTD_compressBound.argtypes = [ctypes.c_size_t]
    lib.ZSTD_compressBound.restype = ctypes.c_size_t
    lib.ZSTD_compress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    lib.ZSTD_compress.restype = ctypes.c_size_t
    lib.ZSTD_isError.argtypes = [ctypes.c_size_t]
    lib.ZSTD_isError.restype = ctypes.c_uint
    dest = ctypes.create_string_buffer(lib.ZSTD_compressBound(len(raw)))
    used = lib.ZSTD_compress(dest, len(dest), raw, len(raw), 3)
    assert not lib.ZSTD_isError(used)
    return dest.raw[:used]

def member(name, data):
    header = f'{name + "/":<16}{0:<12}{0:<6}{0:<6}{"100644":<8}{len(data):<10}`\n'.encode('ascii')
    assert len(header) == 60
    return header + data + (b'\n' if len(data) % 2 else b'')

def deb(raw, suffix=''):
    return b'!<arch>\n' + member('debian-binary', b'2.0\n') + member('control.tar' + suffix, raw) + member('data.tar', b'\0' * 1024)

def fixtures():
    regular = tarfile.REGTYPE
    entries = [('./', b'', tarfile.DIRTYPE, ''), ('./control', CONTROL, regular, ''),
               ('./postinst', SCRIPT, regular, ''), ('./future-field', b'preserve\0all\xffbytes', regular, '')]
    raw = tar(entries)
    yield 'valid-plain', deb(raw)
    yield 'valid-gzip', deb(gzip.compress(raw, mtime=0), '.gz')
    yield 'valid-xz', deb(lzma.compress(raw), '.xz')
    yield 'valid-zstd', deb(zstd(raw), '.zst')
    yield 'valid-gnu', deb(tar(entries, fmt=tarfile.GNU_FORMAT))
    yield 'count-boundary', deb(tar(entries + [(f'extra-{i}', b'', regular, '') for i in range(60)]))
    yield 'pax-attributes', deb(tar(entries, fmt=tarfile.PAX_FORMAT, pax={'SCHILY.xattr.user.fixture': 'retained-in-original'}))
    yield 'missing-control', deb(tar(entries[:1] + entries[2:]))
    yield 'duplicate', deb(tar(entries + [('control', CONTROL, regular, '')]))
    for name in ('../escape', '/absolute', './nested/file', './bad space'):
        label = {'../escape':'traversal','/absolute':'absolute','./nested/file':'nested','./bad space':'space'}[name]
        yield label, deb(tar(entries + [(name, b'', regular, '')]))
    for label, kind in [('symlink', tarfile.SYMTYPE), ('hardlink', tarfile.LNKTYPE), ('device', tarfile.CHRTYPE), ('fifo', tarfile.FIFOTYPE)]:
        yield label, deb(tar(entries + [('extra', b'', kind, 'control' if label.endswith('link') else '')]))
    yield 'directory-file', deb(tar(entries + [('extra', b'', tarfile.DIRTYPE, '')]))
    yield 'bad-checksum', deb(bytes([raw[0] ^ 1]) + raw[1:])
    yield 'truncated-content', deb(raw[:1100])
    yield 'wrong-codec', deb(raw, '.xz')
    yield 'truncated-xz', deb(lzma.compress(raw)[:-12], '.xz')
    compressed = gzip.compress(raw, mtime=0)
    yield 'bad-gzip-crc', deb(compressed[:-8] + bytes([compressed[-8] ^ 1]) + compressed[-7:], '.gz')
    yield 'truncated-zstd', deb(zstd(raw)[:-1], '.zst')
    for label, suffix, encoded in [('gzip', '.gz', gzip.compress(raw, mtime=0)),
                                   ('xz', '.xz', lzma.compress(raw)), ('zstd', '.zst', zstd(raw))]:
        yield 'trailing-' + label, deb(encoded + b'garbage', suffix)
        yield 'concatenated-' + label, deb(encoded + encoded, suffix)
    yield 'too-many', deb(tar(entries + [(f'extra-{i}', b'', regular, '') for i in range(61)]))
    # Tiny compressed fixture expands beyond both the per-file and total budget.
    yield 'expanded-limit', deb(lzma.compress(tar([('control', b'x' * (16 * 1024 * 1024 + 1), regular, '')])), '.xz')
    yield 'total-limit', deb(lzma.compress(tar([('control', b'x' * (9 * 1024 * 1024), regular, ''), ('extra', b'y' * (9 * 1024 * 1024), regular, '')])), '.xz')
    yield 'nested-compression', deb(gzip.compress(gzip.compress(raw, mtime=0), mtime=0), '.gz')
    yield 'tar-padding-limit', deb(lzma.compress(raw + b'\0' * (32 * 1024 * 1024 + 1 - len(raw))), '.xz')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--write', action='store_true')
    mode.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.write:
        DEST.mkdir(parents=True, exist_ok=True)
    manifest = []
    for name, raw in fixtures():
        filename = name + '.deb'
        if args.write:
            (DEST / filename).write_bytes(raw)
        else:
            if (DEST / filename).read_bytes() != raw:
                raise SystemExit('fixture differs: ' + filename)
        manifest.append({'filename': filename, 'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw), 'accepted': name.startswith('valid-') or name == 'count-boundary'})
    encoded = (json.dumps(manifest, indent=2) + '\n').encode()
    if args.write:
        (DEST / 'manifest.json').write_bytes(encoded)
    elif (DEST / 'manifest.json').read_bytes() != encoded:
        raise SystemExit('fixture manifest differs')
    print('Synthetic control fixtures:', len(manifest), 'written' if args.write else 'match')
