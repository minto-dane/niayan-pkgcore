#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Deterministic upstream-codec fixtures; data bytes are never installed."""
import argparse
import bz2
import gzip
import hashlib
import json
import lzma
from pathlib import Path
import subprocess
import tarfile
from make_deb_control_fixtures import CONTROL, member, tar

DEST = Path(__file__).resolve().parent / 'fixtures/deb-data'
PAYLOAD = bytes((i * 17 + i // 251) % 256 for i in range(131079))
RAW = tar([(name, b'', tarfile.DIRTYPE, '') for name in ['./', './usr/', './usr/share/', './usr/share/fixture/']]
          + [('./usr/share/fixture/data.bin', PAYLOAD, tarfile.REGTYPE, '')])
CONTROL_TAR = tar([('./control', CONTROL, tarfile.REGTYPE, '')])
CODECS = {
    'plain': ('', lambda x: x),
    'gzip': ('.gz', lambda x: gzip.compress(x, mtime=0)),
    'bzip2': ('.bz2', bz2.compress),
    'lzma': ('.lzma', lambda x: lzma.compress(x, format=lzma.FORMAT_ALONE)),
    'xz': ('.xz', lzma.compress),
    'zstd': ('.zst', lambda x: subprocess.run(['zstd', '-q', '--check', '-3', '-T1', '-c'], input=x, capture_output=True, check=True).stdout),
}

def deb(encoded, suffix):
    return b'!<arch>\n' + member('debian-binary', b'2.0\n') + member('control.tar', CONTROL_TAR) + member('data.tar' + suffix, encoded)

def fixtures():
    yield 'payload.raw', RAW, None
    for name, (suffix, encode) in CODECS.items():
        encoded = encode(RAW)
        yield name + '.encoded', encoded, None
        yield 'valid-' + name + '.deb', deb(encoded, suffix), True
        yield 'empty-' + name + '.encoded', encode(b''), None
        if name != 'plain':
            yield 'truncated-' + name + '.deb', deb(encoded[:-1], suffix), False
            yield 'trailing-' + name + '.deb', deb(encoded + b'X', suffix), False
            yield 'concatenated-' + name + '.deb', deb(encoded + encoded, suffix), False
            yield 'missing-' + name + '.deb', deb(b'', suffix), False
        if name in ('gzip', 'bzip2', 'xz', 'zstd'):
            offset = {'gzip': -8, 'bzip2': 10, 'xz': -12, 'zstd': -1}[name]
            corrupted = bytearray(encoded); corrupted[offset] ^= 1
            yield 'bad-integrity-' + name + '.deb', deb(bytes(corrupted), suffix), False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--write', action='store_true'); mode.add_argument('--check', action='store_true')
    args = parser.parse_args(); manifest = []
    if args.write: DEST.mkdir(parents=True, exist_ok=True)
    for name, raw, accepted in fixtures():
        path = DEST / name
        if args.write: path.write_bytes(raw)
        elif path.read_bytes() != raw: raise SystemExit('fixture differs: ' + name)
        manifest.append(dict(filename=name,sha256=hashlib.sha256(raw).hexdigest(),size=len(raw),accepted=accepted))
    encoded = (json.dumps(manifest, indent=2) + '\n').encode()
    if args.write: (DEST / 'manifest.json').write_bytes(encoded)
    elif (DEST / 'manifest.json').read_bytes() != encoded: raise SystemExit('fixture manifest differs')
    print('Data-stream fixtures:', len(manifest), 'written' if args.write else 'match')
