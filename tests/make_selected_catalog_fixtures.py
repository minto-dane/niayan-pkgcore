#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Deterministic candidate-set inputs; never installed."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import tarfile
from make_deb_control_fixtures import member, tar
from make_deb_payload_fixtures import entry, archive as payload_archive

DEST = Path(__file__).resolve().parent / 'fixtures/selected-catalog'

def fixtures():
    relations = ('Depends: library:any (>= 2.0) | fallback:arm64, helper\n'
                 'Pre-Depends: bootstrap (>= 1:1.0-1)\nRecommends: optional | another\n'
                 'Suggests: suggestion\nEnhances: editor\nBreaks: obsolete (<< 2)\n'
                 'Conflicts: competing:any\nReplaces: obsolete (<= 1)\n'
                 'Provides: virtual:amd64 (= 1.0), unversioned\n'
                 'Built-Using: source-one (= 1.0)\nStatic-Built-Using: source-two (= 2.0)\n')
    for filename, name, version, arch, extra, payload in [
        ('consumer', 'consumer', '1:1.0-1', 'all', 'Source: consumer-source (1:1.0-2)\nEssential: yes\nProtected: yes\nInstalled-Size: 0\n' + relations, b'first'),
        ('library-amd64', 'library', '2.0', 'amd64', 'Multi-Arch: same\n', b'amd64'),
        ('library-arm64', 'library', '2.0', 'arm64', 'Multi-Arch: same\n', b'arm64'),
        ('empty', 'empty-package', '1', 'all', '', None),
        ('consumer-repacked', 'consumer', '1:1.0-1', 'all', 'Source: consumer-source (1:1.0-2)\nEssential: yes\nProtected: yes\nInstalled-Size: 0\n' + relations, b'second'),
        ('consumer-upgrade', 'consumer', '1:2.0-1', 'all', '', b'upgrade'),
    ]:
        control = (f'Package: {name}\nVersion: {version}\nArchitecture: {arch}\n'
                   'Maintainer: Fixture <fixture@example.invalid>\nDescription: candidate fixture\n 日本語の説明\n' + extra).encode()
        control_tar = tar([('./control', control, tarfile.REGTYPE, '')])
        data_tar = tar([] if payload is None else [('./' + filename, payload, tarfile.REGTYPE, '')])
        raw = b'!<arch>\n' + member('debian-binary', b'2.0\n') + member('control.tar', control_tar) + member('data.tar', data_tar)
        yield filename + '.deb', raw, control, control_tar
    control = b'Package: retention-rich\nVersion: 1\nArchitecture: all\nMaintainer: Fixture <fixture@example.invalid>\nDescription: retention fixture\n'
    control_tar = gzip.compress(tar([('./', b'', tarfile.DIRTYPE, ''),
        ('./control', control, tarfile.REGTYPE, ''), ('./postinst', b'#!/bin/sh\nexit 97\n', tarfile.REGTYPE, ''),
        ('./conffiles', b'/dir/file\n', tarfile.REGTYPE, ''), ('./future-field', b'opaque\x00\xff', tarfile.REGTYPE, '')]), mtime=0)
    data_tar = payload_archive([entry('./dir', kind=tarfile.DIRTYPE, mode=0o2755),
        entry('./dir/file', b'contents', mode=0o640, pax_headers={'SCHILY.xattr.user.demo': 'value',
            'SCHILY.acl.access': 'user::rw-,user:42:r--,group::r--,mask::r--,other::---'}),
        entry('./hard', kind=tarfile.LNKTYPE, link='./dir/file'),
        entry('./sym', kind=tarfile.SYMTYPE, link='dir/file'), entry('./zero'),
        entry('./device', kind=tarfile.CHRTYPE, devmajor=1, devminor=3),
        entry('./block', kind=tarfile.BLKTYPE, devmajor=8, devminor=1), entry('./fifo', kind=tarfile.FIFOTYPE)], tarfile.PAX_FORMAT)
    raw = b'!<arch>\n' + member('debian-binary', b'2.0\n') + member('control.tar.gz', control_tar) + member('data.tar.gz', gzip.compress(data_tar, mtime=0))
    yield 'retention-rich.deb', raw, control, control_tar
    control = b'Package: invalid\nVersion: 1\nArchitecture: all\n'
    control_tar = tar([('./control', control, tarfile.REGTYPE, '')])
    yield 'invalid.deb', b'!<arch>\n' + member('debian-binary', b'2.0\n') + member('control.tar', control_tar) + member('data.tar', tar([])), control, control_tar

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--write', action='store_true'); mode.add_argument('--check', action='store_true')
    args = parser.parse_args(); manifest = []
    if args.write: DEST.mkdir(parents=True, exist_ok=True)
    for name, raw, control, archive in fixtures():
        if args.write: (DEST / name).write_bytes(raw)
        elif (DEST / name).read_bytes() != raw: raise SystemExit('fixture differs: ' + name)
        manifest.append(dict(filename=name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw),
                             control=hashlib.sha256(control).hexdigest(), archive=hashlib.sha256(archive).hexdigest()))
    raw = (json.dumps(manifest, indent=2) + '\n').encode()
    if args.write: (DEST / 'manifest.json').write_bytes(raw)
    elif (DEST / 'manifest.json').read_bytes() != raw: raise SystemExit('manifest differs')
    print('Selected catalog fixtures:', len(manifest), 'written' if args.write else 'match')
