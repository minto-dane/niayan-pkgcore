#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Small deterministic root assembly inputs; never installed or executed."""
import argparse
import hashlib
import json
import tarfile
from pathlib import Path
from make_deb_control_fixtures import member, tar
from make_deb_payload_fixtures import entry, archive

DEST = Path(__file__).resolve().parent / 'fixtures/root-archive'


def fixtures():
    root = entry('./', kind=tarfile.DIRTYPE, mode=0o755)
    directory = entry('./dir', kind=tarfile.DIRTYPE, mode=0o2755)
    long = 'g' * 150
    sources = [
        ('base', tarfile.PAX_FORMAT, [root, directory,
         entry('./forward', kind=tarfile.LNKTYPE, link='./chain'),
         entry('./chain', kind=tarfile.LNKTYPE, link='./dir/file'),
         entry('./dir/file', b'contents\x00\xff', mode=0o640, pax_headers={
             'mtime': '-0.000000001', 'atime': '1700000001.000000007',
             'ctime': '1700000002.42', 'LIBARCHIVE.creationtime': '1700000003.75',
             'SCHILY.fflags': 'nodump', 'SCHILY.xattr.user.demo': 'value',
             'SCHILY.acl.access': 'user::rw-,user:42:r--,group::r--,mask::r--,other::---'}),
         entry('./sym', kind=tarfile.SYMTYPE, link='dir/file'),
         entry('./device', kind=tarfile.CHRTYPE, devmajor=1, devminor=3),
         entry('./block', kind=tarfile.BLKTYPE, devmajor=8, devminor=1),
         entry('./fifo', kind=tarfile.FIFOTYPE), entry('./日本語', b'utf8')]),
        ('overlay', tarfile.USTAR_FORMAT, [entry('./', kind=tarfile.DIRTYPE, mode=0o750),
         entry('./dir', kind=tarfile.DIRTYPE, mode=0o755), entry('./dir/file', b'other'), entry('./extra')]),
        ('conflicting', tarfile.GNU_FORMAT, [root, entry('./dir', b'not a directory'),
         entry('./' + long, b'long', uid=4294967295, gid=4294967294, mtime=-1),
         entry('./long-link', kind=tarfile.SYMTYPE, link=long)]),
    ]
    for name, fmt, entries in sources:
        control = (f'Package: root-{name}\nVersion: 1\nArchitecture: all\n'
                   'Maintainer: Fixture <fixture@example.invalid>\nDescription: root fixture\n').encode()
        yield name + '.deb', (b'!<arch>\n' + member('debian-binary', b'2.0\n') +
            member('control.tar', tar([('./control', control, tarfile.REGTYPE, '')])) +
            member('data.tar', archive(entries, fmt)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--write', action='store_true')
    mode.add_argument('--check', action='store_true')
    args = parser.parse_args()
    values = dict(fixtures())
    values['manifest.json'] = (json.dumps([
        dict(filename=name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
        for name, raw in values.items()], indent=2) + '\n').encode()
    if args.write:
        DEST.mkdir(parents=True, exist_ok=True)
    for name, raw in values.items():
        if args.write:
            (DEST / name).write_bytes(raw)
        elif (DEST / name).read_bytes() != raw:
            raise SystemExit('fixture differs: ' + name)
    print('Root archive fixtures:', len(values) - 1, 'written' if args.write else 'match')
