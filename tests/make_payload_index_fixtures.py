#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Independent-source overlapping claims. Never extracted or installed."""
import argparse
import hashlib
import json
import tarfile
from pathlib import Path
from make_deb_payload_fixtures import entry, archive
from make_deb_data_fixtures import deb

DEST = Path(__file__).resolve().parent / 'fixtures/payload-index'

def fixtures():
    yield 'overlap.deb', deb(archive([
        entry('usr', kind=tarfile.DIRTYPE, mode=0o700),
        entry('absolute/child', b'child'), entry('usr/a', b'other'),
    ]), '')
    yield 'shared.deb', deb(archive([
        entry('usr', kind=tarfile.DIRTYPE, mode=0o2755), entry('empty'),
    ]), '')
    yield 'links.deb', deb(archive([
        entry('alias', kind=tarfile.LNKTYPE, link='basis', mode=0o600),
        entry('basis', b'base', mode=0o6755),
    ]), '')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--write', action='store_true'); mode.add_argument('--check', action='store_true')
    args = parser.parse_args(); manifest = []
    if args.write: DEST.mkdir(parents=True, exist_ok=True)
    for name, data in fixtures():
        if args.write: (DEST / name).write_bytes(data)
        elif (DEST / name).read_bytes() != data: raise SystemExit('fixture differs: ' + name)
        manifest.append(dict(filename=name, sha256=hashlib.sha256(data).hexdigest(), size=len(data)))
    data = (json.dumps(manifest, indent=2) + '\n').encode()
    if args.write: (DEST / 'manifest.json').write_bytes(data)
    elif (DEST / 'manifest.json').read_bytes() != data: raise SystemExit('manifest differs')
    print('Payload index fixtures:', len(manifest), 'written' if args.write else 'match')
