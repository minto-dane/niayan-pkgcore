#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Small native ownership relation fixtures, never installed or executed."""
import argparse
import hashlib
import json
import tarfile
from pathlib import Path
from make_deb_control_fixtures import member, tar
from make_deb_payload_fixtures import entry, archive

DEST = Path(__file__).resolve().parent / 'fixtures/payload-ownership'


def fixtures():
    cases = [
        ('victim', 'victim', 'amd64', 'Provides: virtual-owned\n', b'old', 0o755, 1),
        ('takeover', 'winner', 'amd64', 'Replaces: victim (<< 2)\n', b'new', 0o755, 2),
        ('unjustified', 'winner', 'amd64', '', b'new', 0o755, 2),
        ('virtual', 'winner', 'amd64', 'Replaces: virtual-owned\n', b'new', 0o755, 2),
        ('version', 'winner', 'amd64', 'Replaces: victim (>= 2)\n', b'new', 0o755, 2),
        ('arch-match', 'winner', 'amd64', 'Replaces: victim:amd64 (= 1)\n', b'new', 0o755, 2),
        ('arch-miss', 'winner', 'amd64', 'Replaces: victim:arm64 (= 1)\n', b'new', 0o755, 2),
        ('same-amd64', 'shared-library', 'amd64', 'Multi-Arch: same\n', b'shared', 0o755, 1),
        ('same-arm64', 'shared-library', 'arm64', 'Multi-Arch: same\n', b'shared', 0o755, 2),
        ('different-arm64', 'shared-library', 'arm64', 'Multi-Arch: same\n', b'different', 0o755, 2),
        ('mode-arm64', 'shared-library', 'arm64', 'Multi-Arch: same\n', b'shared', 0o750, 2),
    ]
    for filename, name, arch, extra, data, mode, mtime in cases:
        control = (f'Package: {name}\nVersion: 1\nArchitecture: {arch}\n'
                   'Maintainer: Fixture <fixture@example.invalid>\nDescription: ownership fixture\n' + extra).encode()
        yield filename + '.deb', (b'!<arch>\n' + member('debian-binary', b'2.0\n') +
            member('control.tar', tar([('./control', control, tarfile.REGTYPE, '')])) +
            member('data.tar', archive([entry('./', kind=tarfile.DIRTYPE, mode=mode, mtime=mtime),
                entry('./owned', data, mode=mode, mtime=mtime)])))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--write', action='store_true'); mode.add_argument('--check', action='store_true')
    args = parser.parse_args(); values = dict(fixtures())
    values['manifest.json'] = (json.dumps([dict(filename=name, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
        for name, raw in values.items()], indent=2) + '\n').encode()
    if args.write: DEST.mkdir(parents=True, exist_ok=True)
    for name, raw in values.items():
        if args.write: (DEST / name).write_bytes(raw)
        elif (DEST / name).read_bytes() != raw: raise SystemExit('fixture differs: ' + name)
    print('Ownership fixtures:', len(values) - 1, 'written' if args.write else 'match')
