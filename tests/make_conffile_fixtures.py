#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Script-free deterministic DEBs for native conffile declarations."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile
from make_deb_control_fixtures import member, tar

DEST = Path(__file__).resolve().parent/'fixtures/conffiles'


def fixtures():
    regular = [('./etc/fixture.conf', b'first\n', tarfile.REGTYPE, '')]
    cases = [
        ('normal', b'/etc/fixture.conf\n', regular, True),
        ('updated', b'/etc/fixture.conf\n', [('./etc/fixture.conf', b'second\n', tarfile.REGTYPE, '')], True),
        ('omitted', None, [], True),
        ('remove-current', b'remove-on-upgrade /etc/fixture.conf\n', [], True),
        ('absent', None, regular, True),
        ('empty', b'', regular, True),
        ('missing', b'/etc/missing.conf\n', regular, True),
        ('remove', b'remove-on-upgrade\t/etc/old.conf  \t\n', regular, True),
        ('no-final-newline', b'/etc/fixture.conf', regular, True),
        ('space-name', b'/etc/a b.conf  \n', [('./etc/a b.conf', b'one', tarfile.REGTYPE, '')], True),
        ('byte-name', b'/etc/\xff.conf\n', [('./etc/\udcff.conf', b'one', tarfile.REGTYPE, '')], True),
        ('symbolic', b'/etc/link.conf\n', regular+[('./etc/link.conf', b'', tarfile.SYMTYPE, 'fixture.conf')], True),
        ('blank', b'\n', regular, False),
        ('whitespace', b' \t\n', regular, False),
        ('duplicate', b'/etc/fixture.conf\n/etc/fixture.conf\n', regular, False),
        ('remove-present', b'remove-on-upgrade /etc/fixture.conf\n', regular, False),
        ('unknown-flag', b'future /etc/fixture.conf\n', regular, False),
        ('relative', b'etc/fixture.conf\n', regular, False),
        ('traversal', b'/etc/../fixture.conf\n', regular, False),
        ('nul', b'/etc/bad\x00.conf\n', regular, False),
        ('empty-component', b'/etc//fixture.conf\n', regular, False),
    ]
    control = b'Package: conf-fixture\nVersion: 1\nArchitecture: all\nMaintainer: Fixture <fixture@example.invalid>\nDescription: conffile fixture\n'
    for name, declarations, files, accepted in cases:
        metadata = [('./control', control.replace(b'Version: 1', b'Version: 2') if name in ('updated', 'omitted', 'remove-current') else control, tarfile.REGTYPE, '')]
        if declarations is not None:
            metadata.append(('./conffiles', declarations, tarfile.REGTYPE, ''))
        raw = b'!<arch>\n'+member('debian-binary', b'2.0\n')+member('control.tar', tar(metadata))+member('data.tar', tar(files))
        yield name+'.deb', raw, accepted


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--write', action='store_true'); mode.add_argument('--check', action='store_true')
    args = parser.parse_args(); rows = []
    if args.write: DEST.mkdir(parents=True, exist_ok=True)
    for name, raw, accepted in fixtures():
        if args.write: (DEST/name).write_bytes(raw)
        else: assert (DEST/name).read_bytes() == raw, name
        rows.append(dict(filename=name, sha256=hashlib.sha256(raw).hexdigest(), accepted=accepted))
    wire = (json.dumps(rows, indent=2)+'\n').encode()
    if args.write: (DEST/'manifest.json').write_bytes(wire)
    else: assert (DEST/'manifest.json').read_bytes() == wire
    print('PASS conffile fixtures:', len(rows))
