#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic before/after catalogs for ordinary transition policy; no effects."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import tarfile
from make_deb_control_fixtures import member, tar
from make_deb_final_set_fixtures import package

DEST = Path(__file__).resolve().parent / 'fixtures/deb-transition'

def cases():
    rows = []
    def add(name, before, after, expected='None', kinds=()):
        rows.append(dict(name=name, before=before, after=after, expected=expected, kinds=list(kinds)))
    plain = package('base')
    add('unchanged-anchor-only', [], [])
    add('unchanged', [plain], [plain])
    add('addition', [], [plain], kinds=['Added'])
    add('ordinary-removal', [plain], [], kinds=['Removed'])
    for new, kind in [('3', 'Upgraded'), ('1', 'Downgraded'), ('2-0', 'Repacked'),
                      ('1:1', 'Upgraded'), ('2~rc1', 'Downgraded')]:
        add('version-' + new, [plain], [package('base', version=new)], kinds=[kind])
    add('same-version-different-content', [plain], [package('base', Recommends='optional')], kinds=['Repacked'])
    add('ordinary-crossgrade', [plain], [package('base', 'arm64')], kinds=['Removed', 'Added'])
    flags = [{}, {'Essential': 'yes'}, {'Protected': 'yes'}, {'Essential': 'yes', 'Protected': 'yes'}]
    for old_index, old in enumerate(flags):
        for new_index, new in enumerate(flags):
            lost = bool(set(old) - set(new))
            add(f'flags-{old_index}-{new_index}', [package('base', **old)], [package('base', version='3', **new)],
                'Protection_Migration_Required' if lost else 'None', [] if lost else ['Upgraded'])
        if not old: continue
        for suffix, after in [('remove', []), ('crossgrade', [package('base', 'arm64', **old)]),
                              ('virtual-substitute', [package('replacement', Provides='base', Replaces='base', **old)])]:
            add(f'protected-{old_index}-{suffix}', [package('base', **old)], after, 'Protection_Migration_Required')
    names = ['base', 'base+', 'base-a', 'base.a', 'base0', 'basea']
    add('prefix-order', [], [package(n) for n in reversed(names)], kinds=['Added'] * len(names))
    add('architecture-order', [], [package('library', a, multi='same') for a in ['i386', 'arm64', 'amd64']], kinds=['Added'] * 3)
    broken = package('consumer', Depends='provider')
    add('repair-broken-baseline', [broken], [broken, package('provider')], kinds=['Added'])
    add('reject-broken-target', [], [broken], 'Endpoint_Rejected')
    add('reject-breaking-removal', [broken, package('provider')], [broken], 'Endpoint_Rejected')
    add('reject-conflicting-target', [], [package('consumer', Conflicts='provider'), package('provider')], 'Endpoint_Rejected')
    add('essential-dependency-break', [package('base', Essential='yes')], [package('base', Essential='yes', Depends='absent')], 'Endpoint_Rejected')
    add('partial-plan-discarded', [package('aaa'), package('zzz', Essential='yes')], [package('aaa', version='3')], 'Protection_Migration_Required')
    # Sealed catalogs represent nonempty generations; bootstrap has a separate
    # admission contract. Keep an ordinary unchanged package in each test root.
    for row in rows:
        for side in ['before', 'after']: row[side].append(package('zz-anchor'))
    return rows

def build():
    files = {}; lines = []; matrix = cases()
    for i, row in enumerate(matrix):
        row['id'] = f'case-{i:04d}'
        tokens = [row['id'], row['expected']]
        for side in ['before', 'after']:
            images = []
            for fields in row[side]:
                control = ('\n'.join(k + ': ' + v for k, v in fields.items()) +
                    '\nMaintainer: Fixture <fixture@example.invalid>\nDescription: transition fixture\n').encode()
                encoded = gzip.compress(tar([('./control', control, tarfile.REGTYPE, '')]), mtime=0)
                raw = b'!<arch>\n' + member('debian-binary', b'2.0\n') + member('control.tar.gz', encoded) + member('data.tar', b'\0' * 1024)
                digest = hashlib.sha256(raw).hexdigest(); name = digest + '.deb'
                assert name not in files or files[name] == raw
                files[name] = raw
                images.append(dict(filename=name, original=digest, control=hashlib.sha256(control).hexdigest()))
            row[side + '_images'] = images
            tokens.extend([str(len(images)), *(v['filename'] + '=' + v['control'] for v in images)])
        lines.append(' '.join(tokens))
    files['cases.txt'] = ('\n'.join(lines) + '\n').encode()
    files['cases.json'] = (json.dumps(matrix, indent=2) + '\n').encode()
    return files

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--write', action='store_true'); mode.add_argument('--check', action='store_true')
    args = parser.parse_args(); files = build()
    if args.write: DEST.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        if args.write: (DEST / name).write_bytes(data)
        elif (DEST / name).read_bytes() != data: raise SystemExit('fixture differs: ' + name)
    assert {p.name for p in DEST.iterdir() if p.is_file()} == set(files)
    print('Transition fixtures:', len(files) - 2, 'originals;', len(cases()), 'cases;', 'written' if args.write else 'match')
