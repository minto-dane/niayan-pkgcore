#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded synthetic endpoint cases; no payload files or maintainer scripts."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import tarfile
from make_deb_control_fixtures import member, tar

DEST = Path(__file__).resolve().parent / 'fixtures/deb-final-set'

def package(name, arch='amd64', version='2', multi='no', **fields):
    return dict(Package=name, Version=version, Architecture=arch, **{'Multi-Arch': multi}, **fields)

def cases():
    result = []
    def add(name, packages, expected='No_Violation', native='amd64', reference=True):
        result.append(dict(name=name, packages=packages, expected=expected, native=native,
                           enabled=['amd64', 'arm64', 'i386'], reference=reference))
    add('standalone', [package('standalone')])
    add('weak-and-source-not-runtime-deps', [package('standalone', Recommends='missing', Suggests='absent',
        Enhances='editor', **{'Built-Using': 'source-code (= 1)', 'Static-Built-Using': 'static-code (= 2)', 'Replaces': 'absent'})])
    add('unenabled-architecture', [package('standalone', 'riscv64')], 'Architecture_Not_Enabled')
    add('alternatives-second', [package('consumer', Depends='absent | provider'), package('provider')])
    add('all-groups-required', [package('consumer', Depends='provider, absent | missing'), package('provider')], 'Missing_Dependency')
    add('self-dependency', [package('self-package', Depends='self-package (= 2)')])
    add('self-provided-dependency', [package('self-package', Depends='virtual (= 7)', Provides='virtual (= 7)')])
    add('dependency-cycle', [package('first', Depends='second'), package('second', Depends='first')])
    add('predependency-cycle-endpoint-only', [package('first', **{'Pre-Depends': 'second'}), package('second', **{'Pre-Depends': 'first'})])
    add('predependency-missing', [package('first', **{'Pre-Depends': 'absent'})], 'Missing_Dependency')
    for dep in ['Depends', 'Pre-Depends']:
        for relation, needed, yes in [('<<', '3', True), ('<=', '2', True), ('=', '2', True),
                                      ('>=', '2', True), ('>>', '1', True), ('>>', '2', False), ('=', '1', False)]:
            add(f'{dep.lower()}-version-{relation}-{needed}', [package('consumer', **{dep: f'provider ({relation} {needed})'}), package('provider')],
                'No_Violation' if yes else 'Missing_Dependency')
    add('epoch-and-tilde', [package('consumer', Depends='provider (>= 1:1.0~rc1-1)'), package('provider', version='1:1.0-1')])
    add('epoch-dominates', [package('consumer', Depends='provider (>= 1:1)'), package('provider', version='9999')], 'Missing_Dependency')
    add('coinstall-same-version', [package('library', 'amd64', multi='same'), package('library', 'arm64', multi='same')])
    add('coinstall-equivalent-version', [package('library', 'amd64', version='2', multi='same'), package('library', 'arm64', version='2-0', multi='same')])
    add('coinstall-version-skew', [package('library', 'amd64', multi='same'), package('library', 'arm64', version='3', multi='same')], 'Version_Skew')
    for multi in ['no', 'foreign', 'allowed']:
        add('coinstall-' + multi, [package('library', 'amd64', multi=multi), package('library', 'arm64', multi='same')], 'Not_Coinstallable')
    add('coinstall-all-native', [package('library', 'all'), package('library', 'amd64')], 'Not_Coinstallable')
    # Independent table over literal architectures, including all -> native.
    qualifiers = ['', 'any', 'amd64', 'arm64', 'all', 'native']
    for consumer_arch in ['amd64', 'arm64', 'all']:
        for provider_arch in ['amd64', 'arm64', 'all']:
            for multi in ['no', 'same', 'foreign', 'allowed']:
                if provider_arch == 'all' and multi == 'same': continue
                for qualifier in qualifiers:
                    effective_consumer = 'amd64' if consumer_arch == 'all' else consumer_arch
                    effective_provider = 'amd64' if provider_arch == 'all' else provider_arch
                    expected = {'': multi == 'foreign' or effective_consumer == effective_provider,
                                'any': multi == 'allowed', 'amd64': effective_provider == 'amd64',
                                'arm64': effective_provider == 'arm64', 'all': effective_provider == 'amd64', 'native': False}[qualifier]
                    need = 'provider' + (':' + qualifier if qualifier else '')
                    add('real-' + '-'.join([consumer_arch, provider_arch, multi, qualifier or 'implicit']),
                        [package('consumer', consumer_arch, Depends=need), package('provider', provider_arch, multi=multi)],
                        'No_Violation' if expected else 'Missing_Dependency')
    for consumer_arch in ['amd64', 'arm64']:
        for provider_arch in ['amd64', 'arm64', 'all']:
            for multi in ['no', 'same', 'foreign', 'allowed']:
                if provider_arch == 'all' and multi == 'same': continue
                for provided_arch in ['', 'any', 'amd64', 'arm64']:
                    for qualifier in ['', 'any', 'amd64', 'arm64']:
                        effective = provided_arch or provider_arch
                        if effective == 'all': effective = 'amd64'
                        if not qualifier:
                            expected = multi == 'foreign' or consumer_arch == effective
                        elif qualifier == 'any':
                            expected = multi == 'allowed' or effective == 'any'
                        else: expected = qualifier == effective
                        need = 'virtual' + (':' + qualifier if qualifier else '')
                        provide = 'virtual' + (':' + provided_arch if provided_arch else '') + ' (= 7)'
                        add('virtual-' + '-'.join([consumer_arch, provider_arch, multi, provided_arch or 'implicit', qualifier or 'implicit']),
                            [package('consumer', consumer_arch, Depends=need + ' (>= 7)'), package('provider', provider_arch, multi=multi, Provides=provide)],
                            'No_Violation' if expected else 'Missing_Dependency')
    add('provided-version-not-owner-version', [package('consumer', Depends='virtual (= 7)'), package('provider', version='99', Provides='virtual (= 7)')])
    add('owner-version-not-provided-version', [package('consumer', Depends='virtual (= 99)'), package('provider', version='99', Provides='virtual (= 7)')], 'Missing_Dependency')
    add('unversioned-provide-not-versioned-need', [package('consumer', Depends='virtual (>= 1)'), package('provider', Provides='virtual')], 'Missing_Dependency')
    add('unversioned-provide', [package('consumer', Depends='virtual'), package('provider', Provides='virtual')])
    add('multiple-provided-versions', [package('consumer', Depends='virtual (= 7)'), package('provider', Provides='virtual (= 6), virtual (= 7)')])
    for kind in ['Conflicts', 'Breaks']:
        add(kind.lower() + '-real', [package('first', **{kind: 'second'}), package('second')], 'Present_Conflict')
        add(kind.lower() + '-version-miss', [package('first', **{kind: 'second (<< 2)'}), package('second')])
        add(kind.lower() + '-self', [package('first', **{kind: 'first'})])
        add(kind.lower() + '-virtual', [package('first', **{kind: 'virtual'}), package('provider', Provides='virtual')], 'Present_Conflict')
        add(kind.lower() + '-virtual-version', [package('first', **{kind: 'virtual (= 7)'}), package('provider', version='99', Provides='virtual (= 7)')], 'Present_Conflict')
        add(kind.lower() + '-self-provide', [package('first', Provides='virtual', **{kind: 'virtual'})])
        add(kind.lower() + '-other-provider', [package('first', Provides='virtual', **{kind: 'virtual'}), package('second', Provides='virtual')], 'Present_Conflict')
        add(kind.lower() + '-foreign-implicit', [package('first', **{kind: 'second'}), package('second', 'arm64')], 'Present_Conflict')
        add(kind.lower() + '-foreign-explicit-miss', [package('first', **{kind: 'second:amd64'}), package('second', 'arm64')])
        add(kind.lower() + '-coinstalled-self-name', [package('library', 'amd64', multi='same', **{kind: 'library'}), package('library', 'arm64', multi='same', **{kind: 'library'})],
            'Present_Conflict' if kind == 'Breaks' else 'No_Violation')
    add('other-native-all-provider', [package('consumer', 'arm64', Depends='provider'), package('provider', 'all')], native='arm64')
    add('other-native-all-consumer', [package('consumer', 'all', Depends='provider'), package('provider', 'amd64')], 'Missing_Dependency', native='arm64')
    # The fixed unpack checker applies negative virtual relations by name and
    # provided version; the virtual architecture qualifier does not restrict it.
    for kind in ['Conflicts', 'Breaks']:
        for provider_arch in ['amd64', 'arm64', 'all']:
            for multi in ['no', 'foreign', 'allowed']:
                for provided_arch in ['', 'any', 'amd64', 'arm64']:
                    for qualifier in ['', 'any', 'amd64', 'arm64']:
                        need = 'virtual' + (':' + qualifier if qualifier else '') + ' (= 7)'
                        provide = 'virtual' + (':' + provided_arch if provided_arch else '') + ' (= 7)'
                        add('negative-virtual-' + '-'.join([kind.lower(), provider_arch, multi, provided_arch or 'implicit', qualifier or 'implicit']),
                            [package('first', **{kind: need}), package('provider', provider_arch, multi=multi, Provides=provide)], 'Present_Conflict')
    return result

def build():
    files = {}; entries = []; matrix = cases()
    for i, case in enumerate(matrix):
        # Numeric IDs keep filesystem names independent of relation punctuation.
        case['id'] = f'case-{i:04d}'; images = []
        for fields in case['packages']:
            control = ('\n'.join(key + ': ' + value for key, value in fields.items()) +
                       '\nMaintainer: Fixture <fixture@example.invalid>\nDescription: endpoint fixture\n').encode()
            encoded = gzip.compress(tar([('./control', control, tarfile.REGTYPE, '')]), mtime=0)
            raw = b'!<arch>\n' + member('debian-binary', b'2.0\n') + member('control.tar.gz', encoded) + member('data.tar', b'\0' * 1024)
            digest = hashlib.sha256(raw).hexdigest(); name = digest + '.deb'
            assert name not in files or files[name] == raw; files[name] = raw
            images.append(dict(filename=name, original=digest, control=hashlib.sha256(control).hexdigest()))
        case['images'] = images
        entries.append(' '.join([case['id'], case['expected'], case['native'], ','.join(case['enabled']),
                                *(image['filename'] + '=' + image['control'] for image in images)]))
    files['cases.txt'] = ('\n'.join(entries) + '\n').encode()
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
    expected = set(files)
    assert {p.name for p in DEST.iterdir() if p.is_file()} == expected
    print('Endpoint fixtures:', len(files) - 2, 'originals;', len(cases()), 'cases;', 'written' if args.write else 'match')
