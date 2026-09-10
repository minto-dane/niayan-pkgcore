#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Compare native content decisions with script-free dpkg in private roots."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def digest(data):
    return hashlib.sha256(data).hexdigest() if data is not None else '0'*64


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() != 0, 'requires unprivileged disposable test roots'
    work = args.work.absolute(); work.mkdir(mode=0o700)
    driver = args.driver.resolve()
    env = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL':'C', 'TMPDIR':str(work), 'HOME':str(work)}
    version = subprocess.check_output(['dpkg', '--version'], env=env, text=True).splitlines()[0]
    assert 'version 1.22.22 ' in version, version
    images = {}
    for name, content, flagged, number in [('old', b'old\n', False, 1), ('same', b'old\n', False, 2),
                                          ('new', b'new\n', False, 2), ('removed', None, True, 2),
                                          ('omitted', None, False, 2)]:
        source = work/('package-'+name); (source/'DEBIAN').mkdir(parents=True)
        (source/'DEBIAN/control').write_text('Package: conf-fixture\nVersion: '+str(number)+'\nArchitecture: all\nMaintainer: Fixture <fixture@example.invalid>\nDescription: script-free fixture\n')
        if content is not None or flagged:
            (source/'DEBIAN/conffiles').write_text(('remove-on-upgrade ' if flagged else '')+'/etc/fixture.conf\n')
        if content is not None:
            (source/'etc').mkdir(); (source/'etc/fixture.conf').write_bytes(content)
        deb = work/(name+'.deb')
        build = subprocess.run(['dpkg-deb', '--build', str(source), str(deb)], capture_output=True, text=True, env=env, timeout=10)
        assert build.returncode == 0, build.stderr
        images[name] = deb
    cases = []
    for tracked in [False, True]:
        for local in [None, b'old\n', b'local\n', b'new\n', b'']:
            for incoming in ['same', 'new', 'omitted', 'removed']:
                for choice in ['UNRESOLVED', 'KEEP_LOCAL', 'USE_VENDOR']:
                    cases.append((tracked, local, incoming, choice, 'INSTALL_UPGRADE' if incoming != 'removed' else 'REMOVE_ON_UPGRADE'))
    cases.extend((True, local, 'omitted', 'UNRESOLVED', mode)
                 for mode in ['REMOVE_PACKAGE', 'PURGE_PACKAGE'] for local in [None, b'old\n', b'local\n'])
    results = []
    for index, (tracked, local, incoming, choice, mode) in enumerate(cases):
        case = work/f'case-{index:03d}'; case.mkdir(mode=0o700); root = case/'root'; root.mkdir(mode=0o700)
        prefix = ['dpkg', '--root='+str(root), '--log='+str(case/'dpkg.log'), '--force-not-root']
        if tracked:
            run = subprocess.run(prefix+['--install', str(images['old'])], env=env, capture_output=True, text=True, timeout=10)
            assert run.returncode == 0, run.stderr
        path = root/'etc/fixture.conf'; path.parent.mkdir(exist_ok=True)
        if local is None:
            if path.exists(): path.unlink()
        else: path.write_bytes(local)
        new = b'old\n' if incoming == 'same' else b'new\n' if incoming == 'new' else None
        old = b'old\n' if tracked else None
        cmd = [str(driver), mode, str(tracked).upper(), digest(old) if old is not None else '-',
               digest(local) if local is not None else '-', digest(new) if new is not None else '-', choice, 'decision']
        native = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=10)
        assert native.returncode == 0, native.stdout+native.stderr
        parsed = dict(line.split(' ', 1) for line in native.stdout.splitlines() if line.startswith(('EFFECT ', 'CONTENT ', 'BACKUP ', 'BACKUP_CONTENT ', 'NEXT_VENDOR ')))
        action = ['--remove', 'conf-fixture'] if mode == 'REMOVE_PACKAGE' else ['--purge', 'conf-fixture'] if mode == 'PURGE_PACKAGE' else ['--install', str(images[incoming])]
        run = subprocess.run(prefix+action, input={'UNRESOLVED':'', 'KEEP_LOCAL':'n\n', 'USE_VENDOR':'y\n'}[choice], capture_output=True, text=True, env=env, timeout=10)
        (case/'upstream.log').write_text(run.stdout+run.stderr)
        (case/'native.log').write_text(native.stdout+native.stderr)
        actual = path.read_bytes() if path.exists() else None
        question = 'end of file on stdin at conffile prompt' in run.stderr
        expected_question = parsed['EFFECT'] == 'REQUIRE_CHOICE'
        matches = (question and run.returncode != 0 and actual == local) if expected_question else (run.returncode == 0 and digest(actual) == parsed['CONTENT'])
        if not expected_question:
            suffix = '.dpkg-dist' if parsed['BACKUP'] == 'VENDOR_BACKUP' else '.dpkg-old'
            backup = path.with_name(path.name+suffix)
            if parsed['BACKUP'] != 'NO_BACKUP':
                matches = matches and backup.is_file() and digest(backup.read_bytes()) == parsed['BACKUP_CONTENT']
            if new is not None:
                # The baseline is the newest distributor version even when the
                # user keeps local bytes. This is metadata comparison, not trust.
                status = (root/'var/lib/dpkg/status').read_text()
                matches = matches and ('/etc/fixture.conf '+hashlib.md5(new).hexdigest()) in status
                matches = matches and parsed['NEXT_VENDOR'] == digest(new)
            else:
                expected_baseline = old if mode != 'PURGE_PACKAGE' and not (mode == 'INSTALL_UPGRADE' and local is None) else None
                matches = matches and parsed['NEXT_VENDOR'] == digest(expected_baseline)
                if expected_baseline is not None:
                    status = (root/'var/lib/dpkg/status').read_text()
                    matches = matches and ('/etc/fixture.conf '+hashlib.md5(old).hexdigest()) in status
                elif mode in ('INSTALL_UPGRADE', 'PURGE_PACKAGE'):
                    matches = matches and '/etc/fixture.conf ' not in (root/'var/lib/dpkg/status').read_text()
        row = dict(case=index, tracked=tracked, local=digest(local), incoming=incoming, choice=choice, mode=mode,
                   native=parsed, upstream_exit=run.returncode, upstream_question=question, actual=digest(actual), matches=matches)
        (case/'result.json').write_text(json.dumps(row, indent=2)+'\n'); results.append(row)
    report = dict(upstream=version, cases=len(results), mismatches=[x for x in results if not x['matches']],
                  script_free=True, host_root_changed=False, results=results,
                  source_debs={name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in images.items()})
    (work/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print('Conffile comparison:', len(results), 'cases;', len(report['mismatches']), 'mismatches')
    return bool(report['mismatches'])


if __name__ == '__main__':
    raise SystemExit(main())
