#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Exercise configured publication and source-free accepted metadata recovery."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
from compare_root_publication import check


def run(driver, case, mode="configured-root"):
    media = Path(__file__).resolve().parent / 'fixtures/conffiles'
    for name in ('root', 'state', 'store', 'bank', 'source'):
        (case / name).mkdir(mode=0o700)
    (case / 'source/etc').mkdir(mode=0o700)
    source = case / 'source/etc/fixture.conf'
    source.write_bytes(b'local')
    source.chmod(0o600)
    command = [str(driver.resolve()), *(str(case / name) for name in
        ('root', 'state', 'store', 'bank')), str(media)]

    def invoke(arguments, log, success=True):
        with log.open('wb') as output:
            result = subprocess.run(command + arguments, stdout=output,
                stderr=subprocess.STDOUT, timeout=600, check=False)
        assert log.stat().st_size <= 1024 * 1024
        print(log.read_text(), end='', flush=True)
        if (result.returncode == 0) != success:
            raise SystemExit('unexpected recovery outcome: ' + str(result.returncode))
        if not success:
            assert 'LAB_RESULT ' in log.read_text() and 'LAB_RESULT OK ' not in log.read_text()

    log = case / 'native.log'
    invoke([mode], log)
    if mode != 'configured-root':
        assert 'CONFIGURED_HANDOFF ' + mode in log.read_text()
        return
    report = check(case / 'root', case / 'state', case / 'store', case / 'bank', media, log)
    snapshot = (case / 'state/root.state').read_bytes()
    descriptor = (case / 'root/generation.next').read_bytes()
    invoke(['recover', report['accepted_plan']], case / 'recovery.log')
    assert (case / 'state/root.state').read_bytes() == snapshot
    assert (case / 'root/generation.next').read_bytes() == descriptor
    assert source.read_bytes() == b'new'
    report['fresh_process_terminal_recovery'] = True
    def object_path(address):
        value = address.hex()
        return case / 'store/objects' / value[:2] / value[2:]
    manifest = object_path(descriptor[40:72]).read_bytes()
    stage = case / 'bank' / descriptor[24:40].hex()
    batch = object_path(manifest[320:352]).read_bytes()
    plan = object_path(snapshot[80:112]).read_bytes()
    targets = {
        'configured-record': object_path(manifest[256:288]),
        'configuration-closure': object_path(manifest[288:320]),
        'physical-archive': stage / 'root/tree/root.tar',
        'stage-journal': stage / 'state' / ('tx-' + batch[24:40].hex() + '.log'),
        'publication-journal': case / 'state' / ('tx-' + plan[24:40].hex() + '.log'),
        'generation-pin': case / 'store/pins' / manifest[24:40].hex(),
    }
    for name, target in targets.items():
        saved = case / 'withheld-input'
        original = target.read_bytes()
        target.rename(saved)
        try:
            invoke(['recover', report['accepted_plan']], case / (name + '.log'), success=False)
            assert not target.exists(), 'missing evidence was recreated'
            assert (case / 'state/root.state').read_bytes() == snapshot
            assert (case / 'root/generation.next').read_bytes() == descriptor
            assert saved.read_bytes() == original
        finally:
            saved.rename(target)
    report['terminal_missing_evidence_refusals'] = list(targets)
    (case / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--case', type=Path)
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise SystemExit('Run this private fixture as an unprivileged user')
    if args.case:
        args.case.mkdir(mode=0o700, exist_ok=False)
        run(args.driver, args.case.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix='nia-configured-publication-') as temporary:
            run(args.driver, Path(temporary))
    for mode in ('configured-stale', 'configured-active-stale'):
        if args.case:
            case = args.case.with_name(args.case.name + '-' + mode)
            case.mkdir(mode=0o700, exist_ok=False)
            run(args.driver, case.resolve(), mode)
        else:
            with tempfile.TemporaryDirectory(prefix='nia-' + mode + '-') as temporary:
                run(args.driver, Path(temporary), mode)
    print('PASS configured publication and accepted metadata recovery')


if __name__ == '__main__':
    main()
