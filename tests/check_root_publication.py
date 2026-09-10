#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the registered archive publication variant and its independent oracle."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
from compare_root_publication import check


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise SystemExit('Run this private fixture as an unprivileged user')
    media = Path(__file__).resolve().parent / 'fixtures/root-archive'
    with tempfile.TemporaryDirectory(prefix='nia-root-publication-') as temporary:
        case = Path(temporary)
        for name in ('root', 'state', 'store', 'bank'):
            (case / name).mkdir(mode=0o700)
        with (case / 'native.log').open('wb') as output:
            result = subprocess.run([str(args.driver.resolve()), *(str(case / name) for name in
                ('root', 'state', 'store', 'bank')), str(media), 'root-archive'],
                stdout=output, stderr=subprocess.STDOUT, timeout=600, check=False)
        log = case / 'native.log'
        if log.stat().st_size > 1024 * 1024:
            raise SystemExit('fixture log exceeds bound')
        print(log.read_text(), end='')
        if result.returncode:
            raise SystemExit(result.returncode)
        report = check(case / 'root', case / 'state', case / 'store', case / 'bank', media, log)
        print(json.dumps(report, sort_keys=True))
    print('PASS root publication variant; private fixture removed')


if __name__ == '__main__':
    main()
