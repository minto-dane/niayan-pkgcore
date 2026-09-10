#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Check the real internal bootstrap executable using only private temporary state."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def snapshot(root):
    return {str(path.relative_to(root)): (path.lstat().st_ino, path.lstat().st_mode,
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
            for path in root.rglob('*')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', type=Path, required=True)
    args = parser.parse_args()
    driver = args.driver.resolve(strict=True)
    if os.geteuid() == 0:
        parser.error('run as an ordinary user; the VM covers real root refusal')
    cases = []
    with tempfile.TemporaryDirectory(prefix='nia-store-bootstrap-') as temporary:
        root = Path(temporary)
        store = root / 'store'
        store.mkdir(mode=0o700)

        def call(operation, *, succeeds=False, path=store, label=None):
            before = snapshot(root)
            result = subprocess.run([str(driver), operation, str(path)], capture_output=True,
                                    timeout=10, env={'LC_ALL': 'C.UTF-8', 'PATH': '/usr/bin:/bin'})
            assert (result.returncode == 0) == succeeds, result.stdout + result.stderr
            assert result.stdout.startswith(b'format=nia-store-bootstrap-1\nstatus=')
            if not succeeds or operation == 'check':
                assert snapshot(root) == before, 'refusal/check changed persistent state'
            cases.append({'case': label or operation, 'exit': result.returncode,
                          'result': result.stdout.decode().strip()})

        call('check', label='empty-is-not-initialized')
        call('initialize', succeeds=True)
        assert set(p.name for p in store.iterdir()) == {'store.lock', 'objects', 'incoming', 'pins'}
        assert (store / 'store.lock').stat().st_mode & 0o777 == 0o600
        call('initialize', label='duplicate-initialization')
        call('check', succeeds=True)
        for name in ('store.lock', 'objects', 'incoming', 'pins'):
            original = store / name
            held = root / ('held-' + name)
            original.rename(held)
            try:
                call('check', label='missing-' + name)
                call('initialize', label='no-reinitialize-missing-' + name)
            finally:
                held.rename(original)
        with (store / 'store.lock').open('rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            call('check', label='reservation-conflict')
        call('check', succeeds=True, label='reservation-released')
        store.chmod(0o755)
        call('check', label='nonprivate-root')
        store.chmod(0o700)
        alias = root / 'alias'
        alias.symlink_to(store, target_is_directory=True)
        call('check', path=alias, label='symlink-root')
        call('initialize', path=root / 'absent', label='missing-root')
        call('repair', label='no-repair-operation')
    print(json.dumps({'format': 1, 'result': 'pass', 'cases': cases}, indent=2))


if __name__ == '__main__':
    main()
