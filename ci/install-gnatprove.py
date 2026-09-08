#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Install the checksum-pinned development prover into a private cache (no sudo)."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import tarfile
import tempfile
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, default=Path.home()/'.cache/niaos/toolchains')
    parser.add_argument('--archive', type=Path, help='Use an already downloaded archive, offline')
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('Run as an unprivileged build user')
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        parser.error('The pinned prover targets Linux x86_64')
    lock = json.loads((Path(__file__).with_name('gnatprove.lock.json')).read_text())
    cache = args.cache.expanduser().resolve()
    cache.mkdir(parents=True, exist_ok=True)
    destination = cache/lock['directory']
    receipt = destination/'.nia-archive-sha256'
    if destination.exists():
        if (not receipt.is_file() or receipt.read_text().strip() != lock['sha256']
                or not (destination/'bin/gnatprove').is_file()):
            parser.error('Existing cache lacks the matching receipt; choose an empty cache directory')
        print(destination/'bin')
        return
    with tempfile.TemporaryDirectory(prefix='.gnatprove-', dir=cache) as work:
        work = Path(work)
        archive = args.archive or work/'download.tar.gz'
        if args.archive is None:
            with urllib.request.urlopen(lock['url'], timeout=60) as source, archive.open('xb') as target:
                shutil.copyfileobj(source, target)
        with archive.open('rb') as source:
            observed = hashlib.file_digest(source, 'sha256').hexdigest()
        if observed != lock['sha256']:
            parser.error('GNATprove archive checksum mismatch')
        with tarfile.open(archive) as bundle:
            bundle.extractall(work, filter='data')
        extracted = work/lock['directory']
        if not (extracted/'bin/gnatprove').is_file():
            parser.error('Unexpected GNATprove archive layout')
        (extracted/'.nia-archive-sha256').write_text(observed+'\n')
        extracted.rename(destination)
    print(destination/'bin')


if __name__ == '__main__':
    main()
