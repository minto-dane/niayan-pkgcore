#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Separate Linux-restorable synthetic DEBs; original edge fixtures stay intact."""
import argparse
import hashlib
import json
from pathlib import Path
from make_root_archive_fixtures import fixtures

parser = argparse.ArgumentParser(description=__doc__)
mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument('--write', action='store_true')
mode.add_argument('--check', action='store_true')
args = parser.parse_args()
destination = Path(__file__).resolve().parent / 'fixtures/root-preparation'
values = dict(fixtures(filesystem_profile=True))
values['manifest.json'] = (json.dumps([{'filename': name, 'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)}
    for name, raw in values.items()], indent=2) + '\n').encode()
if args.write:
    destination.mkdir(parents=True, exist_ok=True)
for name, raw in values.items():
    if args.write: (destination / name).write_bytes(raw)
    elif (destination / name).read_bytes() != raw: raise SystemExit('fixture differs: ' + name)
print('Root preparation fixtures:', len(values) - 1, 'written' if args.write else 'match')
