#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent canonical index hash from independently checked payload probes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from compare_deb_payload import compare, observe

KINDS = ['REGULAR', 'DIRECTORY', 'SYMBOLIC_LINK', 'HARD_LINK', 'CHARACTER_DEVICE', 'BLOCK_DEVICE', 'FIFO']

def fingerprint(sources):
    h = hashlib.sha256()
    def number(value): h.update(struct.pack('>Q', value % 2**64))
    def text(value):
        raw = value.encode('utf-8', 'surrogateescape'); number(len(raw)); h.update(raw)
    def digest(value): h.update(bytes.fromhex(value))
    def clock(value):
        present, seconds, ns = value; number(present == 'TRUE'); number(seconds); number(ns)
    rows = sorted(sources, key=lambda s: bytes.fromhex(s['ORIGINAL']))
    assert len({s['ORIGINAL'] for s in rows}) == len(rows)
    claims = sorted(((e['PATH'].encode('utf-8', 'surrogateescape'), s['ORIGINAL'], e) for s in rows for e in s['entries']), key=lambda row: row[:2])
    text('NIAPIDX1'); number(len(rows)); number(len(claims))
    for s in rows:
        digest(s['ORIGINAL']); digest(s['TAR']); number(len(s['entries']))
    for _, original, e in claims:
        text(e['PATH']); digest(original); number(e['index'])
        for key in ['LINK', 'UNAME', 'GNAME']: text(e[key])
        a = e['ATTR']; number(KINDS.index(a[0]))
        for n in a[1:6]: number(n)
        for key in ['MTIME', 'ATIME', 'CTIME', 'BTIME']: clock(e[key])
        for n in a[6:8]: number(n)
        for key in ['CONTENT', 'XATTR', 'ACL']: digest(e[key])
        for n in [a[9], a[10], a[8]]: number(n)
    return dict(INDEX=h.hexdigest(), PACKAGES=len(rows), CLAIMS=len(claims), PATHS=len({r[0] for r in claims}))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--media', type=Path, required=True)
    parser.add_argument('--probes', type=Path, required=True)
    parser.add_argument('--index-log', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); rows = []; checks = []
    for log in sorted(args.probes.glob('*.deb.log')):
        name = log.name.removesuffix('.log'); cas = args.probes / (name + '.cas')
        checks.append(compare(args.media / name, log, cas)); rows.append(observe(log))
    assert rows
    expected = fingerprint(rows); actual = {}
    for line in args.index_log.read_text().splitlines():
        key, _, value = line.partition(' ')
        if key in expected:
            assert key not in actual
            actual[key] = value.strip() if key == 'INDEX' else int(value)
    assert actual == expected, (actual, expected)
    args.output.write_text(json.dumps(dict(result='pass', scope='private source claims only; not package admission or root execution', index=actual, independent_payload_checks=checks), indent=2)+'\n')
    print('Independent payloads and canonical index match:', actual)
