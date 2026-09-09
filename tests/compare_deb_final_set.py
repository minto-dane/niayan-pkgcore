#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent original/control, source-set and endpoint-receipt hash oracle.

Expected relation outcomes come from the declared matrix and separately tested
upstream behavior; hash equality alone does not establish endpoint semantics.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import tarfile

ZERO = '0' * 64
def number(n): return struct.pack('>Q', n)
def text(s):
    raw = s.encode(); return number(len(raw)) + raw
def sha(data): return hashlib.sha256(data).hexdigest()

def original(path):
    raw = path.read_bytes(); assert len(raw) <= 1024 * 1024 and raw.startswith(b'!<arch>\n')
    offset = 8; members = {}
    while offset < len(raw):
        header = raw[offset:offset+60]; assert len(header) == 60 and header[-2:] == b'`\n'
        name = header[:16].decode().strip().removesuffix('/'); size = int(header[48:58])
        assert name not in members
        members[name] = raw[offset+60:offset+60+size]; assert len(members[name]) == size
        offset += 60 + size + size % 2
    assert offset == len(raw) and members['debian-binary'] == b'2.0\n'
    assert set(members) == {'debian-binary', 'control.tar.gz', 'data.tar'}
    assert members['data.tar'] == b'\0' * 1024
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(members['control.tar.gz']))) as archive:
        controls = [entry for entry in archive if entry.name.removeprefix('./') == 'control']; assert len(controls) == 1
        control = archive.extractfile(controls[0]).read()
    fields = dict(line.split(': ', 1) for line in control.decode().splitlines())
    return dict(original=sha(raw), archive=sha(members['control.tar.gz']), control=sha(control), tar=sha(members['data.tar']), fields=fields)

def compare(media, native):
    matrix = json.loads((media/'cases.json').read_text()); cases = {row['id']: row for row in matrix}
    assert len(cases) == len(matrix)
    observed = {}
    for line in native.read_text().splitlines():
        if not line.startswith('CASE '): continue
        row = line.split(); assert len(row) == 13 and row[1] not in observed
        observed[row[1]] = row
    assert set(observed) == set(cases)
    originals = {}; results = []
    for case_id, case in cases.items():
        sources = []
        for expected, fields in zip(case['images'], case['packages'], strict=True):
            name = expected['filename']
            if name not in originals: originals[name] = original(media/name)
            item = originals[name]; assert all(item[key] == expected[key] for key in ('original', 'control'))
            assert all(item['fields'][key] == value for key, value in fields.items())
            sources.append(item)
        sources.sort(key=lambda source: bytes.fromhex(source['original']))
        assert len({row['original'] for row in sources}) == len(sources)
        index = sha(text('NIAPIDX1') + number(len(sources)) + number(0) + b''.join(
            bytes.fromhex(source['original'] + source['tar']) + number(0) for source in sources))
        catalog = sha(text('NIACSEL1') + bytes.fromhex(index) + number(len(sources)) + b''.join(
            bytes.fromhex(source['original'] + source['archive'] + source['control']) for source in sources))
        profile = sha(text('NIADARCH1') + text(case['native']) + number(len(case['enabled'])) +
                      b''.join(text(arch) for arch in sorted(case['enabled'])))
        receipt = sha(text('NIADFINAL1') + bytes.fromhex(catalog + profile))
        row = observed[case_id]; passed = case['expected'] == 'No_Violation'
        assert row[2] == case['expected'].upper() and row[4] == catalog, (case_id, row)
        assert row[3] == ('OK' if passed else 'UNSUPPORTED' if case['expected'] == 'Architecture_Not_Enabled' else 'CONFLICT')
        assert row[5:8] == ([receipt, profile, catalog] if passed else [ZERO]*3), case_id
        if passed: assert row[8:10] == [ZERO, ZERO]
        else:
            identities = {source['original'] for source in sources}
            assert row[8] in identities and row[9] in identities | {ZERO}
            if case['expected'] in ('Present_Conflict', 'Not_Coinstallable', 'Version_Skew'):
                assert row[9] != ZERO and row[8] != row[9]
        if case['name'] == 'all-groups-required': assert row[10:] == ['DEPENDS', '2', '2']
        results.append(dict(id=case_id, name=case['name'], finding=row[2], catalog=catalog, fingerprint=row[5]))
    return dict(result='pass-for-declared-matrix-and-hashes', cases=len(results), originals=len(originals),
                findings=dict(Counter(row['finding'] for row in results)), results=results)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--media', required=True, type=Path); parser.add_argument('--native', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path); args = parser.parse_args()
    result = compare(args.media, args.native); args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'results'}))
