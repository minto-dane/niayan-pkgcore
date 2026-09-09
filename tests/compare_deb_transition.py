#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check exact transition deltas and bindings against independent raw DEB reads."""
import argparse
import json
from pathlib import Path
from compare_deb_final_set import original, sha, text, number, ZERO

KINDS = ['Added', 'Removed', 'Upgraded', 'Downgraded', 'Repacked']

def catalog(sources):
    ordered = sorted(sources, key=lambda p: p['original'])
    index = sha(text('NIAPIDX1') + number(len(ordered)) + number(0) + b''.join(
        bytes.fromhex(p['original'] + p['tar']) + number(0) for p in ordered))
    return sha(text('NIACSEL1') + bytes.fromhex(index) + number(len(ordered)) + b''.join(
        bytes.fromhex(p['original'] + p['archive'] + p['control']) for p in ordered))

def compare(media, native):
    cases = json.loads((media/'cases.json').read_text()); observed = {}; changes = {}
    for line in native.read_text().splitlines():
        row = line.split()
        if row[:1] == ['TRANSITION']:
            assert len(row) == 14 and row[1] not in observed
            observed[row[1]] = row
        elif row[:1] == ['CHANGE']:
            assert len(row) == 10
            changes.setdefault(row[1], []).append(row)
    assert set(observed) == {case['id'] for case in cases}
    assert set(changes) <= set(observed)
    sources = {}; results = []
    for case in cases:
        sides = {}
        for side in ['before', 'after']:
            entries = []
            for expected, fields in zip(case[side+'_images'], case[side], strict=True):
                filename = expected['filename']
                if filename not in sources: sources[filename] = original(media/filename)
                item = sources[filename]
                assert all(item[k] == expected[k] for k in ['original', 'control'])
                assert all(item['fields'][k] == v for k, v in fields.items())
                entries.append(item)
            sides[side] = {(p['fields']['Package'], p['fields']['Architecture']): p for p in entries}
            assert len(sides[side]) == len(entries)
        before, after = sides['before'], sides['after']; row = observed[case['id']]
        before_hash, after_hash = catalog(before.values()), catalog(after.values())
        assert row[2] == case['expected'].upper() and row[4:6] == [before_hash, after_hash], case['name']
        passed = case['expected'] == 'None'
        assert row[3] == ('OK' if passed else 'CONFLICT' if case['expected'] == 'Endpoint_Rejected' else 'DENIED')
        actual = changes.get(case['id'], [])
        if passed:
            profile = sha(text('NIADARCH1') + text('amd64') + number(3) + b''.join(text(a) for a in ['amd64', 'arm64', 'i386']))
            endpoint = sha(text('NIADFINAL1') + bytes.fromhex(after_hash + profile))
            delta = []
            for key in sorted(before.keys() | after.keys()):
                old, new = before.get(key), after.get(key)
                if old and new and old['original'] == new['original']: continue
                delta.append((key, old, new))
            assert len(delta) == len(actual) == int(row[8]) == len(case['kinds'])
            encoded = text('NIADTRANS1') + bytes.fromhex(before_hash + after_hash + endpoint) + number(len(delta))
            for i, ((key, old, new), kind, record) in enumerate(zip(delta, case['kinds'], actual, strict=True), 1):
                old_version = old['fields']['Version'] if old else ''
                new_version = new['fields']['Version'] if new else ''
                old_hash = old['original'] if old else ZERO; new_hash = new['original'] if new else ZERO
                assert record == ['CHANGE', case['id'], str(i), kind.upper(), *key, old_version or '-', new_version or '-', old_hash, new_hash], case['name']
                encoded += number(KINDS.index(kind)) + text(key[0]) + text(key[1]) + text(old_version) + text(new_version) + bytes.fromhex(old_hash + new_hash)
            assert row[6:8] == [sha(encoded), endpoint], case['name']
            assert row[9:] == [ZERO, ZERO, 'FALSE', 'FALSE', 'NOT_CHECKED']
        else:
            assert row[6:9] == [ZERO, ZERO, '0'] and not actual
            if case['expected'] == 'Protection_Migration_Required':
                lost = []
                for key, old in sorted(before.items()):
                    new = after.get(key); fields = new['fields'] if new else {}
                    flags = [old['fields'].get(f) == 'yes' and fields.get(f) != 'yes' for f in ['Essential', 'Protected']]
                    if any(flags): lost.append((old['original'], new['original'] if new else ZERO, flags))
                assert lost
                old_hash, new_hash, flags = lost[0]
                assert row[9:] == [old_hash, new_hash, *[str(v).upper() for v in flags], 'NOT_CHECKED']
            else:
                assert row[9:13] == [ZERO, ZERO, 'FALSE', 'FALSE']
                assert row[13] == ('PRESENT_CONFLICT' if case['name'] == 'reject-conflicting-target' else 'MISSING_DEPENDENCY')
        results.append(dict(id=case['id'], name=case['name'], finding=row[2], before=before_hash, after=after_hash, fingerprint=row[6], changes=int(row[8])))
    return dict(result='pass-for-declared-transition-policy-and-hashes', cases=len(results), originals=len(sources), results=results)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--media', required=True, type=Path); parser.add_argument('--native', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path); args = parser.parse_args()
    result = compare(args.media, args.native); args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'results'}))
