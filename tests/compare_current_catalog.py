#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded independent linkage oracle for two disposable published generations.

Checks native observations against root.state, the accepted plan, descriptor
lineage, manifest, and independently reconstructed catalog frames. This is not
a general journal validator, authorization engine, or physical DEB root check.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
from compare_catalog_store import reference
from compare_catalog_retention import objects
from compare_selected_catalog import original as read_original

def sha(data): return hashlib.sha256(data).digest()
def u64(data, pos): return struct.unpack_from('>Q', data, pos)[0]
def number(value): return struct.pack('>Q', value)
def field(value):
    raw = value.encode('utf-8'); return number(len(raw)) + raw
def cas_read(cas, digest):
    text = digest.hex(); path = cas/'objects'/text[:2]/text[2:]
    assert path.stat().st_size <= 1024 * 1024
    data = path.read_bytes(); assert sha(data) == digest
    return data

def descriptor(cas, digest):
    data = cas_read(cas, digest)
    assert len(data) == 192 and data[:8] == b'NIAPUB01' and data[160:] == sha(data[:160]) and data[144:160] == bytes(16)
    return dict(hash=digest, root=data[8:24], stage=data[24:40], manifest=data[40:72], catalog=data[72:104], generation=u64(data,104), previous=data[112:144])

def check(root, state, cas, bank, media, native):
    raw = (state/'root.state').read_bytes()
    assert len(raw) == 192 and raw[:8] == b'MCROOT02' and raw[160:] == sha(raw[:160])
    assert raw[144:160] == bytes(16) and raw[32:80] == bytes(48)
    root_id = raw[8:24]; assert (root/'.mission/root.id').read_bytes() == root_id
    assert u64(raw,24) == 2
    plan = cas_read(cas,raw[80:112]); assert plan[:8] == b'MCPLAN02' and plan[8:24] == root_id
    assert u64(plan,40) == 1 and u64(plan,48) == 2 and struct.unpack_from('>I',plan,136)[0] == 1
    length = struct.unpack_from('>H',plan,192)[0]; assert plan[194:196] == bytes(2)
    assert plan[196:196+length] == b'generation.next' and len(plan) == 196 + length + 256
    start = 196 + length
    before_hash = plan[start+40:start+72]; after_hash = plan[start+168:start+200]
    before, after = descriptor(cas,before_hash), descriptor(cas,after_hash)
    assert after['previous'] == before_hash and before['previous'] == bytes(32)
    assert after['catalog'] == raw[112:144] == plan[72:104]
    expected = {}; closures = {}; missing = Counter(); sources = {}; retained_hashes = {}
    for d, name, generation in [(before,'empty.deb',1),(after,'consumer-upgrade.deb',2)]:
        assert d['root'] == root_id and d['generation'] == generation
        manifest = cas_read(cas,d['manifest'])
        assert len(manifest) == 224 and manifest[:8] == b'NIAGEN02'
        assert manifest[8:24] == d['stage'] and manifest[56:88] == d['catalog']
        index, frame = reference(media,[name]); assert sha(frame) == d['catalog']
        assert cas_read(cas,d['catalog']) == frame
        original = frame[56:88]; assert cas_read(cas,original) == (media/name).read_bytes()
        retained, _, _ = objects(media/name); retained[sha(frame)] = frame
        closure = b'NIACLOS1' + sha(frame) + bytes.fromhex(index['INDEX']) + struct.pack('>Q',len(retained)) + b''.join(sorted(retained))
        assert manifest[128:160] == sha(closure) and cas_read(cas,sha(closure)) == closure
        assert (cas/'pins'/manifest[24:40].hex()).read_bytes() == d['manifest']
        for digest, data in retained.items(): assert cas_read(cas,digest) == data
        closures[generation] = dict(hash=sha(closure).hex(), objects=len(retained))
        package, relationships, atoms = read_original(media/name)
        assert not atoms and all(int(row[2]) == 0 for row in relationships)
        sources[d['catalog'].hex()] = package
        retained_hashes[generation] = [sha(closure).hex(), *[h.hex() for h in retained]]
        for phase in range(5 if generation == 2 else 4):
            missing.update((str(phase), digest.hex()) for digest in [sha(closure), *retained])
        batch = cas_read(cas,manifest[160:192])
        assert batch[:8] == b'MCPLAN02' and batch[8:24] == d['stage']
        assert batch[24:40] == sha(b'NIAGEN02' + manifest[24:40] + struct.pack('>I',1))[:16]
        assert batch[72:104] == d['catalog']
        stage_root = bank/d['stage'].hex()/'root'
        assert (stage_root/'catalog').read_bytes() == frame
        # The version file is a deliberate synthetic staging effect.
        assert (stage_root/'tree/version').read_bytes() == frame
        expected[generation] = [d['hash'].hex(),str(generation),d['catalog'].hex(),index['INDEX'],'1',str(index['CLAIMS'])]
    lines = native.read_text().splitlines()
    faults = [line.split()[1:] for line in lines if line.startswith('RETENTION_MISSING ')]
    assert all(len(row) == 3 and row[2] not in {'OK', 'CONFLICT'} for row in faults)
    assert Counter((row[0], row[1]) for row in faults) == missing
    rows = [line.split()[1:] for line in lines if line.startswith('CURRENT_CATALOG ')]
    assert rows and {int(row[1]) for row in rows} == {1,2}
    assert [int(row[1]) for row in rows] == sorted(int(row[1]) for row in rows)
    assert all(row == expected[int(row[1])] for row in rows)
    assert rows[-1][0] == after_hash.hex()
    updates = [line.split()[1:] for line in lines if line.startswith('CURRENT_UPDATE ')]
    changes = Counter(tuple(line.split()[1:]) for line in lines if line.startswith('CURRENT_UPDATE_CHANGE '))
    expected_changes = Counter(); bindings = {}; pairs = set()
    descriptors = {d['hash'].hex(): d for d in [before, after]}
    policy = sha(field('NIADARCH1') + field('amd64') + number(1) + field('amd64'))
    for row in updates:
        assert len(row) == 8
        current, old_catalog, new_catalog, retained, endpoint, delta, binding, count = row
        assert current in descriptors and descriptors[current]['catalog'].hex() == old_catalog
        target = next(d for d in [before, after] if d['catalog'].hex() == new_catalog)
        assert retained == closures[target['generation']]['hash']
        old, new = sources[old_catalog], sources[new_catalog]
        old_set = {(old[3], old[5]): old}; new_set = {(new[3], new[5]): new}
        records = []
        for key in sorted(old_set.keys() | new_set.keys()):
            a, b = old_set.get(key), new_set.get(key)
            if a and b:
                assert a == b, 'fixture identity versions unexpectedly changed'
                continue
            kind = 0 if b else 1
            records.append((kind, *key, a[4] if a else '', b[4] if b else '',
                            a[0] if a else '00'*32, b[0] if b else '00'*32))
        calculated_endpoint = sha(field('NIADFINAL1') + bytes.fromhex(new_catalog) + policy)
        encoded = field('NIADTRANS1') + bytes.fromhex(old_catalog + new_catalog) + calculated_endpoint + number(len(records))
        for i, record in enumerate(records, 1):
            kind, name, architecture, old_version, new_version, old_original, new_original = record
            encoded += number(kind) + field(name) + field(architecture) + field(old_version) + field(new_version) + bytes.fromhex(old_original + new_original)
            expected_changes[(binding, str(i), ['ADDED', 'REMOVED'][kind], name, architecture,
                              old_version or '-', new_version or '-', old_original, new_original)] += 1
        calculated_delta = sha(encoded)
        calculated_binding = sha(b'NIAUPD01' + bytes.fromhex(current + new_catalog + retained) + calculated_delta)
        assert (endpoint, delta, binding, count) == (calculated_endpoint.hex(), calculated_delta.hex(), calculated_binding.hex(), str(len(records)))
        pairs.add((current, new_catalog))
        bindings[binding] = dict(current=current, target=new_catalog, retention=retained, endpoint=endpoint, transition=delta, changes=len(records))
    assert changes == expected_changes
    assert pairs == {(d['hash'].hex(), t['catalog'].hex()) for d in [before, after] for t in [before, after]}
    update_missing = [line.split()[1:] for line in lines if line.startswith('UPDATE_MISSING ')]
    assert all(len(row) == 2 and row[1] not in {'OK', 'CONFLICT'} for row in update_missing)
    assert Counter(row[0] for row in update_missing) == Counter(retained_hashes[2])
    return dict(result='pass-for-two-published-native-catalog-observations',root=root_id.hex(),accepted_plan=raw[80:112].hex(),
                observations=len(rows),missing_retention_checks=len(faults),generations=[dict(generation=g,descriptor=v[0],catalog=v[2],payload=v[3],claims=int(v[5]),retention=closures[g]) for g,v in expected.items()],
                update_observations=len(updates),update_bindings=bindings,missing_update_objects=len(update_missing),
                physical_deb_payload_applied=False,production_authorization=False)

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['root','state','cas','bank','media','native','output']:parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args();result=check(args.root,args.state,args.cas,args.bank,args.media,args.native)
    args.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
