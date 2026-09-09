#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded independent linkage oracle for two disposable published generations.

Checks native observations against root.state, the accepted plan, descriptor
lineage, manifest, and independently reconstructed catalog frames. This is not
a general journal validator, authorization engine, or physical DEB root check.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from compare_catalog_store import reference

def sha(data): return hashlib.sha256(data).digest()
def u64(data, pos): return struct.unpack_from('>Q', data, pos)[0]
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
    expected = {}
    for d, name, generation in [(before,'empty.deb',1),(after,'consumer-upgrade.deb',2)]:
        assert d['root'] == root_id and d['generation'] == generation
        manifest = cas_read(cas,d['manifest'])
        assert len(manifest) == 224 and manifest[:8] == b'NIAGEN01'
        assert manifest[8:24] == d['stage'] and manifest[56:88] == d['catalog']
        index, frame = reference(media,[name]); assert sha(frame) == d['catalog']
        assert cas_read(cas,d['catalog']) == frame
        original = frame[56:88]; assert cas_read(cas,original) == (media/name).read_bytes()
        stage_root = bank/d['stage'].hex()/'root'
        assert (stage_root/'catalog').read_bytes() == frame
        # The version file is a deliberate synthetic staging effect.
        assert (stage_root/'tree/version').read_bytes() == frame
        expected[generation] = [d['hash'].hex(),str(generation),d['catalog'].hex(),index['INDEX'],'1',str(index['CLAIMS'])]
    rows = [line.split()[1:] for line in native.read_text().splitlines() if line.startswith('CURRENT_CATALOG ')]
    assert rows and {int(row[1]) for row in rows} == {1,2}
    assert [int(row[1]) for row in rows] == sorted(int(row[1]) for row in rows)
    assert all(row == expected[int(row[1])] for row in rows)
    assert rows[-1][0] == after_hash.hex()
    return dict(result='pass-for-two-published-native-catalog-observations',root=root_id.hex(),accepted_plan=raw[80:112].hex(),
                observations=len(rows),generations=[dict(generation=g,descriptor=v[0],catalog=v[2],payload=v[3],claims=int(v[5])) for g,v in expected.items()],
                physical_deb_payload_applied=False,production_authorization=False)

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['root','state','cas','bank','media','native','output']:parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args();result=check(args.root,args.state,args.cas,args.bank,args.media,args.native)
    args.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
