#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Check accepted root archive bindings independently from actual state bytes."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from compare_root_archive import members, records, path


def sha(raw):
    return hashlib.sha256(raw).digest()


def check(root, state, cas, bank, media, native):
    def read(address):
        text = address.hex()
        file = cas / 'objects' / text[:2] / text[2:]
        assert file.stat().st_size <= 1024 * 1024
        raw = file.read_bytes()
        assert sha(raw) == address
        return raw

    lines = native.read_text().splitlines()
    assert any(line.startswith('PASS assertions=') for line in lines)
    accepted = (state / 'root.state').read_bytes()
    assert len(accepted) == 192 and accepted[:8] == b'MCROOT02' and accepted[160:] == sha(accepted[:160])
    assert struct.unpack_from('>Q', accepted, 24)[0] == 1 and accepted[32:80] == bytes(48)
    assert accepted[144:160] == bytes(16) and (root / '.mission/root.id').read_bytes() == accepted[8:24]
    plan = read(accepted[80:112])
    assert plan[:8] == b'MCPLAN02' and plan[8:24] == accepted[8:24]
    assert struct.unpack_from('>QQ', plan, 40) == (0, 1) and struct.unpack_from('>I', plan, 136)[0] == 1
    length = struct.unpack_from('>H', plan, 192)[0]
    assert plan[196:196 + length] == b'generation.next' and len(plan) == 196 + length + 256
    descriptor = read(plan[196 + length + 168:196 + length + 200])
    assert descriptor[:8] == b'NIAPUB01' and len(descriptor) == 192 and descriptor[160:] == sha(descriptor[:160])
    assert descriptor[8:24] == accepted[8:24] and descriptor[72:104] == accepted[112:144]
    assert struct.unpack_from('>Q', descriptor, 104)[0] == 1 and descriptor[112:160] == bytes(48)
    manifest = read(descriptor[40:72])
    assert len(manifest) == 320 and manifest[:8] == b'NIAGEN05'
    assert manifest[8:24] == descriptor[24:40] and manifest[56:88] == descriptor[72:104]
    assert (cas / 'pins' / manifest[24:40].hex()).read_bytes() == descriptor[40:72]
    root_manifest = read(manifest[224:256])
    assert root_manifest[:8] == b'NIAROOT1' and root_manifest[8:40] == manifest[56:88]
    assert root_manifest[40:72] == manifest[128:160]
    archive = read(root_manifest[104:136])
    assert struct.unpack_from('>Q', root_manifest, 136)[0] == len(archive)
    stage = bank / descriptor[24:40].hex()
    assert (stage / 'root/tree/root.tar').read_bytes() == archive
    assert (stage / 'state/generation.manifest').read_bytes() == manifest
    batch = read(manifest[256:288])
    assert batch[:8] == b'MCPLAN02' and batch[24:40] == sha(b'NIAGEN05' + manifest[24:40] + struct.pack('>I', 1))[:16]
    original = (media / 'base.deb').read_bytes()
    assert read(sha(original)) == original
    originals = {path(item): span for item, span in records(members(original)['data.tar'])}
    assembled = records(archive)
    assert len(assembled) == len(originals) == struct.unpack_from('>Q', root_manifest, 144)[0]
    assert len({path(item) for item, _ in assembled}) == len(originals)
    assert all(span == originals[path(item)] for item, span in assembled)
    assert archive == b''.join(span for _, span in assembled) + bytes(1024)
    assert 'ROOT_GENERATION ' + sha(manifest).hex() in lines
    assert 'ROOT_PLAN ' + accepted[80:112].hex() in lines
    assert 'ROOT_ARCHIVE ' + sha(archive).hex() in lines
    return dict(result='pass', accepted_generation=1, accepted_plan=accepted[80:112].hex(),
                generation_manifest=sha(manifest).hex(), root_manifest=sha(root_manifest).hex(),
                archive=sha(archive).hex(), paths=len(assembled), actual_staged_archive=True,
                original_spans_exact=True, privileged_extraction=False, actual_boot=False,
                production_authorization=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'state', 'cas', 'bank', 'media', 'native', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    result = check(args.root, args.state, args.cas, args.bank, args.media, args.native)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('PASS accepted root publication oracle:', result['paths'], 'paths')
