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
    configured = manifest[:8] == b'NIAGEN06'
    assert (len(manifest), manifest[:8]) in ((320, b'NIAGEN05'), (384, b'NIAGEN06'))
    assert manifest[8:24] == descriptor[24:40] and manifest[56:88] == descriptor[72:104]
    assert (cas / 'pins' / manifest[24:40].hex()).read_bytes() == descriptor[40:72]
    root_manifest = read(manifest[224:256])
    assert root_manifest[:8] == b'NIAROOT2' and root_manifest[8:40] == manifest[56:88]
    assert root_manifest[40:72] == manifest[128:160]
    base_archive = read(root_manifest[104:136])
    archive = base_archive
    configured_record = None
    if configured:
        configured_record = read(manifest[256:288])
        assert configured_record[:8] == b'NIACRT01'
        assert configured_record[8:40] == manifest[224:256]
        assert configured_record[40:104] == manifest[56:88] + manifest[128:160]
        assert configured_record[168:200] == accepted[8:24] + manifest[24:40]
        assert configured_record[200:232] == manifest[160:192]
        assert configured_record[232:264] == sha(b'amd64')
        archive = read(configured_record[264:296])
        assert struct.unpack_from('>Q', configured_record, 296)[0] == len(archive)
        retention = read(manifest[288:320])
        assert retention[:8] == b'NIACRC01' and retention[8:40] == sha(configured_record)
        count, = struct.unpack_from('>Q', retention, 40)
        assert len(retention) == 48 + 32 * count
        retained = [retention[i:i+32] for i in range(48, len(retention), 32)]
        assert retained == sorted(set(retained))
        assert all(read(address) is not None for address in retained)
        assert {sha(configured_record), sha(archive), manifest[224:256], sha(base_archive)} <= set(retained)
    assert struct.unpack_from('>Q', root_manifest, 136)[0] == len(base_archive)
    stage = bank / descriptor[24:40].hex()
    assert (stage / 'root/tree/root.tar').read_bytes() == archive
    assert (stage / 'state/generation.manifest').read_bytes() == manifest
    offset = 320 if configured else 256
    batch = read(manifest[offset:offset+32])
    assert batch[:8] == b'MCPLAN02' and batch[24:40] == sha(manifest[:8] + manifest[24:40] + struct.pack('>I', 1))[:16]
    original = (media / ('layout.deb' if configured else 'base.deb')).read_bytes()
    assert read(sha(original)) == original
    originals = {path(item): span for item, span in records(members(original)['data.tar'])}
    assembled = records(archive)
    if configured:
        import io
        import tarfile
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            entries = {path(m): m for m in tar}
            assert set(entries) == {'', 'etc', 'etc/fixture.conf', 'etc/fixture.conf.save'}
            assert tar.extractfile(entries['etc/fixture.conf']).read() == b'local'
            with tarfile.open(fileobj=io.BytesIO(members(original)['data.tar'])) as vendor:
                expected = vendor.extractfile('./etc/fixture.conf').read()
            assert tar.extractfile(entries['etc/fixture.conf.save']).read() == expected
            assert entries['etc/fixture.conf'].mode == 0o600
        assert len(assembled) == struct.unpack_from('>Q', configured_record, 304)[0] == 4
        assert (root.parent / 'source/etc/fixture.conf').read_bytes() == b'new'
        # The original directory spans remain unchanged; file effects were selected.
        assert all(span == originals[path(item)] for item, span in assembled if item.isdir())
    else:
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
                original_spans_exact=not configured, configured_local_preserved=configured, privileged_extraction=False, actual_boot=False,
                production_authorization=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'state', 'cas', 'bank', 'media', 'native', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    result = check(args.root, args.state, args.cas, args.bank, args.media, args.native)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('PASS accepted root publication oracle:', result['paths'], 'paths')
