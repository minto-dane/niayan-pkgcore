#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Independently check configured root bytes, decisions and exact retained closure."""
import argparse
import base64
from decimal import Decimal
import io
import json
from pathlib import Path
import struct
import tarfile
from urllib.parse import unquote_to_bytes

from compare_root_archive import digest, members, path, records
from check_configuration_entry import observation, acl, LOCAL_CLEAR

NAMES = ('keep', 'vendor', 'links', 'deleted', 'restored', 'empty')
ZERO = '0' * 64


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('native', 'cas', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(exist_ok=False)
    lines = args.native.read_text().splitlines()
    assert any(line.startswith('PASS assertions=') for line in lines)
    cases = [line.split()[1:] for line in lines if line.startswith('CONFIGURED ')]
    assert tuple(row[0] for row in cases) == NAMES

    def obj(address):
        assert len(address) == 64 and all(c in '0123456789abcdef' for c in address)
        file = args.cas/'objects'/address[:2]/address[2:]
        assert file.is_file() and not file.is_symlink() and file.stat().st_size <= 1024*1024
        data = file.read_bytes(); assert digest(data) == address
        return data

    def closure(address, tag, header):
        wire = obj(address); assert wire[:8] == tag
        count, = struct.unpack_from('>I' if header == 76 else '>Q', wire, header-(4 if header == 76 else 8))
        assert len(wire) == header+32*count
        values = [wire[i:i+32].hex() for i in range(header, len(wire), 32)]
        assert values == sorted(set(values)) and ZERO not in values
        return wire, set(values)

    reports = []
    for label, record_id, archive_id, retention_id in cases:
        wire = obj(record_id); data = obj(archive_id)
        assert wire[:8] == b'NIACRT01' and len(wire) >= 320
        base_id, catalog_id, closure_id, base_archive, ownership = [wire[i:i+32].hex() for i in range(8, 168, 32)]
        assert ownership != ZERO and wire[168:184] == bytes([1])*16 and wire[184:200] == bytes([2])*16
        assert wire[200:232] == bytes([3])*32 and wire[232:264].hex() == digest(b'amd64')
        assert wire[264:296].hex() == archive_id
        size, count, choice_count, configured_count = struct.unpack_from('>QQII', wire, 296)
        assert size == len(data) and choice_count == 1 and len(wire) == 320+96*choice_count+80*configured_count
        base = obj(base_id); assert base[:8] == b'NIAROOT2'
        assert base[8:40].hex() == catalog_id and base[40:72].hex() == closure_id and base[104:136].hex() == base_archive
        retained_wire, required = closure(closure_id, b'NIACLOS1', 80)
        assert retained_wire[8:40].hex() == catalog_id and retained_wire[40:72] == base[72:104]
        required |= {closure_id, base_id, base_archive, record_id, archive_id}
        original_entries = {path(item): (item, span) for item, span in records(obj(base_archive))}
        expected = dict(original_entries); effects = {}
        proposal_id, decision_id, choice_closure = [wire[i:i+32].hex() for i in range(320, 416, 32)]
        proposal = obj(proposal_id); decision = obj(decision_id)
        assert proposal[:8] == b'NIACPR01' and decision[:8] == b'NIACCH02' and decision[8:40].hex() == proposal_id
        target = proposal[344:].decode(); assert len(proposal) == 344+struct.unpack_from('>I', proposal, 340)[0]
        assert target == '/etc/fixture.conf' and proposal[8:72] == wire[168:232]
        backup = decision[368:].decode(); assert len(decision) == 368+struct.unpack_from('>I', decision, 204)[0]
        choice_wire, objects = closure(choice_closure, b'NIACCF01', 76)
        assert choice_wire[8:40].hex() == proposal_id and choice_wire[40:72].hex() == decision_id
        required |= objects | {proposal_id, decision_id, choice_closure}
        incoming = decision[140:172].hex()
        source_entries = {path(item): (item, span) for item, span in records(members(obj(incoming))['data.tar'])}
        # This fixture has one selected original. Every unmodified base span
        # must match that original, independently of the root assembler.
        assert set(original_entries) == set(source_entries)
        for name, (item, span) in original_entries.items():
            assert span == source_entries[name][1]
        config_checks = {}
        for offset, name, content_id in ((208, target, decision[44:76].hex()), (288, backup, decision[76:108].hex())):
            if not name:
                continue
            name = name.removeprefix('/')
            source = decision[offset]; assert decision[offset+1:offset+4] == bytes(3)
            mode, uid, gid = struct.unpack_from('>III', decision, offset+4)
            original, override = decision[offset+16:offset+48].hex(), decision[offset+48:offset+80].hex()
            expected.pop(name, None)
            if source == 0:
                assert content_id == ZERO and original == ZERO and override == ZERO
                continue
            content = obj(content_id)
            if source == 1:
                observed = observation(obj(original))
                assert observed['path'] == target.encode() and observed['content'] == content_id and observed['size'] == len(content)
                assert (mode, uid, gid) == (observed['mode'] & 0o7777, observed['uid'], observed['gid'])
                clocks = observed['clocks']; xattrs = observed['xattrs'].copy()
                access = acl(xattrs.pop(b'system.posix_acl_access')) if b'system.posix_acl_access' in xattrs else None
                flags = [observed['flags'] & ~0x80000, LOCAL_CLEAR & ~observed['flags']]
                assert override == ZERO
            else:
                assert source == 2 and original == incoming
                with tarfile.open(fileobj=io.BytesIO(members(obj(original))['data.tar']), mode='r:') as archive:
                    item = archive.getmember('.'+target)
                    assert archive.extractfile(item).read() == content
                    clocks = [int(Decimal(item.pax_headers.get('mtime', str(item.mtime)))*10**9), None, None, None]
                    assert not item.pax_headers  # Known plain USTAR test originals.
                    vendor_permissions = (item.mode, item.uid, item.gid)
                xattrs = {}; access = None; flags = [0, 0]
                if override != ZERO:
                    observed = observation(obj(override)); assert observed['path'] == target.encode()
                    assert (mode, uid, gid) == (observed['mode'] & 0o7777, observed['uid'], observed['gid'])
                else:
                    assert (mode, uid, gid) == vendor_permissions
            effects[name] = dict(content=content_id, size=len(content), mode=mode, uid=uid, gid=gid,
                                 clocks=clocks, xattrs={k.hex(): v.hex() for k, v in xattrs.items()}, acl=access, flags=flags)
            expected[name] = None
        final = records(data); assert len(final) == count and len({path(item) for item, _ in final}) == count
        assert set(path(item) for item, _ in final) == set(expected)
        assert path(final[0][0]) == '' and final[0][0].isdir()
        assert data == b''.join(span for _, span in final)+bytes(1024)
        selected = sorted(expected); rows = {}
        for pos in range(416, len(wire), 80):
            ordinal, = struct.unpack_from('>Q', wire, pos); assert 1 <= ordinal <= count
            name = selected[ordinal-1]; assert name in effects and name not in rows
            prefix, content_id = wire[pos+8:pos+40].hex(), wire[pos+40:pos+72].hex()
            content_size, = struct.unpack_from('>Q', wire, pos+72)
            assert content_id == effects[name]['content'] and content_size == effects[name]['size']
            rows[name] = obj(prefix)+obj(content_id)+bytes((-content_size)%512)
            required |= {prefix, content_id}
        assert set(rows) == set(effects)
        seen = set(); directories = set()
        for item, span in final:
            name = path(item)
            for i, char in enumerate(name):
                if char == '/':
                    assert name[:i] in directories
            if name in effects:
                want = effects[name]; assert item.isreg() and span == rows[name]
                assert (item.mode, item.uid, item.gid, item.size) == tuple(want[k] for k in ('mode', 'uid', 'gid', 'size'))
                for key, value in zip(('mtime', 'atime', 'ctime', 'LIBARCHIVE.creationtime'), want['clocks'], strict=True):
                    assert key not in item.pax_headers if value is None else Decimal(item.pax_headers[key])*10**9 == value
                attrs = {unquote_to_bytes(key[17:]).hex(): base64.b64decode(value+'='*((-len(value))%4), validate=True).hex()
                         for key, value in item.pax_headers.items() if key.startswith('LIBARCHIVE.xattr.')}
                assert attrs == want['xattrs'] and item.pax_headers.get('SCHILY.acl.access') == want['acl']
                config_checks[name] = want
            else:
                assert span == original_entries[name][1]
                if item.isdir():
                    directories.add(name)
                if item.islnk():
                    assert item.linkname.removeprefix('./') in seen
            seen.add(name)
        closure_wire, got = closure(retention_id, b'NIACRC01', 48)
        assert closure_wire[8:40].hex() == record_id and got == required
        for address in got:
            obj(address)
        (args.output/(label+'.tar')).write_bytes(data)
        reports.append(dict(name=label, manifest=record_id, archive=archive_id, retained=retention_id, entries=count,
                            configuration=config_checks, retained_objects=len(got), exact_closure=True, original_spans=True, parent_and_hardlink_order=True))
    (args.output/'report.json').write_text(json.dumps(dict(result='pass', cases=reports, actual_boot=False), indent=2)+'\n')
    print('PASS six complete configured roots, original spans, decisions and exact transitive closures')


if __name__ == '__main__':
    main()
