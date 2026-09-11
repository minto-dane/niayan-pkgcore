#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Check selected source spans and parent/link order independently; export VM inputs."""
import argparse
import json
from pathlib import Path
import struct
from compare_root_archive import digest, members, path, records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--cas', type=Path, required=True)
    parser.add_argument('--media', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(exist_ok=False)
    lines = args.native.read_text().splitlines()
    assert any(line.startswith('PASS assertions=') for line in lines)
    new = [line.split()[1:] for line in lines if line.startswith('ORDER ')]
    old = {parts[1]: parts[2:] for line in lines if (parts := line.split()) and parts[0] == 'LEGACY'}
    assert len(new) == len(old) == 8

    def object_bytes(address):
        raw = (args.cas / 'objects' / address[:2] / address[2:]).read_bytes()
        assert digest(raw) == address
        return raw

    sources, claims = {}, []
    for filename in sorted(args.media.glob('*.deb')):
        raw = filename.read_bytes()
        source = digest(raw)
        assert object_bytes(source) == raw
        sources[source] = records(members(raw)['data.tar'])
        claims.extend((path(item), source, ordinal) for ordinal, (item, _) in enumerate(sources[source], 1))
    assert len(sources) == 2
    claims.sort()
    report = []
    owner_sets = set()
    for case, manifest_id, archive_id in new:
        wire, raw = object_bytes(manifest_id), object_bytes(archive_id)
        assert wire[:8] == b'NIAROOT2' and wire[104:136].hex() == archive_id
        size, count = struct.unpack('>QQ', wire[136:152])
        assert (size, count, len(wire)) == (len(raw), 11, 152 + 8 * 11)
        picks = [claims[index - 1] for index in struct.unpack('>11Q', wire[152:])]
        assert [name for name, _, _ in picks] == sorted({name for name, _, _ in claims})
        expected = {name: (source, ordinal) for name, source, ordinal in picks}
        actual = records(raw)
        assert [path(item) for item, _ in actual[:3]] == ['', 'alpha', 'alpha/beta']
        seen = set()
        for item, span in actual:
            name = path(item)
            assert name not in seen
            source, ordinal = expected[name]
            original, original_span = sources[source][ordinal - 1]
            assert span == original_span and item.get_info() == original.get_info()
            assert item.pax_headers == original.pax_headers
            for length in range(1, len(name.split('/'))):
                assert '/'.join(name.split('/')[:length]) in seen
            if item.islnk():
                target = item.linkname.removeprefix('./')
                assert target in seen and expected[target][0] == source
            seen.add(name)
        assert raw == b''.join(span for _, span in actual) + bytes(1024)
        owners = tuple(expected[name][0] for name in ('', 'alpha', 'alpha/beta'))
        owner_sets.add(owners)
        old_manifest, old_archive = old[case]
        old_wire, old_raw = object_bytes(old_manifest), object_bytes(old_archive)
        assert old_wire[:8] == b'NIAROOT1' and old_wire[8:104] == wire[8:104]
        assert old_wire[104:136].hex() == old_archive and old_wire[136:] == wire[136:]
        ordered = sorted((expected[name][0], expected[name][1]) for name in ('', 'alpha', 'alpha/beta'))
        prefix = b''.join(sources[source][ordinal - 1][1] for source, ordinal in ordered)
        assert old_raw == prefix + b''.join(span for _, span in actual[3:]) + bytes(1024)
        assert old_raw != raw
        (args.output / f'order-{case}.tar').write_bytes(raw)
        report.append(dict(case=int(case), manifest=manifest_id, archive=archive_id, entries=count,
                           selected_directory_owners=owners, legacy_manifest=old_manifest,
                           legacy_archive=old_archive, original_spans_exact=True))
    assert len(owner_sets) == 8
    (args.output / 'report.json').write_text(json.dumps(dict(result='pass', cases=report,
        physical_extraction=False, production_authorization=False), indent=2) + '\n')
    print('PASS independent root order: all eight owner combinations, exact original spans and legacy bytes')


if __name__ == '__main__':
    main()
