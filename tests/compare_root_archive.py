#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independently compare the assembled root's exact spans with original DEBs."""
import argparse
import hashlib
import io
import json
import struct
import tarfile
from pathlib import Path


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def members(raw):
    assert raw[:8] == b'!<arch>\n'
    position, found = 8, {}
    while position < len(raw):
        head = raw[position:position + 60]
        assert len(head) == 60 and head[58:] == b'`\n'
        size = int(head[48:58])
        name = head[:16].decode('ascii').rstrip().rstrip('/')
        assert name not in found
        found[name] = raw[position + 60:position + 60 + size]
        assert len(found[name]) == size
        position += 60 + size + size % 2
    assert position == len(raw)
    return found


def records(raw):
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as stream:
        result = stream.getmembers()
    return [(item, raw[item.offset:item.offset_data + ((item.size + 511) // 512) * 512])
            for item in result]


def path(item):
    name = item.name
    if name.startswith('./'):
        name = name[2:]
    return '' if name == '.' else name.rstrip('/')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--media', type=Path, required=True)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--cas', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    lines = args.native.read_text().splitlines()
    assert any(line.startswith('PASS assertions=') for line in lines)
    selected = [line.split()[1:] for line in lines if line.startswith('CHOICE ')]
    manifest_id, = [line.split()[1] for line in lines if line.startswith('MANIFEST ')]
    archive_id, = [line.split()[1] for line in lines if line.startswith('ARCHIVE ')]

    def object_bytes(address):
        raw = (args.cas / 'objects' / address[:2] / address[2:]).read_bytes()
        assert digest(raw) == address
        return raw

    originals, claims = {}, []
    for filename in sorted(args.media.glob('*.deb')):
        raw = filename.read_bytes()
        source = digest(raw)
        assert object_bytes(source) == raw
        originals[source] = records(members(raw)['data.tar'])
        claims.extend((path(item).encode(), source, ordinal)
                      for ordinal, (item, _) in enumerate(originals[source], 1))
    claims.sort()
    picked = [(source, int(ordinal)) for source, ordinal in selected]
    expected = {path(originals[source][ordinal - 1][0]): (source, ordinal)
                for source, ordinal in picked}
    assert len(expected) == len(picked) == len({name for name, _, _ in claims})
    assert [path(originals[source][ordinal - 1][0]).encode() for source, ordinal in picked] == sorted(
        name.encode() for name in expected)
    wire = object_bytes(manifest_id)
    output = object_bytes(archive_id)
    assert wire[:8] == b'NIAROOT1' and wire[104:136].hex() == archive_id
    assert struct.unpack('>QQ', wire[136:152]) == (len(output), len(picked))
    assert len(wire) == 152 + 8 * len(picked)
    for index, pick in zip(struct.unpack('>' + 'Q' * len(picked), wire[152:]), picked, strict=True):
        assert claims[index - 1][1:] == pick
    assembled = records(output)
    assert len(assembled) == len(picked)
    seen, non_directory, exact = set(), False, bytearray()
    for item, span in assembled:
        name = path(item)
        assert name not in seen and name in expected
        source, ordinal = expected[name]
        original, raw_span = originals[source][ordinal - 1]
        assert span == raw_span, name  # Includes local extension headers and data padding.
        assert item.get_info() == original.get_info() and item.pax_headers == original.pax_headers, name
        if item.isdir():
            assert not non_directory
        else:
            non_directory = True
        if item.islnk():
            target = item.linkname.removeprefix('./')
            assert target in seen and expected[target][0] == source
        seen.add(name)
        exact.extend(span)
    assert output == bytes(exact) + bytes(1024)
    kinds = sorted({item.type.decode('ascii') for item, _ in assembled})
    assert kinds == ['0', '1', '2', '3', '4', '5', '6']
    report = dict(result='pass', manifest=manifest_id, archive=archive_id,
                  original_debs=len(originals), selected_paths=len(picked),
                  archive_bytes=len(output), entry_types=kinds,
                  exact_original_spans=True, hardlink_targets_precede_links=True,
                  physical_extraction=False, production_authorization=False)
    generations = [line.split()[1] for line in lines if line.startswith('GENERATION_MANIFEST ')]
    if generations:
        generation_id, = generations
        generation = object_bytes(generation_id)
        assert len(generation) == 320 and generation[:8] == b'NIAGEN05'
        assert generation[224:256].hex() == manifest_id
        assert generation[56:88] == wire[8:40] and generation[128:160] == wire[40:72]
        assert (args.cas / 'pins' / generation[24:40].hex()).read_bytes().hex() == generation_id
        assert (args.cas.parent / 'archive-stage-root/tree/root.tar').read_bytes() == output
        report.update(generation_manifest=generation_id, generation_pin=True, staged_archive_exact=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS root archive original-span oracle:', len(picked), 'paths')


if __name__ == '__main__':
    main()
