#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent persisted catalog frame and retained metadata oracle.

The four synthetic payloads have only plain regular entries or no entries.
This deliberately bounded reference does not interpret arbitrary system tar.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import tarfile
from compare_selected_catalog import original, compare
from compare_payload_index import fingerprint

NAMES = ['consumer.deb', 'library-amd64.deb', 'library-arm64.deb', 'empty.deb']
def sha(data): return hashlib.sha256(data).hexdigest()

def check(media, native, cas):
    sources = []; packages = []
    for name in NAMES:
        path = media/name; package, _, _ = original(path); packages.append(package)
        raw = subprocess.run(['ar', 'p', str(path), 'data.tar'], capture_output=True, check=True).stdout
        assert len(raw) <= 1024 * 1024
        entries = []
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            assert not archive.pax_headers
            for i, item in enumerate(archive, 1):
                assert item.isfile() and not item.pax_headers and not item.linkname
                assert isinstance(item.mtime, int) and item.name.startswith('./') and '/' not in item.name[2:]
                content = archive.extractfile(item).read(); assert len(content) == item.size
                entries.append(dict(index=i, PATH=item.name[2:], LINK='', UNAME=item.uname, GNAME=item.gname,
                    ATTR=['REGULAR', item.mode, item.uid, item.gid, item.devmajor, item.devminor, item.size, item.size, i, 0, 0],
                    CONTENT=sha(content), XATTR=sha(b'\0\0'), ACL=sha(b'\0\0'), MTIME=['TRUE', item.mtime, 0],
                    ATIME=['FALSE', 0, 0], CTIME=['FALSE', 0, 0], BTIME=['FALSE', 0, 0]))
        sources.append(dict(ORIGINAL=package[0], TAR=sha(raw), entries=entries))
    index = fingerprint(sources)
    retained = compare(media, NAMES, native, index['INDEX'])
    frame = struct.pack('>Q', 8) + b'NIACSEL1' + bytes.fromhex(index['INDEX']) + struct.pack('>Q', len(packages))
    frame += b''.join(bytes.fromhex(''.join(row[:3])) for row in sorted(packages))
    address = sha(frame)
    saved = [line.split() for line in native.read_text().splitlines() if line.startswith('STORED ')]
    assert saved == [['STORED', address, str(len(frame))]]
    assert (cas/'objects'/address[:2]/address[2:]).read_bytes() == frame
    refusals = [line.split() for line in native.read_text().splitlines() if line.startswith('REJECT ')]
    assert len(refusals) == 20 and all(row[2] != 'OK' for row in refusals)
    return dict(result='pass-for-persisted-catalog-and-reobserved-fixtures', address=address, bytes=len(frame),
                frame_hex=frame.hex(), payload_index=index, retained=retained, malformed_cases=len(refusals))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--media', required=True, type=Path); parser.add_argument('--native', required=True, type=Path)
    parser.add_argument('--cas', required=True, type=Path); parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(); result = check(args.media, args.native, args.cas)
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k: result[k] for k in ['result', 'address', 'bytes', 'malformed_cases']}))
