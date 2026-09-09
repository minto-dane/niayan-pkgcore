#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent exact CAS retention reference for two bounded synthetic catalogs.

Reads raw DEBs, control files, tar contents, link text and attribute records.
Never extracts paths, executes scripts, trusts directory contents as membership,
or treats a pin as installation authority. The richer catalog's payload hash is
cross-bound to its stored catalog, not independently recomputed by this oracle.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import tarfile
from compare_catalog_store import NAMES, reference
from compare_deb_payload import xattrs, acl


def sha(raw):
    return hashlib.sha256(raw).digest()


def objects(path):
    raw = path.read_bytes()
    assert len(raw) <= 1024 * 1024 and raw[:8] == b'!<arch>\n'
    members = {}; offset = 8
    while offset < len(raw):
        header = raw[offset:offset + 60]
        assert len(header) == 60 and header[-2:] == b'`\n'
        name = header[:16].decode('ascii').rstrip(' /')
        size = int(header[48:58]); start = offset + 60
        assert name not in members and 0 <= size <= len(raw) - start
        members[name] = raw[start:start + size]; offset = start + size + size % 2
    assert offset == len(raw) and members.pop('debian-binary') == b'2.0\n'
    assert len(members) == 2
    control_name = next(k for k in members if k.startswith('control.tar'))
    data_name = next(k for k in members if k.startswith('data.tar'))
    retained = {sha(raw): raw}; kinds = set(); control = None
    for name in [control_name, data_name]:
        encoded = members[name]; retained[sha(encoded)] = encoded
        assert name.endswith('.tar') or name.endswith('.tar.gz')
        expanded = gzip.decompress(encoded) if name.endswith('.gz') else encoded
        assert len(expanded) <= 1024 * 1024
        if name == data_name:
            retained[sha(expanded)] = expanded
        with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
            assert not archive.pax_headers
            for item in archive:
                if name == control_name:
                    assert item.isfile() or item.isdir()
                    if item.isfile():
                        content = archive.extractfile(item).read()
                        retained[sha(content)] = content
                        if item.name == './control': control = sha(content)
                else:
                    kinds.add(item.type.decode())
                    assert item.type in (tarfile.REGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE,
                                         tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE)
                    for content in [xattrs(item.pax_headers), acl(item.pax_headers)]:
                        retained[sha(content)] = content
                    if item.isfile():
                        content = archive.extractfile(item).read(); retained[sha(content)] = content
                    elif item.issym():
                        content = item.linkname.encode(); retained[sha(content)] = content
    assert control is not None
    return retained, (sha(raw), sha(members[control_name]), control), kinds


def check(media, native, cas):
    lines = native.read_text().splitlines()
    def row(prefix):
        rows = [line.split() for line in lines if line.startswith(prefix + ' ')]
        assert len(rows) == 1
        return rows[0][1:]
    address, size, count, rejected, missing = row('CLOSURE')
    rich_catalog, rich_address = row('RICH_CLOSURE')
    _, catalog_frame = reference(media, NAMES)
    results = []
    for names, catalog_hash, closure_hash, pin in [
        (NAMES, sha(catalog_frame).hex(), address, 73),
        (['retention-rich.deb'], rich_catalog, rich_address, 77),
    ]:
        catalog = (cas/'objects'/catalog_hash[:2]/catalog_hash[2:]).read_bytes()
        assert sha(catalog).hex() == catalog_hash
        retained = {sha(catalog): catalog}; packages = []; kinds = set()
        for name in names:
            observed, package, payload_kinds = objects(media/name)
            retained.update(observed); packages.append(package); kinds.update(payload_kinds)
        assert catalog[:16] == struct.pack('>Q', 8) + b'NIACSEL1'
        assert catalog[48:] == struct.pack('>Q', len(names)) + b''.join(b''.join(p) for p in sorted(packages))
        if pin == 73:
            assert catalog == catalog_frame
        else:
            assert kinds == set('0123456')
        frame = b'NIACLOS1' + sha(catalog) + catalog[16:48] + struct.pack('>Q', len(retained)) + b''.join(sorted(retained))
        assert sha(frame).hex() == closure_hash
        assert (cas/'objects'/closure_hash[:2]/closure_hash[2:]).read_bytes() == frame
        assert (cas/'pins'/(bytes([pin])*16).hex()).read_bytes() == sha(frame)
        for digest, content in retained.items():
            name = digest.hex()
            assert (cas/'objects'/name[:2]/name[2:]).read_bytes() == content
        results.append(dict(catalog=catalog_hash, address=closure_hash, bytes=len(frame),
            objects=len(retained), member_sizes={k.hex(): len(v) for k, v in sorted(retained.items())},
            originals=names, pin=(bytes([pin])*16).hex(), payload_kinds=sorted(kinds)))
    assert int(size) == results[0]['bytes'] and int(count) == results[0]['objects'] == int(missing)
    refusals = [line.split() for line in lines if line.startswith('CLOSURE_REJECT ')]
    assert len(refusals) == int(rejected) == 14 + int(count) and all(r[2] != 'OK' for r in refusals)
    return dict(result='pass-for-two-exact-catalog-retention-closures', catalogs=results,
                rejected_frames=len(refusals), missing_members=int(missing))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['media', 'native', 'cas', 'output']:
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args(); result = check(args.media, args.native, args.cas)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
