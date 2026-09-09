#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent control-tar/field/relationship and candidate hash comparison.

Read-only qualification oracle for specified inputs, never an installed database
or a dependency satisfier. Upstream ar/codecs and Python tarfile read originals.
The caller supplies an independently checked payload-index fingerprint.
"""
import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
from pathlib import Path
import re
import struct
import subprocess
import tarfile

FIELDS = ['depends', 'pre-depends', 'recommends', 'suggests', 'enhances', 'breaks',
          'conflicts', 'replaces', 'provides', 'built-using', 'static-built-using']
OPS = ['', '<<', '<=', '=', '>=', '>>']
ATOM = re.compile(r'([a-z0-9][a-z0-9+.\-]+)(?::([a-z0-9][a-z0-9\-]*))?'
                  r'(?:\s*\((<<|<=|=|>=|>>)\s*([^\s()]+)\))?')

def original(path):
    with path.open('rb') as stream: digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    members = subprocess.run(['ar', 't', str(path)], capture_output=True, check=True).stdout.decode().splitlines()
    names = [name for name in members if name == 'control.tar' or name.startswith('control.tar.')]
    assert len(names) == 1, names
    encoded = subprocess.run(['ar', 'p', str(path), names[0]], capture_output=True, check=True).stdout
    suffix = names[0].removeprefix('control.tar')
    if not suffix: archive = encoded
    elif suffix == '.gz': archive = gzip.decompress(encoded)
    elif suffix == '.bz2': archive = bz2.decompress(encoded)
    elif suffix in ('.xz', '.lzma'): archive = lzma.decompress(encoded)
    elif suffix == '.zst': archive = subprocess.run(['zstd', '-dcq'], input=encoded, capture_output=True, check=True).stdout
    else: raise AssertionError(suffix)
    assert len(archive) <= 64 * 1024 * 1024
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as source:
        controls = [entry for entry in source if entry.name.removeprefix('./') == 'control' and entry.isfile()]
        assert len(controls) == 1
        raw = source.extractfile(controls[0]).read()
    fields = {}; key = None
    for line in raw.decode('utf-8').splitlines():
        if line.startswith((' ', '\t')):
            assert key is not None; fields[key] += ' ' + line.strip()
        elif line:
            key, value = line.split(':', 1); key = key.lower()
            assert key not in fields; fields[key] = value.strip()
    source = re.fullmatch(r'([^\s()]+)(?:\s*\(([^\s()]+)\))?', fields.get('source', fields['package']))
    assert source
    package = [digest, hashlib.sha256(encoded).hexdigest(), hashlib.sha256(raw).hexdigest(),
               fields['package'], fields['version'], fields['architecture'], source[1], source[2] or fields['version'],
               str(['no', 'same', 'foreign', 'allowed'].index(fields.get('multi-arch', 'no'))),
               str(int(fields.get('essential', 'no') == 'yes')), str(int(fields.get('protected', 'no') == 'yes')),
               str(int('installed-size' in fields)), str(int(fields.get('installed-size', '0')))]
    relation_fields = []; atoms = []
    for kind in FIELDS:
        group_count = 0; count = 0
        for group in fields.get(kind, '').split(',') if kind in fields else []:
            group_count += 1
            for alternative in group.split('|'):
                atom = ATOM.fullmatch(alternative.strip()); assert atom, alternative
                count += 1
                atoms.append([digest, kind, str(count), str(group_count), str(OPS.index(atom[3] or '')),
                              atom[1], atom[2] or '', atom[4] or ''])
        relation_fields.append([digest, kind, str(count), str(group_count)])
    return package, relation_fields, atoms

def compare(media, names, native, payload_hash):
    assert len(payload_hash) == 64 and len(bytes.fromhex(payload_hash)) == 32
    expected = {'PACKAGE': [], 'FIELD': [], 'ATOM': []}
    for name in names:
        assert name and '/' not in name and name not in ('.', '..')
        package, fields, atoms = original(media / name)
        expected['PACKAGE'].append(package); expected['FIELD'].extend(fields); expected['ATOM'].extend(atoms)
    assert len({row[0] for row in expected['PACKAGE']}) == len(names)
    assert len({(row[3], row[5]) for row in expected['PACKAGE']}) == len(names)
    actual = {key: [] for key in expected}; hashes = {}
    for line in native.read_text().splitlines():
        parts = line.split('\t')
        if parts[0] in actual: actual[parts[0]].append([item.strip() for item in parts[1:]])
        elif line.startswith(('CATALOG ', 'PAYLOAD ')):
            key, value = line.split(); assert key not in hashes; hashes[key] = value
    for key in expected:
        assert sorted(actual[key]) == sorted(expected[key]), key
    ordered = sorted(expected['PACKAGE'])
    assert actual['PACKAGE'] == ordered, 'canonical package order'
    tag = b'NIACSEL1'
    data = struct.pack('>Q', len(tag)) + tag + bytes.fromhex(payload_hash) + struct.pack('>Q', len(ordered))
    data += b''.join(bytes.fromhex(row[0] + row[1] + row[2]) for row in ordered)
    assert hashes == {'CATALOG': hashlib.sha256(data).hexdigest(), 'PAYLOAD': payload_hash}, hashes
    return dict(result='pass', scope='candidate binding and retained metadata only; no dependency or execution permission',
                packages=len(ordered), fields=len(expected['FIELD']), atoms=len(expected['ATOM']), hashes=hashes,
                originals=[dict(filename=name, original=original(media / name)[0][0]) for name in names])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--media', required=True, type=Path); parser.add_argument('--list', required=True, type=Path)
    parser.add_argument('--native', required=True, type=Path); parser.add_argument('--payload-hash', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = compare(args.media, args.list.read_text().splitlines(), args.native, args.payload_hash)
    args.output.write_text(json.dumps(result, indent=2) + '\n'); print(json.dumps(result, ensure_ascii=False))
