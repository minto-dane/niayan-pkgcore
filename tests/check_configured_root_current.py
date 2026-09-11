#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Reobserve saved roots in fresh processes inside the same mount namespace."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('native', 'cas', 'root', 'driver', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args(); args.output.mkdir(exist_ok=False)
    cases = [line.split()[1:] for line in args.native.read_text().splitlines() if line.startswith('CONFIGURED ')]
    assert [case[0] for case in cases] == ['keep', 'vendor', 'links', 'deleted', 'restored', 'empty']
    reports = []

    def obj(address):
        file = args.cas/'objects'/address[:2]/address[2:]
        assert file.is_file() and not file.is_symlink() and file.stat().st_size < 4*1024*1024
        data = file.read_bytes(); assert hashlib.sha256(data).hexdigest() == address
        return data

    def put(data):
        address = hashlib.sha256(data).hexdigest(); file = args.cas/'objects'/address[:2]/address[2:]
        file.parent.mkdir(exist_ok=True, mode=0o700)
        if file.exists():
            assert obj(address) == data
        else:
            file.write_bytes(data); file.chmod(0o400)
        return address

    def retained(manifest, values):
        return put(b'NIACRC01'+bytes.fromhex(manifest)+struct.pack('>Q', len(values))+
                   b''.join(bytes.fromhex(value) for value in sorted(values)))

    def run(label, manifest, closure, expected, current=True, reason=None):
        # Fresh observations can create unpinned CAS objects, but historical
        # records must stay byte-identical. No local file mutation is requested.
        old_manifest, old_closure = obj(manifest), obj(closure)
        old_members = [old_closure[pos:pos+32].hex() for pos in range(48, len(old_closure), 32)]
        for address in old_members:
            obj(address)
        command = [str(args.driver.resolve()), str(args.cas.resolve())]
        command += ['--current', str(args.root.resolve())] if current else ['--retained']
        result = subprocess.run(command+[manifest, closure, expected], text=True, capture_output=True, timeout=180)
        (args.output/(label+'.log')).write_text(result.stdout+result.stderr)
        assert result.returncode == 0, (label, result.stdout, result.stderr)
        assert 'PASS assertions=' in result.stdout
        assert obj(manifest) == old_manifest and obj(closure) == old_closure
        for address in old_members:
            obj(address)
        if reason:
            assert 'REFUSED '+reason in result.stdout, (label, result.stdout)
        reports.append(dict(case=label, result='pass', expected=expected, current=current,
                            manifest=manifest, retained=closure, historical_records_unchanged=True))

    # The driver leaves the last (empty regular file) configuration in place.
    # Earlier observations name the same inode/path before its changes and must
    # be rejected. Read-only saved-reference inspection still accepts all six.
    for label, manifest, archive, closure in cases:
        run('current-'+label, manifest, closure, 'accept' if label == 'empty' else 'reject',
            reason=None if label == 'empty' else 'STALE')

    _, manifest, archive, closure = cases[-1]
    wire, closure_wire = obj(manifest), obj(closure)
    values = {closure_wire[pos:pos+32].hex() for pos in range(48, len(closure_wire), 32)}
    count, configured = struct.unpack_from('>II', wire, 312)
    assert count == 1 and configured == 2
    start = 320+96*count

    def altered(label, data, additions=(), removals=()):
        record = put(data); kept = retained(record, (values-{manifest}-set(removals)) | {record} | set(additions))
        run(label+'-saved', record, kept, 'accept', current=False)
        run(label+'-current', record, kept, 'reject', reason='CONFLICT')

    wrong = bytearray(wire); wrong[136:168] = bytes([7])*32
    altered('ownership-binding', wrong)
    prefix = wire[start+8:start+40].hex(); prefix_wire = bytearray(obj(prefix)); prefix_wire[0] ^= 1
    new_prefix = put(prefix_wire); wrong = bytearray(wire); wrong[start+8:start+40] = bytes.fromhex(new_prefix)
    altered('configuration-prefix', wrong, (new_prefix,), (prefix,))
    archive_wire = bytearray(obj(archive)); archive_wire[-1] ^= 1; new_archive = put(archive_wire)
    wrong = bytearray(wire); wrong[264:296] = bytes.fromhex(new_archive)
    altered('root-bytes', wrong, (new_archive,), (archive,))

    # An old observation lifetime is historical input, not authority. All other
    # source/attribute/choice bytes must be rederived exactly in the fresh session.
    proposal, decision, choice = [wire[pos:pos+32].hex() for pos in (320,352,384)]
    new = bytearray(obj(proposal)); struct.pack_into('>Q', new, 332, 1); new_proposal = put(new)
    new = bytearray(obj(decision)); new[8:40] = bytes.fromhex(new_proposal); new_decision = put(new)
    new = obj(choice); choice_members = {new[pos:pos+32].hex() for pos in range(76, len(new), 32)}
    choice_members = (choice_members-{proposal,decision}) | {new_proposal,new_decision}
    new_choice = put(b'NIACCF01'+bytes.fromhex(new_proposal+new_decision)+struct.pack('>I',len(choice_members))+
                     b''.join(bytes.fromhex(value) for value in sorted(choice_members)))
    new = bytearray(wire); new[320:416] = bytes.fromhex(new_proposal+new_decision+new_choice); new_manifest = put(new)
    new_closure = retained(new_manifest, (values-{manifest,proposal,decision,choice}) |
                          {new_manifest,new_proposal,new_decision,new_choice})
    run('historical-observation-current', new_manifest, new_closure, 'accept')

    report = dict(result='pass', count=len(reports), cases=reports,
                  scope='fresh current-source verification in the same mount namespace, not admission or reboot identity migration')
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASS configured root current observations:', len(reports))


if __name__ == '__main__':
    main()
