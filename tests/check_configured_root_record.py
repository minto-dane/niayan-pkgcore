#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Read saved configured roots in fresh native processes, without live proposals."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('native', 'cas', 'driver', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(exist_ok=False)
    cases = [line.split()[1:] for line in args.native.read_text().splitlines() if line.startswith('CONFIGURED ')]
    assert [c[0] for c in cases] == ['keep', 'vendor', 'links', 'deleted', 'restored', 'empty']
    reports = []

    def path(address):
        assert len(address) == 64 and all(c in '0123456789abcdef' for c in address)
        return args.cas/'objects'/address[:2]/address[2:]

    def obj(address):
        file = path(address)
        assert file.is_file() and not file.is_symlink() and file.stat().st_size <= 4*1024*1024
        data = file.read_bytes()
        assert digest(data) == address
        return data

    def put(data):
        address = digest(data); file = path(address)
        file.parent.mkdir(mode=0o700, exist_ok=True)
        if file.exists():
            assert obj(address) == data
        else:
            with file.open('xb') as stream:
                stream.write(data)
            file.chmod(0o400)
        return address

    def snapshot():
        # Only this test's bounded disposable store, never the development tree.
        return {file.relative_to(args.cas).as_posix(): digest(file.read_bytes())
                for file in (args.cas/'objects').glob('*/*') if file.is_file()}

    def run(label, manifest, retained, expect='accept', reasons=()):
        before = snapshot()
        result = subprocess.run([str(args.driver.resolve()), str(args.cas.resolve()), '--retained',
                                 manifest, retained, expect], text=True, capture_output=True, timeout=120)
        (args.output/(label+'.log')).write_text(result.stdout+result.stderr)
        assert result.returncode == 0, (label, result.stdout, result.stderr)
        assert any(line.startswith('PASS assertions=') for line in result.stdout.splitlines()), label
        assert before == snapshot(), ('read modified saved CAS', label)
        if reasons:
            assert any('REFUSED '+reason in result.stdout for reason in reasons), (label, result.stdout)
        reports.append(dict(case=label, result='pass', fresh_process=True, cas_objects_unchanged=True))
        return result.stdout.splitlines()

    def rows(wire):
        choices, configured = struct.unpack_from('>II', wire, 312)
        return choices, configured, 320+96*choices

    for label, manifest, archive, retained in cases:
        wire, closure = obj(manifest), obj(retained)
        lines = run('saved-'+label, manifest, retained)
        fields = [wire[start:end].hex() for start, end in
                  [(8,40), (40,72), (72,104), (104,136), (136,168), (168,184), (184,200),
                   (200,232), (232,264), (264,296)]]
        fields += [str(value) for value in struct.unpack_from('>QQ', wire, 296)]
        assert [line.split()[1:] for line in lines if line.startswith('BINDING ')] == [fields]
        choices, configured, start = rows(wire)
        assert [line.split()[1:] for line in lines if line.startswith('CHOICE ')] == [
            [wire[pos:pos+32].hex() for pos in range(320+96*i, 416+96*i, 32)] for i in range(choices)]
        assert [line.split()[1:] for line in lines if line.startswith('ENTRY ')] == [
            [str(struct.unpack_from('>Q', wire, start+80*i)[0]),
             wire[start+80*i+8:start+80*i+40].hex(), wire[start+80*i+40:start+80*i+72].hex(),
             str(struct.unpack_from('>Q', wire, start+80*i+72)[0])] for i in range(configured)]
        assert [line.split()[1] for line in lines if line.startswith('MEMBER ')] == [
            closure[pos:pos+32].hex() for pos in range(48, len(closure), 32)]

    _, manifest, archive, retained = cases[0]
    original, retained_wire = obj(manifest), obj(retained)
    members = {retained_wire[pos:pos+32].hex() for pos in range(48, len(retained_wire), 32)}

    def retention(record, values):
        values = sorted(values)
        return put(b'NIACRC01'+bytes.fromhex(record)+struct.pack('>Q', len(values))+
                   b''.join(bytes.fromhex(value) for value in values))

    def altered(label, change, reasons=('CORRUPT',), additions=(), removals=()):
        data = bytearray(original); change(data); record = put(data)
        values = (members-{manifest}-set(removals)) | {record} | set(additions)
        closure = retention(record, values)
        run(label, record, closure, 'reject', reasons)

    def replace(offset, data):
        def change(wire):
            wire[offset:offset+len(data)] = data
        return change

    altered('unknown-format', replace(7, b'9'), ('UNSUPPORTED',))
    altered('short-header', lambda wire: wire.__delitem__(slice(200, None)))
    altered('trailing-byte', lambda wire: wire.extend(b'\0'))
    altered('zero-root', replace(168, bytes(16)))
    altered('foreign-context', replace(200, bytes([9])*32))
    altered('choice-count-bound', replace(312, struct.pack('>I', 4097)), ('EXHAUSTED',))
    altered('entry-count-bound', replace(304, struct.pack('>Q', 524289)), ('EXHAUSTED',))
    altered('root-size-mismatch', replace(296, struct.pack('>Q', len(obj(archive))+512)))
    count, configured, start = rows(original)
    assert count == 1 and configured == 2
    altered('configuration-at-root', replace(start, struct.pack('>Q', 1)))
    altered('duplicate-configuration-position', replace(start+80, original[start:start+8]))
    altered('configuration-content-size', replace(start+72, struct.pack('>Q', 12345)))
    altered('duplicate-choice', lambda wire: (wire.__setitem__(slice(312,316), struct.pack('>I', 2)),
                                             wire.__setitem__(slice(416,416), original[320:416])))
    extra = put(b'bounded saved record unrelated object\n')
    run('extra-retained-member', manifest, retention(manifest, members | {extra}), 'reject', ('CORRUPT',))
    run('omitted-manifest-member', manifest, retention(manifest, members-{manifest}), 'reject', ('CORRUPT',))
    run('foreign-retention-binding', manifest, retention(archive, members), 'reject', ('CORRUPT',))
    noncanonical = bytearray(retained_wire)
    noncanonical[48:80], noncanonical[80:112] = noncanonical[80:112], noncanonical[48:80]
    run('unordered-members', manifest, put(noncanonical), 'reject', ('CORRUPT',))
    noncanonical[48:80] = noncanonical[80:112]
    run('duplicate-members', manifest, put(noncanonical), 'reject', ('CORRUPT',))
    choice_closure = original[384:416].hex()
    bad_choice = bytearray(obj(choice_closure)); bad_choice[8:40] = bytes(32); bad_id = put(bad_choice)
    altered('choice-closure-binding', replace(384, bytes.fromhex(bad_id)), additions=(bad_id,), removals=(choice_closure,))

    # Persisted boottime belongs to the old proposal session. Reading its history
    # must not require that session to survive or turn it into a fresh proposal.
    old_proposal, old_decision = original[320:352].hex(), original[352:384].hex()
    proposal_wire = bytearray(obj(old_proposal)); struct.pack_into('>Q', proposal_wire, 332, 1)
    new_proposal = put(proposal_wire)
    decision_wire = bytearray(obj(old_decision)); decision_wire[8:40] = bytes.fromhex(new_proposal)
    new_decision = put(decision_wire)
    choice_wire = obj(choice_closure)
    choice_members = {choice_wire[pos:pos+32].hex() for pos in range(76, len(choice_wire), 32)}
    choice_members = (choice_members-{old_proposal, old_decision}) | {new_proposal, new_decision}
    new_choice = put(b'NIACCF01'+bytes.fromhex(new_proposal)+bytes.fromhex(new_decision)+
                     struct.pack('>I', len(choice_members))+
                     b''.join(bytes.fromhex(value) for value in sorted(choice_members)))
    historical = bytearray(original)
    historical[320:416] = bytes.fromhex(new_proposal+new_decision+new_choice)
    historical_id = put(historical)
    historical_members = (members-{manifest, old_proposal, old_decision, choice_closure}) | {
        historical_id, new_proposal, new_decision, new_choice}
    historical_lines = run('historical-deadline', historical_id, retention(historical_id, historical_members))
    assert ['CHOICE', new_proposal, new_decision, new_choice] in [line.split() for line in historical_lines]

    # Each loss is isolated; reading must leave the missing object absent. The
    # fixture harness restores it explicitly only after the reader has exited.
    losses = dict(root=archive, manifest=manifest, retention=retained, base=original[8:40].hex(),
                  proposal=original[320:352].hex(), decision=original[352:384].hex(),
                  choice_closure=choice_closure, prefix=original[start+8:start+40].hex(),
                  content=original[start+40:start+72].hex(), catalog=original[40:72].hex())
    for label, address in losses.items():
        file = path(address); data, mode = obj(address), file.stat().st_mode & 0o7777
        file.unlink()
        try:
            run('missing-'+label, manifest, retained, 'reject')
            assert not file.exists(), ('implicit reconstruction', label)
        finally:
            file.write_bytes(data); file.chmod(mode)

    report = dict(result='pass', cases=reports, count=len(reports),
                  scope='saved reference integrity; no live proposal, execution permission, GC deletion or physical preparation')
    (args.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print('PASS saved configured root records:', len(reports))


if __name__ == '__main__':
    main()
