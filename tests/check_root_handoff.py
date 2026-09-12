# SPDX-License-Identifier: BSD-3-Clause
"""Real UID/pidfd/SCM handoff in an isolated root container; no package effects."""
import array
import ctypes
import dataclasses
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


def main():
    if os.getuid() or not Path('/run/.containerenv').is_file():
        raise RuntimeError('disposable root container required')
    source, library, ada, report = map(Path, sys.argv[1:])
    spec = importlib.util.spec_from_file_location('handoff', source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    lib = ctypes.CDLL(str(library))
    lib.nia_root_handoff_open.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_int, ctypes.c_ulonglong]
    lib.nia_root_handoff_prepare.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    lib.nia_root_handoff_close.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    lib.nia_root_handoff_close.restype = None
    passed = []
    modes = ['normal', 'scope-mismatch', 'extra-request-fds', 'truncated-request-controls', 'descendant-sender',
             'bad-reply', 'trailing-reply', 'reply-fds', 'truncated-reply-controls', 'silent',
             'cancel-before-completion', 'forked-handle', 'no-passcred', 'ada']
    for mode in modes:
        before = len(os.listdir('/proc/self/fd'))
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        for peer in (parent, child):
            peer.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        if mode == 'no-passcred':
            child.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 0)
        scope = module.Scope(*(bytes([0x22]) * 32 for _ in range(4)), bytes([0x11]) * 16,
                             1024, 1, module.now_ms() + (250 if mode == 'silent' else 5000))
        wire = scope.wire()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'archive').write_bytes(bytes(1024))
            archive = os.open(path / 'archive', os.O_RDONLY | os.O_CLOEXEC)
            lease = os.open(path / 'lease', os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result_read, result_write = os.pipe2(os.O_CLOEXEC)
            ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
            pid = os.fork()
            if not pid:
                try:
                    parent.close(); os.close(result_read); os.close(ready_write)
                    assert os.read(ready_read, 1) == b'1'; os.close(ready_read)
                    os.setgroups([]); os.setgid(1000); os.setuid(1000)
                    if mode == 'ada':
                        for fd in (child.fileno(), archive, lease): os.set_inheritable(fd, True)
                        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8', 'NIA_TEST_HANDOFF_FD': str(child.fileno()),
                               'NIA_TEST_HANDOFF_DEADLINE': str(scope.deadline), 'NIA_TEST_ARCHIVE_FD': str(archive),
                               'NIA_TEST_LEASE_FD': str(lease)}
                        os.execve(str(ada), [str(ada)], env)
                    baseline = len(os.listdir('/proc/self/fd'))
                    handle = ctypes.c_void_p()
                    opened = lib.nia_root_handoff_open(ctypes.byref(handle), child.fileno(), scope.deadline)
                    if mode == 'no-passcred':
                        assert opened == 1, opened
                    else:
                        assert opened == 0, opened
                        assert lib.nia_root_handoff_open(ctypes.byref(handle), child.fileno(), scope.deadline) == 4
                        if mode == 'forked-handle':
                            forked = os.fork()
                            if not forked:
                                os._exit(0 if lib.nia_root_handoff_prepare(handle, wire, archive, lease) == 1 else 1)
                            assert os.waitpid(forked, 0)[1] == 0
                        if mode in ('extra-request-fds', 'truncated-request-controls', 'descendant-sender'):
                            forked = os.fork() if mode == 'descendant-sender' else 0
                            if not forked:
                                count = 40 if mode == 'truncated-request-controls' else 3 if mode == 'extra-request-fds' else 2
                                child.sendmsg([wire], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [archive] * count))])
                                if mode == 'descendant-sender': os._exit(0)
                            else:
                                assert os.waitpid(forked, 0)[1] == 0
                            # Keep the authenticated direct child alive until refusal.
                            child.settimeout(5); assert child.recv(128) == b''
                        elif mode == 'cancel-before-completion':
                            child.sendmsg([wire], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [archive, lease]))])
                            child.send(b'cancel'); child.settimeout(5)
                            try: assert child.recv(128) == b''
                            except ConnectionResetError: pass
                        else:
                            outcome = lib.nia_root_handoff_prepare(handle, wire, archive, lease)
                            assert outcome == (0 if mode in ('normal', 'forked-handle') else 2), (mode, outcome)
                            assert lib.nia_root_handoff_prepare(handle, wire, archive, lease) == 4
                        lib.nia_root_handoff_close(ctypes.byref(handle))
                        assert not handle.value
                    assert len(os.listdir('/proc/self/fd')) == baseline
                    assert os.pread(archive, 1024, 0) == bytes(1024)
                    os.fstat(lease); os.fstat(child.fileno())
                    os.write(result_write, b'pass')
                    os._exit(0)
                except BaseException as error:
                    os.write(result_write, repr(error).encode()[:2048]); os._exit(1)
            child.close(); os.close(result_write); os.close(ready_read)
            channel = None
            try:
                expected = dataclasses.replace(scope, generation=bytes([0x33]) * 32) if mode == 'scope-mismatch' else scope
                channel = module.Channel(parent, pid, 1000, expected)
                os.write(ready_write, b'1'); os.close(ready_write); ready_write = -1
                if mode == 'no-passcred':
                    pass
                elif mode == 'silent':
                    channel.receive()
                    try: channel._wait(0)
                    except module.Rejected: pass
                elif mode in ('scope-mismatch', 'extra-request-fds', 'truncated-request-controls', 'descendant-sender', 'cancel-before-completion'):
                    try:
                        channel.receive()
                        if mode == 'cancel-before-completion':
                            channel._wait(__import__('select').POLLIN); channel.complete()
                    except (module.Rejected, OSError): pass
                    else: raise AssertionError('bad request was accepted: ' + mode)
                else:
                    fds = channel.receive()
                    assert os.pread(fds[0], 1024, 0) == bytes(1024)
                    other = os.open(path / 'lease', os.O_RDWR)
                    try:
                        try: fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        except BlockingIOError: pass
                        else: raise AssertionError('actual reservation not retained')
                    finally: os.close(other)
                    if mode in ('normal', 'forked-handle', 'ada'):
                        channel.complete(); assert channel.descriptors == []
                        try: channel.complete()
                        except module.Rejected: pass
                        else: raise AssertionError('duplicate completion')
                    else:
                        reply = b'NIAHOK01' + hashlib.sha256(wire).digest()
                        if mode == 'bad-reply': reply = b'X' + reply[1:]
                        if mode == 'trailing-reply': reply += b'X'
                        controls = []
                        if mode in ('reply-fds', 'truncated-reply-controls'):
                            controls = [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                         array.array('i', [archive] * (40 if mode == 'truncated-reply-controls' else 1)))]
                        parent.sendmsg([reply], controls)
                if mode in ('normal', 'forked-handle', 'ada', 'bad-reply', 'trailing-reply', 'reply-fds', 'truncated-reply-controls'):
                    # Retain the root endpoint while the C client checks the reply.
                    status = os.waitpid(pid, 0)[1]
                else:
                    channel.close(); parent.close(); status = os.waitpid(pid, 0)[1]
                details = os.read(result_read, 2048)
                assert status == 0 and (mode == 'ada' or details == b'pass'), (mode, status, details)
            finally:
                if ready_write >= 0: os.close(ready_write)
                if channel is not None: channel.close()
                parent.close(); os.close(result_read); os.close(archive); os.close(lease)
                try:
                    pending = os.waitpid(pid, os.WNOHANG)
                    if pending == (0, 0): os.kill(pid, 9); os.waitpid(pid, 0)
                except ChildProcessError: pass
        assert len(os.listdir('/proc/self/fd')) == before, (mode, 'supervisor FD leak')
        passed.append(mode)
        print('PASS', mode, flush=True)
    handle = ctypes.c_void_p()
    assert lib.nia_root_handoff_open(ctypes.byref(handle), 0, module.now_ms() + 1000) == 1
    passed.append('root-worker-refused')
    report.write_text(json.dumps(dict(result='pass',checks=passed,physical_effects=False,
        native_admission=False,real_kernel_credentials=True), indent=2) + '\n')


if __name__ == '__main__':
    main()
