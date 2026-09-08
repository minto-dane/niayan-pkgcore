#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bound a trusted Linux proof toolchain; this is not a sandbox.

RLIMIT_AS is an inherited, per-process hard ceiling, including GNATwhy3.
RSS and MemAvailable are sampled stop conditions, NOT a cgroup memory limit.
All copies use one per-UID lock in /tmp, independent of HOME and TMPDIR.
"""
from __future__ import annotations
import argparse
import ctypes
import fcntl
import json
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import sys
import time

MIB = 1024 * 1024
ADDRESS_MIB = 1536
SESSION_MIB = 2048
RESERVE_MIB = 2048
SECONDS = 3600
INTERVAL = 0.1


def available_bytes() -> int:
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) * 1024
    raise RuntimeError('MemAvailable is unavailable')


def session_rss(session_id: int) -> int:
    pages = 0
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            # comm may contain spaces or parentheses; fields after its final )
            # begin at field 3 (state), with session=6 and rss=24. Why3 starts
            # solvers in separate process groups inside this same session.
            fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
            if int(fields[3]) == session_id:
                pages += max(0, int(fields[21]))
        except (FileNotFoundError, ProcessLookupError):
            continue
        # An unreadable live entry is not silently interpreted as zero memory.
    return pages * os.sysconf('SC_PAGE_SIZE')


def direct_children() -> list[int]:
    return [int(x) for x in Path(f'/proc/self/task/{os.getpid()}/children').read_text().split()]


def subreaper(value: int | None = None) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(previous), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'PR_GET_CHILD_SUBREAPER')
    if value is not None and libc.prctl(36, value, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER')
    return previous.value


def stop_children(child: subprocess.Popen) -> int:
    """Reap the entire tool tree, including solvers with their own pgrp.

    No unrelated children may exist when supervise starts. With subreaping,
    orphaned tool descendants become our direct children. Default SIGCHLD and
    exclusive wait ownership keep their PIDs reserved until we reap them.
    """
    os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        for pid in direct_children():
            if pid == child.pid:
                continue  # Popen owns its unreaped leader until the final wait.
            # Every listed PID is our unreaped child; do not signal it again
            # after waitpid releases that ownership.
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, os.WNOHANG)
        observed = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if observed is not None and direct_children() == [child.pid]:
            return child.wait(timeout=1)
        time.sleep(0.01)
    raise RuntimeError('tool descendants were not all reaped within cleanup deadline')


def acquire_lock() -> int:
    path = f'/tmp/niaos-proof-{os.geteuid()}.lock'
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or s.st_mode & 0o077 or s.st_nlink != 1:
            raise RuntimeError('proof lock must be a private regular file owned by this user')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise
    # Never unlink: another caller must lock this same inode after release.


def lower_limit(kind: int, value: int) -> None:
    _, hard = resource.getrlimit(kind)
    if hard != resource.RLIM_INFINITY:
        value = min(value, hard)
    resource.setrlimit(kind, (value, value))


def child_main(args: list[str]) -> int:
    memory, cpu = int(args[0]), int(args[1])
    lower_limit(resource.RLIMIT_AS, memory * MIB)
    lower_limit(resource.RLIMIT_CORE, 0)
    lower_limit(resource.RLIMIT_CPU, cpu)
    os.nice(15)
    os.execvp(args[2], args[2:])
    return 127


def supervise(command: list[str], *, seconds: float = SECONDS,
              address_mib: int = ADDRESS_MIB, session_mib: int = SESSION_MIB,
              reserve_mib: int = RESERVE_MIB) -> dict:
    """Run one trusted command. Smaller limits are useful for low-impact tests."""
    if not (0 < seconds <= SECONDS and 32 <= address_mib <= ADDRESS_MIB
            and 1 <= session_mib <= SESSION_MIB and reserve_mib >= RESERVE_MIB):
        raise ValueError('limits may only be tightened')
    result = dict(result='not-run', reason=None, returncode=None, peak_session_rss_bytes=0,
                  limits=dict(address_mib_per_process=address_mib,
                              sampled_session_rss_mib=session_mib,
                              minimum_available_mib=reserve_mib, seconds=seconds,
                              sample_interval_seconds=INTERVAL, nice_increment=15))
    start = time.monotonic()
    lock = None
    child = None
    owned = False
    interrupted = []
    handlers = {}
    previous_subreaper = None

    def on_signal(number, frame):
        interrupted.append(number)

    try:
        lock = acquire_lock()
        if available_bytes() < (reserve_mib + session_mib) * MIB:
            result['reason'] = 'insufficient-memory-before-start'
            return result
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise RuntimeError('default SIGCHLD and exclusive child ownership required')
        if direct_children():
            raise RuntimeError('guard requires an isolated process with no existing children')
        previous_subreaper = subreaper(1)
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            handlers[number] = signal.signal(number, on_signal)
        child = subprocess.Popen(
            [sys.executable, '-I', str(Path(__file__).resolve()), '--child',
             str(address_mib), str(max(1, int(seconds))), *command],
            stdin=subprocess.DEVNULL, start_new_session=True, pass_fds=(lock,))
        owned = True
        while True:
            # Keep the leader unreaped until killpg, so its PID cannot be reused.
            observed = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if interrupted:
                result['reason'] = 'signal-interrupted'
                break
            rss = session_rss(child.pid)
            result['peak_session_rss_bytes'] = max(result['peak_session_rss_bytes'], rss)
            if rss > session_mib * MIB:
                result['reason'] = 'session-memory-stop'
                break
            if available_bytes() < reserve_mib * MIB:
                result['reason'] = 'host-memory-stop'
                break
            if time.monotonic() - start >= seconds:
                result['reason'] = 'wall-time-limit'
                break
            if observed is not None:
                break
            time.sleep(INTERVAL)
    except BlockingIOError:
        result['reason'] = 'another-proof-is-running'
    except ChildProcessError:
        owned = False
        result['reason'] = 'child-ownership-lost'
    except (OSError, RuntimeError, ValueError, IndexError) as exc:
        result['reason'] = 'guard-error: ' + str(exc)
    finally:
        if owned:
            try:
                result['returncode'] = stop_children(child)
            except (OSError, RuntimeError, ChildProcessError, subprocess.TimeoutExpired) as exc:
                result['reason'] = 'cleanup-failed: ' + str(exc)
        if previous_subreaper is not None:
            try:
                subreaper(previous_subreaper)
            except OSError as exc:
                result['reason'] = 'subreaper-restore-failed: ' + str(exc)
        for number, handler in handlers.items():
            signal.signal(number, handler)
        if lock is not None:
            os.close(lock)
        if child is not None:
            result['result'] = 'pass' if result['reason'] is None and result['returncode'] == 0 else 'fail'
        result['seconds'] = round(time.monotonic() - start, 3)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=SECONDS)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command or not 1 <= args.seconds <= SECONDS:
        parser.error('provide a command after -- and seconds in 1..3600')
    if os.geteuid() == 0:
        parser.error('proof execution requires an unprivileged user')
    # GNATprove parallelism is fixed here as well as in the Makefile. Diagnostic
    # callers may select units, levels and timeouts, but cannot increase jobs.
    if any(x.startswith('-j') or x.startswith('--jobs') for x in command[1:]):
        parser.error('omit job options; the guard supplies -j1')
    command.insert(1, '-j1')
    print('proof-guard: ' + json.dumps(dict(command=command, address_mib_per_process=ADDRESS_MIB,
          sampled_session_rss_mib=SESSION_MIB, minimum_available_mib=RESERVE_MIB,
          seconds=args.seconds)), flush=True)
    result = supervise(command, seconds=args.seconds)
    print('proof-guard: ' + json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['result'] == 'pass' else 1


if __name__ == '__main__':
    if sys.argv[1:2] == ['--child']:
        raise SystemExit(child_main(sys.argv[2:]))
    raise SystemExit(main())
