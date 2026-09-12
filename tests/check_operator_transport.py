#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Bounded sd-bus protocol tests in a disposable container, never the host bus."""
import argparse
import ctypes as C
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',type=Path,required=True);parser.add_argument('--authority',type=Path,required=True)
    parser.add_argument('--vm-helper',type=Path,required=True);parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    assert os.getuid()==os.geteuid()==0 and Path('/run/.containerenv').exists()
    bus_path=Path('/run/dbus/system_bus_socket');assert not bus_path.exists()
    bus_path.parent.mkdir(mode=0o755,exist_ok=True)
    spec=importlib.util.spec_from_file_location('vm_helper',args.vm_helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    passed=[];context=module.Decision(args.library)
    with tempfile.TemporaryDirectory(prefix='nia-operator-protocol-') as temporary:
        directory=Path(temporary);directory.chmod(0o755);mode=directory/'mode';mode.write_text('normal')
        with (directory/'bus.log').open('w') as log:
            bus=subprocess.Popen(['dbus-daemon','--session','--nofork','--nopidfile','--address=unix:path='+str(bus_path)],stdout=log,stderr=subprocess.STDOUT)
            authority=None
            try:
                until=time.monotonic()+3
                while not bus_path.exists():
                    assert bus.poll() is None and time.monotonic()<until
                    time.sleep(.01)
                authority=subprocess.Popen([str(args.authority),str(mode)],stdout=subprocess.PIPE,stderr=log)
                assert select.select([authority.stdout],[],[],3)[0] and authority.stdout.readline()==b'ready\n'
                peer=module.Peer(directory,65534,65534)
                try:
                    for name in ('normal','deny','challenge','retained','large-detail','many-details','bad-signature','changed','silent'):
                        mode.write_text(name);before=len(os.listdir('/proc/self/fd'))
                        deadline=int(time.clock_gettime(time.CLOCK_BOOTTIME)*1000)+(300 if name=='silent' else 5000)
                        result=context.open(peer.peer,deadline=deadline)
                        if name=='normal':assert result==0 and context.check()==0
                        elif name=='silent':assert result==3 and not context.handle.value
                        else:assert result==1 and not context.handle.value,(name,result)
                        context.close();assert len(os.listdir('/proc/self/fd'))==before,(name,'FD leak')
                        passed.append(name)
                    mode.write_text('normal')
                    assert context.open(peer.peer)==0
                    child=os.fork()
                    if child==0:os._exit(0 if context.check()==1 else 1)
                    assert os.waitpid(child,0)[1]==0 and context.check()==0
                    context.close();passed.append('forked-check-denied')
                    child=os.fork()
                    if child==0:
                        os.setgroups([]);os.setgid(65534);os.setuid(65534)
                        os._exit(0 if context.open(peer.peer)==1 else 1)
                    assert os.waitpid(child,0)[1]==0;passed.append('nonroot-supervisor-denied')
                    assert context.open(peer.peer,deadline=int(time.clock_gettime(time.CLOCK_BOOTTIME)*1000)+120001)==3
                    passed.append('deadline-upper-bound')
                finally:context.close();peer.close()
            finally:
                if authority is not None:authority.terminate();authority.wait(timeout=3)
                bus.terminate();bus.wait(timeout=3)
                if bus_path.exists():bus_path.unlink()
    args.report.write_text(json.dumps(dict(result='pass',checks=passed,real_polkit=False,physical_effects=False),indent=2)+'\n')
    print('PASS operator transport',len(passed))


if __name__=='__main__':main()
