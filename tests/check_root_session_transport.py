#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Bounded private transport peers, run as UID0 only in an isolated container.

These tests do not mount or mutate a bank and do not establish site admission.
The separate VM acceptance uses the delivered real controller/worker.
"""
import argparse
import array
import ctypes as C
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import multiprocessing
import time


def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()


class Client:
    def __init__(self,library):
        self.lib=C.CDLL(str(library));self.handle=C.c_void_p();self.inode=C.c_ulonglong()
        self.lib.nia_root_session_open.argtypes=[C.POINTER(C.c_void_p)]+[C.c_char_p]*8+[C.c_ulonglong]*7+[C.c_int]*2+[C.POINTER(C.c_ulonglong)]
        self.lib.nia_root_session_open.restype=C.c_int
        for name in ('held','observe'):
            fn=getattr(self.lib,'nia_root_session_'+name);fn.argtypes=[C.c_void_p]+([C.c_int]*2 if name=='observe' else []);fn.restype=C.c_int
        self.lib.nia_root_session_close.argtypes=[C.POINTER(C.c_void_p)];self.lib.nia_root_session_close.restype=C.c_int
        self.lib.nia_root_session_discard.argtypes=[C.POINTER(C.c_void_p)];self.lib.nia_root_session_discard.restype=None
    def start(self,path,fd,deadline=None):
        if deadline is None:deadline=int(time.clock_gettime(time.CLOCK_BOOTTIME)*1000)+5000
        return self.lib.nia_root_session_open(C.byref(self.handle),str(path).encode(),*[b'2'*64]*4,b'1'*32,b'2'*64,
            b'12345678-1234-1234-1234-123456789abc',1024,1,deadline,69,2,8,1,fd,fd,C.byref(self.inode))
    def held(self):return self.lib.nia_root_session_held(self.handle)==1
    def observe(self,fd):return self.lib.nia_root_session_observe(self.handle,fd,fd)
    def close(self):return self.lib.nia_root_session_close(C.byref(self.handle))
    def discard(self):self.lib.nia_root_session_discard(C.byref(self.handle))


def receive(peer):
    raw,controls,flags,_=peer.recvmsg(4096,socket.CMSG_SPACE(8),socket.MSG_CMSG_CLOEXEC)
    fds=[]
    for level,kind,data in controls:
        assert (level,kind)==(socket.SOL_SOCKET,socket.SCM_RIGHTS)
        values=array.array('i');values.frombytes(data);fds.extend(values)
    for fd in fds:os.close(fd)
    assert not flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC)
    return raw,len(fds)


def response(request):
    deadline=request['request']['deadline_ms']
    return dict(version=1,state='frozen',stage=request['request']['stage'],deadline_ms=deadline,published=False,
        observation=dict(original_deadline_ms=deadline,root=dict(mount_id=69,inode=123,device_major=8,device_minor=1)))


class Peer:
    def __init__(self,path,handler):
        self.path=path;self.handler=handler
        self.listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);self.listener.bind(str(path));self.listener.listen(2);self.listener.settimeout(8)
        self.parent,self.child=multiprocessing.Pipe(duplex=False)
        self.process=multiprocessing.get_context('fork').Process(target=self.run);self.process.start()
        self.listener.close();self.child.close()
    def run(self):
        self.parent.close()
        try:self.handler(self.listener);self.child.send(None)
        except BaseException as error:self.child.send(repr(error))
        finally:self.listener.close();self.child.close()
    def finish(self):
        self.process.join(10)
        if self.process.is_alive():self.process.terminate();self.process.join();raise AssertionError('peer stalled')
        self.path.unlink()
        assert self.process.exitcode==0 and self.parent.poll(),'peer failed without result'
        error=self.parent.recv();self.parent.close();self.process.close()
        assert error is None,error


def initial(listener):
    peer,_=listener.accept();peer.settimeout(7)
    raw,count=receive(peer);request=json.loads(raw)
    assert count==2 and raw==canonical(request)
    assert set(request)=={'bank','boot_id','device_plan_sha256','operation','request','version','worker_sha256'}
    assert request['operation']=='prepare-freeze'
    assert request['bank']==dict(mount_id=69,inode=2,device_major=8,device_minor=1)
    assert request['request']['generation']=='2'*64 and request['request']['size']==1024
    return peer,response(request)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--ada',type=Path);parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args();assert os.getuid()==os.geteuid()==0
    passed=[]
    with tempfile.TemporaryDirectory(prefix='root-session-protocol-') as directory:
        path=Path(directory)/'socket';fd=os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC)
        client=Client(args.library)
        for name,edit in (
            ('wrong-stage',lambda r:r.update(stage='3'*32)),('published',lambda r:r.update(published=True)),
            ('wrong-deadline',lambda r:r.update(deadline_ms=r['deadline_ms']+1)),
            ('wrong-original-deadline',lambda r:r['observation'].update(original_deadline_ms=r['deadline_ms']+1)),
            ('wrong-mount',lambda r:r['observation']['root'].update(mount_id=70)),
            ('wrong-device',lambda r:r['observation']['root'].update(device_minor=2)),
            ('zero-inode',lambda r:r['observation']['root'].update(inode=0)),
            ('overflow-inode',lambda r:r['observation']['root'].update(inode=2**64)),
            ('extra-field',lambda r:r.update(extra=True)),('wrong-state',lambda r:r.update(state='extracted')),
            ('boolean-version',lambda r:r.update(version=True)),('string-inode',lambda r:r['observation']['root'].update(inode='123')),
        ):
            def handler(listener):
                peer,r=initial(listener);edit(r);peer.sendall(canonical(r));assert peer.recv(4096)==b'';peer.close()
            server=Peer(path,handler)
            assert client.start(path,fd)==2 and not client.held() and not client.handle.value
            server.finish();passed.append(name)
        for name in ('nul-tail','noncanonical','oversize','rights','truncated-rights','eof'):
            def handler(listener):
                peer,r=initial(listener);raw=canonical(r)
                if name=='eof':peer.close();return
                if name=='nul-tail':raw+=b'\0hidden'
                elif name=='noncanonical':raw=raw.rstrip()+b' \n'
                elif name=='oversize':raw+=b' '*5000
                controls=[]
                if name in ('rights','truncated-rights'):
                    controls=[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]*(1 if name=='rights' else 32)))]
                peer.sendmsg([raw],controls)
                assert peer.recv(4096)==b'';peer.close()
            server=Peer(path,handler);before=len(os.listdir('/proc/self/fd'))
            assert client.start(path,fd)==2 and not client.held()
            # Listener closes asynchronously; delivered rights must not remain.
            server.finish();assert len(os.listdir('/proc/self/fd'))<=before;passed.append(name)
        def unprivileged_reply(listener):
            peer,r=initial(listener)
            os.setgroups([]);os.setgid(65534);os.setuid(65534)
            peer.sendall(canonical(r));assert peer.recv(4096)==b'';peer.close()
        server=Peer(path,unprivileged_reply)
        assert client.start(path,fd)==2 and not client.held()
        server.finish();passed.append('reply-nonroot-credentials')
        def replaced_sender(listener):
            peer,r=initial(listener);peer.sendall(canonical(r));raw,count=receive(peer);assert count==2
            child=os.fork()
            if child==0:
                peer.sendall(canonical(r));os._exit(0)
            assert os.waitpid(child,0)[1]==0
            raw,count=receive(peer);assert not count and json.loads(raw)['operation']=='close';peer.close()
        server=Peer(path,replaced_sender);assert client.start(path,fd)==0
        assert client.observe(fd)==2 and not client.held() and client.close()==0
        server.finish();passed.append('reply-changed-process')
        def success(listener):
            peer,r=initial(listener);peer.sendall(canonical(r))
            raw,count=receive(peer);assert count==2 and json.loads(raw)['operation']=='observe'
            peer.sendall(canonical(r));raw,count=receive(peer);assert not count and json.loads(raw)['operation']=='close'
            peer.close()
        server=Peer(path,success)
        assert client.start(path,fd)==0 and client.inode.value==123 and client.held()
        assert client.start(path,fd)==4 and client.held()
        child=os.fork()
        if child==0:
            valid=not client.held() and client.observe(fd)==1
            client.discard();os._exit(0 if valid else 1)
        assert os.waitpid(child,0)[1]==0 and client.held()
        assert client.observe(fd)==0 and client.close()==0 and not client.held()
        os.fstat(fd);server.finish();passed.extend(['normal-observe-close','busy-handle','fork-copy-refused','borrowed-fd-preserved'])
        def changed(listener):
            peer,r=initial(listener);peer.sendall(canonical(r));raw,count=receive(peer);assert count==2
            r['observation']['root']['inode']+=1;peer.sendall(canonical(r))
            raw,count=receive(peer);assert not count and json.loads(raw)['operation']=='close';peer.close()
        server=Peer(path,changed);assert client.start(path,fd)==0
        assert client.observe(fd)==2 and not client.held() and client.handle.value
        assert client.start(path,fd)==4 and client.close()==0;server.finish();passed.append('changed-observation-retains-handle')
        def silent(listener):
            peer,r=initial(listener);peer.sendall(canonical(r));assert peer.recv(4096)==b'';peer.close()
        server=Peer(path,silent)
        assert client.start(path,fd,int(time.clock_gettime(time.CLOCK_BOOTTIME)*1000)+250)==0
        time.sleep(.3);assert not client.held() and client.observe(fd)==3 and client.handle.value
        assert client.close()==3;server.finish();passed.append('expiry-no-renewal')
        def delayed(listener):
            peer,_=initial(listener);assert peer.recv(4096)==b'';peer.close()
        server=Peer(path,delayed)
        assert client.start(path,fd,int(time.clock_gettime(time.CLOCK_BOOTTIME)*1000)+150)==2
        server.finish();passed.append('uncertain-initial-timeout')
        # A non-root process cannot create a supervisor connection at all.
        child=os.fork()
        if child==0:
            os.setgroups([]);os.setgid(65534);os.setuid(65534)
            os._exit(0 if client.start(path,fd)==1 else 1)
        assert os.waitpid(child,0)[1]==0;passed.append('nonroot-refused')
        if args.ada:
            def ada_peer(listener):
                success(listener)
                peer,r=initial(listener);peer.sendall(canonical(r));assert peer.recv(4096)==b'';peer.close()
            server=Peer(path,ada_peer)
            env=dict(os.environ,NIA_TEST_SESSION_SOCKET=str(path),NIA_TEST_SESSION_FD=str(fd))
            subprocess.run([str(args.ada)],env=env,pass_fds=(fd,),check=True,timeout=15)
            server.finish();passed.append('ada-live-ffi-and-finalization')
        os.close(fd)
    args.report.write_text(json.dumps(dict(result='pass',checks=passed,site_admission=False,physical_bank=False),indent=2)+'\n')
    print('PASS root session transport',len(passed))


if __name__=='__main__':main()
