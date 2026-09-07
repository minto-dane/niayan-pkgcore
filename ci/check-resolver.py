#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check an exact pinned independent resolver source copy before building."""
from pathlib import Path
import hashlib,json,re,stat,os
R=Path(__file__).resolve().parents[1]
def regular(p):
 # Check before open (FIFO), pin the descriptor (symlink), bound IO, and
 # compare before/after metadata. A developer checkout is not an authority.
 before=p.lstat()
 if not stat.S_ISREG(before.st_mode) or before.st_size>8*1024*1024:
  raise ValueError('not bounded regular source '+str(p))
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  opened=os.fstat(fd)
  identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
  if identity(before)!=identity(opened):raise ValueError('source changed during open')
  chunks=[];size=0
  while True:
   b=os.read(fd,min(65536,8*1024*1024+1-size))
   if not b:break
   chunks.append(b);size+=len(b)
   if size>8*1024*1024:raise ValueError('source grew beyond limit')
  if identity(opened)!=identity(os.fstat(fd)) or size!=opened.st_size:
   raise ValueError('source changed while reading')
  return b''.join(chunks)
 finally:os.close(fd)

def check():
 root=R/'vendor/resolver'
 for d in (R/'vendor',root,root/'src'):
  if d.is_symlink() or not d.is_dir():raise ValueError('linked/missing resolver source directory')
 lock=json.loads(regular(root/'source-lock.json'))
 if set(lock)!={'format','resolver_profile','shared_profile','files'} or type(lock['format']) is not int or lock['format']!=1:raise ValueError('lock schema')
 if not re.fullmatch('[0-9a-f]{64}',lock['resolver_profile']):raise ValueError('resolver profile hash')
 if lock['shared_profile']!=regular(R/'vendor/contracts/contract-profile.hex').decode().strip():raise ValueError('incompatible shared profile')
 names=set(lock['files'])
 if not names or any(not re.fullmatch(r'src/[a-z0-9_]+\.(ads|adb)',x) for x in names):raise ValueError('lock path')
 actual={'src/'+p.name for p in (root/'src').iterdir()}
 if names!=actual:raise ValueError('missing/extra resolver source')
 for name,h in lock['files'].items():
  if not re.fullmatch('[0-9a-f]{64}',h) or hashlib.sha256(regular(root/name)).hexdigest()!=h:raise ValueError('changed resolver source')
 print(json.dumps({'result':'source-lock-only-pass','resolver_profile':lock['resolver_profile']}))
if __name__=='__main__':
 try:check()
 except (ValueError,OSError) as e:raise SystemExit(str(e))
