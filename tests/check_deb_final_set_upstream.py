# SPDX-License-Identifier: MIT
# Qualification only: fixed upstream dpkg, --simulate, empty synthetic payloads,
# private status files under a disposable root, UID 1000, no maintainer scripts.
import argparse,json,os,re,subprocess,time
from pathlib import Path
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--media',type=Path,required=True)
parser.add_argument('--work',type=Path,required=True)
parser.add_argument('--expected-version',default='1.22.22')
args=parser.parse_args()
if os.geteuid()==0: raise SystemExit('Use an unprivileged disposable test environment')
base=args.work.absolute();base.mkdir(mode=0o700)
media=args.media.resolve()
version=subprocess.check_output(['dpkg','--version'],text=True).splitlines()[0]
assert ('version '+args.expected_version+' ') in version,version
matrix=json.loads((media/'cases.json').read_text());assert 0<len(matrix)<=4096
results=[];started=time.monotonic()
for case in matrix:
 assert re.fullmatch(r'case-[0-9]{4}',case['id'])
 assert all(re.fullmatch(r'[0-9a-f]{64}\.deb',image['filename']) for image in case['images'])
 case_dir=base/case['id'];case_dir.mkdir(mode=0o700,exist_ok=True)
 root=case_dir/'root';admin=root/'var/lib/dpkg';admin.mkdir(parents=True,exist_ok=True)
 for name in ['updates','info','triggers']: (admin/name).mkdir(exist_ok=True)
 (admin/'arch').write_text('\n'.join(case['enabled'])+'\n');(admin/'arch-native').write_text(case['native']+'\n')
 env={**os.environ,'TMPDIR':str(case_dir),'LC_ALL':'C','PATH':'/usr/sbin:/usr/bin:/sbin:/bin'}
 prefix=['dpkg','--root='+str(root),'--admindir='+str(admin),'--log='+str(case_dir/'dpkg.log'),'--force-not-root','--simulate']
 runs=[]
 for action in ['configure','unpack']:
  for i,pkg in enumerate(case['packages']):
   stanzas=[]
   for j,fields in enumerate(case['packages']):
    state='unpacked' if action=='configure' and j==i else 'installed'
    stanzas.append('\n'.join([*(k+': '+v for k,v in fields.items()),'Status: install ok '+state,'Maintainer: Fixture <fixture@example.invalid>','Description: endpoint fixture']))
   status='\n\n'.join(stanzas)+'\n';(admin/'status').write_text(status)
   target=(pkg['Package']+':'+pkg['Architecture']) if action=='configure' else str(media/case['images'][i]['filename'])
   cmd=prefix+['--'+action,target]
   run=subprocess.run(cmd,env=env,capture_output=True,text=True,timeout=20)
   assert (admin/'status').read_text()==status,'simulate wrote status'
   assert len(run.stdout)+len(run.stderr)<=32768,'unexpected unbounded output'
   runs.append(dict(action=action,target=target,returncode=run.returncode,stdout=run.stdout,stderr=run.stderr))
 actual=all(run['returncode']==0 for run in runs);expected=case['expected']=='No_Violation'
 row=dict(id=case['id'],name=case['name'],expected=expected,upstream=actual,matches=actual==expected,runs=runs)
 (case_dir/'result.json').write_text(json.dumps(row,indent=2)+'\n');results.append({k:v for k,v in row.items() if k!='runs'})
 if len(results)%50==0:print('checked',len(results),'mismatches',sum(not x['matches'] for x in results),flush=True)
report=dict(upstream=version,scope='independent per-target simulated configure and unpack from synthetic complete installed sets; no real phase schedule or scripts',cases=len(results),seconds=time.monotonic()-started,mismatches=[x for x in results if not x['matches']],results=results)
(base/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='results'}),flush=True)
raise SystemExit(bool(report['mismatches']))
