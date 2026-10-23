#!/usr/bin/env python3
"""Validate migration, idempotence and exact rollback on a networkless pilot clone."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import configure as manage
import policy


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',type=Path,default=Path('/home/web'))
    parser.add_argument('--work-dir',type=Path,required=True)
    parser.add_argument('--modsec-dir',type=Path,required=True)
    parser.add_argument('--image',required=True)
    args=parser.parse_args()
    work=args.work_dir.absolute()
    work.mkdir(parents=True)
    (work/'conf.d').mkdir()
    if (args.source/'conf.d/csp').is_dir():
        shutil.copytree(args.source/'conf.d/csp',work/'conf.d/csp')
    if (args.source/'conf.d/waf').is_dir():
        shutil.copytree(args.source/'conf.d/waf',work/'conf.d/waf',ignore=shutil.ignore_patterns('__pycache__'))
    (work/'log/nginx').mkdir(parents=True)
    originals={}
    for source in [args.source/'nginx.conf',*sorted((args.source/'conf.d').glob('*.conf'))]:
        relative=source.relative_to(args.source)
        shutil.copyfile(source,work/relative)
        originals[str(relative)]=hashlib.sha256(source.read_bytes()).hexdigest()
    name='waf-pilot-config-'+uuid.uuid4().hex[:8]
    config=json.loads((Path(__file__).resolve().parents[1]/'example-policy.json').read_text())
    config.update(container=name,mode='detect',cdn='mixed',sites={
        n:{'profile':'wordpress'} for n in ['app.kejilion.pro','art.kejilion.pro','blog.kejilion.pro']})
    argslist=['docker','run','-d','--name',name,'--pull=never','--network=none','--read-only',
              '--memory=1g','--cpus=1','--pids-limit=128',
              '--tmpfs','/tmp:rw,nosuid,size=64m','--tmpfs','/run:rw,nosuid,size=8m',
              '--tmpfs','/var/cache/nginx:rw,nosuid,size=128m']
    mounts=[(work/'nginx.conf','/etc/nginx/nginx.conf'),(work/'conf.d','/etc/nginx/conf.d'),
            (work/'log/nginx','/var/log/nginx'),(args.source/'certs','/etc/nginx/certs'),
            (args.source/'html','/var/www/html'),
            (args.source/'stream.d','/etc/nginx/stream.d'),(args.modsec_dir,'/etc/nginx/modsec')]
    for source,target in mounts:
        argslist+=['--mount','type=bind,src='+str(source)+',dst='+target+('' if target=='/var/log/nginx' else ',readonly')]
    argslist+=['--entrypoint','nginx',args.image,'-g','daemon off;']
    results=[]
    try:
        manage.execute(*argslist)
        time.sleep(1)
        if manage.execute('docker','inspect','-f','{{.State.Running}}',name).strip()!='true':
            raise RuntimeError(manage.execute('docker','logs',name)[-2000:])
        manage.execute('docker','exec',name,'nginx','-t')
        applied=manage.apply(work,config)
        results.append({'test':'all-pilot-configurations-migrate','passed':True,'sites':len(applied['sites'])})
        changes,_=manage.make_plan(work,config)
        differences=[str(p) for p,data in changes.items() if p.read_bytes()!=data]
        assert not differences,differences
        results.append({'test':'repeat-plan-is-idempotent','passed':True})
        manage.restore(work,Path(applied['backup']))
        manage.execute('docker','exec',name,'nginx','-t')
        manage.execute('docker','exec',name,'nginx','-s','reload')
        for relative,digest in originals.items():
            assert hashlib.sha256((work/relative).read_bytes()).hexdigest()==digest,relative
        results.append({'test':'exact-pilot-config-rollback','passed':True})
        print(json.dumps(results))
    finally:
        (work/'results.json').write_text(json.dumps(results,indent=2))
        log=subprocess.run(['docker','logs',name],capture_output=True)
        (work/'container.log').write_bytes(log.stdout+log.stderr)
        subprocess.run(['docker','rm','-f',name],capture_output=True)


if __name__=='__main__':main()
