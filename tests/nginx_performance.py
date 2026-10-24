#!/usr/bin/env python3
"""Compare the real shared template on official Nginx and WAF, offline."""
import argparse
import gzip
import hashlib
import http.client
import json
import os
from pathlib import Path
import random
import re
import signal
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'waf/tests'))
from performance import cgroup, resources, run
sys.path.insert(0, str(ROOT / 'waf'))
import policy
import nginx_edit


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--official-image',required=True)
    p.add_argument('--waf-image',required=True)
    p.add_argument('--php-image',default='kjlion/php:fpm-alpine')
    p.add_argument('--baseline',type=Path,required=True)
    p.add_argument('--candidate',type=Path,default=ROOT/'nginx10.conf')
    p.add_argument('--work-dir',type=Path,required=True)
    p.add_argument('--seconds',type=int,default=8)
    p.add_argument('--concurrency',type=int,default=16)
    p.add_argument('--cpus',type=int,choices=[1,2],default=1)
    p.add_argument('--engines',default='official,waf-off,waf-on')
    p.add_argument('--variants',default='baseline,candidate')
    p.add_argument('--cases',default='small-http2,php-http2,static-tls,static-gzip,proxy-gzip,slow-static,slow-gzip')
    args=p.parse_args()
    engines=args.engines.split(',')
    variants=args.variants.split(',')
    selected=args.cases.split(',')
    allowed={'small-http2','php-http2','static-tls','static-gzip','proxy-gzip','slow-static','slow-gzip'}
    if not engines or len(engines)!=len(set(engines)) or set(engines)-{'official','waf-off','waf-on'} or not 4<=args.seconds<=30 or not 1<=args.concurrency<=32 or not variants or len(variants)!=len(set(variants)) or set(variants)-{'baseline','candidate'} or not selected or len(selected)!=len(set(selected)) or set(selected)-allowed:
        p.error('Invalid bounded test profile')
    work=args.work_dir.absolute()
    if work.exists() or len(str(work/'front.sock'))>103:p.error('Use a new short directory')
    work.mkdir(parents=True,mode=0o755);work.chmod(0o755)
    if shutil.disk_usage(work).free<1024*1048576:p.error('At least 1 GiB free disk is required')
    def interrupted(number,_):raise TimeoutError(f'Interrupted {number}')
    for number in (signal.SIGALRM,signal.SIGTERM,signal.SIGINT):signal.signal(number,interrupted)
    signal.alarm(1800)
    names={k:'nginx-perf-'+uuid.uuid4().hex[:9]+'-'+k for k in ('origin','php','front','client')}
    (work/'containers.json').write_text(json.dumps(names))
    owned=[];results=[];checks=[]
    identity=dict(images={k:json.loads(run('docker','image','inspect',v).stdout)[0] for k,v in [('official',args.official_image),('waf',args.waf_image),('php',args.php_image)]},
        sourceSHA256={str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in (args.baseline,args.candidate,ROOT/'waf/tests/performance_client.go',Path(__file__))},
        cpus=args.cpus,memoryMiB=512,sites=20,startedAt=time.time(),sampleIntervalSeconds=.1,
        boundaries='Isolated fixture origins and simulated CDN identity, no external network/public ports. Same template per image; not an Internet/CDN capacity guarantee.')
    (work/'identity.json').write_text(json.dumps(identity,indent=2))
    run('go','build','-trimpath','-o',str(work/'runner'),str(ROOT/'waf/tests/performance_client.go'),env=dict(os.environ,CGO_ENABLED='0',GOTOOLCHAIN='local'),timeout=120)
    run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(work/'key.pem'),'-out',str(work/'cert.pem'),'-days','1','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1')
    (work/'key.pem').chmod(0o600)
    alphabet=b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_'
    data=random.Random(119).randbytes(8*1024*1024).translate(bytes(alphabet[i%64] for i in range(256)))
    (work/'large.txt').write_bytes(data);(work/'asset.txt').write_bytes(b'A'*1024)
    (work/'index.php').write_text('<?php header("Content-Type: application/json"); echo json_encode(["fixture"=>true,"method"=>$_SERVER["REQUEST_METHOD"],"bytes"=>strlen(file_get_contents("php://input"))]);')
    (work/'fpm.conf').write_text('[global]\nerror_log=/tmp/fpm.log\n[fixture]\nuser=www-data\ngroup=www-data\nlisten=/test/php.sock\nlisten.mode=0666\npm=static\npm.max_children=2\ncatch_workers_output=yes\n')
    def start(key,image,cpu,memory,entry,rest,network='none',extra=()):
        name=names[key];owned.append(name)
        run('docker','run','-d','--pull=never','--name',name,'--network',network,'--read-only','--cpuset-cpus',cpu,'--memory',memory,'--memory-swap',memory,'--pids-limit=128',
            '--cap-drop=ALL','--cap-add=SETUID','--cap-add=SETGID','--cap-add=CHOWN','--security-opt=no-new-privileges',
            '--tmpfs','/tmp:rw,nosuid,size=64m','--tmpfs','/run:rw,nosuid,size=8m','--tmpfs','/var/cache/nginx:rw,nosuid,size=64m',
            '--mount',f'type=bind,src={work},dst=/test',*extra,'--entrypoint',entry,image,*rest)
    def remove(key):
        run('docker','rm','-f',names[key]);owned.remove(names[key])
    def ready(path):
        for _ in range(100):
            if path.exists():return
            time.sleep(.1)
        raise RuntimeError('Socket did not become ready: '+str(path))
    def request(path,headers=None,body=None):
        conn=http.client.HTTPConnection('fixture',timeout=30)
        def connect():
            conn.sock=socket.socket(socket.AF_UNIX);conn.sock.settimeout(30);conn.sock.connect(str(work/'front.sock'))
        conn.connect=connect
        conn.request('POST' if body is not None else 'GET',path,body,{'Host':'proxy0.example','CF-Connecting-IP':'198.18.10.1','User-Agent':'Nginx-performance-fixture/1.0',**(headers or {})})
        resp=conn.getresponse();answer=(resp.status,dict(resp.getheaders()),resp.read());conn.close();return answer
    try:
        start('origin',args.official_image,'3','256m','/test/runner',['-mode','backend','-socket','/test/backend.sock'])
        start('php',args.php_image,'3','256m','php-fpm',['-F','-y','/test/fpm.conf'])
        ready(work/'backend.sock');ready(work/'php.sock')
        for engine in engines:
            for variant in variants:
                source=args.baseline if variant=='baseline' else args.candidate
                if (work/'front.sock').exists():(work/'front.sock').unlink()
                cell_dir=work/(engine+'-'+variant);cell_dir.mkdir();(cell_dir/'logs').mkdir();conf=cell_dir/'conf.d';conf.mkdir();waf=conf/'waf';waf.mkdir()
                text=source.read_text();text,n=re.subn(r'(?m)^worker_processes\s+[^;]+;',f'worker_processes {args.cpus};',text);assert n==1
                if engine!='official':
                    config=json.loads((ROOT/'waf/example-policy.json').read_text());config.update(mode='on' if engine=='waf-on' else 'off',cdn='direct',sites={})
                    for name,value in policy.bundle_files(config,policy.networks(json.loads((ROOT/'waf/cloudflare-ips.json').read_text()))).items():(waf/name).write_text(value)
                    text=nginx_edit.patch_main(text,enabled=engine=='waf-on')
                (cell_dir/'nginx.conf').write_text(text)
                aliases=[prefix+str(i)+'.example' for prefix in ('proxy','direct') for i in range(10)]
                server='''server {
listen unix:/test/front.sock;
listen 127.0.0.1:18443 ssl;
server_name FIXTURE_HOST;
ssl_certificate /test/cert.pem; ssl_certificate_key /test/key.pem;
set_real_ip_from unix:; set_real_ip_from 127.0.0.1/32; real_ip_header CF-Connecting-IP;
root /test;
location = /large.txt { aio threads; }
location = /asset.txt { }
location = /index.php { include /etc/nginx/fastcgi_params; fastcgi_param SCRIPT_FILENAME /test/index.php; fastcgi_pass unix:/test/php.sock; }
location /api/ { proxy_http_version 1.1; proxy_set_header Connection ""; proxy_set_header Host $host; proxy_pass http://fixture_origin/; }
location /sse { proxy_buffering off; proxy_http_version 1.1; proxy_set_header Connection ""; proxy_pass http://fixture_origin; }
}
'''
                (conf/'fixture.conf').write_text('''map $http_upgrade $fixture_upgrade { default upgrade; '' ''; }
upstream fixture_origin { server unix:/test/backend.sock; keepalive 32; }
'''+''.join(server.replace('FIXTURE_HOST',host) for host in aliases))
                image=args.official_image if engine=='official' else args.waf_image
                start('front',image,'0' if args.cpus==1 else '0,1','512m','nginx',['-g','daemon off;'],extra=['--mount',f'type=bind,src={cell_dir/"nginx.conf"},dst=/etc/nginx/nginx.conf,readonly',
                    '--mount',f'type=bind,src={conf},dst=/etc/nginx/conf.d,readonly','--mount',f'type=bind,src={cell_dir/"logs"},dst=/var/log/nginx'])
                ready(work/'front.sock');run('docker','exec',names['front'],'nginx','-t')
                proofs={}
                for label,path,headers,body,status in [('small','/asset.txt',{},None,200),('range','/large.txt',{'Range':'bytes=0-255'},None,206),('large','/large.txt',{},None,200),
                    ('gzip','/large.txt',{'Accept-Encoding':'gzip'},None,200),('php','/index.php',{},None,200),
                    ('proxy-gzip','/api/large.txt',{'Accept-Encoding':'gzip'},None,200),('php-post','/index.php',{'Content-Type':'application/json'},b'{"name":"hello"}',200),('sse','/sse',{},None,200)]:
                    actual,head,content=request(path,headers,body)
                    assert actual==status,(engine,variant,label,actual)
                    if label=='range':assert content==data[:256]
                    if label=='small':assert content==b'A'*1024
                    if label=='large':assert content==data
                    if label in ('gzip','proxy-gzip'):assert head.get('Content-Encoding')=='gzip' and gzip.decompress(content)==data
                    if label.startswith('php'):assert json.loads(content)['fixture'] is True
                    if label=='sse':assert b'data: 19' in content
                    checks.append(dict(engine=engine,variant=variant,test=label,passed=True))
                    if body is None:proofs[(path,headers.get('Accept-Encoding',''))]=(len(content),hashlib.sha256(content).hexdigest())
                start('client',args.official_image,'2','256m','/bin/sleep',['1800'],network='container:'+names['front'])
                cg=cgroup(names['front']);client_cg=cgroup(names['client'])
                cases=[('small-http2','/asset.txt','',0,8,100,False),('php-http2','/index.php','',0,8,50,False),
                       ('static-tls','/large.txt','',0,8,0,True),('static-gzip','/large.txt','gzip',0,8,0,False),
                       ('proxy-gzip','/api/large.txt','gzip',0,8,0,False),
                       ('slow-static','/large.txt','',1024,args.concurrency,0,True),('slow-gzip','/large.txt','gzip',1024,args.concurrency,0,False)]
                for label,path,encoding,read_kib,concurrency,rate,http1 in cases:
                    if label not in selected:continue
                    before=resources(cg);aux=resources(client_cg);samples=[];stop=threading.Event();fault=[]
                    def sample():
                        while not stop.wait(.1):
                            value=resources(cg);samples.append(value)
                            if value['events'].get('oom_kill',0)>before['events'].get('oom_kill',0) or sum(f.stat().st_size for f in (cell_dir/'logs').glob('*') if f.is_file())>128*1048576:
                                fault.append('resource-budget');subprocess.run(['docker','kill',names['client']],capture_output=True,timeout=10);return
                    thread=threading.Thread(target=sample,daemon=True);thread.start();at=time.monotonic()
                    try:
                        result=run('docker','exec','-e','GOMAXPROCS=1',names['client'],'/test/runner','-target','tls','-workload','static','-path',path,'-encoding',encoding,
                            '-read-kib',str(read_kib),'-http1='+str(http1).lower(),'-timeout','45s','-duration',str(args.seconds)+'s','-concurrency',str(concurrency),'-rate',str(rate),'-hosts','10',timeout=args.seconds+50)
                    finally:stop.set();thread.join(2)
                    elapsed=time.monotonic()-at;after=resources(cg);r=json.loads(result.stdout)
                    final_logs=sum(f.stat().st_size for f in (cell_dir/'logs').glob('*') if f.is_file())
                    if after['events'].get('oom_kill',0)>before['events'].get('oom_kill',0) or final_logs>128*1048576 or shutil.disk_usage(work).free<1024*1048576:fault.append('terminal-resource-budget')
                    r.update(engine=engine,variant=variant,case=label,path=path,readKiBPerSecond=read_kib,http1=http1,serverCpuPercent=(after['cpu']['usage_usec']-before['cpu']['usage_usec'])/elapsed/10000,
                        anonymousPeakMiB=max(x['memoryStat']['anon'] for x in [before,after,*samples])/1048576,memoryPeakMiB=max(x['memory'] for x in [before,after,*samples])/1048576,
                        memoryEndMiB=after['memory']/1048576,clientCpuPercent=(resources(client_cg)['cpu']['usage_usec']-aux['cpu']['usage_usec'])/elapsed/10000,
                        expectedRps=r['expectedResponses']/r['elapsedSeconds'],wireMiBPerSecond=r['responseBytes']/r['elapsedSeconds']/1048576)
                    r['passed']=not fault and not r['networkErrors'] and not r['skipped'] and r['requests']>0 and r['codes']=={'200':r['requests']}
                    r['passed']=r['passed'] and r['protocols']=={'HTTP/1.1' if http1 else 'HTTP/2.0':r['requests']}
                    if encoding:r['passed']=r['passed'] and r['encodings']=={encoding:r['requests']}
                    expected_bytes,body_sha=proofs[(path,encoding)]
                    r['expectedBodyBytes']=expected_bytes;r['preflightBodySHA256']=body_sha
                    r['resourceFaults']=fault;r['finalLogBytes']=final_logs;r['oomKillDelta']=after['events'].get('oom_kill',0)-before['events'].get('oom_kill',0)
                    r['passed']=r['passed'] and r['responseBytes']==expected_bytes*r['requests']
                    post_status,post_headers,post_body=request(path,{'Accept-Encoding':encoding} if encoding else {})
                    r['passed']=r['passed'] and post_status==200 and hashlib.sha256(post_body).hexdigest()==body_sha
                    results.append(r)
                    with (work/'results.jsonl').open('a') as f:f.write(json.dumps(r)+'\n')
                    print(json.dumps({k:r[k] for k in ['engine','variant','case','expectedRps','wireMiBPerSecond','anonymousPeakMiB','serverCpuPercent','passed']}),flush=True)
                    if not r['passed']:raise AssertionError(r)
                remove('client');remove('front')
        (work/'results.json').write_text(json.dumps(dict(identity=identity,checks=checks,results=results,complete=True),indent=2))
    finally:
        signal.alarm(0)
        for name in reversed(owned):
            log=subprocess.run(['docker','logs','--tail','100',name],capture_output=True,timeout=15);(work/(name+'.log')).write_bytes(log.stdout+log.stderr)
            subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=30)


if __name__=='__main__':main()
