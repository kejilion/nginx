#!/usr/bin/env python3
"""Public application request shapes behind a networkless WAF and inert backend.

Contracts checked against KPanel 4206ce3a (v1.28.0-rc.7). These tests never
execute Docker actions, terminal commands or production application requests.
Application authentication is checked separately by kpanel_profile.py.
"""
import argparse
import base64
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import policy
import nginx_edit
from integration import Backend, UnixHTTP


class ApplicationBackend(Backend):
    def do_GET(self):
        if self.path.split('?',1)[0]!='/cache-fixture':return super().do_GET()
        identity=self.headers.get('Cookie') or self.headers.get('Authorization')
        data=(identity or 'anonymous').encode()
        self.send_response(200 if identity else 404)
        self.send_header('Content-Length',str(len(data)));self.send_header('Content-Type','text/plain')
        self.send_header('Connection','close');self.end_headers();self.wfile.write(data);self.close_connection=True


def cases():
    result=[]
    def add(label,method,path,body=None,expected=200,headers=None,host='panel.example',expected_body=None,expected_cache=None):
        result.append(dict(label=label,method=method,path=path,body=body,expected=expected,headers=headers or {},host=host,expected_body=expected_body,expected_cache=expected_cache))
    for label,headers,status,body,cache in [
        ('anonymous-miss',{},404,b'anonymous','MISS'),('anonymous-hit',{},404,b'anonymous','HIT'),
        ('cookie-a',{'Cookie':'session=a'},200,b'session=a','BYPASS'),
        ('cookie-b',{'Cookie':'session=b'},200,b'session=b','BYPASS'),
        ('authorization',{'Authorization':'Bearer fixture'},200,b'Bearer fixture','BYPASS'),
        ('anonymous-remains-anonymous',{},404,b'anonymous','HIT')]:
        add('auth-cache-'+label,'GET','/cache-fixture',expected=status,headers=headers,expected_body=body,expected_cache=cache)
    for label,host,path,headers,cache in [
        ('http-inherited','panel.example','/cache-fixture?nocache=1',{},'BYPASS'),
        ('server-own','servercache.example','/cache-fixture',{'X-Skip-Cache':'1'},'BYPASS'),
        ('server-replaces-http','servercache.example','/cache-fixture?nocache=1',{},'MISS'),
        ('location-own','locationcache.example','/cache-fixture',{'X-Location-Cache':'1'},'BYPASS'),
        ('location-replaces-server','locationcache.example','/cache-fixture?nocache=1',{},'MISS')]:
        add('cache-predicate-'+label,'GET',path,expected=404,headers=headers,host=host,expected_body=b'anonymous',expected_cache=cache)
    for suffix in ['summary','environment','containers','compose-projects','images','networks','volumes','backups','jobs']:
        add('docker-'+suffix,'GET','/api/v1/docker/'+suffix)
    for method in ['GET','HEAD']:
        for path in ['/desktop-icons/docker-kpanel-flat-v1.webp','/desktop-icons/modern/docker-v1.svg','/assets/docker-compose-client.js']:
            add('bundled-static-'+method+path,method,path)
    for path in ['/desktop-icons/docker-kpanel-flat-v1.webp?q=%3Cscript%3Ealert(1)%3C/script%3E','/desktop-icons/docker-;id.webp','/desktop-icons/docker-../icon.webp','/desktop-icons/docker-kpanel-flat-v1.php']:
        add('asset-must-not-borrow-exclusion-'+path,'GET',path,expected=403)
    add('asset-exclusion-is-read-only','POST','/desktop-icons/docker-kpanel-flat-v1.webp',{},403)
    add('asset-exclusion-is-profile-scoped','GET','/desktop-icons/docker-kpanel-flat-v1.webp',expected=403,host='other.example')
    for suffix in ['logs','stats','run-command']:
        add('docker-container-'+suffix,'GET','/api/v1/docker/containers/'+'a'*64+'/'+suffix)
    for suffix in ['start','stop','restart','pause','unpause','remove','check_update']:
        add('docker-action-'+suffix,'POST','/api/v1/docker/containers/'+'a'*64+'/'+suffix,{'expectedResourceVersion':'fixture'})
    add('docker-exec','POST','/api/v1/docker/containers/'+'a'*64+'/exec',{'command':'cat /etc/passwd; printf "<script>fixture</script>"','resourceVersion':'fixture'})
    add('docker-compose','POST','/api/v1/docker/tasks',{'action':'compose_deploy','compose':'services:\n  app:\n    image: alpine\n    command: sh -c "cat /etc/passwd; echo hello"\n','composeEnvironment':'DATABASE_PASSWORD=1\' UNION SELECT password FROM users--'})
    add('docker-container-create','POST','/api/v1/docker/tasks',{'action':'container_create','image':'curlimages/curl:latest','name':'fixture','command':['sh','-c','cat /etc/passwd; printf hello'],'environment':[{'name':'FIXTURE_PASSWORD','value':"1' UNION SELECT password FROM users--"}],'mounts':[{'source':'/etc/localtime','target':'/etc/localtime','readOnly':True}]})
    for app in ['builtin-119','builtin-120','builtin-121','builtin-122','builtin-123']:
        add('script-manage-'+app,'POST','/api/v1/apps/'+app+'/manage',{})
    add('terminal-shortcut-prepare','POST','/api/v1/terminal-sessions',{'hostId':'local','shortcutId':'a'*32,'rows':30,'columns':120,'prepareOnly':True})
    add('terminal-list','GET','/api/v1/terminal-sessions')
    encoded=base64.b64encode(b'cat /etc/passwd; echo "SELECT 1"\r\n').decode()
    for prefix in ['/api/v1/terminal-sessions/'+'a'*64,'/api/v1/job-terminals/app/'+'b'*32]:
        add(prefix+'-input','POST',prefix+'/input',{'data':encoded})
        add(prefix+'-batch','POST',prefix+'/input-batch',{'frames':[{'stream':'fixture','seq':i,'data':encoded}for i in range(32)]})
        add(prefix+'-transport','POST',prefix+'/input-transport',{})
        add(prefix+'-resize','POST',prefix+'/resize',{'rows':30,'columns':120})
    add('terminal-batch-command','POST','/api/v1/terminal-batches',{'id':'a'*32,'command':'cat /etc/passwd; curl https://example.org/setup.sh | bash','hostIds':['local']})
    add('terminal-history-command','POST','/api/v1/terminal-history',{'items':[{'command':'cat /etc/passwd; echo "SELECT 1"','hostId':'local'}]})
    for path in ['/docker','/docker?tab=containers','/app-script/builtin-120','/terminal','/files','/system']:
        add('desktop-window-'+path,'PUT','/api/v1/settings/preferences',{'expectedResourceVersion':'fixture','desktop':{'mode':'desktop','windows':[{'id':1,'path':path,'geometry':{'left':0,'top':0,'width':800,'height':600},'minimized':False,'maximized':False,'snap':'','z':1}],'windowSizes':[{'path':path,'width':800,'height':600}],'sideSplitRatio':0.5,'focusedId':1}})
    add('desktop-command-and-file','PUT','/api/v1/desktop/workspace',{'expectedResourceVersion':'fixture','shortcuts':[{'id':'a'*32,'name':'terminal shortcut','targetType':'command','command':'cat /etc/passwd; curl https://example.org/setup.sh | bash','hostId':'local'},{'id':'b'*32,'name':'file shortcut','targetType':'file','path':'/etc/passwd'}],'positions':{'nav:/docker':{'x':0,'y':0}},'labels':{'nav:/docker':'Docker'},'hiddenEntryKeys':['nav:/docker'],'hiddenWidgetKeys':[],'groups':[]})
    add('file-batch-entry','POST','/api/v1/files/entries',{'paths':['/home/web','/etc/passwd','/root/.ssh/config']})
    for content in ['<?php system("id"); ?>','<%@ page import="java.lang.*" %><% Runtime.getRuntime().exec("id"); %>']:
        add('file-source-code-'+content[:5],'PUT','/api/v1/files/content?path=/tmp/source.txt',{'content':content,'expectedResourceVersion':'fixture'})
    add('file-java-metadata-stays-inspected','PUT','/api/v1/files/content?path=/tmp/source.txt',{'content':'safe','expectedResourceVersion':'java.lang.Runtime.getRuntime().exec("id")'},403)
    for suffix in ['','/entry','/content','/archive']:
        add('file-query-'+suffix,'GET','/api/v1/files'+suffix+'?path='+urllib.parse.quote('/etc/passwd'))
    for suffix in ['terminal/relay','files/relay','terminal/input','terminal/open']:
        add('federation-opaque-'+suffix,'POST','/api/v2/federation/'+suffix,{'protocol':'fixture','controllerId':'a'*32,'targetId':'b'*32,'timestamp':12345,'requestId':'c'*32,'message':base64.b64encode(bytes(range(256))*2).decode()})
    for path in ['/api/v1/health','/api/v1/apps/builtin-120/manage','/api/v1/docker/summary']:
        add('query-still-protected-'+path,'POST'if path.endswith('/manage')else'GET',path+'?q=1%27%20UNION%20SELECT%20password%20FROM%20users--',{}if path.endswith('/manage')else None,403)
    add('other-site-stays-protected','PUT','/api/v1/desktop/workspace',{'shortcuts':[{'command':'cat /etc/passwd'}]},403,host='other.example')
    add('wrong-method-stays-protected','POST','/api/v1/settings/preferences',{'desktop':{'windows':[{'path':'/app-script/builtin-120'}]}},403)
    add('invalid-json-stays-rejected','POST','/api/v1/terminal-sessions',b'{broken',400)
    add('override-keeps-strict-targets','POST','/api/v1/terminal-batches',{'command':'cat /etc/passwd'},403,{'X-HTTP-Method-Override':'DELETE'})
    for path in ['/api/v1/desktop/workspace','/api/v1/docker/tasks']:
        add('metadata-still-inspected-'+path,'PUT'if path.endswith('workspace')else'POST',path,{'name':'<script>alert(1)</script>'},403)
    for path,field in [('/api/v1/terminal-batches','command'),('/api/v2/federation/terminal/relay','message')]:
        add('query-cannot-borrow-json-selector-'+field,'POST',path+'?json.'+field+'=1%27%20UNION%20SELECT%20password%20FROM%20users--',{'command':'echo hello','message':'fixture'},403)
    keys=[f'nav:/app-script/builtin-{i}'for i in range(512)]
    add('desktop-workspace-schema-capacity','PUT','/api/v1/desktop/workspace',{'expectedResourceVersion':'fixture','positions':{key:{'x':1,'y':2}for key in keys},'hiddenEntryKeys':keys,'labels':{key:'Label'for key in keys},'shortcuts':[],'groups':[],'hiddenWidgetKeys':[]})
    add('workspace-64-code-shortcuts','PUT','/api/v1/desktop/workspace',{'shortcuts':[{'id':str(i),'command':'cat /etc/passwd; curl https://example.org/setup.sh | bash'}for i in range(64)]})
    for host,path,method,limit in [('generic.example','/api/items','POST',2048),('panel.example','/api/v1/settings/preferences','PUT',2048),('panel.example','/api/v1/desktop/workspace','PUT',8192)]:
        add('argument-budget-below-'+host+path,method,path,{str(i):'ok'for i in range(limit-1)},host=host)
        for count in [limit,limit+1]:
            body={str(i):'ok'for i in range(count)};body['tail']='<script>alert(1)</script>'
            add('argument-budget-reject-'+host+path+'-'+str(count),method,path,body,400,host=host)
    for path in ['/category/docker-;cat%20/etc/passwd/','/category/docker-%252e%252e/','/wp-admin/docker-compose']:
        add('wordpress-noncanonical-path-not-exempt-'+path,'GET',path,expected=403,host='cms.example')
    add('forum-title-still-inspected','POST','/api/discussions',{'data':{'attributes':{'content':'cat /etc/passwd','title':'<script>alert(1)</script>'}}},403,host='forum.example')
    add('forum-json-query-not-exempt','POST','/api/posts?json.data.attributes.content=%3Cscript%3Ealert(1)%3C/script%3E',{'data':{'attributes':{'content':'safe'}}},403,host='forum.example')
    for method,path,content_type in [('POST','/api/v1/files/upload?path=/tmp&name=fixture.bin','application/octet-stream'),('PUT','/api/v1/files/transfer/sessions?id=fixture','application/octet-stream'),('PUT','/api/v1/desktop/shortcuts/'+'a'*32+'/icon','image/png')]:
        add('opaque-upload-'+path,method,path,b'\x89PNG\r\n\x1a\nfixture <script>alert(1)</script> java.lang.Runtime.getRuntime().exec("id")',headers={'Content-Type':content_type})
        add('upload-query-still-inspected-'+path,method,path+'&q=%3Cscript%3Ealert(1)%3C/script%3E'if'?'in path else path+'?q=%3Cscript%3Ealert(1)%3C/script%3E',b'fixture',403,headers={'Content-Type':content_type})
    add('binary-legacy-upload-over-8MiB','POST','/api/v1/files/upload?path=/tmp&name=fixture.bin',b'X'*(9*1024*1024),headers={'Content-Type':'application/octet-stream'})
    add('binary-upload-filesystem-path','POST','/api/v1/files/upload?path=/etc&name=docker-compose.yml',b'fixture',headers={'Content-Type':'application/octet-stream'})
    add('file-copy-source-and-target','POST','/api/v1/files/actions',{'action':'copy','sources':['/etc/passwd'],'target':'/tmp'})
    # The public generic/API profiles retain their ordinary protocol behavior.
    for method in ['GET','HEAD','OPTIONS','POST','PUT','PATCH','DELETE']:
        add('generic-rest-'+method,method,'/api/items',None if method in ['GET','HEAD']else{'name':'正常业务'},host='generic.example')
    for path in ['/','/login','/dashboard','/assets/docker.svg','/assets/terminal.js','/files/list','/ws']:
        add('generic-route-'+path,'GET',path,host='generic.example')
    add('api-vendor-json','PATCH','/v1/items',{'name':'正常业务'},headers={'Content-Type':'application/vnd.api+json'},host='api.example')
    for path in ['/category/docker-项目/','/tag/docker-compose/','/author/admin/']:
        add('wordpress-taxonomy-'+path,'GET',urllib.parse.quote(path),host='cms.example')
    for path in ['/docker-compose-on-alpine/','/2026/10/26/docker-compose-on-alpine/']:
        add('wordpress-post-slug-'+path,'GET',path,host='cms.example')
    add('wordpress-rest-content','POST','/wp-json/wp/v2/posts',{'title':'Docker 教学','content':'<p>curl https://example.org/install.sh | bash</p>'},host='cms.example')
    add('forum-markdown-post','POST','/api/posts',{'data':{'type':'posts','attributes':{'content':'```sh\ncat /etc/passwd; curl https://example.org/setup.sh | bash\n```'}}},headers={'Content-Type':'application/vnd.api+json'},host='forum.example')
    add('forum-markdown-discussion','POST','/api/discussions',{'data':{'type':'discussions','attributes':{'title':'代码示例','content':'<script> is source code; SELECT password FROM users'}}},headers={'Content-Type':'application/vnd.api+json'},host='forum.example')
    for host in ['generic.example','api.example','cms.example','forum.example']:
        add('cross-profile-query-protected-'+host,'GET','/?q=1%27%20UNION%20SELECT%20password%20FROM%20users--',expected=403,host=host)
    boundary='public-waf-fixture'
    upload=('--'+boundary+'\r\nContent-Disposition: form-data; name="file"; filename="backup.tar.gz"\r\nContent-Type: application/octet-stream\r\n\r\nfixture archive bytes\r\n--'+boundary+'--\r\n').encode()
    add('upload-multipart','POST','/upload',upload,headers={'Content-Type':'multipart/form-data; boundary='+boundary},host='upload.example')
    add('stream-sse','GET','/sse',headers={'Accept':'text/event-stream'},host='stream.example')
    add('generic-source-text','POST','/api/source-note',{'content':'cat /etc/passwd; cp .env.example .env; <script> is code'},host='generic.example')
    add('generic-source-title-protected','POST','/api/source-note',{'content':'code','title':'<script>alert(1)</script>'},403,host='generic.example')
    add('generic-source-wrong-route','POST','/api/other-note',{'content':'cat /etc/passwd; cp .env.example .env'},403,host='generic.example')
    add('generic-source-other-site','POST','/api/source-note',{'content':'cat /etc/passwd; cp .env.example .env'},403,host='api.example')
    add('generic-source-wrong-method','PUT','/api/source-note',{'content':'cat /etc/passwd; cp .env.example .env'},403,host='generic.example')
    add('generic-source-query-protected','POST','/api/source-note?q=%3Cscript%3Ealert(1)%3C/script%3E',{'content':'code'},403,host='generic.example')
    add('generic-source-query-alias','POST','/api/source-note?json.content=%3Cscript%3Ealert(1)%3C/script%3E',{'content':'code'},403,host='generic.example')
    add('generic-source-query-method-override','POST','/api/source-note?_method=DELETE',{'content':'cat /etc/passwd; cp .env.example .env'},403,host='generic.example')
    add('generic-source-body-method-override','POST','/api/source-note',{'_method':'DELETE','content':'cat /etc/passwd; cp .env.example .env'},403,host='generic.example')
    add('generic-source-override','POST','/api/source-note',{'content':'cat /etc/passwd; cp .env.example .env'},403,headers={'X-HTTP-Method-Override':'PATCH'},host='generic.example')
    add('generic-source-duplicate-type','POST','/api/source-note',{'content':'cat /etc/passwd; cp .env.example .env'},403,headers={'Content-Type':'application/json','content-type':'text/plain'},host='generic.example')
    add('generic-source-duplicate-field','POST','/api/source-note',b'{"content":"safe","content":"cat /etc/passwd; cp .env.example .env"}',403,headers={'Content-Type':'application/json'},host='generic.example')
    add('generic-file-resource','GET','/desktop-icons/xp/docker-v1.svg',host='static.example')
    add('generic-file-resource-head','HEAD','/desktop-icons/xp/docker-v1.svg',host='static.example')
    add('generic-file-query-protected','GET','/desktop-icons/xp/docker-v1.svg?q=%3Cscript%3Ealert(1)%3C/script%3E',expected=403,host='static.example')
    add('generic-proxy-not-exempt','GET','/desktop-icons/xp/docker-v1.svg',expected=403,host='generic.example')
    add('generic-file-post-not-exempt','POST','/desktop-icons/xp/docker-v1.svg',expected=403,host='static.example')
    add('generic-file-encoding-not-exempt','GET','/desktop-icons/xp/%64ocker-v1.svg',expected=403,host='static.example')
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image',required=True);parser.add_argument('--work-dir',type=Path,required=True);parser.add_argument('--observe',action='store_true');args=parser.parse_args()
    work=args.work_dir.absolute();work.mkdir(mode=0o755)
    bundle=Path(__file__).resolve().parents[1];generated=work/'waf';generated.mkdir();logs=work/'logs';logs.mkdir()
    profiles={'panel.example':'kpanel','servercache.example':'kpanel','locationcache.example':'kpanel','generic.example':'generic','api.example':'api','cms.example':'wordpress','forum.example':'flarum','upload.example':'upload','stream.example':'streaming'}
    config=json.loads((bundle/'example-policy.json').read_text());config.update(mode='on',cdn='direct',sites={name:{'profile':profile}for name,profile in profiles.items()})
    config['sites']['generic.example']['sourceText']=[{'method':'POST','path':'/api/source-note','fields':['content']}]
    # A fresh static site has no explicit policy/profile entry.
    assets=work/'desktop-icons/xp';assets.mkdir(parents=True);(assets/'docker-v1.svg').write_text('<svg/>')
    cf=policy.networks(json.loads((bundle/'cloudflare-ips.json').read_text()))
    def server(host):
        own='proxy_cache_bypass $http_x_skip_cache; proxy_no_cache $http_x_skip_cache;' if host=='servercache.example' else ''
        location='proxy_cache_bypass $http_x_location_cache; proxy_no_cache $http_x_location_cache;' if host=='locationcache.example' else ''
        return 'server { listen unix:/test/front.sock; server_name '+host+'; '+own+' location = /cache-fixture { '+location+' proxy_pass http://fixture; proxy_cache fixture; proxy_cache_valid 200 404 10m; proxy_cache_key "$host$request_uri"; add_header X-Fixture-Cache $upstream_cache_status always; } location / { proxy_pass http://fixture; proxy_http_version 1.1; proxy_set_header Connection close; } }'
    raw_servers='\n'.join(server(host)for host in [*profiles,'other.example'])
    raw_servers+='server { listen unix:/test/front.sock; server_name static.example; root /var/www/html/fixture; location / { try_files $uri =404; } }'
    inherited='proxy_cache_bypass $arg_nocache; proxy_no_cache $arg_nocache;'
    controls=nginx_edit.cache_inheritance('# configuration file /etc/nginx/nginx.conf:\nhttp { '+inherited+raw_servers+' }')
    resources=nginx_edit.static_resource_controls('# configuration file /etc/nginx/nginx.conf:\nhttp { '+inherited+raw_servers+' }')
    assert resources['static.example']=='file-only' and resources['generic.example']!='file-only'
    for name,text in policy.bundle_files(config,cf,cache_controls=controls,resource_controls=resources).items():(generated/name).write_text(text)
    (generated/'blocked.map').write_text(policy.render_bans({},int(time.time())))
    backend=UnixHTTP(str(work/'backend.sock'),ApplicationBackend);os.chmod(work/'backend.sock',0o666)
    threading.Thread(target=backend.serve_forever,daemon=True).start()
    servers=nginx_edit.patch_site(raw_servers,config)
    (work/'nginx.conf').write_text('load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;\npid /run/nginx.pid;\nerror_log /var/log/nginx/error.log error;\nworker_processes 1;\nevents { worker_connections 128; }\nhttp { proxy_cache_path /var/cache/nginx/fixture levels=1:2 keys_zone=fixture:1m; client_max_body_size 16m; modsecurity on; include /etc/nginx/conf.d/waf/http.conf; upstream fixture {server unix:/test/backend.sock;}\n'+inherited+servers+'\n}\n')
    name='waf-kpanel-contract-'+uuid.uuid4().hex[:8];results=[]
    def run(cmd):return subprocess.run(cmd,capture_output=True,check=True,timeout=60)
    try:
        run(['docker','run','-d','--pull=never','--name',name,'--network=none','--read-only','--memory=768m','--cpus=1','--pids-limit=64','--tmpfs','/tmp:rw,nosuid,size=64m','--tmpfs','/run:rw,nosuid,size=8m','--tmpfs','/var/cache/nginx:rw,nosuid,size=16m','--mount','type=bind,src='+str(work)+',dst=/test','--mount','type=bind,src='+str(logs)+',dst=/var/log/nginx','--mount','type=bind,src='+str(generated)+',dst=/etc/nginx/conf.d/waf,readonly','--mount','type=bind,src='+str(work/'nginx.conf')+',dst=/etc/nginx/nginx.conf,readonly','--mount','type=bind,src='+str(work)+',dst=/var/www/html/fixture,readonly','--entrypoint','nginx',args.image,'-g','daemon off;'])
        for _ in range(100):
            if(work/'front.sock').exists():break
            time.sleep(.1)
        run(['docker','exec',name,'nginx','-t'])
        for item in cases():
            c=http.client.HTTPConnection('localhost',timeout=15)
            def connect():
                c.sock=socket.socket(socket.AF_UNIX);c.sock.settimeout(15);c.sock.connect(str(work/'front.sock'))
            c.connect=connect
            body=item['body'];headers={'Host':item['host'],'Connection':'close',**item['headers']}
            if body is not None:
                if not isinstance(body,bytes):body=json.dumps(body).encode()
                headers.setdefault('Content-Type','application/json')
            started=time.monotonic()
            c.request(item['method'],item['path'],body,headers);r=c.getresponse();payload=r.read();status=r.status;cache=r.getheader('X-Fixture-Cache');c.close()
            passed=status==item['expected'] and (item['expected_body'] is None or payload==item['expected_body']) and (item['expected_cache'] is None or cache==item['expected_cache'])
            results.append({'test':item['label'],'status':status,'expected':item['expected'],'passed':passed,'cache':cache,'elapsed_ms':round((time.monotonic()-started)*1000,2)})
        failures=[r for r in results if not r['passed']]
        print(json.dumps({'cases':len(results),'passed':len(results)-len(failures),'failures':failures,'workspace':str(work)}),flush=True)
        if failures and not args.observe:raise AssertionError('KPanel contract regression failed')
    finally:
        (work/'results.json').write_text(json.dumps(results,indent=2))
        log=subprocess.run(['docker','logs',name],capture_output=True);(work/'container.log').write_bytes(log.stdout+log.stderr)
        subprocess.run(['docker','rm','-f',name],capture_output=True);backend.shutdown();backend.server_close()


if __name__=='__main__':main()
