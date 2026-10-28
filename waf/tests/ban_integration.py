#!/usr/bin/env python3
"""Real Fail2Ban/Nginx integration in a disposable networkless container.

Image: kjlion/nginx:alpine. Fail2Ban is extracted to a private directory, never
installed as a host service. A private crontab shim isolates schedule writes.
Never run against production; all HTTP goes through a private Unix socket.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import policy


def run(*args):
    result=subprocess.run(args,capture_output=True,text=True,timeout=120)
    if result.returncode:raise RuntimeError(' '.join(args[:4])+': '+result.stderr[-3000:]+result.stdout[-3000:])
    return result.stdout


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--image',required=True)
    parser.add_argument('--work-dir',type=Path,required=True)
    parser.add_argument('--fail2ban-source',type=Path,required=True)
    args=parser.parse_args()
    root=args.work_dir.absolute()
    root.mkdir(mode=0o755)
    bundle=Path(__file__).resolve().parents[1]
    web=root/'web';web.mkdir()
    name='waf-ban-test-'+uuid.uuid4().hex[:8]
    f2b=root/'fail2ban';shutil.copytree(args.fail2ban_source/'etc/fail2ban',f2b)
    for filename in (f2b/'jail.d').glob('*'):filename.unlink()
    for filename in (f2b/'fail2ban.d').glob('*'):filename.unlink()
    (f2b/'fail2ban.local').write_text('[Definition]\nloglevel = DEBUG\nlogtarget = '+str(root/'fail2ban.log')+'\ndbfile = '+str(root/'fail2ban.sqlite3')+'\n')
    bins=root/'bin';bins.mkdir()
    prefix=[sys.executable,str(args.fail2ban_source/'usr/bin/fail2ban-client'),'-c',str(f2b),'-s',str(root/'f2b.sock'),'-p',str(root/'f2b.pid')]
    import shlex
    failure=root/'fail-reload-once'
    (bins/'fail2ban-client').write_text('#!/bin/sh\nif [ "$1" = reload ] && [ -f '+shlex.quote(str(failure))+' ]; then rm '+shlex.quote(str(failure))+'; exit 1; fi\nexec '+shlex.join(prefix)+' "$@"\n')
    (bins/'crontab').write_text('#!'+sys.executable+'\nimport pathlib,sys\np=pathlib.Path('+repr(str(root/'crontab'))+')\nif sys.argv[1]=="-l":\n print(p.read_text() if p.exists() else "",end="")\nelse:p.write_text(sys.stdin.read())\n')
    for path in bins.iterdir():path.chmod(0o700)
    os.environ['PATH']=str(bins)+':'+os.environ['PATH']
    os.environ['PYTHONPATH']=str(args.fail2ban_source/'usr/lib/python3/dist-packages')
    (root/'crontab').write_text('0 0 * * * echo custom-task\n')
    config=json.loads((bundle/'example-policy.json').read_text())
    config.update(mode='on',cdn='direct',container=name,attackRetries=10,rateRetries=30,banSeconds=60)
    directory=web/'conf.d/waf';directory.mkdir(parents=True)
    for filename,text in policy.bundle_files(config,[]).items():(directory/filename).write_text(text)
    (directory/'blocked.map').write_text(policy.render_bans({},int(time.time())))
    state=web/'config/waf';state.mkdir(parents=True)
    (state/'policy.json').write_text(json.dumps(config));(state/'policy.json').chmod(0o600)
    (state/'cloudflare-ips.json').write_bytes((bundle/'cloudflare-ips.json').read_bytes())
    (web/'log/nginx').mkdir(parents=True)
    proxy='proxy_pass http://127.0.0.1:18081;'
    blocks=[]
    for host in ['one.example.com','two.example.com']:
        blocks.append('server { listen unix:/test/front.sock; server_name '+host+'; '
                      'include /etc/nginx/conf.d/waf/server-default*.inc; '
                      'location / { '+proxy+' } }')
    blocks.append('server { listen 127.0.0.1:18081; server_name backend; location / { return 200 "ok"; } location /business403 { return 403; } }')
    (web/'conf.d/site.conf').write_text('\n'.join(blocks))
    (web/'nginx.conf').write_text('''load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;
worker_processes 1;
events { worker_connections 256; }
http {
include /etc/nginx/mime.types;
modsecurity on;
include /etc/nginx/conf.d/waf/http*.conf;
access_log /var/log/nginx/access.log combined;
include /etc/nginx/conf.d/*.conf;
}
''')
    results=[]
    def check(label,condition):
        results.append({'test':label,'passed':bool(condition)})
        if not condition:raise AssertionError(label)
    def execute(*command):return run('docker','exec',name,*command)
    def tool(*command):
        code='import sys;sys.path.insert(0,'+repr(str(bundle))+');import ban,configure;from pathlib import Path;ban.F2B=Path('+repr(str(f2b))+');sys.argv=["configure.py","--root",'+repr(str(web))+']+sys.argv[1:];configure.main()'
        return run(sys.executable,'-B','-c',code,*command)
    def inject_identity():
        # Test-only identity injection after policy application. Production CF
        # CIDR trust is covered separately; no external traffic reaches this socket.
        (directory/'realip.conf').write_text('set_real_ip_from unix:;\nreal_ip_header CF-Connecting-IP;\n')
        execute('nginx','-s','reload');time.sleep(.5)
    def request(host='one.example.com',path='/',ip='8.8.8.8'):
        connection=http.client.HTTPConnection('localhost',timeout=10)
        def connect():
            connection.sock=socket.socket(socket.AF_UNIX)
            connection.sock.settimeout(10);connection.sock.connect(str(root/'front.sock'))
        connection.connect=connect
        connection.request('GET',path,headers={'Host':host,'CF-Connecting-IP':ip,'Connection':'close'})
        response=connection.getresponse();status=response.status;response.read();connection.close()
        return status
    def wait(label,probe):
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            if probe():check(label,True);return
            time.sleep(.25)
        check(label,False)
    command=['docker','run','-d','--name',name,'--network=none','--memory=512m','--cpus=1',
             '--mount','type=bind,src='+str(root)+',dst=/test',
             '--mount','type=bind,src='+str(web/'conf.d')+',dst=/etc/nginx/conf.d',
             '--mount','type=bind,src='+str(web/'nginx.conf')+',dst=/etc/nginx/nginx.conf',
             '--mount','type=bind,src='+str(web/'log/nginx')+',dst=/var/log/nginx',
             '--entrypoint','nginx',args.image,'-g','daemon off;']
    try:
        run(*command)
        wait('nginx-started',lambda:(root/'front.sock').exists())
        run('fail2ban-client','-x','start')
        check('ordinary-request-before-install',request()==200)
        before_policy=(state/'policy.json').read_bytes();before_main=(web/'nginx.conf').read_bytes()
        failure.touch()
        try:
            tool('ban-install')
            check('install-failure-is-reported',False)
        except RuntimeError:check('install-failure-is-reported',True)
        check('failed-install-restores-policy',(state/'policy.json').read_bytes()==before_policy)
        check('failed-install-restores-nginx',(web/'nginx.conf').read_bytes()==before_main)
        check('failed-install-restores-jails',not (f2b/'jail.d/zz-waf-managed.local').exists())
        check('failed-install-restores-cron',(root/'crontab').read_text()=='0 0 * * * echo custom-task\n')
        tool('ban-install')
        inject_identity()
        check('unified-jails-running',json.loads(tool('ban-status'))['running'])
        check('legacy-jails-retired','enabled = false' in (f2b/'jail.d/zz-kejilion-web-baseline.local').read_text())
        check('expiry-cron-installed','kejilion-waf-bans' in run('crontab','-l'))
        check('existing-cron-preserved','custom-task' in run('crontab','-l'))
        # Ordinary application errors never enter attack/rate event counters.
        for _ in range(12):check('business-403',request(path='/business403')==403)
        check('business-errors-not-banned',request()==200)
        for _ in range(10):check('waf-secret-path-blocked',request(path='/.env')==403)
        wait('real-waf-log-to-fail2ban-to-origin',lambda:request()==403)
        wait('ban-action-completed',lambda:'Banned 1 / 1' in (root/'fail2ban.log').read_text())
        check('same-ip-other-site-unaffected',request(host='two.example.com')==200)
        check('other-ip-unaffected',request(ip='9.9.9.9')==200)
        check('original-ticket-recorded','one.example.com|8.8.8.8' in json.loads((state/'bans.json').read_text())['records'])
        run('fail2ban-client','set','waf-attack','unbanip','one.example.com|8.8.8.8')
        wait('manual-unban-restores-request',lambda:request()==200)
        # Rate event filter and its independent source use a real F2B reader.
        line=time.strftime('%Y-%m-%dT%H:%M:%S+00:00',time.gmtime())+' key="two.example.com|9.9.9.9" event=rate request_limit="REJECTED" connection_limit=""\n'
        with (web/'log/nginx/waf-rate.log').open('a') as stream:stream.write(line*30)
        wait('rate-log-to-fail2ban-to-origin',lambda:request(host='two.example.com',ip='9.9.9.9')==403)
        tool('ban-clear')
        check('clear-restores-both-sites',request()==200 and request(host='two.example.com',ip='9.9.9.9')==200)
        check('clear-removes-fail2ban-tickets',not run('fail2ban-client','get','waf-rate','banip').strip())
        # Simulate a persisted action whose ticket was cancelled before F2B
        # initialized actionunban; the actual cron command must repair it.
        execute_code='import sys;sys.path.insert(0,'+repr(str(bundle))+');import ban;from pathlib import Path;import time;ban.stage(Path('+repr(str(web))+'),"ban","one.example.com|4.2.2.2","attack",600,time.time())'
        run(sys.executable,'-c',execute_code)
        cron_command=(root/'crontab').read_text().split('* * * * * ',1)[1].split('\n',1)[0]
        run('sh','-c',cron_command)
        check('cron-repairs-orphaned-cancelled-ticket','one.example.com|4.2.2.2' not in json.loads((state/'bans.json').read_text())['records'])
        # Reinstall preserves administrator jail thresholds and other cron jobs.
        jail=f2b/'jail.d/zz-waf-managed.local';jail.write_text(jail.read_text().replace('maxretry = 10','maxretry = 17'))
        tool('ban-install')
        inject_identity()
        check('reinstall-keeps-thresholds','maxretry = 17' in jail.read_text())
        check('reinstall-keeps-one-cron',run('crontab','-l').count('kejilion-waf-bans')==1)
        # Several live tickets must not deadlock the reload/unban lifecycle.
        for last in range(1,9):
            run('fail2ban-client','set','waf-attack','banip','one.example.com|8.8.4.'+str(last))
        wait('multiple-tickets-reach-state',lambda:len(json.loads((state/'bans.json').read_text())['records'])>=8)
        tool('ban-remove')
        check('remove-stops-managed-jails',not json.loads(tool('ban-status'))['running'])
        check('remove-cleans-expiry-cron','kejilion-waf-bans' not in run('crontab','-l'))
        check('remove-keeps-user-cron','custom-task' in run('crontab','-l'))
        check('remove-keeps-waf',request(path='/.env')==403 and request()==200)
        tool('ban-remove');check('remove-is-idempotent',True)
        tool('ban-install');check('reinstall-after-remove',json.loads(tool('ban-status'))['running'])
        check('reinstall-does-not-restore-cleared-tickets',not json.loads(tool('ban-status'))['activeBans'])
        tool('ban-remove')
    finally:
        try:
            (root/'container.log').write_text(run('docker','logs',name))
        except Exception:pass
        (root/'results.json').write_text(json.dumps(results,indent=2))
        try:run('fail2ban-client','stop')
        except Exception:pass
        run('docker','rm','-f',name)
    print(json.dumps({'passed':len(results),'workspace':str(root)}))


if __name__=='__main__':main()
