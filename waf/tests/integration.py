#!/usr/bin/env python3
"""Real Nginx/ModSecurity black-box tests in a resource-limited, networkless container."""
import argparse
import base64
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import policy
import nginx_edit


class Backend(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def do_request(self):
        length = int(self.headers.get('Content-Length', '0'))
        if length > 16 * 1024 * 1024:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        if self.path.startswith('/sse'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Connection', 'close')
            self.end_headers()
            for i in range(3):
                self.wfile.write(('data: ' + str(i) + '\n\n').encode())
                self.wfile.flush()
                time.sleep(0.05)
            self.close_connection = True
            return
        if self.path.startswith('/ws') and self.headers.get('Upgrade', '').lower() == 'websocket':
            value = self.headers['Sec-WebSocket-Key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
            self.send_response(101)
            self.send_header('Upgrade', 'websocket')
            self.send_header('Connection', 'Upgrade')
            self.send_header('Sec-WebSocket-Accept', base64.b64encode(hashlib.sha1(value.encode()).digest()).decode())
            self.end_headers()
            self.wfile.flush()
            self.close_connection = True
            return
        status = int(self.path.rsplit('/', 1)[-1]) if self.path.startswith('/status/') else 200
        data = json.dumps({'method': self.command, 'bytes': len(body), 'client': self.headers.get('X-Real-IP'),
                           'forwarded': self.headers.get('X-Forwarded-For'),'forwardedAll':self.headers.get_all('X-Forwarded-For'),'host':self.headers.get('Host'),'proto':self.headers.get('X-Forwarded-Proto'),'authorization':self.headers.get('Authorization')}).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Connection', 'close')
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(data)
        self.close_connection = True

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_request


class UnixHTTP(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 128


def run(*args, **kw):
    return subprocess.run(args, check=True, capture_output=True, timeout=60, **kw)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--modsec-dir', type=Path)
    parser.add_argument('--work-dir', type=Path, required=True)
    args = parser.parse_args()
    if args.work_dir.exists():
        raise ValueError('Use a new work directory for immutable evidence')
    work = args.work_dir.absolute()
    if len(str(work / 'front.sock')) > 103:
        raise ValueError('Use a shorter Unix socket workspace')
    work.mkdir(parents=True)
    os.chmod(work, 0o755)
    bundle = Path(__file__).resolve().parents[1]
    config = json.loads((bundle / 'example-policy.json').read_text())
    name = 'waf-validation-' + uuid.uuid4().hex[:10]
    config.update(mode='on', cdn='direct', container=name,
                  sites={'wordpress.example': {'profile': 'wordpress'}, 'off.example': {'mode': 'off'},
                         'detect.example': {'mode': 'detect'}, 'stream.example': {'profile': 'streaming'},
                         'upload.example': {'profile': 'upload'}, 'api.example': {'profile': 'api'},'artifact.example':{'profile':'artifact-proxy'},
                         'proxy.example': {'cdn':'proxy','trustedProxies':['127.0.0.1/32','127.0.0.2/32']}})
    cf = policy.networks(json.loads((bundle / 'cloudflare-ips.json').read_text()))
    generated = work / 'conf.d/waf'
    generated.mkdir(parents=True)
    for filename, text in policy.bundle_files(config, cf).items():
        (generated / filename).write_text(text)
    (generated / 'blocked.map').write_text(policy.render_bans({}, int(time.time())))
    (generated / 'cloudflare-ips.json').write_bytes((bundle / 'cloudflare-ips.json').read_bytes())
    shutil.copytree(bundle, generated / 'runtime', ignore=shutil.ignore_patterns('__pycache__'))
    state = work / 'config/waf'
    state.mkdir(parents=True)
    (state / 'policy.json').write_text(json.dumps(config))
    os.chmod(state / 'policy.json', 0o600)
    (work / 'logs').mkdir()
    backend = UnixHTTP(str(work / 'backend.sock'), Backend)
    os.chmod(work / 'backend.sock', 0o666)
    threading.Thread(target=backend.serve_forever, daemon=True).start()

    proxy = '''proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $fixture_connection;
proxy_http_version 1.1;
proxy_buffering off;
proxy_pass http://fixture_backend;
'''
    blocks = []
    for host in ['one.example', 'two.example', 'wordpress.example', 'off.example', 'detect.example',
                 'stream.example', 'upload.example', 'api.example', 'rate.example','artifact.example']:
        blocks.append('server { listen unix:/test/front.sock; server_name ' + host + ';\n'
                      'set_real_ip_from unix:; real_ip_header CF-Connecting-IP;\n'
                      'include /etc/nginx/conf.d/waf/server-default.inc;\n'
                      'client_max_body_size 64m;\n'
                      'location / {\n' + ('limit_req zone=fixture_rate burst=2 nodelay;\n' if host == 'rate.example' else '')
                      + proxy + '\n}\n}\n')
    blocks.append('server { listen 127.0.0.1:18080; server_name direct.example; '
                  'include /etc/nginx/conf.d/waf/server-default.inc; location / { ' + proxy + ' } }')
    proxy_id=hashlib.sha256(b'proxy.example').hexdigest()[:16]
    blocks.append('server { listen 127.0.0.1:18081; server_name proxy.example; '
                  'include /etc/nginx/conf.d/waf/server-'+proxy_id+'.inc; location / { '+proxy+' } }')
    parent='server { listen unix:/test/front.sock; server_name parent.example; set_real_ip_from unix:; real_ip_header CF-Connecting-IP; include /etc/nginx/conf.d/waf/server-default.inc; location / { proxy_http_version 1.1; proxy_pass http://fixture_backend; } }'
    main_headers='proxy_set_header Host preserved.example; proxy_set_header X-Forwarded-Proto https; proxy_set_header Authorization fixture-token;'
    dump='# configuration file /etc/nginx/nginx.conf:\nhttp { '+main_headers+' include /etc/nginx/conf.d/parent.conf; }\n# configuration file /etc/nginx/conf.d/parent.conf:\n'+parent+'\n# configuration file /etc/nginx/conf.d/waf/server-default.inc:\n# Hook contains no inherited business headers.\n'
    blocks.append(nginx_edit.patch_application(parent,nginx_edit.configuration_headers(dump),'/etc/nginx/conf.d/parent.conf'))
    duplicate='server { listen unix:/test/front.sock; server_name duplicate.example; set_real_ip_from unix:; real_ip_header CF-Connecting-IP; include /etc/nginx/conf.d/waf/server-default.inc; location / { proxy_set_header x-forwarded-for $http_x_forwarded_for; proxy_set_header X-Forwarded-For bad; proxy_pass http://fixture_backend; } }'
    blocks.append(nginx_edit.patch_application(duplicate))
    child='server { listen unix:/test/front.sock; server_name child.example; modsecurity on; set_real_ip_from unix:; real_ip_header CF-Connecting-IP; location / { modsecurity on; '+proxy+' } location /custom-off { modsecurity off; '+proxy+' } }'
    migrated=nginx_edit.patch_site(child,config)
    assert 'modsecurity on;' not in migrated and 'modsecurity off;' in migrated
    blocks.append(migrated)
    fixture = '''load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log error;
worker_processes 1;
events { worker_connections 256; }
http {
include /etc/nginx/mime.types;
modsecurity on;
include /etc/nginx/conf.d/waf/http.conf;
map $http_upgrade $fixture_connection { default upgrade; '' close; }
limit_req_zone $remote_addr zone=fixture_rate:1m rate=1r/s;
upstream fixture_backend { server unix:/test/backend.sock; }
''' + main_headers+'\n'+'\n'.join(blocks) + '\n}\n'
    (work / 'nginx.conf').write_text(fixture)
    command = ['docker', 'run', '-d', '--pull=never', '--name', name, '--network=none', '--read-only',
               '--memory=768m', '--cpus=1', '--pids-limit=64',
               '--tmpfs', '/tmp:rw,nosuid,size=64m', '--tmpfs', '/run:rw,nosuid,size=8m',
               '--tmpfs', '/var/cache/nginx:rw,nosuid,size=128m',
               '--mount', 'type=bind,src=' + str(work) + ',dst=/test',
               '--mount', 'type=bind,src=' + str(work / 'logs') + ',dst=/var/log/nginx',
               '--mount', 'type=bind,src=' + str(generated) + ',dst=/etc/nginx/conf.d/waf,readonly',
               '--mount', 'type=bind,src=' + str(work / 'nginx.conf') + ',dst=/etc/nginx/nginx.conf,readonly']
    if args.modsec_dir:
        command += ['--mount', 'type=bind,src=' + str(args.modsec_dir.absolute()) + ',dst=/etc/nginx/modsec,readonly']
    command += ['--entrypoint', 'nginx', args.image, '-g', 'daemon off;']
    results = []
    def request(host='one.example', path='/', method='GET', body=None, headers=None):
        conn = http.client.HTTPConnection('localhost', timeout=10)
        def connect():
            conn.sock = socket.socket(socket.AF_UNIX)
            conn.sock.settimeout(10)
            conn.sock.connect(str(work / 'front.sock'))
        conn.connect = connect
        base = {'Host': host, 'CF-Connecting-IP': '8.8.8.8', 'Connection': 'close'}
        base.update(headers or {})
        conn.request(method, path, body, base)
        response = conn.getresponse()
        status, head = response.status, dict(response.getheaders())
        data = response.read()
        conn.close()
        return status, head, data

    def check(label, host='one.example', path='/', method='GET', body=None, headers=None, expected=200):
        status, head, data = request(host, path, method, body, headers)
        ok = status in expected if isinstance(expected, tuple) else status == expected
        results.append({'test': label, 'status': status, 'passed': ok})
        print(json.dumps(results[-1]), flush=True)
        if not ok:
            raise AssertionError(label + ': HTTP ' + str(status))
        return head, data

    try:
        run(*command)
        for _ in range(100):
            if (work / 'front.sock').exists():
                break
            process = run('docker', 'inspect', '-f', '{{.State.Running}}', name)
            if process.stdout.strip() != b'true':
                raise RuntimeError(run('docker', 'logs', name).stdout.decode())
            time.sleep(0.1)
        run('docker', 'exec', name, 'nginx', '-t')
        for method in ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']:
            check('REST-' + method, host='api.example', method=method)
        _,data=check('migrated-http-parent-business-headers',host='parent.example')
        value=json.loads(data)
        assert (value['host'],value['proto'],value['authorization'])==('preserved.example','https','fixture-token'),value
        _,data=check('migrated-duplicate-case-identity-headers',host='duplicate.example',headers={'X-Forwarded-For':'6.6.6.6'})
        assert json.loads(data)['forwardedAll']==['8.8.8.8'],data
        for path in ['/https://github.com/kejilion/sh/raw/main/kejilion.sh','/https://github.com/kejilion/sh.git/info/refs?service=git-upload-pack','/v2/library/alpine/manifests/latest','/https://huggingface.co/org/model/resolve/main/config.json','/raw.githubusercontent.com/kejilion/sh/main/cn/kejilion.sh','/github.com/kejilion/apps.git/info/refs?service=git-upload-pack']:
            check('artifact-proxy-legitimate-route-'+path,host='artifact.example',path=path)
        check('artifact-Git-clone-packet',host='artifact.example',path='/https://github.com/kejilion/sh.git/git-upload-pack',method='POST',body=b'0032want 0123456789012345678901234567890123456789\n0000',headers={'Content-Type':'application/x-git-upload-pack-request'})
        check('artifact-schemeless-Git-packet',host='artifact.example',path='/github.com/kejilion/apps.git/git-upload-pack',method='POST',body=b'0032want 0123456789012345678901234567890123456789\n0000',headers={'Content-Type':'application/x-git-upload-pack-request'})
        check('artifact-schemeless-query-SQLi-still-denied',host='artifact.example',path='/raw.githubusercontent.com/org/repo/main/test.sh?q=1%27%20UNION%20SELECT%20password%20FROM%20users--',expected=403)
        check('artifact-extension-check-kept-outside-proxy-route',host='artifact.example',path='/local.sh',expected=403)
        check('artifact-query-file-traversal-still-denied',host='artifact.example',path='/?file=../../etc/passwd',expected=403)
        check('schemeless-exclusion-never-applies-to-other-sites',path='/raw.githubusercontent.com/org/repo/main/test.sh',expected=403)
        check('JSON', host='api.example', method='POST', body=b'{"name":"hello","count":2}', headers={'Content-Type': 'application/json'})
        check('vendor-JSON', host='api.example', method='PATCH', body=b'{"name":"hello"}', headers={'Content-Type': 'application/vnd.api+json'})
        check('XML',host='api.example',method='POST',body=b'<root>hello</root>',headers={'Content-Type':'application/xml'})
        check('malformed-XML',host='api.example',method='POST',body=b'<root>',headers={'Content-Type':'application/xml'},expected=(400,403))
        check('statistics-API-request-shape',host='api.example',path='/api/log',method='POST',body=json.dumps({'country':'中国','cpu_arch':'x86_64','os_info':'Debian GNU/Linux 13','version':'v4','action':'安装 Nginx'},ensure_ascii=False).encode(),headers={'Content-Type':'application/json'})
        for path in ['/feed', '/readme.html', '/xmlrpc.php', '/.well-known/security.txt', '/.well-known/acme-challenge/valid-token']:
            check('legitimate-path-' + path, path=path)
        for code in [401, 403, 404, 429]:
            check('upstream-status-' + str(code), path='/status/' + str(code), expected=code)
        check('secret-git', path='/.git/HEAD', expected=403)
        check('nested-secret-env', path='/assets/.env', expected=403)
        check('secret-wordpress', path='/wp-config.php.bak', expected=403)
        sqli = '/?q=' + urllib.parse.quote("1' UNION SELECT password FROM users--")
        xss = '/?q=' + urllib.parse.quote('<script>alert(1)</script>')
        check('SQLi', path=sqli, expected=403)
        check('XSS', path=xss, expected=403)
        check('artifact-proxy-query-SQLi-still-denied',host='artifact.example',path='/https://github.com/org/repo/raw/main/test.sh'+sqli[1:],expected=403)
        check('artifact-proxy-query-XSS-still-denied',host='artifact.example',path='/https://github.com/org/repo/raw/main/test.sh'+xss[1:],expected=403)
        check('artifact-exclusion-never-applies-to-other-sites',path='/https://github.com/org/repo/raw/main/test.sh',expected=403)
        check('ACME-does-not-bypass-CRS', path='/.well-known/acme-challenge/token' + sqli[1:], expected=403)
        check('detection-mode', host='detect.example', path=sqli)
        check('early-header-denial', host='api.example', path='/early-header', method='POST',
              body=json.dumps({'text':'normal body '*4096}).encode(),
              headers={'Content-Type':'application/json','User-Agent':'sqlmap/1.8'}, expected=403)
        check('early-blocking-detection-mode-keeps-body-processing', host='detect.example', path='/detect-early-header', method='POST',
              body=json.dumps({'text':"1' UNION SELECT password FROM users--"}).encode(),
              headers={'Content-Type':'application/json','User-Agent':'sqlmap/1.8'})
        # The response may finish before phase-5 serial audit logging. Wait for
        # these exact complete transactions, rather than racing the worker.
        wanted = {'/early-header', '/detect-early-header'}
        deadline = time.monotonic() + 2
        while True:
            transactions = []
            for line in (work / 'logs/waf-audit.json').read_text().splitlines(keepends=True):
                if line.endswith('\n'):
                    transactions.append(json.loads(line)['transaction'])
            if wanted <= {item['request']['uri'] for item in transactions}:
                break
            if time.monotonic() >= deadline:
                raise AssertionError('Early-blocking audit transactions did not finish within two seconds')
            time.sleep(.025)
        early = next(item for item in transactions if item['request']['uri'] == '/early-header')
        detect = next(item for item in transactions if item['request']['uri'] == '/detect-early-header')
        early_ids = {message['details']['ruleId'] for message in early['messages']}
        detect_ids = {message['details']['ruleId'] for message in detect['messages']}
        assert '949111' in early_ids and not any(rule.startswith('942') for rule in early_ids), early_ids
        assert '913100' in detect_ids and '942100' in detect_ids, detect_ids
        check('off-mode', host='off.example', path=sqli)
        check('absolute-form-cannot-select-off-policy', host='off.example', path='http://one.example' + sqli, expected=403)
        check('WordPress-password', host='wordpress.example', path='/wp-login.php', method='POST',
              body=urllib.parse.urlencode({'log': 'user', 'pwd': "1' UNION SELECT password FROM users--"}),
              headers={'Content-Type': 'application/x-www-form-urlencoded'})
        check('malformed-JSON', host='api.example', method='POST', body=b'{broken', headers={'Content-Type': 'application/json'}, expected=(400, 403))
        check('deep-JSON', host='api.example', method='POST', body=('[' * 70 + '0' + ']' * 70).encode(), headers={'Content-Type': 'application/json'}, expected=(400, 403))
        check('large-valid-JSON', host='api.example', method='POST', body=json.dumps({'text': 'a' * (1024*1024)}).encode(), headers={'Content-Type': 'application/json'})
        boundary = 'fixtureBoundary'
        multipart = ('--'+boundary+'\r\nContent-Disposition: form-data; name="file"; filename="sample.txt"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--'+boundary+'--\r\n').encode()
        check('multipart-upload', host='upload.example', method='POST', body=multipart, headers={'Content-Type': 'multipart/form-data; boundary="'+boundary+'"'})
        _, data = check('SSE', host='stream.example', path='/sse')
        assert data.count(b'data:') == 3
        check('WebSocket-upgrade', host='stream.example', path='/ws',
              headers={'Upgrade': 'websocket', 'Connection': 'Upgrade', 'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==', 'Sec-WebSocket-Version': '13'}, expected=101)
        _, data = check('spoofed-XFF-sanitized', headers={'X-Forwarded-For': '6.6.6.6'})
        assert json.loads(data)['forwarded'] == '8.8.8.8'
        _, data = check('trusted-proxy-IPv6', headers={'CF-Connecting-IP': '2001:4860:4860::8888'})
        assert json.loads(data)['client'] == '2001:4860:4860::8888'
        # Direct TCP listener does not trust arbitrary XFF/CF headers.
        direct = run('docker', 'exec', name, 'wget', '-q', '-T', '5', '-O', '-',
                     '--header=Host: direct.example', '--header=CF-Connecting-IP: 6.6.6.6',
                     '--header=X-Forwarded-For: 7.7.7.7', 'http://127.0.0.1:18080/').stdout
        assert b'"client": "127.0.0.1"' in direct
        results.append({'test': 'direct-header-forgery', 'passed': True})
        chain=run('docker','exec',name,'wget','-q','-T','5','-O','-',
                  '--header=Host: proxy.example','--header=CF-Connecting-IP: 6.6.6.6',
                  '--header=X-Forwarded-For: 7.7.7.7, 8.8.8.8, 127.0.0.2',
                  'http://127.0.0.1:18081/').stdout
        assert json.loads(chain)['client']=='8.8.8.8'
        results.append({'test':'explicit-multi-hop-proxy-last-untrusted-address','passed':True})
        check('nonfile-body-budget',host='api.example',method='POST',body=json.dumps({'text':'a'*(9*1024*1024)}).encode(),headers={'Content-Type':'application/json'},expected=(400,413))
        large_file=multipart.replace(b'hello',b'x'*(9*1024*1024))
        check('large-multipart-file-headroom',host='upload.example',method='POST',body=large_file,headers={'Content-Type':'multipart/form-data; boundary='+boundary})
        check('argument-budget', host='api.example', method='POST', body=urllib.parse.urlencode({'p'+str(i):'x' for i in range(2050)}), headers={'Content-Type':'application/x-www-form-urlencoded'}, expected=400)
        statuses=[request(host='rate.example',headers={'CF-Connecting-IP':'1.1.1.1'})[0] for _ in range(8)]
        assert 429 in statuses,statuses
        results.append({'test':'actual-request-limit-rejects-with-429','passed':True})
        check('rate-limits-are-isolated-between-sites',host='two.example',headers={'CF-Connecting-IP':'1.1.1.1'})
        check('long-URI-attack',path=xss+'&padding='+'a'*3000,expected=403)
        assert 'auth_request' not in (generated/'http.conf').read_text()
        results.append({'test':'configuration-only-backend-boundary','passed':True})
        # Emulate the historical native sed toggle on a fully disabled policy.
        check('migrated-child-on-blocks-before-global-off',host='child.example',path=sqli,expected=403)
        check('custom-location-off-preserved',host='child.example',path='/custom-off'+sqli)
        # Its HTTP switch remains authoritative without hidden ctl=Off fallback.
        disabled=json.loads(json.dumps(config));disabled['mode']='off'
        for site in disabled['sites'].values():site.pop('mode',None)
        (generated/'profile-rules.conf').write_text(policy.render_profile_rules(disabled))
        (work/'nginx.conf').write_text(fixture.replace('modsecurity on;','# modsecurity on;'))
        def reload_fixture():
            before={line.split()[0] for line in run('docker','top',name,'-eo','pid,args').stdout.decode().splitlines() if 'nginx: worker process' in line}
            run('docker','exec',name,'nginx','-s','reload')
            for _ in range(100):
                after={line.split()[0] for line in run('docker','top',name,'-eo','pid,args').stdout.decode().splitlines() if 'nginx: worker process' in line}
                if after and not (after & before):return
                time.sleep(0.1)
            raise RuntimeError('No new fixture worker after toggle')
        reload_fixture()
        check('legacy-global-off-with-disabled-policy',path=sqli)
        check('global-off-also-disables-migrated-server-and-location-on',host='child.example',path=sqli)
        (work/'nginx.conf').write_text(fixture)
        reload_fixture()
        check('legacy-global-on-after-disabled-policy',path=sqli,expected=403)
        check('global-on-restores-migrated-server-and-location',host='child.example',path=sqli,expected=403)
        # Keep raw evidence without request bodies or secrets.
        (work / 'results.json').write_text(json.dumps(results, indent=2))
        print(json.dumps({'passed': len(results), 'container': name, 'workspace': str(work)}), flush=True)
    finally:
        (work / 'results.json').write_text(json.dumps(results, indent=2))
        process = subprocess.run(['docker', 'logs', name], capture_output=True)
        (work / 'container.log').write_bytes(process.stdout + process.stderr)
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
        backend.shutdown()
        backend.server_close()


if __name__ == '__main__':
    main()
