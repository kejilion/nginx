#!/usr/bin/env python3
"""Real Panel/Agent upload behind WAF, with synthetic data and no external network.

The Agent has no host files, Docker socket or system services. Only the fixture
directory, private Agent state and its test-only socket/token are writable.
"""
import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time
import urllib.parse
import uuid
import zipfile


def run(*args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=90)
    if p.returncode:
        raise RuntimeError('Fixture command failed: ' + ' '.join(args[:3]) + ': ' + p.stderr[-1200:])
    return p.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--bundle-dir', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--nginx-image', required=True)
    parser.add_argument('--panel-image', required=True)
    parser.add_argument('--baseline', action='store_true')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('fixture_policy', args.bundle_dir / 'policy.py')
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    work = args.work_dir.absolute()
    work.mkdir(mode=0o755)
    dirs = {name: work / name for name in ['data', 'state', 'files', 'web', 'run', 'sockets', 'waf', 'logs']}
    for path in dirs.values():
        path.mkdir(mode=0o755)
    os.chown(dirs['data'], 65532, 65532)
    os.chown(dirs['run'], 0, 65532)
    os.chmod(dirs['run'], 0o750)
    token = work / 'agent.token'
    token.write_text(secrets.token_hex(32))
    os.chown(token, 0, 65532)
    os.chmod(token, 0o640)
    (work / 'group').write_text('root:x:0:\nfixture:x:65532:\n')
    (work / 'passwd').write_text('root:x:0:0:root:/:/bin/false\nfixture:x:65532:65532:fixture:/:/bin/false\n')
    suffix = uuid.uuid4().hex[:8]
    panel, agent, front = ['waf-file-' + name + '-' + suffix for name in ['panel', 'agent', 'front']]
    config = json.loads((args.bundle_dir / 'example-policy.json').read_text())
    config.update(mode='on', cdn='direct', sites={'panel.example': {'profile': 'kpanel'}})
    cf = policy.networks(json.loads((args.bundle_dir / 'cloudflare-ips.json').read_text()))
    for name, content in policy.bundle_files(config, cf).items():
        (dirs['waf'] / name).write_text(content)
    (dirs['waf'] / 'blocked.map').write_text(policy.render_bans({}, int(time.time())))
    ident = hashlib.sha256(b'panel.example').hexdigest()[:16]
    (work / 'nginx.conf').write_text('''include /etc/nginx/conf.d/waf/load-module.conf;
worker_processes 1;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log error;
events { worker_connections 128; }
http {
modsecurity on;
include /etc/nginx/conf.d/waf/http.conf;
server {
listen unix:/sockets/front.sock;
server_name panel.example;
include /etc/nginx/conf.d/waf/server-''' + ident + '''.inc;
client_max_body_size 16m;
location / {
proxy_http_version 1.1;
proxy_set_header Host panel.example;
proxy_set_header X-Forwarded-Proto http;
proxy_set_header X-Real-IP 8.8.8.8;
proxy_pass http://127.0.0.1:18082;
}
}
}
''')
    created, results, cookies = [], [], {}

    def request(label, method, path, body=None, expected=200, auth=True, csrf=True, origin='http://panel.example', media=None):
        client = http.client.HTTPConnection('localhost', timeout=20)
        def connect():
            client.sock = socket.socket(socket.AF_UNIX)
            client.sock.settimeout(20)
            client.sock.connect(str(dirs['sockets'] / 'front.sock'))
        client.connect = connect
        headers = {'Host': 'panel.example', 'Origin': origin, 'Connection': 'close'}
        if body is not None:
            if not isinstance(body, bytes):
                body = json.dumps(body, ensure_ascii=False).encode()
            headers['Content-Type'] = media or 'application/json'
        if auth:
            headers['Cookie'] = '; '.join(k + '=' + v for k, v in cookies.items())
            for name, value in cookies.items():
                if csrf and 'csrf' in name:
                    headers['X-CSRF-Token'] = value
        client.request(method, path, body, headers)
        response = client.getresponse()
        payload = response.read()
        for value in response.headers.get_all('Set-Cookie', []):
            name, value = value.split(';', 1)[0].split('=', 1)
            cookies[name] = value
        accepted = (expected,) if isinstance(expected, int) else expected
        record = {'test': label, 'status': response.status, 'passed': response.status in accepted}
        results.append(record)
        print(json.dumps(record), flush=True)
        client.close()
        if not record['passed']:
            raise AssertionError(label + ': HTTP ' + str(response.status))
        return json.loads(payload) if payload[:1] in {b'{', b'['} else payload

    def mount(source, destination, readonly=False):
        return ['--mount', 'type=bind,src=' + str(source) + ',dst=' + destination + (',readonly' if readonly else '')]

    try:
        run(*(['docker', 'run', '-d', '--name', agent, '--pull=never', '--network=none', '--read-only',
               '--memory=384m', '--cpus=1', '--pids-limit=128', '--cap-drop=ALL', '--cap-add=CHOWN',
               '--security-opt=no-new-privileges:true', '--user=0:65532', '--tmpfs', '/tmp:rw,nosuid,size=16m']
              + mount(dirs['state'], '/state') + mount(dirs['files'], '/fixture')
              + mount(dirs['web'], '/web') + mount(dirs['run'], '/run/kejilion-panel')
              + mount(token, '/secrets/agent.token', True) + mount(work / 'group', '/etc/group', True)
              + mount(work / 'passwd', '/etc/passwd', True)
              + ['--entrypoint', '/release/kejilion-agent', args.panel_image,
                 '--socket=/run/kejilion-panel/agent.sock', '--socket-group=fixture',
                 '--token-file=/secrets/agent.token', '--state-dir=/state', '--web-root=/web',
                 '--enable-system-writes=false', '--public-network-lookup=false']))
        created.append(agent)
        deadline = time.monotonic() + 20
        while not (dirs['run'] / 'agent.sock').exists() and time.monotonic() < deadline:
            time.sleep(.1)
        if not (dirs['run'] / 'agent.sock').exists():
            raise AssertionError('Isolated Agent did not start')
        run(*(['docker', 'run', '-d', '--name', panel, '--pull=never', '--network=none', '--read-only',
               '--memory=384m', '--cpus=1', '--pids-limit=128', '--cap-drop=ALL',
               '--security-opt=no-new-privileges:true', '--user=65532:65532', '--tmpfs', '/tmp:rw,nosuid,size=16m']
              + mount(dirs['data'], '/var/lib/kejilion-panel') + mount(dirs['run'], '/run/kejilion-panel', True)
              + mount(token, '/secrets/agent.token', True)
              + ['-e', 'KEJILION_PANEL_LISTEN=127.0.0.1:18082', '-e', 'KEJILION_PANEL_DATA_DIR=/var/lib/kejilion-panel',
                 '-e', 'KEJILION_PANEL_PUBLIC_URL=http://panel.example', '-e', 'KEJILION_PANEL_SECURE_COOKIE=false',
                 '-e', 'KEJILION_PANEL_AGENT_SOCKET=/run/kejilion-panel/agent.sock',
                 '-e', 'KEJILION_PANEL_AGENT_TOKEN_FILE=/secrets/agent.token',
                 '-e', 'KEJILION_PANEL_TRUSTED_PROXY_CIDRS=127.0.0.1/32', args.panel_image]))
        created.append(panel)
        deadline = time.monotonic() + 20
        while not (dirs['data'] / 'bootstrap.token').exists() and time.monotonic() < deadline:
            time.sleep(.1)
        bootstrap = (dirs['data'] / 'bootstrap.token').read_text().strip()
        run(*(['docker', 'run', '-d', '--name', front, '--pull=never', '--network=container:' + panel,
               '--read-only', '--memory=768m', '--cpus=1', '--pids-limit=64',
               '--tmpfs', '/tmp:rw,nosuid,size=64m', '--tmpfs', '/run:rw,nosuid,size=8m',
               '--tmpfs', '/var/cache/nginx:rw,nosuid,size=16m']
              + mount(dirs['waf'], '/etc/nginx/conf.d/waf', True) + mount(dirs['logs'], '/var/log/nginx')
              + mount(dirs['sockets'], '/sockets') + mount(work / 'nginx.conf', '/etc/nginx/nginx.conf', True)
              + ['--entrypoint', 'nginx', args.nginx_image, '-g', 'daemon off;']))
        created.append(front)
        deadline = time.monotonic() + 10
        while not (dirs['sockets'] / 'front.sock').exists() and time.monotonic() < deadline:
            time.sleep(.1)
        request('health', 'GET', '/api/v1/health', auth=False)
        password = 'Fixture9!StablePassword'
        request('bootstrap', 'POST', '/api/v1/auth/bootstrap', {'token': bootstrap, 'username': 'waf-fixture', 'password': password}, 201, auth=False)
        cookies.clear()
        request('login', 'POST', '/api/v1/auth/login', {'username': 'waf-fixture', 'password': password}, auth=False)
        receive = '/api/v1/files/transfer/sessions'
        filename = '0017.\u6b4c\u624b--\u6b4c\u66f2 (live).mp3'
        content = b'ID3' + bytes(range(256)) * 6144
        source_key = 'a' * 64
        command = {'operation': 'create', 'input': {'directory': '/fixture', 'name': filename,
                   'kind': 'file', 'sizeBytes': len(content), 'sourceKey': source_key}}
        if args.baseline:
            request('baseline-reproduces-filename-403', 'POST', receive, command, 403)
            assert not list(dirs['files'].iterdir())
            return
        request('upload-requires-login', 'POST', receive, command, 401, auth=False)
        for label, kwargs in [('csrf', {'csrf': False}), ('origin', {'origin': 'http://other.example'})]:
            denied = request('upload-requires-' + label, 'POST', receive, command, 403, **kwargs)
            assert isinstance(denied, dict) and denied.get('code'), 'Expected real application denial'
        session = request('create-upload-session', 'POST', receive, command)
        query = {'id': session['id'], 'sourceKey': source_key, 'offset': 0, 'sha256': hashlib.sha256(content).hexdigest()}
        bad = dict(query, sourceKey='b' * 64)
        request('chunk-requires-source-key', 'PUT', receive + '?' + urllib.parse.urlencode(bad), content, (400, 403, 404), media='application/octet-stream')
        bad = dict(query, sha256='0' * 64)
        request('chunk-requires-valid-digest', 'PUT', receive + '?' + urllib.parse.urlencode(bad), content, (400, 409, 422), media='application/octet-stream')
        request('write-upload-chunk', 'PUT', receive + '?' + urllib.parse.urlencode(query), content, media='application/octet-stream')
        committed = request('commit-upload-session', 'POST', receive, {'operation': 'commit', 'id': session['id'], 'sourceKey': source_key,
                'sizeBytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()})
        assert (dirs['files'] / filename).read_bytes() == content
        results.append({'test': 'uploaded-name-and-bytes-match', 'passed': True})
        listing = request('list-uploaded-file', 'GET', '/api/v1/files?path=%2Ffixture')
        assert any(e.get('name') == filename for e in listing['entries'])
        path = '/fixture/' + filename
        request('stat-uploaded-file', 'GET', '/api/v1/files/entry?' + urllib.parse.urlencode({'path': path}))
        downloaded = request('read-uploaded-file', 'GET', '/api/v1/files/content?' + urllib.parse.urlencode({'path': path, 'disposition': 'attachment'}))
        assert downloaded == content
        results.append({'test': 'downloaded-bytes-match', 'passed': True})
        request('query-cannot-impersonate-body', 'POST', receive + '?json.input.name=safe', command, (400, 403))
        for index, name in enumerate(['../outside', '..', 'bad/name', 'bad\\name', '\x00bad', 'a' * 256, '.kpanel-upload-reserved']):
            invalid = {'operation': 'create', 'input': dict(command['input'], name=name, sourceKey=format(index + 10, '064x'))}
            request('reject-invalid-filename-' + str(index), 'POST', receive, invalid, (400, 403, 422))
        invalid = {'operation': 'create', 'input': dict(command['input'], name=42)}
        request('reject-non-string-name', 'POST', receive, invalid, 400)
        dirname = '0018.\u6d4b\u8bd5--\u76ee\u5f55'
        request('create-directory-literal-name', 'POST', '/api/v1/files/actions', {'action': 'mkdir', 'target': '/fixture', 'name': dirname})
        assert (dirs['files'] / dirname).is_dir()
        archive_name = '0019.\u6b4c\u624b--\u5f52\u6863.zip'
        job = request('create-archive-literal-name', 'POST', '/api/v1/files/archive-jobs',
                      {'operation': 'create', 'input': {'action': 'compress', 'sources': [path],
                       'target': '/fixture', 'name': archive_name, 'format': 'zip',
                       'expectedResourceVersions': {path: committed['entry']['resourceVersion']}}}, 202)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            current = request('archive-job-status', 'GET', '/api/v1/files/archive-jobs?' + urllib.parse.urlencode({'id': job['id']}))
            if current['state'] not in {'queued', 'running'}:
                break
            time.sleep(.1)
        assert current['state'] == 'complete', current.get('state')
        with zipfile.ZipFile(dirs['files'] / archive_name) as archive:
            assert archive.read(filename) == content
        results.append({'test': 'archive-original-name-and-bytes-match', 'passed': True})
        print(json.dumps({'passed': len(results), 'baseline': args.baseline, 'workspace': str(work)}), flush=True)
    finally:
        (work / 'results.json').write_text(json.dumps(results, indent=2))
        for name in reversed(created):
            p = subprocess.run(['docker', 'logs', name], capture_output=True)
            (work / (name + '.log')).write_bytes(p.stdout + p.stderr)
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True)


if __name__ == '__main__':
    main()
