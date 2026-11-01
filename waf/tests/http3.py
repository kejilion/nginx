#!/usr/bin/env python3
"""Real HTTP/1.1, HTTP/2 and QUIC regression in an isolated network namespace."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import policy


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f'{args}: {result.stdout} {result.stderr}')
    return result.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    args = parser.parse_args()
    work = args.work_dir.absolute()
    work.mkdir(mode=0o755)
    generated = work / 'waf'
    generated.mkdir()
    (work / 'index.html').write_text('http3 regression fixture\n')
    bundle = Path(__file__).resolve().parents[1]
    config = json.loads((bundle / 'example-policy.json').read_text())
    config.update(mode='on', cdn='direct')
    files = policy.bundle_files(config, policy.networks(json.loads((bundle / 'cloudflare-ips.json').read_text())))
    for name, content in files.items():
        (generated / name).write_text(content)
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-keyout', str(work / 'key.pem'), '-out', str(work / 'cert.pem'), '-subj', '/CN=h3.example')
    fixture = '''load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log error;
events { worker_connections 128; }
http {
    modsecurity on;
    include /etc/nginx/conf.d/waf/http.conf;
    server {
        listen 443 ssl;
        listen 443 quic reuseport;
        http2 on;
        http3 on;
        ssl_certificate /test/cert.pem;
        ssl_certificate_key /test/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        server_name h3.example;
        include /etc/nginx/conf.d/waf/server-default.inc;
        root /test;
    }
}
'''
    (work / 'nginx.conf').write_text(fixture)
    name = 'waf-http3-' + uuid.uuid4().hex[:10]
    results = []
    try:
        run('docker', 'run', '-d', '--pull=never', '--name', name, '--network=none',
            '--read-only', '--memory=256m', '--cpus=1', '--pids-limit=64',
            '--tmpfs', '/run', '--tmpfs', '/tmp', '--tmpfs', '/var/log/nginx',
            '--tmpfs', '/var/cache/nginx',
            '-v', str(work) + ':/test:ro',
            '-v', str(generated) + ':/etc/nginx/conf.d/waf:ro',
            '-v', str(work / 'nginx.conf') + ':/etc/nginx/nginx.conf:ro',
            '--entrypoint', 'nginx', args.image, '-g', 'daemon off;')
        pid = run('docker', 'inspect', '-f', '{{.State.Pid}}', name).strip()
        time.sleep(1)
        run('docker', 'exec', name, 'nginx', '-t')

        def check(label, protocol, path='/index.html', expected=200, headers=()):
            command = ['nsenter', '-t', pid, '-n', 'curl', '-sk', '--max-time', '10', protocol,
                       '--resolve', 'h3.example:443:127.0.0.1', '-o', str(work / 'response.txt'), '-w', '%{http_code} %{http_version}']
            for header in headers:
                command += ['-H', header]
            output = run(*command, 'https://h3.example' + path).strip()
            status, version = output.split()
            item = dict(test=label, status=int(status), protocol=version, passed=int(status) == expected)
            results.append(item)
            print(json.dumps(item), flush=True)
            assert item['passed'], item
            assert version == {'--http1.1':'1.1', '--http2':'2', '--http3-only':'3'}[protocol]
            if expected == 200:
                assert (work / 'response.txt').read_text() == 'http3 regression fixture\n'

        for protocol in ('--http1.1', '--http2', '--http3-only'):
            check('normal-' + protocol, protocol)
            check('sqli-' + protocol, protocol, '/index.html?id=1%20OR%201=1--', 403)
            check('xss-' + protocol, protocol, '/index.html?q=%3Cscript%3Ealert(1)%3C/script%3E', 403)
            check('secret-' + protocol, protocol, '/.env', 403)
        check('h3-without-authority', '--http3-only', expected=400, headers=('Host:',))
        # Client-controlled forwarding headers cannot activate the exception.
        check('h1-fake-protocol', '--http1.1', headers=('X-Forwarded-Proto: HTTP/3.0',))
        for version in ('HTTP/1.0', 'HTTP/3.0'):
            code = 'import socket,ssl; s=ssl._create_unverified_context().wrap_socket(socket.create_connection(("127.0.0.1",443)),server_hostname="h3.example"); s.sendall(' + repr(('GET /index.html ' + version + '\r\nX-Forwarded-Proto: HTTP/3.0\r\n\r\n').encode()) + '); print(s.recv(4096).split(b"\\r\\n")[0].decode())'
            output = run('nsenter', '-t', pid, '-n', 'python3', '-c', code)
            expected = 403 if version == 'HTTP/1.0' else 505
            results.append(dict(test='missing-host-' + version, response=output.strip(), passed=f' {expected} ' in output))
            assert results[-1]['passed'], results[-1]
        # Prove the original failure with exactly the same fixture and engine.
        fixed = files['modsecurity.conf']
        old = '\n'.join(line for line in fixed.splitlines() if 'id:200008,' not in line and 'ctl:ruleRemoveById=920280' not in line) + '\n'
        (generated / 'modsecurity.conf').write_text(old)
        run('docker', 'exec', name, 'nginx', '-s', 'reload')
        time.sleep(1)
        check('old-bundle-h3-reproduces', '--http3-only', expected=403)
        for mode in ('detect', 'off', 'on'):
            config['mode'] = mode
            # The native global switch owns Off; bundle generation alone does
            # not rewrite nginx.conf (configure.apply performs that step).
            (work / 'nginx.conf').write_text(fixture.replace('modsecurity on;',
                'modsecurity on;' if policy.engine_enabled(config) else 'modsecurity off;'))
            for filename, content in policy.bundle_files(config, policy.networks(json.loads((bundle / 'cloudflare-ips.json').read_text()))).items():
                (generated / filename).write_text(content)
            run('docker', 'exec', name, 'nginx', '-s', 'reload')
            time.sleep(1)
            check(mode + '-normal-h3', '--http3-only')
            check(mode + '-sqli-h3', '--http3-only', '/index.html?id=1%20OR%201=1--', 403 if mode == 'on' else 200)
        print(json.dumps({'passed':len(results)}), flush=True)
    finally:
        (work / 'results.json').write_text(json.dumps(results, indent=2))
        log = subprocess.run(['docker', 'logs', name], capture_output=True)
        (work / 'container.log').write_bytes(log.stdout + log.stderr)
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True)


if __name__ == '__main__':
    main()
