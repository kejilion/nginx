#!/usr/bin/env python3
"""Bounded, offline performance matrix. Never mounts a host's real Nginx config.

Requires Linux Docker, Go and openssl; all three containers have no public ports.
Results describe this fixture/hardware, not a promise of customer capacity.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import threading
import time
import uuid


def run(*args, timeout=90, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=timeout, **kwargs)


def load_policy(root):
    spec = importlib.util.spec_from_file_location('benchmark_policy', root / 'policy.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cgroup(container):
    pid = json.loads(run('docker', 'inspect', container).stdout)[0]['State']['Pid']
    rel = next(line.split(':', 2)[2] for line in Path(f'/proc/{pid}/cgroup').read_text().splitlines() if line.startswith('0::'))
    return Path('/sys/fs/cgroup') / rel.lstrip('/')


def resources(root):
    def pairs(name):
        return {k: int(v) for k, v in (line.split() for line in (root / name).read_text().splitlines())}
    return dict(cpu=pairs('cpu.stat'), memory=int((root / 'memory.current').read_text()), memoryStat=pairs('memory.stat'),
                events=pairs('memory.events'), io=(root / 'io.stat').read_text())


def assess(result, variant, workload, limit_boundary=False):
    """Validate responses separately from the count of completed HTTP transactions."""
    expected = 403 if workload.startswith('attack') and variant != 'off' else 200
    codes = {int(k): n for k, n in result['codes'].items()}
    allowed = {200, 429} if limit_boundary else {expected}
    unexpected = sum(n for code, n in codes.items() if code not in allowed)
    rate_evidence = not limit_boundary or (codes.get(200, 0) > 0 and codes.get(429, 0) > 0)
    return dict(expectedStatus=expected, allowedStatuses=sorted(allowed), expectedResponses=codes.get(expected, 0),
                expectedRps=codes.get(expected, 0) / result['elapsedSeconds'], unexpectedResponses=unexpected,
                limitBoundary=limit_boundary,
                responseValidationPassed=(result['requests'] > 0 and not unexpected and not result['networkErrors']
                                          and not result['skipped'] and rate_evidence))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image', required=True)
    p.add_argument('--work-dir', type=Path, required=True)
    p.add_argument('--baseline', type=Path, required=True, help='Immutable baseline waf directory')
    p.add_argument('--candidate', type=Path, help='Candidate waf directory; defaults to this tree')
    p.add_argument('--suite', choices=['probe', 'matrix', 'soak', 'guard'], default='probe')
    p.add_argument('--seconds', type=int, default=8)
    p.add_argument('--cpus', type=int, choices=[1, 2], default=1)
    p.add_argument('--sites', type=int, choices=[20, 200], default=20)
    p.add_argument('--early-blocking', action='store_true', help='Experiment only, not a runtime policy field')
    p.add_argument('--variants', default='off,baseline,candidate', help='Explicit order/subset of off,baseline,candidate')
    p.add_argument('--log-budget-mib', type=int, default=128, help='Live watchdog threshold (1..128 MiB)')
    args = p.parse_args()
    if not 4 <= args.seconds <= 120:
        p.error('Measurement window must be 4..120 seconds')
    if not 1 <= args.log_budget_mib <= 128:
        p.error('Log watchdog budget must be 1..128 MiB')
    log_budget = args.log_budget_mib * 1024 * 1024
    variants = args.variants.split(',')
    if not variants or len(variants) != len(set(variants)) or set(variants) - {'off', 'baseline', 'candidate'}:
        p.error('Invalid variant set')
    work = args.work_dir.absolute()
    if work.exists() or len(str(work / 'front.sock')) > 103:
        p.error('Use a new short evidence path')
    work.mkdir(parents=True, mode=0o755)
    os.chmod(work, 0o755)
    source = Path(__file__).resolve().parent
    candidate = (args.candidate or source.parent).absolute()
    baseline = args.baseline.absolute()
    # Tool and source identity are saved before load begins.
    identity = {'image': args.image, 'imageInspect': json.loads(run('docker', 'image', 'inspect', args.image).stdout)[0],
                'cpuCount': os.cpu_count(), 'uname': run('uname', '-a').stdout.decode().strip(),
                'go': run('go', 'version').stdout.decode().strip(),
                'cpus': args.cpus, 'memoryLimitMiB': 512 if args.cpus == 1 else 1024,
                'sites': args.sites, 'suite': args.suite, 'variants': variants, 'earlyBlockingExperiment': args.early_blocking,
                'logWatchdogMiB': args.log_budget_mib,
                'sources': {str(root): {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in root.glob('*.py')} for root in (baseline, candidate)},
                'harnessSHA256': {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in (source/'performance.py', source/'performance_client.go')},
                'startedAt': time.time(), 'limits': 'No external network or host configuration mounts; origin is a fixture; proxy identity is simulated; not a real CDN benchmark.'}
    # Docker image inspect may contain benign build metadata but never runtime env/secrets.
    (work / 'identity.json').write_text(json.dumps(identity, indent=2))
    run('go', 'build', '-trimpath', '-o', str(work / 'runner'), str(source / 'performance_client.go'),
        env=dict(os.environ, CGO_ENABLED='0', GOTOOLCHAIN='local'), timeout=120)
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(work / 'key.pem'),
        '-out', str(work / 'cert.pem'), '-days', '1', '-subj', '/CN=127.0.0.1',
        '-addext', 'subjectAltName=IP:127.0.0.1')
    (work / 'key.pem').chmod(0o600)
    (work / 'asset.txt').write_bytes(b'A' * 1024)
    for name in ('logs', 'generated'):
        (work / name).mkdir()
    baseconfig = json.loads((baseline / 'example-policy.json').read_text())
    profiles = ['generic', 'api', 'wordpress', 'generic', 'upload', 'streaming', 'generic', 'api', 'artifact-proxy', 'kpanel']
    sites = {f'{prefix}{i}.example': {'profile': profiles[i % len(profiles)]}
             for prefix in ('direct', 'proxy') for i in range(args.sites // 2)}
    baseconfig.update(mode='on', cdn='direct', banBackend='none', sites=sites)
    # Capacity cells distribute clients. Default rate/connection limits remain active.
    cf = load_policy(baseline).networks(json.loads((baseline / 'cloudflare-ips.json').read_text()))
    (work / 'policy.json').write_text(json.dumps(baseconfig, indent=2))
    uid = uuid.uuid4().hex[:10]
    origin, nginx, client = (f'waf-perf-{uid}-{part}' for part in ('origin', 'nginx', 'client'))
    owned = []
    def interrupted(signum, _frame):
        raise TimeoutError(f'Performance job interrupted by signal {signum}')
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(signum, interrupted)
    signal.alarm(1800)
    (work / 'containers.json').write_text(json.dumps([origin, nginx, client]))

    def container(name, cpu, memory, entrypoint, rest, network='none', mounts=()):
        cmd = ['docker', 'run', '-d', '--pull=never', '--name', name, '--network', network,
               '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=128',
               '--cpuset-cpus', cpu, '--memory', memory, '--memory-swap', memory,
               '--tmpfs', '/tmp:rw,nosuid,size=64m', '--tmpfs', '/run:rw,nosuid,size=8m',
               '--tmpfs', '/var/cache/nginx:rw,nosuid,size=64m',
               '--mount', f'type=bind,src={work},dst=/test', *mounts,
               '--entrypoint', entrypoint, args.image, *rest]
        # The owned unique name is registered before starting, so failed starts are cleaned too.
        owned.append(name)
        run(*cmd)

    def wait_path(path):
        for _ in range(100):
            if path.exists():
                return
            time.sleep(.1)
        raise RuntimeError(f'Fixture socket not ready: {path}')

    def logs_size():
        return {f.name: f.stat().st_size for f in (work / 'logs').glob('*') if f.is_file()}

    results = []
    try:
        container(origin, '3', '256m', '/test/runner', ['-mode', 'backend', '-socket', '/test/backend.sock'])
        wait_path(work / 'backend.sock')
        for variant in variants:
            if nginx in owned:
                run('docker', 'rm', '-f', nginx)
                owned.remove(nginx)
            front = work / 'front.sock'
            if front.exists():
                front.unlink()
            root = baseline if variant in ('off', 'baseline') else candidate
            files = load_policy(root).bundle_files(baseconfig, cf)
            if variant == 'candidate' and args.early_blocking:
                files['profile-rules.conf'] += 'SecAction "id:1113,phase:1,pass,nolog,t:none,setvar:tx.early_blocking=1"\n'
            for name, content in files.items():
                (work / 'generated' / name).write_text(content)
            blocks = []
            for name in sites:
                trust = 'set_real_ip_from unix:; set_real_ip_from 127.0.0.1/32; real_ip_header CF-Connecting-IP;' if name.startswith('proxy') else ''
                blocks.append('server { listen unix:/test/front.sock; listen 127.0.0.1:18443 ssl; server_name ' + name + '; ' + trust + '''
include /etc/nginx/conf.d/waf/server-default.inc;
location = /asset.txt { root /test; }
location / { proxy_http_version 1.1; proxy_set_header Connection ""; proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $remote_addr;
proxy_buffering off; proxy_pass http://fixture_origin; }
}''')
            # Per-server trust above is a test-only substitute for a real CDN peer.
            text = f'''load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;
user root;
worker_processes {args.cpus};
pid /run/nginx.pid;
error_log /var/log/nginx/error.log error;
events {{ worker_connections 2048; }}
http {{
include /etc/nginx/mime.types;
server_names_hash_bucket_size 128;
server_names_hash_max_size 1024;
variables_hash_max_size 2048;
modsecurity {'off' if variant == 'off' else 'on'};
include /etc/nginx/conf.d/waf/http.conf;
access_log /var/log/nginx/access.log combined buffer=32k flush=1s;
keepalive_timeout 10s;
keepalive_requests 10000;
client_max_body_size 16m;
client_body_buffer_size 128k;
ssl_certificate /test/cert.pem;
ssl_certificate_key /test/key.pem;
ssl_protocols TLSv1.3;
ssl_session_cache shared:SSL:1m;
http2 on;
upstream fixture_origin {{ server unix:/test/backend.sock; keepalive 64; }}
''' + '\n'.join(blocks) + '\n}\n'
            config_file = work / 'nginx.conf'
            config_file.write_text(text)
            snapshots = work / variant
            snapshots.mkdir()
            shutil.copytree(work / 'generated', snapshots / 'generated')
            shutil.copyfile(config_file, snapshots / 'nginx.conf')
            start = time.monotonic()
            container(nginx, '0' if args.cpus == 1 else '0,1', '512m' if args.cpus == 1 else '1024m', 'nginx', ['-g', 'daemon off;'],
                      mounts=['--mount', f'type=bind,src={config_file},dst=/etc/nginx/nginx.conf,readonly',
                              '--mount', f'type=bind,src={work / "generated"},dst=/etc/nginx/conf.d/waf,readonly',
                              '--mount', f'type=bind,src={work / "logs"},dst=/var/log/nginx'])
            wait_path(front)
            syntax = run('docker', 'exec', nginx, 'nginx', '-t')
            (snapshots / 'nginx-t.log').write_bytes(syntax.stdout + syntax.stderr)
            rootcg = cgroup(nginx)
            startup = {'seconds': time.monotonic() - start, 'memoryBytes': resources(rootcg)['memory']}
            container(client, '2', '256m', '/bin/sleep', ['1800'], network='container:' + nginx)
            clientcg, origincg = cgroup(client), cgroup(origin)
            def cell(workload='static', rate=100, concurrency=32, target='unix', identity_mode='proxy', duration=None, record=True, host_count=None):
                if sum(logs_size().values()) > log_budget:
                    raise RuntimeError('Fixture logs exceeded watchdog budget; stopping without deleting evidence')
                before = resources(rootcg)
                aux = {'client': resources(clientcg), 'origin': resources(origincg)}
                log_before = logs_size()
                samples, stop = [], threading.Event()
                def sample():
                    while not stop.wait(.25):
                        samples.append(resources(rootcg))
                        size, free = sum(logs_size().values()), shutil.disk_usage(work).free
                        if size > log_budget or free < 512 * 1024 * 1024:
                            (work / 'budget-failure.json').write_text(json.dumps(dict(logBytes=size, freeBytes=free, variant=variant, workload=workload)))
                            stop.set()
                            # Stop only this job's load container, then let finally retain logs/clean up.
                            subprocess.run(['docker', 'kill', client], capture_output=True, timeout=10)
                            return
                thread = threading.Thread(target=sample, daemon=True)
                thread.start()
                at = time.monotonic()
                try:
                    response = run('docker', 'exec', '-e', 'GOMAXPROCS=1', client, '/test/runner', '-workload', workload,
                                   '-duration', f'{duration or args.seconds}s', '-rate', str(rate), '-concurrency', str(concurrency),
                                   '-hosts', str(host_count or args.sites // 2), '-identity', identity_mode, '-target', target,
                                   '-expected-status', str(403 if workload.startswith('attack') and variant != 'off' else 200),
                                   timeout=(duration or args.seconds) + 15)
                finally:
                    stop.set()
                    thread.join(2)
                elapsed = time.monotonic() - at
                if (work / 'budget-failure.json').exists() or sum(logs_size().values()) > log_budget or shutil.disk_usage(work).free < 512 * 1024 * 1024:
                    raise RuntimeError('Resource watchdog budget exceeded; retained evidence')
                after = resources(rootcg)
                result = json.loads(response.stdout)
                result.update(assess(result, variant, workload, host_count == 1 and identity_mode == 'direct'))
                result.update(variant=variant, cpuCores=args.cpus, sites=args.sites, startup=startup,
                              serverCpuPercent=(after['cpu']['usage_usec'] - before['cpu']['usage_usec']) / elapsed / 10000,
                              memoryPeakBytes=max(s['memory'] for s in [before, after, *samples]),
                              memoryEndBytes=after['memory'], memoryEventsDelta={k: after['events'][k] - before['events'][k] for k in after['events']},
                              anonymousPeakBytes=max(s['memoryStat']['anon'] for s in [before, after, *samples]),
                              anonymousEndBytes=after['memoryStat']['anon'],
                              cpuThrottledUsec=after['cpu'].get('throttled_usec', 0) - before['cpu'].get('throttled_usec', 0),
                              logBytesDelta={k: n - log_before.get(k, 0) for k, n in logs_size().items()},
                              auxiliaryCpuPercent={k: (resources(cg)['cpu']['usage_usec'] - aux[k]['cpu']['usage_usec']) / elapsed / 10000 for k, cg in [('client', clientcg), ('origin', origincg)]},
                              memorySamples=[s['memory'] for s in samples], anonymousSamples=[s['memoryStat']['anon'] for s in samples],
                              sampleIntervalSeconds=.25, ioBefore=before['io'], ioAfter=after['io'])
                if record:
                    results.append(result)
                    with (work / 'results.jsonl').open('a') as f:
                        f.write(json.dumps(result) + '\n')
                    print(json.dumps({k: result[k] for k in ['variant', 'workload', 'target', 'identity', 'targetRps', 'expectedRps', 'codes', 'skipped', 'responseValidationPassed', 'p99Ms', 'serverCpuPercent', 'memoryPeakBytes']}), flush=True)
                if not result['responseValidationPassed'] or result['memoryEventsDelta'].get('oom_kill'):
                    raise RuntimeError('Unexpected response, incomplete offered load, network error or OOM; retained raw result')
                return result
            cell(rate=50, duration=4, record=False)
            if args.suite == 'guard':
                cell('static', 0, concurrency=8)
            elif args.suite == 'probe':
                for kind, rate in [('static', 100), ('json', 50), ('json64', 2), ('upload', 5), ('attack-json', 3), ('attack', 10)]:
                    cell(kind, rate)
            elif args.suite == 'matrix':
                for kind, rate in [('static', 50), ('static', 100), ('static', 150 * args.cpus), ('json', 25), ('json', 50 * args.cpus), ('json64', 2 * args.cpus), ('upload', 5 * args.cpus), ('attack-json', 3 * args.cpus), ('attack', 10 * args.cpus)]:
                    cell(kind, rate)
                for kind in ('static', 'json'):
                    cell(kind, 50, target='tls')
                    cell(kind, 50, identity_mode='direct')
                cell('sse', 0, concurrency=64)
                for kind in ('static', 'json'):
                    cell(kind, 0, concurrency=8)
                cell('json64', 0, concurrency=2)
                cell('static', 100, identity_mode='direct', host_count=1)
            else:
                cell('json', 50 * args.cpus, duration=args.seconds)
                cell('upload', 5, duration=args.seconds)
                # Recovery after load: 100 requests/s must still remain usable.
                cell('static', 100, duration=8)
            run('docker', 'rm', '-f', client)
            owned.remove(client)
        (work / 'results.json').write_text(json.dumps({'identity': identity, 'results': results, 'complete': True}, indent=2))
    finally:
        signal.alarm(0)
        for name in reversed(owned):
            log = subprocess.run(['docker', 'logs', '--tail', '200', name], capture_output=True, timeout=15)
            (work / f'{name}.log').write_bytes(log.stdout + log.stderr)
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=30)


if __name__ == '__main__':
    main()
