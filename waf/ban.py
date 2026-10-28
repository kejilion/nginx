#!/usr/bin/env python3
"""Fail2Ban event adapter: site-scoped origin bans and optional CF custom rules.

No daemon and no account-wide IP access rules. Only our uniquely referenced
zone rules are changed. Cron retries failed edge sync and expires local state.
"""
from __future__ import annotations
import argparse
import copy
import contextlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request
import uuid

import configure as manage
import nginx_edit
import policy

PHASE = 'http_request_firewall_custom'
MARKER = '# Managed shared WAF; unified event bans v1\n'
DISABLED = MARKER+'[waf-attack]\nenabled = false\n[waf-rate]\nenabled = false\n'
MAX_EXPRESSION = 4096
F2B = Path('/etc/fail2ban')


def read(root, name, default):
    path = root / 'config/waf' / name
    value = manage.load_json(path, default)
    if path.exists() and path.stat().st_mode & 0o077:
        raise ValueError('Private ban state permissions required')
    return value


def save(root, name, value):
    data=(json.dumps(value, sort_keys=True)+'\n').encode()
    if len(data)>policy.MAX_STATE_BYTES:
        raise ValueError('Ban state byte budget exceeded')
    manage.atomic(root / 'config/waf' / name,data)


def state(root):
    if not (root/'config/waf/bans.json').exists() and read(root,'ban-cf.json',{}).get('auth'):
        raise ValueError('CF owner state is missing; restore bans.json before cleanup')
    value = read(root, 'bans.json', {'owner': uuid.uuid4().hex, 'records': {}})
    if not re.fullmatch('[a-f0-9]{32}', value.get('owner', '')):
        raise ValueError('Invalid ban state owner')
    if len(value['records']) > policy.MAX_BANS:
        raise ValueError('Ban state budget exceeded')
    for key, sources in value['records'].items():
        policy.key(key)
        if set(sources) - {'attack', 'rate'}:
            raise ValueError('Invalid ban source')
        if any(type(expiry) is not int for expiry in sources.values()):
            raise ValueError('Invalid ban expiry')
    return value


def live_records(value, now):
    return {key: {source: expiry for source, expiry in sources.items() if expiry > now}
            for key, sources in value['records'].items() if any(x > now for x in sources.values())}


def inventory(root):
    result = {}
    owners = {}
    paths = sorted((root/'conf.d').glob('*.conf'))
    if len(paths) > 250:
        raise ValueError('Site inventory budget exceeded')
    for path in paths:
        for block in nginx_edit.server_blocks(manage.read_config(path)):
            if not block['names'] or block['names'][0] == '_':
                continue
            name = block['names'][0]
            aliases = sorted(set(block['names']))
            for alias in aliases:
                if alias in owners and owners[alias]!=name:
                    raise ValueError('Conflicting site alias: '+alias)
                owners[alias]=name
            if name in result and result[name] != aliases:
                raise ValueError('Ambiguous site aliases')
            result[name] = aliases
    if len(result) > policy.MAX_SITES:
        raise ValueError('Site inventory budget exceeded')
    return result


class Cloudflare:
    def __init__(self, auth):
        self.auth = auth
        self.deadline = time.monotonic()+40

    def request(self, method, path, body=None, missing=False):
        if not re.fullmatch(r'/[A-Za-z0-9_/?=&.-]+', path):
            raise ValueError('Invalid CF resource path')
        headers = {'Content-Type': 'application/json'}
        if self.auth.get('email'):
            headers.update({'X-Auth-Email': self.auth['email'], 'X-Auth-Key': self.auth['key']})
        else:
            headers['Authorization'] = 'Bearer '+self.auth['key']
        req = urllib.request.Request('https://api.cloudflare.com/client/v4'+path,
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers=headers, method=method)
        try:
            remaining = self.deadline-time.monotonic()
            if remaining <= 0:
                raise RuntimeError('CF synchronization time budget exceeded')
            # Never forward credentials through an HTTP redirect.
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *_args, **_kwargs):
                    return None
            with urllib.request.build_opener(NoRedirect).open(req, timeout=min(5, remaining)) as response:
                data = response.read(2*1024*1024+1)
        except urllib.error.HTTPError as error:
            if missing and error.code == 404:
                return None
            raise RuntimeError('Cloudflare HTTP failure '+str(error.code)) from None
        except (OSError, ValueError):
            raise RuntimeError('Cloudflare connection failed') from None
        if len(data) > 2*1024*1024:
            raise ValueError('CF response budget exceeded')
        parsed = json.loads(data)
        if parsed.get('success') is not True:
            raise RuntimeError('Cloudflare rejected the operation')
        return parsed

    def zones(self):
        zones = []
        for page in range(1, 5):
            data = self.request('GET', '/zones?status=active&per_page=50&page='+str(page))
            zones += data['result']
            if page >= data.get('result_info', {}).get('total_pages', 1):
                break
        else:
            raise ValueError('More than 200 zones; use a scoped API token')
        return {item['name']: item['id'] for item in zones}


def targets(root, config, zones):
    result = {}
    for site, aliases in inventory(root).items():
        mode = config['sites'].get(site, {}).get('cdn', config['cdn'])
        if mode not in {'cloudflare', 'mixed'}:
            continue
        entries = []
        for alias in aliases:
            # Explicit hostnames only: wildcard ownership/alias expansion needs
            # a separate mapping, never widen a ban to the whole zone.
            if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', alias) or '.' not in alias:
                raise ValueError('CF bans require explicit DNS hostnames: '+site)
            matches = [z for z in zones if alias == z or alias.endswith('.'+z)]
            if not matches:
                raise ValueError('No accessible active CF zone for '+alias)
            zone = zones[max(matches, key=len)]
            if not re.fullmatch('[a-f0-9]{32}', zone):
                raise ValueError('Invalid CF zone ID')
            entries.append({'host': alias, 'zone': zone})
        result[site] = entries
    if not result:
        raise ValueError('No Cloudflare/mixed sites to protect')
    return result


def expressions(records, mapping, overflow=None):
    grouped = {}
    for raw in sorted(records):
        site, address = policy.key(raw)
        for target in mapping.get(site, []):
            grouped.setdefault(target['zone'], {}).setdefault(target['host'], set()).add(address)
    result = {}
    for zone, hosts in grouped.items():
        expression = ' or '.join('(lower(http.host) eq '+json.dumps(host)+' and ip.src in {'+
                                 ' '.join(sorted(ips))+'})' for host, ips in sorted(hosts.items()))
        if len(expression.encode()) > MAX_EXPRESSION:
            if overflow is None:
                raise ValueError('Cloudflare expression limit; origin bans remain active')
            overflow.append(zone)
            expression='false'
        result[zone] = expression
    return result


def sync_edge(cf, value, client=None):
    if not cf.get('auth'):
        return
    client = client or Cloudflare(cf['auth'])
    zones = sorted(set(cf.get('zones', [])) | {t['zone'] for items in cf['targets'].values() for t in items})
    if len(zones)>20 or any(not re.fullmatch('[a-f0-9]{32}', z) for z in zones):
        raise ValueError('CF zone budget exceeded (maximum 20)')
    active_zones={t['zone'] for entries in cf['targets'].values() for t in entries}
    desired = {zone: 'false' for zone in active_zones} if cf['mode'] == 'cloudflare' else {}
    overflow=[]
    if cf['mode'] == 'cloudflare':
        desired.update(expressions(value['records'], cf['targets'],overflow))
    ref = 'kejilion_waf_'+value['owner']
    # Rotate the starting zone so repeated timeouts cannot starve later zones.
    offset=int(time.time()//60)%len(zones) if zones else 0
    zones=zones[offset:]+zones[:offset]
    for zone in zones:
        base = '/zones/'+zone+'/rulesets'
        data = client.request('GET', base+'/phases/'+PHASE+'/entrypoint', missing=True)
        expression = desired.get(zone)
        if data is None:
            # Empty entrypoint creation never replaces any existing ruleset.
            if expression is None:
                continue
            data = client.request('POST', base, {'name': 'Zone custom rules', 'kind': 'zone',
                                                 'phase': PHASE, 'rules': []})
        ruleset = data['result']
        ident = ruleset['id']
        if not re.fullmatch('[a-f0-9]{32}', ident):
            raise ValueError('Invalid CF ruleset ID')
        found = [rule for rule in ruleset.get('rules', []) if rule.get('ref') == ref]
        if len(found) > 1:
            raise ValueError('Duplicate managed CF rules')
        rule = found[0] if found else None
        if rule and (rule.get('description') != ref or rule.get('action') != 'block'):
            raise ValueError('Managed CF rule changed externally')
        endpoint = base+'/'+ident+'/rules'
        if rule:
            if not re.fullmatch('[a-f0-9]{32}', rule['id']):
                raise ValueError('Invalid CF rule ID')
            endpoint += '/'+rule['id']
        if expression is None:
            if rule:
                client.request('DELETE', endpoint)
        elif not rule or rule.get('expression') != expression or not rule.get('enabled', True):
            body = {'ref': ref, 'description': ref, 'action': 'block',
                    'expression': expression, 'enabled': True}
            if not rule:
                body['position']={'index':1}
            client.request('PATCH' if rule else 'POST', endpoint, body)
    if overflow:
        raise ValueError('CF capacity exceeded; affected edge rules cleared, origin bans retained')


def origin(root, config, value):
    records = {key: {'expires': max(sources.values())} for key, sources in value['records'].items()}
    data = policy.render_bans(records, int(time.time())).encode()
    path = root/'conf.d/waf/blocked.map'
    before = manage.read_config(path).encode()
    if before == data:
        return
    manage.atomic(path, data, 0o644)
    try:
        manage.execute('docker', 'exec', config['container'], 'nginx', '-t')
        manage.reload_nginx(config['container'])
    except Exception:
        manage.atomic(path, before, 0o644)
        manage.execute('docker', 'exec', config['container'], 'nginx', '-s', 'reload')
        raise


def reconcile(root, config, value, cf, edge=True):
    value['records'] = live_records(value, int(time.time()))
    # Persist desired TTL state before changing either enforcement point. Cron
    # retries an interrupted or failed operation, including an overdue unban.
    save(root, 'bans.json', value)
    try:
        origin(root, config, value)
        if edge:
            changed=False
            if cf.get('mode')=='cloudflare':
                current=inventory(root)
                expected={site:aliases for site,aliases in current.items()
                          if config['sites'].get(site,{}).get('cdn',config['cdn']) in {'cloudflare','mixed'}}
                known={site:sorted(t['host'] for t in entries) for site,entries in cf['targets'].items()}
                changed=expected!=known
                cf=dict(cf,targets={site:[t for t in entries if t['host'] in expected.get(site,[])]
                                    for site,entries in cf['targets'].items() if site in expected})
            sync_edge(cf, value)
            if changed:
                raise ValueError('CF site inventory changed; stale rules cleaned, reconfigure CF mode')
    except Exception:
        save(root, 'ban-health.json', {'ok': False, 'checked': int(time.time()),
                                     'error': 'Ban enforcement synchronization failed'})
        raise
    if edge:
        save(root, 'ban-health.json', {'ok': True, 'checked': int(time.time()),
                                     'originGeneration':value.get('generation',0),'syncedGeneration':value.get('generation',0)})
    else:
        health=read(root,'ban-health.json',{'ok':False,'checked':0})
        health['pending']=True
        health['originGeneration']=value.get('generation',0)
        save(root,'ban-health.json',health)


def stage(root, operation, identity, source, seconds, started):
    # Persist the desired event without holding the configuration lock. If an
    # upgrade is busy, cron can replay it after that transaction completes.
    with manage.locked(root/'config/waf/ban.lock',timeout=90):
        config=policy.validate(manage.load_json(root/'config/waf/policy.json'))
        value=state(root)
        value['records']=live_records(value,int(time.time()))
        site,address=policy.key(identity)
        identity=site+'|'+address
        if source not in {'attack','rate'}:
            raise ValueError('Invalid event source')
        if operation=='ban':
            proxies=policy.networks(manage.load_json(root/'config/waf/cloudflare-ips.json'))
            proxies+=config.get('trustedProxies',[])+config.get('banIgnore',[])
            proxies+=[p for s in config['sites'].values() for p in s.get('trustedProxies',[])]
            local=json.loads(manage.execute('ip','-j','address','show'))
            proxies+=[a['local'] for interface in local for a in interface.get('addr_info',[])]
            if site not in inventory(root) or not policy.eligible(address,proxies):
                raise ValueError('Untrusted site or protected infrastructure address')
            if type(seconds) is not int or not 60<=seconds<=3600:
                raise ValueError('Ban duration outside supported range')
            if started is None or not __import__('math').isfinite(started) or started>time.time()+5:
                raise ValueError('Valid original ticket time required')
            if identity not in value['records'] and len(value['records'])>=policy.MAX_BANS:
                raise ValueError('Ban budget exceeded')
            expiry=int(started)+seconds
            if expiry>time.time():
                value['records'].setdefault(identity,{})[source]=expiry
        elif identity in value['records']:
            value['records'][identity].pop(source,None)
        value['records']=live_records(value,int(time.time()))
        rendered=policy.render_bans({key:{'expires':max(items.values())} for key,items in value['records'].items()},int(time.time()))
        if len(rendered.encode())>2*1024*1024:
            raise ValueError('Origin map byte budget exceeded')
        value['generation']=value.get('generation',0)+1
        save(root,'bans.json',value)


def query_tickets(source):
    process=__import__('subprocess').run(['fail2ban-client','get','waf-'+source,'banip'],capture_output=True,text=True,timeout=5)
    if process.returncode or len(process.stdout)>policy.MAX_STATE_BYTES:
        raise ValueError('Cannot read complete Fail2Ban tickets')
    tickets=set(process.stdout.split())
    if len(tickets)>policy.MAX_BANS:raise ValueError('Ticket budget exceeded')
    for ticket in tickets:policy.key(ticket)
    return tickets


def ticket_snapshot(root):
    # RPC must stay outside configuration/ban locks: a simultaneous unban can
    # wait for its action process, which itself needs those locks.
    generation=state(root).get('generation',0)
    try:
        return {'generation':generation,'sources':{source:query_tickets(source) for source in ['attack','rate']}}
    except Exception:
        return None  # Unavailable/restarting jail is not proof of a removal.


def reconcile_tickets(value,snapshot):
    if snapshot is None or value.get('generation',0)!=snapshot['generation']:
        return
    for identity,sources in value['records'].items():
        for source in list(sources):
            if identity not in snapshot['sources'][source]:
                sources.pop(source)
                value['generation']=value.get('generation',0)+1


def change(root, operation, identity=None, source=None, seconds=None, lock_held=False, started=None):
    if operation in {'ban','unban'}:
        stage(root,operation,identity,source,seconds,started)
        operation='local'
    snapshot=ticket_snapshot(root) if operation=='sync' and not lock_held else None
    try:
        return _change(root,operation,lock_held,snapshot)
    except RuntimeError as error:
        if operation=='local' and str(error)=='Configuration is busy; retry later':
            return  # Desired ticket is persisted; the next sync replays it.
        raise


def _change(root,operation,lock_held,snapshot):
    with contextlib.nullcontext() if lock_held else manage.locked(root/'config/waf/install.lock',timeout=0 if operation=='local' else 10):
      with manage.locked(root/'config/waf/ban.lock',timeout=10):
        config = policy.validate(manage.load_json(root/'config/waf/policy.json'))
        if config.get('banBackend') != 'existing' and operation not in {'clear','sync'}:
            raise ValueError('Unified origin ban hook is not enabled')
        value = state(root)
        value['records'] = live_records(value, int(time.time()))
        if operation=='sync':
            reconcile_tickets(value,snapshot)
        cf = read(root, 'ban-cf.json', {'mode': 'local'})
        if operation == 'clear':
            value['records'] = {}
        reconcile(root, config, value, cf, edge=operation in {'sync','clear'})


def configure_cf(root, auth=None, disable=False):
    if disable and not (root/'config/waf/ban-cf.json').exists() and not (root/'config/waf/bans.json').exists():
        return status(root)
    if not disable and not status(root)['running']:
        raise ValueError('Install and start unified Fail2Ban jails first')
    with manage.locked(root/'config/waf/install.lock',timeout=10), manage.locked(root/'config/waf/ban.lock',timeout=10):
        value = state(root)
        previous = read(root, 'ban-cf.json', {'mode': 'local'})
        if disable:
            cf = dict(previous, mode='local')
        else:
            if previous.get('mode') == 'cloudflare' and previous.get('auth') != auth:
                raise ValueError('Disable CF mode before changing credentials')
            if not isinstance(auth, dict) or set(auth) != {'email', 'key'}:
                raise ValueError('Expected email/key credentials on stdin')
            if not isinstance(auth['key'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{20,200}', auth['key']):
                raise ValueError('Invalid CF key/token')
            if not isinstance(auth['email'], str) or (auth['email'] and not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', auth['email'])):
                raise ValueError('Invalid CF email')
            config = policy.validate(manage.load_json(root/'config/waf/policy.json'))
            client = Cloudflare(auth)
            mapping = targets(root, config, client.zones())
            historical=set(previous.get('zones', [])) | {t['zone'] for entries in previous.get('targets',{}).values() for t in entries}
            historical.update(t['zone'] for entries in mapping.values() for t in entries)
            if len(historical)>20 or any(not re.fullmatch('[a-f0-9]{32}',z) for z in historical):
                raise ValueError('CF zone budget exceeded; previous configuration retained')
            cf = {'mode': 'cloudflare', 'auth': auth, 'targets': mapping,'zones': sorted(historical)}
        # Keep desired configuration and credentials on failure so the scheduled
        # retry can repair partial remote writes; never falsely report healthy.
        save(root, 'ban-cf.json', cf)
        config = policy.validate(manage.load_json(root/'config/waf/policy.json'))
        reconcile(root, config, value, cf)
        if disable:
            save(root, 'ban-cf.json', {'mode': 'local'})
    return status(root)


def status(root):
    cf = read(root, 'ban-cf.json', {'mode': 'local'})
    health = read(root, 'ban-health.json', {'ok': False, 'checked': 0})
    jail = F2B/'jail.d/zz-waf-managed.local'
    configured = jail.exists() and manage.read_config(jail).startswith(MARKER)
    running = False
    if configured:
        try:
            for name in ['waf-attack', 'waf-rate']:
                manage.execute('fail2ban-client', 'status', name)
            running = True
        except Exception:
            pass
    healthy = health.get('ok') is True and 0 <= int(time.time())-health.get('checked', 0) <= 180
    value=state(root)
    healthy=healthy and health.get('originGeneration')==value.get('generation',0)
    pending=health.get('syncedGeneration')!=value.get('generation',0)
    return {'mode': cf['mode'], 'cleanupPending':cf['mode']=='local' and bool(cf.get('auth')),
            'configured': configured, 'running': running,
            'healthy': healthy and running, 'pending': pending,
            'activeBans': len(live_records(value, int(time.time())))}


def install(root):
    """Explicit migration entry point; SSH/custom jails are left intact."""
    with manage.locked(root/'config/waf/install.lock',timeout=10):
        return _install(root)


def set_cron(text):
    process = __import__('subprocess').run(['crontab', '-'], input=text, capture_output=True, text=True, timeout=10)
    if process.returncode:
        raise RuntimeError('Failed to update ban expiry schedule')


def clear(root):
    # Remove Fail2Ban's tickets/database records as well as our projection, so
    # a later reload cannot resurrect a manually cleared ban.
    # Callbacks persist their source removal and immediately defer a busy
    # configuration lock. Thus one final reload replaces per-ticket reloads.
    with manage.locked(root/'config/waf/install.lock',timeout=10):
        for source in ['attack','rate']:
            tickets=sorted(query_tickets(source))
            for offset in range(0,len(tickets),100):
                manage.execute('fail2ban-client','set','waf-'+source,'unbanip',*tickets[offset:offset+100])
        change(root,'clear',lock_held=True)


def remove(root):
    initial=policy.validate(manage.load_json(root/'config/waf/policy.json'))
    cf=read(root,'ban-cf.json',{'mode':'local'})
    if initial.get('banBackend')=='none' and not state(root)['records'] and cf=={'mode':'local'}:
        return {'updated':False}
    configure_cf(root,disable=True)
    clear(root)
    with manage.locked(root/'config/waf/install.lock',timeout=10):
        jail=F2B/'jail.d/zz-waf-managed.local'
        if not jail.exists() or not manage.read_config(jail).startswith(MARKER):
            raise ValueError('Only the unified managed integration can be removed')
        config=policy.validate(manage.load_json(root/'config/waf/policy.json'))
        cron=__import__('subprocess').run(['crontab','-l'],capture_output=True,text=True,timeout=10)
        if cron.returncode and 'no crontab' not in cron.stderr.lower():
            raise ValueError('Cannot read expiry schedule')
        text=''.join(line+'\n' for line in cron.stdout.splitlines() if not line.endswith('# kejilion-waf-bans'))
        def deactivate():
            manage.execute('fail2ban-client','-t')
            manage.execute('fail2ban-client','reload')
            change(root,'sync',lock_held=True)
            set_cron(text)
            manage.apply(root,dict(config,banBackend='none'),lock_held=True)
        try:
            return manage._external_update(root,{jail:DISABLED.encode()},'remove-bans',deactivate)
        except Exception:
            try:set_cron(cron.stdout)
            finally:manage.execute('fail2ban-client','reload')
            raise


def _install(root):
    config = policy.validate(manage.load_json(root/'config/waf/policy.json'))
    if not __import__('shutil').which('fail2ban-client') or not __import__('shutil').which('crontab'):
        raise ValueError('Install Fail2Ban and enable the existing cron service first')
    json.loads(manage.execute('ip','-j','address','show'))
    directory = root/'conf.d/waf'
    runner = directory/'ban.py'
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(root)):
        raise ValueError('Unsupported integration path')
    jail = F2B/'jail.d/zz-waf-managed.local'
    if jail.exists() and not manage.read_config(jail).startswith(MARKER):
        raise ValueError('Custom/previous ban backend requires explicit migration')
    existing_map = manage.read_config(directory/'blocked.map')
    if not (root/'config/waf/bans.json').exists() and any(line.strip() and not line.lstrip().startswith('#') for line in existing_map.splitlines()):
        raise ValueError('Existing bans require expiry-aware migration')
    cron = __import__('subprocess').run(['crontab', '-l'], capture_output=True, text=True, timeout=10)
    if cron.returncode and 'no crontab' not in cron.stderr.lower():
        raise ValueError('Unable to preserve existing crontab')
    command = f'* * * * * {sys.executable} -E -s -B {runner} --root {root} sync # kejilion-waf-bans\n'
    cron_text = ''.join(line+'\n' for line in cron.stdout.splitlines() if not line.endswith('# kejilion-waf-bans'))+command
    config_before = copy.deepcopy(config)
    config['banBackend'] = 'existing'
    timezone=manage.execute('docker','exec',config['container'],'date','+%z').strip()
    if not re.fullmatch('[+-][0-9]{4}',timezone):
        raise ValueError('Cannot determine audit log timezone')
    config['logTimezone']='UTC'+timezone
    interpreter = sys.executable
    action = ('[Definition]\nactionban = '+interpreter+' -E -s -B '+str(runner)+
              ' --root '+str(root)+' ban --identity "<fid>" --source <source> --seconds <bantime> --started <time>\n'+
              'actionunban = '+interpreter+' -E -s -B '+str(runner)+
              ' --root '+str(root)+' unban --identity "<fid>" --source <source>\n[Init]\nsource = attack\ntimeout = 180\n')
    content = MARKER
    for name, retries, log in [('attack', config.get('attackRetries', 20), 'waf-audit.json'),
                               ('rate', config.get('rateRetries', 120), 'waf-rate.log')]:
        content += (f'[waf-{name}]\nenabled = true\nbackend = polling\nusedns = no\nfilter = waf-{name}\n'
                    f'logpath = {root}/log/nginx/{log}\nfindtime = 300\nmaxretry = {retries}\n'
                    f'bantime = {config.get("banSeconds", 600)}\nbantime.increment = false\n'
                    f'logtimezone = {config["logTimezone"]}\n'
                    f'action = waf-unified[source={name}]\n')
    if jail.exists() and manage.read_config(jail)!=DISABLED:
        previous=manage.read_config(jail)
        parsed=__import__('configparser').ConfigParser(interpolation=None)
        parsed.read_string(previous)
        for source in ['attack','rate']:
            section='waf-'+source
            if parsed.get(section,'action',fallback='')!='waf-unified[source='+source+']':
                raise ValueError('Custom ban action requires explicit migration')
            for field,low,high in [('maxretry',1,10000),('findtime',1,86400),('bantime',60,3600)]:
                if not low<=parsed.getint(section,field)<=high:
                    raise ValueError('Unsupported jail threshold: '+field)
            if parsed.getboolean(section,'bantime.increment',fallback=False):
                raise ValueError('Incremental bans are outside the bounded unified policy')
        content=previous
    files = {jail: content.encode(), F2B/'action.d/waf-unified.conf': action.encode(),
             F2B/'jail.d/zz-kejilion-web-baseline.local': (manage.BUNDLE/'legacy-jails.local').read_bytes()}
    for name, text in policy.render_filters().items():
        files[F2B/'filter.d'/name] = text.encode()
    for name in ['waf-rate.log', 'waf-audit.json']:
        path = root/'log/nginx'/name
        manage.safe_parent(path)
        if path.is_symlink():
            raise ValueError('Unsafe event log')
        path.touch(exist_ok=True)
        path.chmod(0o640)
    def activate():
        manage.execute('fail2ban-client', '-t')
        change(root, 'sync',lock_held=True)
        manage.execute('fail2ban-client', 'reload')
        change(root,'sync',lock_held=True)
        for name in ['waf-attack', 'waf-rate']:
            manage.execute('fail2ban-client', 'status', name)
        set_cron(cron_text)
    policy_result = manage.apply(root, config,lock_held=True)
    try:
        result = manage._external_update(root, files, 'unified-bans', activate)
    except Exception:
        errors=[]
        for restore in [lambda:set_cron(cron.stdout),lambda:manage.execute('fail2ban-client','reload'),
                        lambda:manage.restore(root,Path(policy_result['backup'])) if policy_result.get('backup') else None,
                        lambda:manage.reload_nginx(config_before['container'])]:
            try:restore()
            except Exception as error:errors.append(type(error).__name__)
        if errors:
            raise RuntimeError('Ban installation failed; rollback needs inspection: '+','.join(errors)) from None
        raise
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path('/home/web'))
    parser.add_argument('operation', choices=['ban', 'unban', 'sync', 'clear'])
    parser.add_argument('--identity')
    parser.add_argument('--source', choices=['attack', 'rate'])
    parser.add_argument('--seconds', type=int)
    parser.add_argument('--started', type=float)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.root.resolve() != args.root or str(args.root) == '/':
        raise ValueError('Canonical root and root privileges required')
    change(args.root, args.operation, args.identity, args.source, args.seconds, started=args.started)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('WAF ban operation failed: '+str(error)[:300], file=sys.stderr)
        raise SystemExit(1)
