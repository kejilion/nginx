#!/usr/bin/env python3
"""Fail2Ban event adapter: site-scoped origin bans and optional CF custom rules.

No daemon and no account-wide IP access rules. Only our uniquely referenced
zone rules are changed. Cron retries failed edge sync and expires local state.
"""
from __future__ import annotations
import argparse
import copy
import contextlib
import configparser
import fnmatch
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import configure as manage
import nginx_edit
import policy

PHASE = 'http_request_firewall_custom'
# Cloudflare expressions do not support a bare boolean literal. This
# contradiction is valid in the Ruleset Engine and cannot match any request.
CF_NEVER_MATCH = '(ip.src eq 192.0.2.1 and ip.src ne 192.0.2.1)'
MARKER = '# Managed shared WAF; unified event bans v1\n'
LEGACY_MARKER = '# Managed shared WAF; only trusted defence events, isolated by canonical site and client.\n'
DISABLED = MARKER+'[waf-attack]\nenabled = false\n[waf-rate]\nenabled = false\n[waf-api-invalid]\nenabled = false\n'
MAX_EXPRESSION = 4096
MAX_LEGACY_EXPIRY = 24 * 60 * 60
PROGRESSIVE_MARKER = '# Managed WAF progressive bans v1'
PROGRESSIVE_OPTIONS = {
    'bantime.increment':'true',
    'bantime.factor':'1',
    'bantime.multipliers':'1 6 36 144',
    'bantime.maxtime':'86400',
    'bantime.overalljails':'false',
    'bantime.rndtime':'0',
}
F2B = Path('/etc/fail2ban')
LEGACY_RECONCILER = Path('/etc/systemd/system/kejilion-waf.service')
LEGACY_CF_ACTION = F2B/'action.d/cloudflare-docker.conf'
LEGACY_SOURCES = {'attack':'attack','waf-attack':'attack','rate':'rate','waf-rate':'rate',
                  'api':'api','waf-api-invalid':'api','manual':'legacy','migration':'legacy'}


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
    if not isinstance(value,dict) or not re.fullmatch('[a-f0-9]{32}', value.get('owner', '')):
        raise ValueError('Invalid ban state owner')
    if not isinstance(value.get('records'),dict) or len(value['records']) > policy.MAX_BANS:
        raise ValueError('Ban state budget exceeded')
    for key, sources in value['records'].items():
        policy.key(key)
        if not isinstance(sources,dict) or set(sources) - {'attack', 'rate', 'api', 'legacy'}:
            raise ValueError('Invalid ban source')
        if any(type(expiry) is not int for expiry in sources.values()):
            raise ValueError('Invalid ban expiry')
    return value


def legacy_state(root):
    """Validate the exact site-scoped WAFCTL state before importing it."""
    path=root/'config/waf/state.json'
    mapped=root/'conf.d/waf/blocked.map'
    if not path.exists():
        if not mapped.exists():
            return None
        text=manage.read_config(mapped)
        if any(line.strip() and not line.lstrip().startswith('#') for line in text.splitlines()):
            raise ValueError('Existing bans require expiry-aware migration')
        return None
    if path.stat().st_mode & 0o077:
        raise ValueError('Legacy WAF state permissions required')
    value=manage.load_json(path)
    if not isinstance(value,dict) or set(value)!={'schemaVersion','bans','appliedDigest','lastReload'}:
        raise ValueError('Unknown legacy WAF state schema; previous backend retained')
    if value.get('schemaVersion')!=1 or not isinstance(value.get('bans'),dict) or len(value['bans'])>policy.MAX_BANS:
        raise ValueError('Invalid legacy WAF state; previous backend retained')
    if type(value.get('lastReload')) is not int or not re.fullmatch('[a-f0-9]{64}',str(value.get('appliedDigest',''))):
        raise ValueError('Invalid legacy WAF state digest; previous backend retained')
    text=manage.read_config(mapped)
    raw=mapped.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=value['appliedDigest']:
        raise ValueError('Legacy ban map changed since WAFCTL state; previous backend retained')
    expected=set()
    imported={}
    now=int(time.time())
    for identity,record in value['bans'].items():
        site,address=policy.key(identity)
        canonical=site+'|'+address
        if identity!=canonical or not isinstance(record,dict) or set(record)!={'expires','sources'}:
            raise ValueError('Invalid legacy ban record; previous backend retained')
        expiry=record['expires'];sources=record['sources']
        if (type(expiry) is not int or expiry<0 or expiry>now+MAX_LEGACY_EXPIRY or
            not isinstance(sources,dict) or len(sources)>8):
            raise ValueError('Invalid legacy ban expiry; previous backend retained')
        if expiry>now:expected.add(canonical)
        for source,source_expiry in sources.items():
            if (source not in LEGACY_SOURCES or type(source_expiry) is not int or source_expiry<0 or
                source_expiry>now+MAX_LEGACY_EXPIRY):
                raise ValueError('Unknown legacy ban source; previous backend retained')
            if source_expiry>expiry:
                raise ValueError('Legacy ban source expiry exceeds its applied record; previous backend retained')
        if expiry>now:
            imported[canonical]={'legacy':expiry}
    found=set()
    for line in text.splitlines():
        stripped=line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        match=re.fullmatch(r'"([^"\r\n]+)"[ \t]+1;',stripped)
        if not match:
            raise ValueError('Unrecognized legacy ban map; previous backend retained')
        site,address=policy.key(match.group(1))
        identity=site+'|'+address
        if identity!=match.group(1) or identity in found:
            raise ValueError('Non-canonical legacy ban map; previous backend retained')
        found.add(identity)
    if found!=expected:
        raise ValueError('Legacy ban map does not match its expiry state; previous backend retained')
    return {'records':imported,'importedRecords':len(imported),'mapDigest':value['appliedDigest']}


def canonicalize_waf_section_names(text):
    """Normalize case variants of product-owned jail names without touching others."""
    names={'waf-attack','waf-rate','waf-api-invalid'}
    lines=text.splitlines(keepends=True)
    seen=set()
    for index,line in enumerate(lines):
        match=re.match(r'^([ \t]*\[)([^\]]+)(\][ \t]*)(\r?\n)?$',line)
        if not match:
            continue
        original=match[2].strip()
        canonical=original.lower()
        if canonical not in names:
            continue
        if canonical in seen:
            raise ValueError('Duplicate WAF jail section after case normalization')
        seen.add(canonical)
        if original!=canonical:
            lines[index]=match[1]+canonical+match[3]+(match[4] or '')
    return ''.join(lines)


def parse_jail(text):
    parser=configparser.ConfigParser(interpolation=None,strict=True)
    parser.read_string(canonicalize_waf_section_names(text.removeprefix('\ufeff')))
    return parser


def managed_jail_marker(text):
    """Recognize current and historical shared-WAF headers before the first jail.

    Older script releases wrote the legacy header, sometimes with a BOM,
    whitespace, or operator comments ahead of it. Earlier shared-WAF releases
    used several product-owned header suffixes, so accept that namespace only
    before any jail/data. The jail names, actions, and action implementation are
    validated separately; unknown/unmarked files remain fail-closed.
    """
    current=MARKER.rstrip('\r\n')
    legacy=LEGACY_MARKER.rstrip('\r\n')
    for line in text.splitlines():
        candidate=line.strip().removeprefix('\ufeff').strip()
        if candidate==current:return 'current'
        if candidate==legacy:return 'legacy'
        if is_legacy_managed_jail_marker(candidate):return 'legacy'
        if not candidate or candidate.startswith('#'):
            continue
        # Do not accept a marker hidden after any jail section or data line.
        break
    return None


def is_unmarked_legacy_managed_jail(text,root=Path('/home/web')):
    """Recognize old WAF jails without a header by their action and log contract."""
    try:
        parsed=parse_jail(text)
    except (ValueError,configparser.Error):
        return False
    known={'waf-attack','waf-rate','waf-api-invalid'}
    if any(section.lower().startswith('waf-') and section.lower() not in known
           for section in parsed.sections()):
        return False
    sections=[(section,source) for section,source in [('waf-attack','attack'),('waf-rate','rate')]
              if parsed.has_section(section)]
    if not sections:
        return False
    for section,source in sections:
        if parsed.get(section,'filter',fallback=section).strip()!=section:
            return False
        if not legacy_waf_action_matches(parsed.get(section,'action',fallback=''),source):
            return False
        paths=parsed.get(section,'logpath',fallback='').split()
        if paths and paths[-1].lower()=='tail':
            paths.pop()
        if not paths or not all(legacy_waf_logpath_matches(section,path,root) for path in paths):
            return False
    return True


def legacy_waf_action_matches(action,source):
    match=re.fullmatch(r'waf-local\s*\[\s*reason\s*=\s*([a-z0-9-]+)\s*\]',action.strip(),re.I)
    return bool(match and LEGACY_SOURCES.get(match.group(1).lower())==source)


def has_legacy_waf_actions(text):
    try:
        parsed=parse_jail(text)
    except (ValueError,configparser.Error):
        return False
    return any(legacy_waf_action_matches(parsed.get('waf-'+source,'action',fallback=''),source)
               for source in ('attack','rate') if parsed.has_section('waf-'+source))


def legacy_waf_logpath_matches(section,path,root=Path('/home/web')):
    directory=str(root).replace('\\','/').rstrip('/')+'/log/nginx/'
    filename=path.removeprefix(directory)
    if filename==path or '/' in filename or '\\' in filename:
        return False
    patterns={
        # Older WAF releases wrote ModSecurity audit events to error.log.
        # Only the attack jail may claim that product-owned legacy path.
        'waf-attack':('waf-audit.json','waf-audit.json.*','waf-audit-*.json','waf-audit*.json',
                      'error.log','error.log.*','error.log-*'),
        'waf-rate':('waf-rate.log','waf-rate.log.*','waf-rate-*.log','waf-rate*.log'),
    }
    return any(fnmatch.fnmatchcase(filename,pattern) for pattern in patterns.get(section,()))


def is_legacy_managed_jail_marker(candidate):
    return re.fullmatch(r'#\s*Managed shared WAF(?:\s*(?:[;.:—-])\s*.*|\s+.*)?', candidate, re.I) is not None


def replace_managed_jail_marker(text):
    lines=text.splitlines(keepends=True)
    current=MARKER.rstrip('\r\n')
    legacy=LEGACY_MARKER.rstrip('\r\n')
    for index,line in enumerate(lines):
        candidate=line.strip().removeprefix('\ufeff').strip()
        if candidate not in {current,legacy} and not is_legacy_managed_jail_marker(candidate):
            if candidate and not candidate.startswith('#'):
                break
            continue
        ending='\r\n' if line.endswith('\r\n') else '\n' if line.endswith('\n') else ''
        lines[index]=current+ending
        return ''.join(lines)
    raise ValueError('Managed WAF marker disappeared during migration')


def validate_legacy_wafctl_action(name):
    action_file=F2B/'action.d'/(name+'.conf')
    parser=parse_jail(manage.read_config(action_file))
    if set(parser.sections()) not in ({'Definition'},{'Definition','Init'}):
        raise ValueError('Unknown legacy WAF action implementation; previous backend retained')
    definition=parser['Definition']
    if (not {'actionban','actionunban'}<=set(definition) or
        set(definition)-{'actionstart','actionstop','actioncheck','actionban','actionunban'}):
        raise ValueError('Unknown legacy WAF action implementation; previous backend retained')
    has_init=parser.has_section('Init')
    python=r'(?:<python>|/(?:usr/bin|usr/local/bin)/python3(?:\.[0-9]+)?)' if has_init else r'/(?:usr/bin|usr/local/bin)/python3(?:\.[0-9]+)?'
    runtime=r'(?:<runtime>|/home/web/conf\.d/waf/wafctl\.py)' if has_init else r'/home/web/conf\.d/waf/wafctl\.py'
    root=r'(?:<root>|/home/web)' if has_init else r'/home/web'
    ip=r'"?<ip>"?'
    reason=r'(?:<reason>|attack|waf-attack|rate|waf-rate|api|waf-api-invalid|manual|migration)'
    root_arg=rf'(?:--root\s+{root}\s+)?'
    ban_pattern=re.compile(rf'{python}\s+{runtime}\s+{root_arg}ban\s+--key\s+{ip}\s+--ttl\s+<bantime>\s+--reason\s+{reason}')
    unban_pattern=re.compile(rf'{python}\s+{runtime}\s+{root_arg}unban\s+--key\s+{ip}\s+--reason\s+{reason}')
    # An older API jail used an explicitly scoped key and expiry instead of
    # an unban action. Preserve that site when adapting its IP-only tickets.
    if name=='waf-api-invalid' and not has_init:
        scoped=re.fullmatch(rf'{python}\s+{runtime}\s+{root_arg}ban\s+--key\s+"([A-Za-z0-9_.-]+)\|<ip>"\s+--ttl\s+<bantime>\s+--reason\s+rate',definition.get('actionban','').strip())
        if scoped and not definition.get('actionunban','').strip() and not any(definition.get(field,'').strip() for field in ('actionstart','actionstop','actioncheck')):
            site=policy.scope(scoped.group(1))
            if site!=scoped.group(1):
                raise ValueError('Non-canonical legacy API site; previous backend retained')
            return site
    if (not ban_pattern.fullmatch(definition.get('actionban','').strip()) or
        not unban_pattern.fullmatch(definition.get('actionunban','').strip()) or
        any(definition.get(field,'').strip() for field in ('actionstart','actionstop','actioncheck'))):
        raise ValueError('Unknown legacy WAF action implementation; previous backend retained')
    if has_init:
        init=parser['Init']
        if not set(init)<= {'python','runtime','root','reason'}:
            raise ValueError('Unknown legacy WAF action settings; previous backend retained')
        if (init.get('python') is not None and not re.fullmatch(r'/(?:usr/bin|usr/local/bin)/python3(?:\.[0-9]+)?',init.get('python','')) or
            init.get('runtime') is not None and init.get('runtime')!='/home/web/conf.d/waf/wafctl.py' or
            init.get('root') is not None and init.get('root')!='/home/web' or
            init.get('reason') is not None and init.get('reason') not in {'attack','waf-attack','rate','waf-rate','api','waf-api-invalid','manual','migration'}):
            raise ValueError('Unknown legacy WAF action settings; previous backend retained')
        if any('<reason>' in definition.get(field,'') for field in ('actionban','actionunban')) and init.get('reason') is None:
            raise ValueError('Unknown legacy WAF action settings; previous backend retained')


def validate_managed_jail(text,allow_unmarked_legacy=False,root=Path('/home/web')):
    marker=managed_jail_marker(text)
    if marker is None and allow_unmarked_legacy and is_unmarked_legacy_managed_jail(text,root):
        marker='legacy'
    if marker is None:
        raise ValueError('Custom/previous ban backend requires explicit migration')
    parsed=parse_jail(text)
    present=0
    for source in ['attack','rate']:
        section='waf-'+source
        if not parsed.has_section(section):
            if marker=='legacy':
                continue
            raise ValueError('Managed jail is incomplete; previous backend retained')
        present+=1
        action=parsed.get(section,'action',fallback='').strip()
        accepted={'waf-unified[source='+source+']'}
        if marker=='legacy':
            accepted.add('waf-local[reason='+source+']')
        if action not in accepted and not (marker in {'current','legacy'} and
                                           legacy_waf_action_matches(action,source)):
            raise ValueError('Custom ban action requires explicit migration')
        for field,low,high in [('maxretry',1,10000),('findtime',1,86400),('bantime',60,86400)]:
            try:value=parsed.getint(section,field)
            except (ValueError,configparser.Error):
                raise ValueError('Unsupported jail threshold: '+field) from None
            if not low<=value<=high:
                raise ValueError('Unsupported jail threshold: '+field)
        validate_progressive_settings(parsed,section)
    if not present:
        raise ValueError('Managed jail is incomplete; previous backend retained')
    return parsed


def validate_progressive_settings(parsed,section):
    try:
        enabled=parsed.getboolean(section,'bantime.increment',fallback=False)
        if not enabled:return
        maximum=parsed.getint(section,'bantime.maxtime',fallback=0)
        factor=parsed.get(section,'bantime.factor',fallback='1').strip()
        multipliers=parsed.get(section,'bantime.multipliers',fallback='').split()
        overall=parsed.getboolean(section,'bantime.overalljails',fallback=False)
        random=parsed.getint(section,'bantime.rndtime',fallback=0)
    except (ValueError,configparser.Error):
        raise ValueError('Unsupported progressive ban configuration') from None
    if (not 60<=maximum<=MAX_LEGACY_EXPIRY or factor!='1' or overall or random!=0 or
        not 1<=len(multipliers)<=8 or any(not x.isdigit() or not 1<=int(x)<=1440 for x in multipliers) or
        [int(x) for x in multipliers]!=sorted(int(x) for x in multipliers) or
        parsed.has_option(section,'bantime.formula')):
        raise ValueError('Unsupported progressive ban configuration')


def api_jail():
    directory=F2B/'jail.d'
    managed_path=directory/'zz-waf-managed.local'
    files={path for path in directory.glob('*') if path.suffix in {'.local','.conf'}}
    files.update(path for path in (F2B/'jail.conf',F2B/'jail.local') if path.exists())
    files=sorted(files)
    if len(files)>250:
        raise ValueError('Fail2Ban jail inventory budget exceeded')
    matches=[]
    for path in files:
        text=manage.read_config(path)
        if not re.search(r'(?m)^\s*\[waf-api-invalid\]\s*$',text,re.I):
            continue
        parsed=parse_jail(text)
        if parsed.has_section('waf-api-invalid'):
            matches.append((path,text,parsed))
    if not matches:
        return None
    managed=[item for item in matches if item[0]==managed_path]
    sources=[item for item in matches if item[0]!=managed_path]
    if len(managed)>1 or len(sources)>1:
        raise ValueError('Ambiguous waf-api-invalid jail; previous backend retained')
    if managed and not sources and managed[0][1]==DISABLED:
        return None
    if managed:
        managed_text=managed[0][1]
        marker=managed_jail_marker(managed_text)
        if marker is None and is_unmarked_legacy_managed_jail(managed_text):
            marker='legacy'
        if marker not in {'current','legacy'}:
            raise ValueError('Unexpected managed API jail override; previous backend retained')
        override=parse_jail(managed_text)
        api_action=override.get('waf-api-invalid','action',fallback='').strip()
        api_options=set(override._sections.get('waf-api-invalid',{}))
        legacy_api_options={'action','enabled','filter','logpath','maxretry','findtime','bantime','bantime.increment'}
        scoped_action=re.fullmatch(r'waf-unified-api\[site=([A-Za-z0-9_.-]+)\]',api_action)
        current_api_options=legacy_api_options|set(PROGRESSIVE_OPTIONS) if not sources else {'action'}|set(PROGRESSIVE_OPTIONS)
        if (marker=='current' and ((api_action!='waf-unified[source=api]' and not scoped_action) or not api_options<=current_api_options)) or (
                marker=='legacy' and not api_options<=legacy_api_options):
            raise ValueError('Unexpected managed API jail override; previous backend retained')
        validate_progressive_settings(override,'waf-api-invalid')
    if sources:
        path,text,parsed=sources[0]
    else:
        path,text,parsed=managed[0]
    section='waf-api-invalid'
    if path!=managed_path and (path.parent!=directory or path.name>=managed_path.name):
        raise ValueError('API jail cannot be safely overridden without changing load order')
    action=parsed.get(section,'action',fallback='').strip()
    scoped_action=re.fullmatch(r'waf-unified-api\[site=([A-Za-z0-9_.-]+)\]',action)
    if action not in {'waf-api-invalid','waf-local[reason=api]','waf-local[reason=waf-api-invalid]','waf-unified[source=api]'} and not scoped_action:
        raise ValueError('Custom API jail action requires explicit migration')
    if parsed.get(section,'filter',fallback='').strip()!='waf-api-invalid':
        raise ValueError('Unknown API jail filter; previous backend retained')
    logpath=parsed.get(section,'logpath',fallback='').strip().split()[0:1]
    if not logpath or not re.fullmatch(r'/home/web/log/nginx/[A-Za-z0-9_.-]{1,128}',logpath[0]):
        raise ValueError('Unknown API jail log path; previous backend retained')
    site=policy.scope(scoped_action.group(1)) if scoped_action else None
    if action!='waf-unified[source=api]' and not scoped_action:
        site=validate_legacy_wafctl_action('waf-api-invalid' if action=='waf-api-invalid' else 'waf-local')
    if managed and sources and marker=='current':
        expected='waf-unified-api[site='+site+']' if site else 'waf-unified[source=api]'
        if api_action!=expected:
            raise ValueError('API site scope changed; previous backend retained')
    for field,low,high in [('maxretry',1,10000),('findtime',1,86400),('bantime',60,86400)]:
        raw=parsed.get(section,field,fallback=None)
        if raw is None:
            continue
        try:value=int(raw.strip())
        except ValueError:raise ValueError('Invalid API jail threshold: '+field) from None
        if not low<=value<=high:
            raise ValueError('Invalid API jail threshold: '+field)
    validate_progressive_settings(parsed,section)
    try:enabled=parsed.getboolean(section,'enabled',fallback=False)
    except ValueError:raise ValueError('Invalid API jail enabled state') from None
    own=parsed._sections.get(section,{})
    custom_progression=any(k.startswith('bantime.') and k!='bantime.increment' for k in own)
    info={'path':path,'enabled':enabled,'action':action,'text':text,'site':site,
          'customProgression':custom_progression,
          'progressive':parsed.getboolean(section,'bantime.increment',fallback=False)}
    if path==managed_path:info['managed']=True
    return info


def legacy_reconciler_state():
    path=LEGACY_RECONCILER
    if path.is_symlink():
        raise ValueError('Unknown legacy WAF reconciler unit; previous backend retained')
    if not path.exists():
        return {'recognized':False,'enabled':False,'active':False}
    info=path.stat()
    if not path.is_file() or info.st_uid!=os.geteuid() or info.st_size>16384 or info.st_mode&0o022:
        raise ValueError('Unknown legacy WAF reconciler unit; previous backend retained')
    text=path.read_text(encoding='utf-8')
    lines=[line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]
    allowed={'[Unit]','[Service]','[Install]'}
    if any(line.startswith('[') and line.endswith(']') and line not in allowed for line in lines):
        raise ValueError('Unknown legacy WAF reconciler unit; previous backend retained')
    allowed_directives={
        'Description=Shared site-scoped WAF ban reconciler',
        'After=docker.service','Requires=docker.service',
        'Type=simple','User=root','Group=root','Restart=on-failure','RestartSec=5',
        'UMask=0077','NoNewPrivileges=true','PrivateTmp=true','ProtectHome=read-only',
        'ProtectSystem=strict','ReadWritePaths=/home/web/config/waf /home/web/conf.d/waf',
        'WantedBy=multi-user.target',
    }
    directives=[line for line in lines if not (line.startswith('[') and line.endswith(']'))]
    exec_lines=[line for line in directives if line.startswith('ExecStart=')]
    if (any(line not in allowed_directives for line in directives if not line.startswith('ExecStart=')) or
        'Description=Shared site-scoped WAF ban reconciler' not in directives or
        'Restart=on-failure' not in directives or len(exec_lines)!=1 or
        not re.fullmatch(r'ExecStart=/(?:usr/bin|usr/local/bin)/python3(?:\.[0-9]+)? /home/web/conf\.d/waf/wafctl\.py --root /home/web watch',exec_lines[0])):
        raise ValueError('Unknown legacy WAF reconciler unit; previous backend retained')
    dropins=path.with_name(path.name+'.d')
    if dropins.is_symlink():
        raise ValueError('Legacy WAF reconciler has custom drop-ins; previous backend retained')
    if dropins.exists():
        dropin_info=dropins.stat()
        if (not dropins.is_dir() or dropin_info.st_uid!=os.geteuid() or dropin_info.st_mode&0o022 or
            any(dropins.iterdir())):
            raise ValueError('Legacy WAF reconciler has custom drop-ins; previous backend retained')
    import subprocess
    active=subprocess.run(['systemctl','is-active','kejilion-waf.service'],capture_output=True,text=True,timeout=10)
    enabled=subprocess.run(['systemctl','is-enabled','kejilion-waf.service'],capture_output=True,text=True,timeout=10)
    if active.returncode not in {0,3,4} or enabled.returncode not in {0,1,3,4}:
        raise ValueError('Cannot inspect legacy WAF reconciler state; previous backend retained')
    fragment=subprocess.run(['systemctl','show','-p','FragmentPath','--value','kejilion-waf.service'],capture_output=True,text=True,timeout=10)
    dropin_state=subprocess.run(['systemctl','show','-p','DropInPaths','--value','kejilion-waf.service'],capture_output=True,text=True,timeout=10)
    if (fragment.returncode or fragment.stdout.strip()!=str(path) or dropin_state.returncode or dropin_state.stdout.strip()):
        raise ValueError('Loaded legacy WAF reconciler differs from the verified unit; previous backend retained')
    return {'recognized':True,'enabled':enabled.returncode==0,'active':active.returncode==0}


def migration_plan(root):
    saved_migration=read(root,'ban-migration.json',{})
    old=legacy_state(root) if not saved_migration else None
    jail_path=F2B/'jail.d/zz-waf-managed.local'
    previous=manage.read_config(jail_path) if jail_path.exists() else ''
    managed=None
    if previous and previous!=DISABLED:
        validate_managed_jail(previous,allow_unmarked_legacy=True,root=root)
        managed=previous
        if has_legacy_waf_actions(previous):
            validate_legacy_wafctl_action('waf-local')
    api=api_jail()
    reconciler=legacy_reconciler_state()
    old_cf=LEGACY_CF_ACTION.exists()
    imported=old is not None
    legacy_marker=bool(previous and (managed_jail_marker(previous)=='legacy' or
                                     managed_jail_marker(previous) is None and
                                     is_unmarked_legacy_managed_jail(previous,root) or
                                     has_legacy_waf_actions(previous)))
    managed_api=False
    if previous:
        parsed_previous=parse_jail(previous)
        managed_action=parsed_previous.get('waf-api-invalid','action',fallback='').strip()
        managed_api=(managed_action=='waf-unified[source=api]' or bool(re.fullmatch(r'waf-unified-api\[site=[A-Za-z0-9_.-]+\]',managed_action)))
    legacy_api=bool(api and api['action']!='waf-unified[source=api]' and not managed_api)
    reentry_required=bool(saved_migration.get('cfReentryRequired',old_cf))
    requires=(imported or legacy_marker or legacy_api or
              (reconciler['recognized'] and (reconciler['active'] or reconciler['enabled'])) or
              (old_cf and not saved_migration))
    return {'legacyState':old if imported else None,'managedJail':managed,'apiJail':api,
            'reconciler':reconciler,'legacyCFDetected':old_cf,
            'cfReentryRequired':reentry_required,'imported':imported,
            'requiresMigration':requires}


def public_preflight(plan):
    return {'safe':True,'migration':{'state':'legacy-ready' if plan['requiresMigration'] else 'current',
        'importedRecords':plan['legacyState']['importedRecords'] if plan['legacyState'] else 0,
        'apiJailDetected':plan['apiJail'] is not None,
        'apiJailEnabled':bool(plan['apiJail'] and plan['apiJail']['enabled']),
        'legacyCFDetected':plan['legacyCFDetected'],
        'cfReentryRequired':plan['cfReentryRequired'],
        'legacyReconcilerDetected':plan['reconciler']['recognized']}}


def managed_jail_content(previous,api,root=Path('/home/web'),defaults=None):
    if previous and previous!=DISABLED:
        validate_managed_jail(previous,allow_unmarked_legacy=True,root=root)
        marker=managed_jail_marker(previous)
        if marker is None:
            bom='\ufeff' if previous.startswith('\ufeff') else ''
            source=previous[1:] if bom else previous
            content=bom+MARKER+source
        elif marker=='legacy':
            content=replace_managed_jail_marker(previous)
        else:
            content=previous
        content=canonicalize_waf_section_names(content)
        parsed=parse_jail(content)
        action_overrides={}
        api_action=('waf-unified-api[site='+api['site']+']' if api and api.get('site')
                    else 'waf-unified[source=api]')
        for section,source in [('waf-attack','attack'),('waf-rate','rate'),('waf-api-invalid','api')]:
            if not parsed.has_section(section):
                continue
            action=parsed.get(section,'action',fallback='').strip()
            if (legacy_waf_action_matches(action,source) or
                action=='waf-api-invalid' and source=='api' or
                source=='api' and re.fullmatch(r'waf-unified-api\[site=[A-Za-z0-9_.-]+\]',action) or
                action=='waf-unified[source='+source+']'):
                # DEFAULT action values are inherited by all sections. Add a
                # local WAF action instead of changing the administrator's
                # shared default for unrelated jails.
                action_overrides[section]=api_action if source=='api' else 'waf-unified[source='+source+']'

        attack_logpath=None
        if parsed.has_section('waf-attack'):
            value=parsed.get('waf-attack','logpath',fallback=None)
            if value is not None:
                tokens=value.split()
                tail=bool(tokens and tokens[-1].lower()=='tail')
                if tail:
                    tokens.pop()
                root_path=str(root).replace('\\','/').rstrip('/')
                old=root_path+'/log/nginx/error.log'
                new=root_path+'/log/nginx/waf-audit.json'
                migrated=[]
                changed=False
                for token in tokens:
                    suffix=token[len(old):] if token.startswith(old) else None
                    if (suffix is not None and
                        (suffix=='' or suffix[0] in '.*?-' and re.fullmatch(r'[.A-Za-z0-9*?_-]+',suffix))):
                        migrated.append(new+suffix)
                        changed=True
                    else:
                        migrated.append(token)
                if changed:
                    attack_logpath=' '.join(migrated+(['tail'] if tail else []))

        lines=content.splitlines(keepends=True)
        output=[]
        section=''
        for line in lines:
            header=re.match(r'^\s*\[([^\]]+)\]',line)
            if header:
                section=header[1]
                output.append(line)
                local_options={key for key in parsed._sections.get(section,{}) if key!='__name__'}
                additions=[]
                if section in action_overrides and 'action' not in local_options:
                    additions.append('action = '+action_overrides[section])
                if section=='waf-attack' and attack_logpath is not None and 'logpath' not in local_options:
                    additions.append('logpath = '+attack_logpath)
                ending='\r\n' if line.endswith('\r\n') else '\n' if line.endswith('\n') else ''
                if additions and not ending:
                    output[-1]=line+'\n'
                    ending='\n'
                output.extend(value+ending for value in additions)
                continue
            if section in action_overrides:
                option=re.match(r'(?i)^([ \t]*action[ \t]*[=:][ \t]*)(.*?)([ \t]*)(\r?\n)?$',line)
                if option:
                    line=option[1]+action_overrides[section]+option[3]+(option[4] or '')
            if section=='waf-attack' and attack_logpath is not None:
                option=re.match(r'(?i)^([ \t]*logpath[ \t]*[=:][ \t]*)(.*?)([ \t]*)(\r?\n)?$',line)
                if option:
                    line=option[1]+attack_logpath+option[3]+(option[4] or '')
            output.append(line)
        content=''.join(output)
        parsed=parse_jail(content)
        missing=[section for section in ('waf-attack','waf-rate') if not parsed.has_section(section)]
        if missing:
            if not defaults:
                raise ValueError('Partial legacy WAF configuration requires install defaults')
            default_blocks={}
            current=''
            block=[]
            for line in canonicalize_waf_section_names(defaults).splitlines(keepends=True):
                header=re.match(r'^\s*\[([^\]]+)\]',line)
                if header:
                    if current:
                        default_blocks[current]=''.join(block)
                    current=header[1].lower()
                    block=[line]
                elif current:
                    block.append(line)
            if current:
                default_blocks[current]=''.join(block)
            for section in missing:
                if section not in default_blocks:
                    raise ValueError('Install defaults are missing a required WAF jail')
                if content and not content.endswith(('\n','\r')):
                    content+='\n'
                content+=default_blocks[section]
            content=canonicalize_waf_section_names(content)
    else:
        content=''
    if api and not re.search(r'(?m)^\s*\[waf-api-invalid\]\s*$',content):
        if content and not content.endswith('\n'):content+='\n'
        api_action=('waf-unified-api[site='+api['site']+']' if api.get('site') else 'waf-unified[source=api]')
        content+='\n[waf-api-invalid]\naction = '+api_action+'\n'
    return content


def progressive_jail_content(content,api):
    """Enable bounded defaults once while preserving explicit custom policies."""
    parsed=parse_jail(content)
    marked=PROGRESSIVE_MARKER in content.splitlines()
    chosen=set()
    custom_keys=set(PROGRESSIVE_OPTIONS)-{'bantime.increment'}
    inherited_custom=bool(custom_keys & set(parsed.defaults()))
    for section in ('waf-attack','waf-rate','waf-api-invalid'):
        if not parsed.has_section(section):continue
        own=parsed._sections.get(section,{})
        if section=='waf-api-invalid' and api and api.get('customProgression') and not any(k in own for k in custom_keys):
            continue
        if inherited_custom or any(k in own for k in custom_keys):continue
        if marked and 'bantime.increment' in own:continue
        if parsed.getboolean(section,'bantime.increment',fallback=False):continue
        chosen.add(section)
    lines=content.splitlines(keepends=True)
    output=[];section=''
    for line in lines:
        header=re.match(r'^\s*\[([^\]]+)\]',line)
        if header:
            section=header[1].strip().lower();output.append(line)
            if section in chosen:
                ending='\r\n' if line.endswith('\r\n') else '\n'
                if not line.endswith(('\r','\n')):output[-1]=line+ending
                output.extend(k+' = '+v+ending for k,v in PROGRESSIVE_OPTIONS.items())
            continue
        if section in chosen and re.match(r'^\s*bantime\.increment\s*[=:]',line,re.I):continue
        output.append(line)
    result=''.join(output)
    if not marked:
        lines=result.splitlines(keepends=True)
        for i,line in enumerate(lines):
            if line.strip().removeprefix('\ufeff')==MARKER.strip():
                ending='\r\n' if line.endswith('\r\n') else '\n'
                if not line.endswith(('\r','\n')):lines[i]=line+ending
                lines.insert(i+1,PROGRESSIVE_MARKER+ending);break
        else:raise ValueError('Managed WAF marker missing')
        result=''.join(lines)
    result_parsed=parse_jail(result)
    sources=[]
    for section,source in (('waf-attack','attack'),('waf-rate','rate'),('waf-api-invalid','api')):
        if not result_parsed.has_section(section):continue
        if source=='api' and api and not api.get('enabled'):continue
        fallback=bool(api and api.get('progressive')) if source=='api' else False
        if result_parsed.getboolean(section,'bantime.increment',fallback=fallback):
            if not (source=='api' and api and api.get('customProgression') and
                    'bantime.increment' not in result_parsed._sections.get(section,{})):
                validate_progressive_settings(result_parsed,section)
            sources.append(source)
    return result,sources


def private_snapshot(paths):
    result={}
    for path in paths:
        if path.is_symlink():
            raise ValueError('Refusing symlink: '+str(path))
        result[path]=(path.read_bytes(),path.stat().st_mode&0o777) if path.exists() else None
    return result


def restore_private(snapshot):
    for path,value in snapshot.items():
        if value is None:
            if path.exists():path.unlink()
        else:
            manage.atomic(path,value[0],value[1])


def set_legacy_reconciler(plan,enabled):
    before=plan['reconciler']
    if not before['recognized']:
        return
    import subprocess
    if not enabled:
        try:
            if before['active'] or before['enabled']:
                result=subprocess.run(['systemctl','disable','--now','kejilion-waf.service'],capture_output=True,text=True,timeout=20)
                if result.returncode:
                    raise RuntimeError('Failed to stop the exact legacy WAF reconciler')
            after=legacy_reconciler_state()
            if after['active'] or after['enabled']:
                raise RuntimeError('Legacy WAF reconciler is still active')
        except Exception:
            if before['active'] or before['enabled']:
                set_legacy_reconciler(plan,True)
            raise
        return
    if before['enabled'] and before['active']:
        command=['systemctl','enable','--now','kejilion-waf.service']
    elif before['enabled']:
        command=['systemctl','enable','kejilion-waf.service']
    elif before['active']:
        command=['systemctl','start','kejilion-waf.service']
    else:
        return
    result=subprocess.run(command,capture_output=True,text=True,timeout=20)
    if result.returncode:
        raise RuntimeError('Failed to restore the previous WAF reconciler state')


def ban_preflight(root):
    plan=migration_plan(root)
    return public_preflight(plan)


def live_records(value, now):
    return {key: {source: expiry for source, expiry in sources.items() if expiry > now}
            for key, sources in value['records'].items() if any(x > now for x in sources.values())}


def hold_unverified_progressive(root,value):
    """Do not expire a progressive ticket until a current snapshot proves it."""
    migration=read(root,'ban-migration.json',{})
    sources=migration.get('progressiveSources',[]) if isinstance(migration,dict) else []
    if not isinstance(sources,list) or set(sources)-{'attack','rate','api'}:
        raise ValueError('Invalid progressive source configuration')
    now=int(time.time())
    for entries in value['records'].values():
        for source in sources:
            if source in entries and entries[source]<=now:
                # This is a provisional projection, not a new Fail2Ban ticket.
                # A later verified snapshot or explicit unban restores the real
                # deadline; persistent verification failure remains visible.
                entries[source]=now+120
                value['ticketVerificationPending']=True


def merge_legacy_records(value, records):
    if len(set(value['records'])|set(records))>policy.MAX_BANS:
        raise ValueError('Combined legacy ban state exceeds the safe migration budget')
    for identity,sources in records.items():
        value['records'].setdefault(identity,{})['legacy']=sources['legacy']
    value['generation']=value.get('generation',0)+1
    return value


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
            expression=CF_NEVER_MATCH
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
    desired = {zone: CF_NEVER_MATCH for zone in active_zones} if cf['mode'] == 'cloudflare' else {}
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
                body['position']={'before':''}
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


def reconcile(root, config, value, cf, edge=True, verified=False):
    if not verified:
        hold_unverified_progressive(root,value)
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
            if cf.get('mode')=='cloudflare' and cf.get('auth'):
                migration=read(root,'ban-migration.json',{})
                if migration.get('cfReentryRequired'):
                    migration['cfReentryRequired']=False
                    save(root,'ban-migration.json',migration)
    except Exception:
        save(root, 'ban-health.json', {'ok': False, 'checked': int(time.time()),
                                     'error': 'Ban enforcement synchronization failed'})
        raise
    if edge:
        save(root, 'ban-health.json', {'ok': not value.get('ticketVerificationPending',False), 'checked': int(time.time()),
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
        hold_unverified_progressive(root,value)
        value['records']=live_records(value,int(time.time()))
        site,address=policy.key(identity)
        identity=site+'|'+address
        if source not in {'attack','rate','api'}:
            raise ValueError('Invalid event source')
        if operation=='ban':
            proxies=policy.networks(manage.load_json(root/'config/waf/cloudflare-ips.json'))
            proxies+=config.get('trustedProxies',[])+config.get('banIgnore',[])
            proxies+=[p for s in config['sites'].values() for p in s.get('trustedProxies',[])]
            local=json.loads(manage.execute('ip','-j','address','show'))
            proxies+=[a['local'] for interface in local for a in interface.get('addr_info',[])]
            if site not in inventory(root) or not policy.eligible(address,proxies):
                raise ValueError('Untrusted site or protected infrastructure address')
            if type(seconds) is not int or not 60<=seconds<=MAX_LEGACY_EXPIRY:
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


def source_jail(source):
    if source not in {'attack','rate','api'}:
        raise ValueError('Invalid ban source')
    return 'waf-api-invalid' if source=='api' else 'waf-'+source


def configured_sources(root):
    result=['attack','rate']
    migration=read(root,'ban-migration.json',{})
    if isinstance(migration,dict) and migration.get('apiJailEnabled') is True:
        result.append('api')
    return result


def migration_status(root):
    migration=read(root,'ban-migration.json',{})
    if migration:
        if not isinstance(migration,dict) or migration.get('state') not in {'current','legacy-imported','legacy-compatible'}:
            return {'state':'unknown','importedRecords':0,'apiJailEnabled':False,
                    'legacyCFDetected':False,'cfReentryRequired':False,
                    'legacyReconcilerStopped':False}
        imported=migration.get('importedRecords',0)
        if type(imported) is not int or not 0<=imported<=policy.MAX_BANS:
            imported=0
        return {key:migration.get(key,default) for key,default in {
            'state':'unknown','importedRecords':imported,'apiJailEnabled':False,
            'legacyCFDetected':False,'cfReentryRequired':False,
            'legacyReconcilerStopped':False}.items()}
    try:
        plan=migration_plan(root)
        result=public_preflight(plan)['migration']
        return {'state':'legacy-pending' if result['state']=='legacy-ready' else 'current',
                'importedRecords':result['importedRecords'],
                'apiJailEnabled':result['apiJailEnabled'],
                'legacyCFDetected':result['legacyCFDetected'],
                'cfReentryRequired':result['cfReentryRequired'],
                'legacyReconcilerStopped':False}
    except Exception:
        return {'state':'unknown','importedRecords':0,'apiJailEnabled':False,
                'legacyCFDetected':False,'cfReentryRequired':False,
                'legacyReconcilerStopped':False}


def query_tickets(source, allow_missing=False):
    process=__import__('subprocess').run(['fail2ban-client','get',source_jail(source),'banip'],capture_output=True,text=True,timeout=5)
    # An explicitly absent jail has no live tickets. Only cleanup may accept
    # this reply; socket failures and incomplete reads must still stop cleanup.
    if (allow_missing and process.returncode and
        process.stdout.strip()==f"Sorry but the jail '{source_jail(source)}' does not exist"):
        return set()
    if process.returncode or len(process.stdout)>policy.MAX_STATE_BYTES:
        raise ValueError('Cannot read complete Fail2Ban tickets')
    tickets=set(process.stdout.split())
    if len(tickets)>policy.MAX_BANS:raise ValueError('Ticket budget exceeded')
    for ticket in tickets:
        if source=='api' and '|' not in ticket:
            ipaddress.ip_address(ticket)
        else:
            policy.key(ticket)
    return tickets


def query_ticket_times(source):
    """Read Fail2Ban's live start and duration for compatibility checks."""
    process=__import__('subprocess').run(['fail2ban-client','get',source_jail(source),'banip','--with-time'],
                                         capture_output=True,text=True,timeout=5)
    if process.returncode or len(process.stdout)>policy.MAX_STATE_BYTES:
        raise ValueError('Cannot read complete Fail2Ban ticket times')
    result={}
    pattern=r'^(\S+)\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\+\s+(-?\d+)\s+=\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$'
    for line in process.stdout.splitlines():
        if not line.strip():continue
        match=re.fullmatch(pattern,line.strip())
        if not match or match[1] in result:
            raise ValueError('Unsupported Fail2Ban ticket time format')
        if source=='api' and '|' not in match[1]:ipaddress.ip_address(match[1])
        else:policy.key(match[1])
        result[match[1]]=(match[2],int(match[3]),match[4])
    if len(result)>policy.MAX_BANS:raise ValueError('Ticket budget exceeded')
    return result


def fail2ban_database():
    output=manage.execute('fail2ban-client','get','dbfile').strip().splitlines()
    match=re.fullmatch(r'(?:[`|]-\s*)?(/[^\r\n]+)',output[-1].strip()) if output else None
    if not match:
        raise ValueError('Fail2Ban persistent database is unavailable')
    path=Path(match.group(1))
    manage.safe_parent(path)
    info=path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_uid!=os.geteuid() or info.st_mode&0o022:
        raise ValueError('Fail2Ban database is not trusted')
    return path


def progressive_expiries(raw_sources, progressive_sources, reject_legacy_active=False, live_tickets=None):
    """Read actual observer-adjusted ticket expiry; F2B action bantime is the base."""
    if not progressive_sources:
        return {}
    path=fail2ban_database()
    uri='file:'+urllib.parse.quote(str(path),safe='/')+'?mode=ro'
    result={}
    with contextlib.closing(sqlite3.connect(uri,uri=True,timeout=5)) as db:
        db.execute('PRAGMA query_only=ON')
        columns={row[1] for row in db.execute('PRAGMA table_info(bips)')}
        if not {'jail','ip','timeofban','bantime'}<=columns:
            raise ValueError('Unsupported Fail2Ban database schema')
        for source in progressive_sources:
            if reject_legacy_active:
                # Check every still-valid historical row, not just our snapshot:
                # old effective/global policies can leave longer live tickets.
                # Reading SQLite here avoids Fail2Ban RPC while holding the
                # install lock, which can deadlock against an action callback.
                unsafe=db.execute('SELECT 1 FROM bips WHERE jail=? AND '
                                  '(bantime<0 OR (bantime>? AND timeofban+bantime>?)) LIMIT 1',
                                  (source_jail(source),MAX_LEGACY_EXPIRY,int(time.time()))).fetchone()
                if unsafe:
                    raise ValueError('Existing long or permanent '+source_jail(source)+
                                     ' ticket requires explicit migration; previous backend retained')
            tickets=sorted(raw_sources.get(source,set()))
            values={}
            live_times=(live_tickets[source] if live_tickets is not None else query_ticket_times(source)) if tickets else {}
            if set(live_times)!=set(tickets):
                raise ValueError('Fail2Ban tickets changed during verification')
            for offset in range(0,len(tickets),200):
                chunk=tickets[offset:offset+200]
                sql='SELECT ip,timeofban,bantime FROM bips WHERE jail=? AND ip IN ('+','.join('?' for _ in chunk)+')'
                for key,started,duration in db.execute(sql,[source_jail(source),*chunk]):
                    if key in values or type(started) is not int or type(duration) is not int or not 1<=duration<=MAX_LEGACY_EXPIRY:
                        raise ValueError('Invalid progressive ticket metadata')
                    if started>time.time()+5:
                        raise ValueError('Invalid progressive ticket time')
                    # Fail2Ban may extend an already banned ticket in memory
                    # without updating bips. Match both ends of the live
                    # ticket to its stored start to reject a stale DB row.
                    live=live_times.get(key)
                    # bips rounds fractional timestamps but --with-time
                    # truncates them, so its start can be one second earlier.
                    matching=next(((t,extra) for t in (started,started-1) for extra in (0,1) if live and live[1]>0 and
                        live[0]==time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(t)) and
                        live[2]==time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(t+live[1]+extra))),None)
                    if matching is None or started+live[1]+matching[1]<=time.time():
                        raise ValueError('Progressive ticket database is not current')
                    # Each published projection is bounded to 24 hours ahead.
                    # An ongoing attack can prolong the live F2B ticket, in
                    # which case scheduled reconciliation extends it again.
                    # The live display truncates subsecond ticket times.
                    values[key]=min(started+live[1]+matching[1]+1,int(time.time())+MAX_LEGACY_EXPIRY)
            if set(tickets)!=set(values):
                raise ValueError('Incomplete progressive ticket metadata')
            result[source]=values
    return result


def ticket_snapshot(root):
    # RPC must stay outside configuration/ban locks: a simultaneous unban can
    # wait for its action process, which itself needs those locks.
    saved_state=state(root)
    generation=saved_state.get('generation',0)
    try:
        configured=configured_sources(root)
        migration=read(root,'ban-migration.json',{})
        progressive=migration.get('progressiveSources',[]) if isinstance(migration,dict) else []
        if not isinstance(progressive,list) or len(progressive)!=len(set(progressive)) or set(progressive)-set(configured):
            raise ValueError('Invalid progressive source configuration')
        live_tickets={source:query_ticket_times(source) for source in progressive}
        sources={source:set(live_tickets[source]) if source in live_tickets else query_tickets(source)
                 for source in configured}
        expiries=progressive_expiries(sources,progressive,live_tickets=live_tickets)
        if 'api' in sources:
            api_site=migration.get('apiSite') if isinstance(migration,dict) else None
            converted=set()
            for ticket in sources['api']:
                if '|' not in ticket:
                    if not api_site:raise ValueError('Missing API ticket site')
                    original=ticket
                    ticket=policy.scope(api_site)+'|'+str(ipaddress.ip_address(ticket))
                    if 'api' in expiries:expiries['api'][ticket]=expiries['api'].pop(original)
                policy.key(ticket)
                converted.add(ticket)
            sources['api']=converted
        missing={(source,identity) for source,entries in expiries.items() for identity,expiry in entries.items()
                 if expiry>time.time() and source not in saved_state['records'].get(identity,{})}
        recoverable=set()
        if missing:
            config=policy.validate(manage.load_json(root/'config/waf/policy.json'))
            protected=policy.networks(manage.load_json(root/'config/waf/cloudflare-ips.json'))
            protected+=config.get('trustedProxies',[])+config.get('banIgnore',[])
            protected += [p for s in config['sites'].values() for p in s.get('trustedProxies',[])]
            local=json.loads(manage.execute('ip','-j','address','show'))
            protected += [a['local'] for interface in local for a in interface.get('addr_info',[])]
            sites=inventory(root)
            for source,identity in missing:
                site,address=policy.key(identity)
                if site in sites and policy.eligible(address,protected):recoverable.add((source,identity))
        return {'generation':generation,'sources':sources,'expiries':expiries,'recoverable':recoverable}
    except Exception:
        return None  # Unavailable/restarting jail is not proof of a removal.


def reconcile_tickets(value,snapshot):
    if snapshot is None or value.get('generation',0)!=snapshot['generation']:
        return False
    uncertain=False
    for identity,sources in value['records'].items():
        for source in list(sources):
            if source!='legacy' and source in snapshot['sources'] and identity not in snapshot['sources'][source]:
                sources.pop(source)
                value['generation']=value.get('generation',0)+1
            elif source in snapshot.get('expiries',{}):
                expiry=snapshot['expiries'][source].get(identity)
                if expiry is not None and expiry>sources[source]:
                    sources[source]=expiry
                    value['generation']=value.get('generation',0)+1
                elif expiry is not None and expiry<sources[source]:
                    # A bips row can still describe the previous ticket while
                    # the observer is asynchronously processing a new one.
                    # Never shorten an enforcement projection on that basis.
                    uncertain=True
    for source,identity in snapshot.get('recoverable',set()):
        expiry=snapshot['expiries'][source][identity]
        if expiry>time.time() and source not in value['records'].get(identity,{}):
            if identity not in value['records'] and len(value['records'])>=policy.MAX_BANS:
                raise ValueError('Ban budget exceeded during ticket recovery')
            value['records'].setdefault(identity,{})[source]=expiry
            value['generation']=value.get('generation',0)+1
    if uncertain:value['ticketVerificationPending']=True
    else:value.pop('ticketVerificationPending',None)
    return True


def change(root, operation, identity=None, source=None, seconds=None, lock_held=False, started=None):
    if operation in {'ban','unban'}:
        stage(root,operation,identity,source,seconds,started)
        operation='local'
    snapshot=ticket_snapshot(root) if operation=='sync' and not lock_held else None
    if operation=='sync' and not lock_held and snapshot is None and read(root,'ban-migration.json',{}).get('progressiveSources'):
        with manage.locked(root/'config/waf/ban.lock',timeout=10):
            save(root,'ban-health.json',{'ok':False,'checked':int(time.time()),
                                        'error':'Progressive ticket verification failed'})
        raise ValueError('Cannot verify progressive tickets; previous enforcement retained')
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
        verified=False
        if operation=='sync' and snapshot is not None:
            if not reconcile_tickets(value,snapshot):
                save(root,'ban-health.json',{'ok':False,'checked':int(time.time()),
                                            'error':'Ban state changed during ticket verification'})
                raise ValueError('Ban state changed during ticket verification; retry sync')
            verified=True
        if operation!='clear' and not verified:
            hold_unverified_progressive(root,value)
        value['records'] = live_records(value, int(time.time()))
        cf = read(root, 'ban-cf.json', {'mode': 'local'})
        if operation == 'clear':
            value['records'] = {}
            value.pop('ticketVerificationPending',None)
        reconcile(root, config, value, cf, edge=operation in {'sync','clear'},verified=verified or operation=='clear')


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


def required_jail_actions(migration):
    actions={'waf-attack':'waf-unified','waf-rate':'waf-unified'}
    if migration.get('apiJailEnabled'):
        actions['waf-api-invalid']='waf-unified-api' if migration.get('apiSite') else 'waf-unified'
    return actions


def live_jail_actions(jail):
    manage.execute('fail2ban-client','status',jail)
    output=manage.execute('fail2ban-client','get',jail,'actions')
    return {line.strip() for line in output.splitlines()
            if re.fullmatch(r'[A-Za-z0-9_.-]+',line.strip())}


def jail_action_loaded(jail, action):
    return action in live_jail_actions(jail)


def recover_jail_actions(jail,expected):
    # Fail2Ban can discard a newly named action during an ordinary reload.
    # Restart only an affected jail, without --unban, so database tickets can
    # be restored with their original expiry. Never restart unrelated jails.
    if expected and not expected<=live_jail_actions(jail):
        before=set(manage.execute('fail2ban-client','get',jail,'banip').split())
        if len(before)>policy.MAX_BANS:
            raise ValueError('Fail2Ban ticket budget exceeded for '+jail)
        if before:
            database=manage.execute('fail2ban-client','get','dbfile').strip().splitlines()
            dbpath=re.fullmatch(r'(?:[`|]-\s*)?(/[^\r\n]+)',database[-1].strip()) if database else None
            if not dbpath or not Path(dbpath.group(1)).is_file():
                raise ValueError('Cannot recover active tickets without a Fail2Ban database for '+jail)
        manage.execute('fail2ban-client','reload','--restart',jail)
        if not expected<=live_jail_actions(jail):
            raise ValueError('Fail2Ban action not loaded for '+jail)
        if before:
            deadline=time.monotonic()+5
            while True:
                after=set(manage.execute('fail2ban-client','get',jail,'banip').split())
                if before<=after:
                    break
                if time.monotonic()>=deadline:
                    raise ValueError('Fail2Ban tickets changed during recovery for '+jail)
                time.sleep(.2)


def ensure_jail_actions(migration):
    for jail,action in required_jail_actions(migration).items():
        recover_jail_actions(jail,{action})


def verify_progressive_jails(migration):
    enabled=set(migration.get('progressiveSources',[]))
    for source in ('attack','rate')+ (('api',) if migration.get('apiJailEnabled') else ()):
        jail=source_jail(source)
        value=manage.execute('fail2ban-client','get',jail,'bantime.increment').strip().lower()
        if value not in {'true','false'} or (value=='true')!=(source in enabled):
            raise ValueError('Fail2Ban progressive setting mismatch for '+jail)
        if source in enabled:
            fields={key:manage.execute('fail2ban-client','get',jail,'bantime.'+key).strip()
                    for key in ('factor','multipliers','maxtime','overalljails','rndtime')}
            probe=configparser.RawConfigParser(interpolation=None)
            probe.add_section(jail)
            probe.set(jail,'bantime.increment','true')
            for key,value in fields.items():probe.set(jail,'bantime.'+key,value)
            validate_progressive_settings(probe,jail)


def status(root):
    cf = read(root, 'ban-cf.json', {'mode': 'local'})
    health = read(root, 'ban-health.json', {'ok': False, 'checked': 0})
    jail = F2B/'jail.d/zz-waf-managed.local'
    configured = jail.exists() and managed_jail_marker(manage.read_config(jail))=='current'
    running = False
    progressive=[]
    if configured:
        try:
            migration=read(root,'ban-migration.json',{})
            for name,action in required_jail_actions(migration).items():
                if not jail_action_loaded(name,action):
                    raise ValueError('Fail2Ban action not loaded for '+name)
            progressive=migration.get('progressiveSources',[])
            if not isinstance(progressive,list) or set(progressive)-set(configured_sources(root)):
                raise ValueError('Invalid progressive source configuration')
            if progressive:
                fail2ban_database()
                for source in progressive:
                    if manage.execute('fail2ban-client','get',source_jail(source),'bantime.increment').strip().lower()!='true':
                        raise ValueError('Fail2Ban progressive setting mismatch')
            running = True
        except Exception:
            pass
    value=state(root)
    healthy = (health.get('ok') is True and not value.get('ticketVerificationPending',False) and
               0 <= int(time.time())-health.get('checked', 0) <= 180)
    healthy=healthy and health.get('originGeneration')==value.get('generation',0)
    pending=health.get('syncedGeneration')!=value.get('generation',0) or value.get('ticketVerificationPending') is True
    migration=migration_status(root)
    return {'mode': cf['mode'], 'cleanupPending':cf['mode']=='local' and bool(cf.get('auth')),
            'configured': configured, 'running': running,
            'healthy': healthy and running, 'pending': pending,
            'progressiveSources':progressive,
            'activeBans': len(live_records(value, int(time.time()))),
            'migration': migration}


def install(root):
    """Explicit migration entry point; SSH/custom jails are left intact."""
    with manage.locked(root/'config/waf/install.lock',timeout=10):
        return _install(root)


def set_cron(text):
    process = __import__('subprocess').run(['crontab', '-'], input=text, capture_output=True, text=True, timeout=10)
    if process.returncode:
        raise RuntimeError('Failed to update ban expiry schedule')


def clear(root, allow_missing=False):
    # Remove Fail2Ban's tickets/database records as well as our projection, so
    # a later reload cannot resurrect a manually cleared ban.
    # Callbacks persist their source removal and immediately defer a busy
    # configuration lock. Thus one final reload replaces per-ticket reloads.
    with manage.locked(root/'config/waf/install.lock',timeout=10):
        for source in configured_sources(root):
            tickets=sorted(query_tickets(source,allow_missing=allow_missing))
            for offset in range(0,len(tickets),100):
                manage.execute('fail2ban-client','set',source_jail(source),'unbanip',*tickets[offset:offset+100])
        change(root,'clear',lock_held=True)


def remove(root):
    initial=policy.validate(manage.load_json(root/'config/waf/policy.json'))
    cf=read(root,'ban-cf.json',{'mode':'local'})
    if initial.get('banBackend')=='none' and not state(root)['records'] and cf=={'mode':'local'}:
        return {'updated':False}
    configure_cf(root,disable=True)
    clear(root,allow_missing=True)
    with manage.locked(root/'config/waf/install.lock',timeout=10):
        jail=F2B/'jail.d/zz-waf-managed.local'
        if not jail.exists() or managed_jail_marker(manage.read_config(jail))!='current':
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
    plan=migration_plan(root)
    config = policy.validate(manage.load_json(root/'config/waf/policy.json'))
    if not __import__('shutil').which('fail2ban-client') or not __import__('shutil').which('crontab'):
        raise ValueError('Install Fail2Ban and enable the existing cron service first')
    previous_actions={}
    for jail_name in ('waf-attack','waf-rate','waf-api-invalid'):
        try:
            manage.execute('fail2ban-client','status',jail_name)
        except RuntimeError:
            continue  # A new installation may not have this jail yet.
        previous_actions[jail_name]=live_jail_actions(jail_name)
    json.loads(manage.execute('ip','-j','address','show'))
    directory = root/'conf.d/waf'
    runner = directory/'ban.py'
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(root)):
        raise ValueError('Unsupported integration path')
    jail = F2B/'jail.d/zz-waf-managed.local'
    previous=manage.read_config(jail) if jail.exists() else ''
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
    content=managed_jail_content(content if not previous or previous==DISABLED else previous,
                                 plan['apiJail'],root,defaults=content)
    content,progressive_sources=progressive_jail_content(content,plan['apiJail'])
    if progressive_sources:
        # Verify DB support before changing any production files or services.
        progressive_expiries({source:set() for source in progressive_sources},progressive_sources,
                             reject_legacy_active=True)
    files = {jail: content.encode(), F2B/'action.d/waf-unified.conf': action.encode(),
             F2B/'jail.d/zz-kejilion-web-baseline.local': (manage.BUNDLE/'legacy-jails.local').read_bytes()}
    api_site=plan['apiJail'].get('site') if plan['apiJail'] else None
    if api_site:
        if api_site not in inventory(root):
            raise ValueError('Legacy API site is not present in the site inventory')
        api_action=('[Definition]\nactionban = '+interpreter+' -E -s -B '+str(runner)+
                    ' --root '+str(root)+' ban --identity "<site>|<ip>" --source api --seconds <bantime> --started <time>\n'+
                    'actionunban = '+interpreter+' -E -s -B '+str(runner)+
                    ' --root '+str(root)+' unban --identity "<site>|<ip>" --source api\n[Init]\nsite = '+api_site+'\ntimeout = 180\n')
        files[F2B/'action.d/waf-unified-api.conf']=api_action.encode()
    for name, text in policy.render_filters().items():
        files[F2B/'filter.d'/name] = text.encode()
    for name in ['waf-rate.log', 'waf-audit.json']:
        path = root/'log/nginx'/name
        manage.safe_parent(path)
        if path.is_symlink():
            raise ValueError('Unsafe event log')
    state_path=root/'config/waf/bans.json'
    migration_path=root/'config/waf/ban-migration.json'
    private_before=private_snapshot([state_path,migration_path,root/'conf.d/waf/blocked.map'])
    files_before=private_snapshot(files.keys())
    reconciler_stopped=False
    policy_result=None
    result=None
    migration=read(root,'ban-migration.json',{})
    if plan['requiresMigration'] and not migration:
        migration={'state':'legacy-imported' if plan['imported'] else 'legacy-compatible',
                   'importedRecords':plan['legacyState']['importedRecords'] if plan['legacyState'] else 0,
                   'apiJailEnabled':bool(plan['apiJail'] and plan['apiJail']['enabled']),
                   'legacyCFDetected':plan['legacyCFDetected'],
                   'cfReentryRequired':plan['cfReentryRequired'],
                   'legacyReconcilerStopped':False}
    elif not migration:
        migration={'state':'current','importedRecords':0,
                   'apiJailEnabled':bool(plan['apiJail'] and plan['apiJail']['enabled']),
                   'legacyCFDetected':plan['legacyCFDetected'],
                   'cfReentryRequired':plan['cfReentryRequired'],
                   'legacyReconcilerStopped':False}
    else:
        migration=dict(migration)
        migration['apiJailEnabled']=bool(plan['apiJail'] and plan['apiJail']['enabled']) or migration.get('apiJailEnabled',False)
        migration['legacyCFDetected']=plan['legacyCFDetected'] or migration.get('legacyCFDetected',False)
        migration['cfReentryRequired']=plan['cfReentryRequired'] or migration.get('cfReentryRequired',False)
    if api_site:
        migration['apiSite']=api_site
    migration['progressiveSources']=progressive_sources
    def activate():
        for name in ['waf-rate.log','waf-audit.json']:
            path=root/'log/nginx'/name
            path.touch(exist_ok=True);path.chmod(0o640)
        manage.execute('fail2ban-client', '-t')
        change(root, 'sync',lock_held=True)
        manage.execute('fail2ban-client', 'reload')
        ensure_jail_actions(migration)
        verify_progressive_jails(migration)
        progressive_expiries({source:set() for source in progressive_sources},progressive_sources,
                             reject_legacy_active=True)
        change(root,'sync',lock_held=True)
        set_cron(cron_text)
    def restore_fail2ban():
        manage.execute('fail2ban-client','reload')
        for jail_name,actions in previous_actions.items():
            recover_jail_actions(jail_name,actions)
    try:
        if plan['requiresMigration'] and plan['reconciler']['recognized']:
            set_legacy_reconciler(plan,False)
            reconciler_stopped=True
            after=legacy_state(root) if plan['imported'] else None
            before_digest=plan['legacyState']['mapDigest'] if plan['legacyState'] else None
            if after and after['mapDigest']!=before_digest:
                raise ValueError('Legacy ban state changed during migration; previous backend retained')
        if plan['imported']:
            if state_path.exists():
                current=merge_legacy_records(state(root),plan['legacyState']['records'])
            else:
                current={'owner':uuid.uuid4().hex,'records':plan['legacyState']['records'],'generation':0}
            save(root,'bans.json',current)
        migration['legacyReconcilerStopped']=reconciler_stopped or migration.get('legacyReconcilerStopped',False)
        save(root,'ban-migration.json',migration)
        policy_result = manage.apply(root, config,lock_held=True)
        result = manage._external_update(root, files, 'unified-bans', activate)
        result['migration']=status(root)['migration']
        result['progressiveSources']=progressive_sources
    except Exception:
        errors=[]
        for restore in [lambda:restore_private(files_before),
                        lambda:restore_private(private_before),
                        lambda:set_cron(cron.stdout),
                        lambda:manage.restore(root,Path(policy_result['backup'])) if policy_result and policy_result.get('backup') else None,
                        lambda:manage.reload_nginx(config_before['container']) if policy_result else None,
                        restore_fail2ban,
                        lambda:set_legacy_reconciler(plan,True) if reconciler_stopped else None]:
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
    parser.add_argument('--source', choices=['attack', 'rate', 'api'])
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
