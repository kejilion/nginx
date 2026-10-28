#!/usr/bin/env python3
"""Configure the existing Nginx/ModSecurity chain without installing a service."""
from __future__ import annotations
import argparse
import base64
import contextlib
import configparser
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import shutil
import urllib.request
import nginx_edit
import policy
BUNDLE=Path(__file__).resolve().parent
MAX_BACKUPS=128
MAX_BACKUP_BYTES=64*1024*1024

def safe_parent(path: Path):
    """Root actions must not follow replaceable directories supplied by a web user."""
    for parent in [path.parent, *path.parent.parents]:
        if not parent.exists() and not parent.is_symlink():
            continue
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError('Unsafe parent directory: ' + str(parent))
        if hasattr(os, 'geteuid') and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
            raise ValueError('Untrusted parent ownership/permissions: ' + str(parent))


def atomic(path: Path, data: bytes, mode: int = 0o600) -> None:
    safe_parent(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("Refusing symlink: " + str(path))
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_json(path: Path, default=None):
    safe_parent(path)
    if path.is_symlink():
        raise ValueError("Refusing symlink: " + str(path))
    if not path.exists():
        if default is not None:
            return default
        raise FileNotFoundError(path)
    info = path.stat()
    if info.st_size > policy.MAX_STATE_BYTES or (os.name=='posix' and info.st_mode & 0o022):
        raise ValueError("Unsafe state size or permissions: " + str(path))
    if hasattr(os, 'geteuid') and info.st_uid != os.geteuid():
        raise ValueError("State owner mismatch")
    return json.loads(path.read_text(encoding='utf-8'))


@contextlib.contextmanager
def locked(path: Path, timeout=None):
    import fcntl
    safe_parent(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('Unsafe lock file')
        if timeout is None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        else:
            deadline=time.monotonic()+timeout
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic()>=deadline:raise RuntimeError('Configuration is busy; retry later')
                    time.sleep(0.1)
        yield
    finally:
        os.close(fd)


def reload_nginx(container):
    def workers():
        output=execute('docker','top',container,'-eo','pid,args')
        return {line.split()[0] for line in output.splitlines() if 'nginx: worker process' in line and 'shutting down' not in line}
    before=workers()
    if not before:raise RuntimeError('No serving Nginx workers')
    execute('docker','exec',container,'nginx','-s','reload')
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        after=workers()
        if after and not (after & before):return
        time.sleep(0.2)
    raise RuntimeError('New Nginx worker generation was not observed')

def external_update(root,files,label,apply_command):
    """Fixed integration files; preserve preimage on validation failure."""
    with locked(root/'config/waf/install.lock'):
        return _external_update(root,files,label,apply_command)


def _external_update(root,files,label,apply_command):
    backup_budget(root)
    directory=root/'backups/waf-managed'/(
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'-'+label)
    safe_parent(directory/'preimage.json')
    directory.mkdir(parents=True,mode=0o700)
    previous={}
    for path in files:
        safe_parent(path)
        if path.exists():read_config(path)
        previous[str(path)]={'before':base64.b64encode(path.read_bytes()).decode() if path.exists() else None,
                             'mode':path.stat().st_mode & 0o777 if path.exists() else 0o644}
    atomic(directory/'preimage.json',(json.dumps(previous)+'\n').encode())
    try:
        for path,data in files.items():atomic(path,data,0o644)
        apply_command()
    except Exception:
        for raw,item in previous.items():
            path=Path(raw)
            if item['before'] is None:
                if path.exists():path.unlink()
            else:atomic(path,base64.b64decode(item['before']),item['mode'])
        raise
    return {'updated':True,'backup':str(directory)}


def fail2ban_update(root,legacy=False):
    if not shutil.which('fail2ban-client'):return {'updated':False,'reason':'fail2ban-not-installed'}
    if legacy:files={Path('/etc/fail2ban/jail.d/zz-kejilion-web-baseline.local'):(BUNDLE/'legacy-jails.local').read_bytes()}
    else:
        jail=Path('/etc/fail2ban/jail.d/zz-waf-managed.local')
        if not jail.exists():return {'updated':False,'reason':'no-existing-shared-jails'}
        before=read_config(jail)
        migrated=migrate_existing_jail(root,before)
        files={Path('/etc/fail2ban/filter.d')/name:data.encode() for name,data in policy.render_filters().items()}
        files[jail]=migrated.encode()
        log=root/'log/nginx/waf-audit.json'
        safe_parent(log)
        if log.is_symlink():raise ValueError('Unsafe audit log')
        log.touch(exist_ok=True);log.chmod(0o640)
    active=subprocess.run(['fail2ban-client','ping'],capture_output=True,timeout=10).returncode==0
    def validate():
        execute('fail2ban-client','-t')
        if active:execute('fail2ban-client','reload')
    try:return external_update(root,files,'legacy-jails' if legacy else 'filters',validate)
    except Exception:
        if active:execute('fail2ban-client','reload')
        raise


def migrate_existing_jail(root,text):
    import ban
    if not has_managed_shared_waf_header(text):
        # A small number of older script installs created the exact WAF jails
        # without a managed header. Reuse the ban migration classifier so this
        # path accepts only the known filters/actions/logs, never arbitrary
        # Fail2Ban configurations.
        ban.validate_managed_jail(text,allow_unmarked_legacy=True,root=root)
        if ban.has_legacy_waf_actions(text):
            ban.validate_legacy_wafctl_action('waf-local')
    text=ban.canonicalize_waf_section_names(text)
    parsed=ban.parse_jail(text)
    # Earlier installations could enable only rate defense (or only attack
    # auditing). The normal ban-install path fills the missing product jail;
    # a filter refresh must not invent it or reject the existing one.
    if not parsed.has_section('waf-attack'):
        return text
    old=str(root/'log/nginx/error.log');new=str(root/'log/nginx/waf-audit.json')
    value=parsed.get('waf-attack','logpath',fallback=None)
    if value is None:raise ValueError('Existing attack log path must be explicit in its jail')
    tokens=value.split();tail=bool(tokens and tokens[-1].lower()=='tail')
    if tail:tokens.pop()
    if not tokens:raise ValueError('Existing attack log path requires explicit migration')
    migrated=[]
    for token in tokens:
        base=next((candidate for candidate in (old,new)
                   if token==candidate or token.startswith(candidate) and
                   token[len(candidate):][:1] in {'.','*','?'} and
                   re.fullmatch(r'[.A-Za-z0-9*?_-]+',token[len(candidate):])),None)
        if base is None:raise ValueError('Existing attack log path requires explicit migration')
        migrated.append(new+token[len(base):])
    new_value=' '.join(migrated+(['tail'] if tail else []))
    # Only the attack logpath changes, including inherited DEFAULT values;
    # preserve formatting, other options and action arguments.
    section=None;changed=0;insert=None;newline='\r\n' if '\r\n' in text else '\n';lines=text.splitlines(keepends=True)
    for index,line in enumerate(lines):
        header=re.match(r'^\s*\[([^\]]+)\]',line)
        if header:
            section=header[1]
            if section=='waf-attack' and insert is None:insert=index+1
        if section!='waf-attack':continue
        value=re.match(r'(?i)^([ \t]*logpath[ \t]*[=:][ \t]*)(.*?)([ \t]*)(\r?\n)?$',line)
        if not value:continue
        if changed:raise ValueError('Existing attack log path is ambiguous')
        lines[index]=value[1]+new_value+value[3]+(value[4] or '')
        changed+=1
    if changed==0:
        if insert is None:raise ValueError('Existing attack log path must be explicit in its jail')
        lines.insert(insert,'logpath = '+new_value+newline)
    return ''.join(lines)


def has_managed_shared_waf_header(text):
    marker=re.compile(r'#\s*Managed shared WAF(?:\s*(?:[;.:—-])\s*.*|\s+.*)?',re.I)
    for line in text.splitlines():
        candidate=line.strip().removeprefix('\ufeff').strip()
        if marker.fullmatch(candidate):return True
        if candidate and not candidate.startswith('#'):break
    return False


def rotation(root,config):
    with locked(root/'config/waf/install.lock'):
        return _rotation(root,config)


def _rotation(root,config):
    binary=shutil.which('logrotate')
    if not binary or not shutil.which('crontab'):raise ValueError('Install logrotate and enable the existing cron service first')
    if not all(re.fullmatch(r'/[A-Za-z0-9_./-]+',x) for x in [str(root),binary]):raise ValueError('Unsupported rotation paths')
    directory=root/'config/waf';path=directory/'logrotate.conf'
    content=(str(root/'log/nginx/waf-rate.log')+' '+str(root/'log/nginx/waf-audit.json')+''' {
    daily
    maxsize 10M
    rotate 4
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0640 root root
}
'''+str(root/'log/nginx/error.log')+' '+str(root/'log/nginx/access.log')+' '+str(root/'log/nginx/waf-protocol.log')+''' {
    daily
    maxsize 50M
    rotate 4
    missingok
    notifempty
    compress
    copytruncate
}
''').encode()
    crontab=subprocess.run(['crontab','-l'],capture_output=True,text=True,timeout=10)
    if crontab.returncode and 'no crontab' not in crontab.stderr.lower():raise ValueError('Unable to preserve existing crontab')
    before=crontab.stdout if crontab.returncode==0 else ''
    marker='# kejilion-waf-logrotate'
    job='* * * * * '+binary+' --state '+str(directory/'logrotate.status')+' '+str(path)+' >/dev/null 2>&1 '+marker
    legacy='0 2 * * * docker exec nginx apk add logrotate && docker exec nginx logrotate -f /etc/logrotate.conf'
    lines=[line for line in before.splitlines() if not line.endswith(marker) and line!=legacy]
    updated='\n'.join([*lines,job])+'\n'
    backup=directory/'logrotate-cron-preimage.txt'
    if not backup.exists():atomic(backup,before.encode())
    def validate():
        execute(binary,'--debug','--state',str(directory/'logrotate.status'),str(path))
        try:
            subprocess.run(['crontab','-'],input=updated,text=True,capture_output=True,timeout=10,check=True)
        except Exception:
            # A failed or interrupted installer may already have changed cron.
            # Restore exactly the preimage instead of dropping unrelated jobs.
            subprocess.run(['crontab','-'],input=before,text=True,capture_output=True,timeout=10,check=True)
            raise
    return _external_update(root,{path:content},'rotation',validate)


def trust_cloudflare(root,config,expected):
    if (root/'config/waf/policy.json').exists():
        config['cdn']='mixed'
        return apply(root,config,expected=expected,respect_native=True)
    path=root/'conf.d/default.conf'
    cf=load_json(BUNDLE/'cloudflare-ips.json')
    networks=policy.networks(cf)
    replacement=nginx_edit.strip_legacy_default_realip(read_config(path),networks)+policy.render_realip({'cdn':'cloudflare'},networks)
    changes={path:replacement.encode()}
    with locked(root/'config/waf/install.lock'):
        backup=snapshot(root,changes,'cloudflare')
        try:
            atomic(path,changes[path],0o644)
            execute('docker','exec',config['container'],'nginx','-t')
            reload_nginx(config['container'])
        except Exception:
            restore(root,backup,verify=False)
            execute('docker','exec',config['container'],'nginx','-t')
            reload_nginx(config['container'])
            raise
    return {'cdn':'cloudflare','inspectionChanged':False,'backup':str(backup)}


def execute(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(args[:4]) + ': ' + (result.stderr or result.stdout)[-1600:])
    return result.stdout


def kpanel_endpoints():
    """Identify the native KPanel container without reading credentials/env."""
    result=subprocess.run(['docker','inspect','kejilion-panel','--format','{{json .NetworkSettings}}'],
                          capture_output=True,text=True,timeout=10)
    if result.returncode:return set()
    if len(result.stdout)>65536:raise ValueError('Container endpoint metadata exceeds budget')
    data=json.loads(result.stdout)
    addresses=set()
    for name,bindings in (data.get('Ports') or {}).items():
        if not name.endswith('/tcp'):continue
        port=name.split('/')[0]
        for binding in bindings or []:
            addresses.update((host,binding['HostPort']) for host in ['127.0.0.1','0.0.0.0','localhost'])
        for network in (data.get('Networks') or {}).values():
            for field in ['IPAddress','GlobalIPv6Address']:
                if network.get(field):addresses.add((network[field],port))
    return addresses


def app_is_kpanel(text,block,endpoints):
    if not endpoints:return False
    import urllib.parse
    groups=nginx_edit.statement_scopes(nginx_edit.tokens(text))
    upstreams={}
    for group in groups.values():
        if group['kind'].strip('\"\'')=='upstream':
            head=group['head']
            if len(head)>1:
                # URL hostnames are case-insensitive; native reverse-proxy
                # templates deliberately generate mixed-case upstream names.
                upstreams[head[1].strip('\"\'').lower()]=[s[1].value.strip('\"\'') for s in group['statements'] if s[0].value.strip('\"\'')=='server']
    body=text[block['open']:block['close']]
    matched=[]
    for group in nginx_edit.statement_scopes(nginx_edit.tokens(body)).values():
        for statement in group['statements']:
            directive=statement[0].value.strip('\"\'')
            if directive in {'fastcgi_pass','uwsgi_pass','scgi_pass','grpc_pass'} or directive.startswith(('access_by_lua','rewrite_by_lua','content_by_lua','js_','perl')):return False
            if directive=='include':
                include=statement[1].value.strip('\"\'')
                if not re.fullmatch(r'/etc/nginx/conf\.d/waf/(?:server-(?:default\*?|[a-f0-9]{16})|access-log\*?)\.inc',include):return False
            if directive!='proxy_pass':continue
            target_value=statement[1].value.strip('\"\'')
            value=urllib.parse.urlsplit(target_value)
            targets=upstreams.get(value.hostname,[target_value])
            for target in targets:
                address=urllib.parse.urlsplit(target if '://' in target else 'http://'+target)
                try:port=str(address.port or (443 if address.scheme=='https' else 80))
                except ValueError:return False
                matched.append(address.scheme in {'http','https'} and (address.hostname,port) in endpoints)
    # A mixed application or mixed upstream must retain its explicit/default
    # profile rather than inheriting another application's typed exceptions.
    return bool(matched) and all(matched)


def app_is_flarum(document_root):
    project=document_root.parent if document_root.name=='public' else document_root
    paths=[project/'composer.json',project/'vendor/flarum/core/composer.json']
    metadata=[]
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.stat().st_size>65536:return False
        try:metadata.append(json.loads(path.read_text(encoding='utf-8')))
        except (ValueError,OSError):return False
    return (all(isinstance(item,dict) for item in metadata) and
            isinstance(metadata[0].get('require'),dict) and
            'flarum/core' in metadata[0]['require'] and metadata[1].get('name')=='flarum/core')


def flarum_scope_is_unmixed(groups):
    """Do not infer source-text exclusions for another app in a shared vhost."""
    for scope,group in groups.items():
        for statement in group['statements']:
            directive=statement[0].value.strip('\"\'')
            if directive in {'proxy_pass','uwsgi_pass','scgi_pass','grpc_pass','alias'}:return False
            if directive.startswith(('access_by_lua','rewrite_by_lua','content_by_lua','js_','perl')):return False
            if directive=='root' and scope!=0:return False
            if directive=='fastcgi_param' and statement[1].value.strip('\"\'').upper()=='SCRIPT_FILENAME' and statement[2].value.strip('\"\'') not in {'$document_root$fastcgi_script_name','$realpath_root$fastcgi_script_name'}:return False
            if directive=='include':
                value=statement[1].value.strip('\"\'')
                if value not in {'fastcgi_params','fastcgi.conf','/etc/nginx/fastcgi_params','/etc/nginx/fastcgi.conf'} and not re.fullmatch(r'/etc/nginx/conf\.d/waf/(?:server-(?:default\*?|[a-f0-9]{16})|access-log\*?)\.inc',value):return False
    return True


def read_config(path):
    safe_parent(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError('Unsafe or excessive configuration: ' + str(path))
    info=path.stat()
    if hasattr(os,'geteuid') and (info.st_uid!=os.geteuid() or info.st_mode & 0o022):
        raise ValueError('Untrusted configuration ownership/permissions: '+str(path))
    return path.read_text(encoding='utf-8')


def write(path, data, mode=0o644, inplace=False):
    if not inplace:
        atomic(path, data, mode)
        return
    # Docker single-file bind mounts retain their inode. The candidate was already
    # syntax checked; preserve that inode and fsync, with an exact preimage rollback.
    safe_parent(path)
    fd = os.open(path, os.O_WRONLY | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def make_plan(root, config, cfdata=None):
    policy.validate(config)
    current=root/'config/waf/cloudflare-ips.json'
    cfdata=cfdata or load_json(current if current.exists() else BUNDLE/'cloudflare-ips.json')
    cloudflare = policy.networks(cfdata)
    changes = {}
    main = root / 'nginx.conf'
    allowed_proxy_files={'/etc/nginx/conf.d/'+p.name for p in (root/'conf.d').glob('*.conf')}
    effective=execute('docker','exec',config['container'],'nginx','-T')
    header_scopes=nginx_edit.configuration_headers(effective,allowed_proxy_files)
    method_controls=nginx_edit.method_override_controls(effective)
    cache_controls=nginx_edit.cache_inheritance(effective)
    if any(name not in allowed_proxy_files and not name.startswith('/etc/nginx/conf.d/waf/') for name,_ in header_scopes):
        raise ValueError('Proxy directives outside managed site files need explicit integration')
    main_text=read_config(main)
    if not (root/'config/waf/policy.json').exists():
        for field,pattern in [('rate',r'zone=example_zone:[^;]+rate=(\d+)r/s'),
                              ('burst',r'limit_req zone=example_zone burst=(\d+)'),
                              ('connections',r'limit_conn addr (\d+);')]:
            found=re.search(pattern,main_text)
            if found:config[field]=max(config.get(field,{'rate':50,'burst':200,'connections':256}[field]),int(found[1]))
        policy.validate(config)
    changes[main] = nginx_edit.absolute_includes(nginx_edit.patch_main(main_text,enabled=policy.engine_enabled(config))).encode()
    discovered = []
    panel=kpanel_endpoints()
    configs = list(sorted((root / 'conf.d').glob('*.conf')))
    if len(configs) > 250:
        raise ValueError('Site file count exceeds supported budget')
    for path in configs:
        text = read_config(path)
        scopes = nginx_edit.site_scopes(text)
        discovered += [s for s in scopes if s != '_']
        if not scopes:
            continue
        for block in nginx_edit.server_blocks(text):
            if not block['names'] or block['names'][0]=='_':continue
            name=block['names'][0]
            if app_is_kpanel(text,block,panel):config['sites'].setdefault(name,{}).setdefault('profile','kpanel')
            # Only the server's own document root identifies its application.
            groups=nginx_edit.statement_scopes(nginx_edit.tokens(text[block['open']:block['close']]))
            roots=[s[1].value.strip('\"\'') for s in groups[0]['statements'] if s[0].value=='root']
            roots=[r for r in roots if re.fullmatch(r'/var/www/html/[A-Za-z0-9_./-]+',r)]
            if any((root/'html'/value.removeprefix('/var/www/html/')/'wp-includes').is_dir() for value in roots):
                config['sites'].setdefault(name,{}).setdefault('profile','wordpress')
            if flarum_scope_is_unmixed(groups) and any(app_is_flarum(root/'html'/value.removeprefix('/var/www/html/')) for value in roots):
                config['sites'].setdefault(name,{}).setdefault('profile','flarum')
        text=nginx_edit.patch_application(text,header_scopes,'/etc/nginx/conf.d/'+path.name)
        if path.name == 'default.conf':
            text = nginx_edit.strip_legacy_default_realip(text,cloudflare)
        # Historical whole-site switches are migration work, not permanent bypasses.
        # Preserve an explicit replacement; otherwise start that site in detection.
        text,legacy_off=nginx_edit.migrate_server_off(text)
        if config['mode']!='off':
            for name in legacy_off:config['sites'].setdefault(name,{}).setdefault('mode','detect')
        changes[path] = nginx_edit.absolute_includes(nginx_edit.patch_site(text, config)).encode()
    if not discovered:
        raise ValueError('No application sites found')
    if len(set(discovered)) > policy.MAX_SITES:
        raise ValueError('Site count exceeds supported budget')
    policy.validate(config)
    directory = root / 'conf.d/waf'
    for name, content in policy.bundle_files(config, cloudflare,method_controls,cache_controls).items():
        changes[directory / name] = content.encode()
    changes[directory / 'cloudflare-ips.json'] = (json.dumps(cfdata, sort_keys=True)+'\n').encode()
    changes[current] = (json.dumps(cfdata, sort_keys=True)+'\n').encode()
    # The package is managed as a unit; no code or credentials are downloaded at run time.
    for name in ['policy.py', 'nginx_edit.py', 'configure.py', 'ban.py', 'example-policy.json', 'legacy-jails.local']:
        changes[directory / name] = (BUNDLE / name).read_bytes()
    changes[root / 'config/waf/policy.json'] = (json.dumps(config, indent=2, sort_keys=True)+'\n').encode()
    blocked=directory/'blocked.map'
    if blocked.exists() or blocked.is_symlink():read_config(blocked)
    else:
        changes[directory / 'blocked.map'] = policy.render_bans({}, int(time.time())).encode()
    for path in changes:
        safe_parent(path)
        if path.is_symlink():
            raise ValueError('Symlink target refused: ' + str(path))
        if len(changes[path])>2*1024*1024:raise ValueError('Generated configuration exceeds per-file budget: '+str(path))
        if path.exists():read_config(path)
    return changes, sorted(set(discovered))


def snapshot(root, changes, label):
    backup_budget(root)
    directory = root / 'backups/waf-managed' / (datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'-'+label)
    safe_parent(directory/'manifest.json')
    directory.mkdir(parents=True, mode=0o700)
    records = {}
    total = 0
    for path in changes:
        before = path.read_bytes() if path.exists() else None
        total += len(before or b'')
        if total > 2*1024*1024:
            raise ValueError('Backup budget exceeded')
        records[str(path.relative_to(root))] = {
            'before': base64.b64encode(before).decode() if before is not None else None,
            'mode': (path.stat().st_mode & 0o777) if before is not None else 0o644,
            'afterSha256': hashlib.sha256(changes[path]).hexdigest(),
        }
    atomic(directory / 'manifest.json', (json.dumps({'schemaVersion':1, 'files':records},sort_keys=True)+'\n').encode())
    return directory


def backup_budget(root):
    """Refuse unbounded backup growth; never silently prune user recovery points."""
    directory=root/'backups/waf-managed'
    safe_parent(directory/'manifest.json')
    if not directory.exists():return
    count=total=0
    with os.scandir(directory) as entries:
        for entry in entries:
            count+=1
            if count>=MAX_BACKUPS:raise ValueError('Managed backup count limit reached; archive older recovery points first')
            if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):raise ValueError('Unrecognized managed backup entry')
            for name in ['manifest.json','preimage.json']:
                path=Path(entry.path)/name
                if path.is_symlink():raise ValueError('Unsafe backup manifest')
                if path.exists():total+=path.stat().st_size
            if total>MAX_BACKUP_BYTES-4*1024*1024:raise ValueError('Managed backup byte limit reached; archive older recovery points first')


def check_trust_dump(text):
    files=re.split(r'(?m)^# configuration file ([^\r\n]+):\n',text)
    for index in range(1,len(files),2):
        current,body=files[index:index+2]
        stream=nginx_edit.tokens(body)
        for i,token in enumerate(stream):
            if i and stream[i-1].value not in {';','{','}'}:continue
            if token.value in {'set_real_ip_from','real_ip_header','real_ip_recursive'}:
                if not re.fullmatch(r'/etc/nginx/conf\.d/waf/realip(?:-[a-f0-9]{16})?\.conf',current):
                    raise ValueError('Unmanaged proxy trust requires explicit policy migration: '+current)


def restore(root, backup, verify=True):
    directory = (root / 'backups/waf-managed').resolve()
    backup = backup.absolute()
    if backup.resolve() != backup or directory not in backup.parents:
        raise ValueError('Rollback must use a managed backup inside the installation')
    manifest = load_json(backup / 'manifest.json')
    paths = []
    for relative, item in manifest['files'].items():
        path = root / relative
        if path.resolve() != path or root not in path.parents:
            raise ValueError('Invalid backup target')
        safe_parent(path)
        if verify and (not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != item['afterSha256']):
            raise ValueError('Configuration changed since install; explicit conflict resolution required: '+relative)
        paths.append((path,item))
    # Restore the main configuration first so no new includes remain on next reload.
    for path,item in paths:
        if item['before'] is None:
            if path.exists():
                path.unlink()
        else:
            write(path,base64.b64decode(item['before']),item['mode'],inplace=path==root/'nginx.conf')


UNSET=object()


def native_engine_enabled(text):
    groups=nginx_edit.statement_scopes(nginx_edit.tokens(text))
    http=[group for group in groups.values() if group['kind']=='http']
    if len(http)!=1:raise ValueError('Expected one authoritative HTTP switch')
    return any([token.value for token in statement[:-1]]==['modsecurity','on'] for statement in http[0]['statements'])


def reconcile_native_switch(root,config):
    enabled=native_engine_enabled(read_config(root/'nginx.conf'))
    if not enabled or not policy.engine_enabled(config):
        mode='on' if enabled else 'off'
        config=dict(config,mode=mode,sites={name:{key:value for key,value in site.items() if key!='mode'} for name,site in config['sites'].items()})
    return config


def apply(root, config, cfdata=None, expected=UNSET, respect_native=False, lock_held=False):
    with contextlib.nullcontext() if lock_held else locked(root / 'config/waf/install.lock'):
        current=root/'config/waf/policy.json'
        actual=hashlib.sha256(current.read_bytes()).hexdigest() if current.exists() else None
        if expected is not UNSET and actual!=expected:
            raise ValueError('Policy changed concurrently; retry against current configuration')
        if respect_native:config=reconcile_native_switch(root,config)
        changes, sites = make_plan(root, config,cfdata)
        changes={path:data for path,data in changes.items() if not path.exists() or path.read_bytes()!=data}
        if not changes:
            check_trust_dump(execute('docker','exec',config['container'],'nginx','-T'))
            reload_nginx(config['container'])
            return {'applied':False,'mode':config['mode'],'sites':sites,'version':policy.VERSION}
        backup = snapshot(root, changes, 'policy')
        container = config['container']
        candidate = root / 'conf.d/waf/pending-nginx.conf'
        try:
            for path,content in changes.items():
                if path != root / 'nginx.conf':
                    atomic(path,content,0o600 if path.name=='policy.json' else 0o644)
            atomic(candidate,changes.get(root/'nginx.conf',(root/'nginx.conf').read_bytes()))
            dump=execute('docker','exec',container,'nginx','-T','-c','/etc/nginx/conf.d/waf/pending-nginx.conf')
            check_trust_dump(dump)
            if root/'nginx.conf' in changes:write(root/'nginx.conf',changes[root/'nginx.conf'],inplace=True)
            execute('docker','exec',container,'nginx','-t')
            reload_nginx(config['container'])
        except Exception:
            restore(root,backup,verify=False)
            execute('docker','exec',container,'nginx','-t')
            execute('docker','exec',container,'nginx','-s','reload')
            raise
        finally:
            if candidate.exists():
                candidate.unlink()
        atomic(root/'config/waf/last-backup.json',(json.dumps({'path':str(backup)})+'\n').encode())
        return {'applied':True,'mode':config['mode'],'sites':sites,'backup':str(backup),'version':policy.VERSION}


def configured_status(root,config):
    files=list((root/'conf.d').glob('*.conf'))
    if len(files)>250:raise ValueError('Site file count exceeds supported budget')
    names={name for path in files for name in nginx_edit.site_scopes(read_config(path)) if name!='_'}
    modes={config['sites'].get(name,{}).get('mode',config['mode']) for name in names} or {config['mode']}
    engine=native_engine_enabled(read_config(root/'nginx.conf'))
    if not engine and any([t.value for t in s[:-1]]==['modsecurity','on'] for path in files for group in nginx_edit.statement_scopes(nginx_edit.tokens(read_config(path))).values() for s in group['statements']):
        raise ValueError('Child WAF switch conflicts with the global Off state; apply migration first')
    # Verify the expanded source graph before claiming a global mode. External
    # HTTP fragments can otherwise override the main file's apparent Off state.
    effective=execute('docker','exec',config.get('container','nginx'),'nginx','-T')
    nginx_edit.configuration_headers(effective,{'/etc/nginx/conf.d/'+path.name for path in files})
    strict_all,strict_sites=nginx_edit.method_override_controls(effective)
    profile=root/'conf.d/waf/profile-rules.conf'
    synchronized=profile.exists() and read_config(profile)==policy.render_profile_rules(config,(strict_all,strict_sites))
    mode='off' if not engine else ('on' if not policy.engine_enabled(config) else (next(iter(modes)) if len(modes)==1 else 'mixed'))
    return {'mode':mode,'engineEnabled':engine,'sites':config['sites'],'siteCount':len(names),
            'banBackend':config.get('banBackend','existing'),'source':'configuration',
            'methodOverride':{'configured':config.get('methodOverride','guarded'),
                              'gatewayStrictAll':strict_all,'gatewayStrictSites':sorted(strict_sites),
                              'synchronized':synchronized}}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--root',type=Path,default=Path('/home/web'))
    parser.add_argument('action',choices=['plan','apply','configure','doctor','status','rollback','refresh-ips','retire-jails','existing-filters','rotation','trust-cloudflare','ban-preflight','ban-install','ban-remove','ban-status','ban-clear','cf-on','cf-off'])
    parser.add_argument('--policy',type=Path)
    parser.add_argument('--backup',type=Path)
    parser.add_argument('--mode',choices=sorted(policy.MODES))
    parser.add_argument('--cdn',choices=['direct','cloudflare','mixed','proxy'])
    parser.add_argument('--site')
    parser.add_argument('--profile',choices=sorted(policy.PROFILES))
    parser.add_argument('--method-override',choices=['guarded','strict'])
    args=parser.parse_args()
    if args.profile and not args.site:parser.error('--profile requires --site')
    if args.action!='configure' and any([args.mode,args.site,args.profile,args.cdn,args.method_override]):parser.error('Policy options require configure')
    if os.geteuid()!=0:parser.error('Root privileges required')
    root=args.root.absolute()
    safe_parent(root/'config/waf/policy.json')
    if root.resolve()!=root or str(root)=='/':raise ValueError('Unsafe root')
    default=root/'config/waf/policy.json'
    expected=hashlib.sha256(default.read_bytes()).hexdigest() if default.exists() else None
    if args.action in {'configure','retire-jails','trust-cloudflare','ban-preflight','ban-install'} and not default.exists():default=BUNDLE/'example-policy.json'
    config=policy.validate(load_json(args.policy or default))
    if args.action=='rollback':
        if not args.backup:parser.error('--backup required')
        with locked(root/'config/waf/install.lock'):
            restore(root,args.backup)
            execute('docker','exec',config['container'],'nginx','-t')
            reload_nginx(config['container'])
        result={'rolledBack':True}
    else:
        if args.action=='configure':
            if args.site:
                site=config['sites'].setdefault(policy.scope(args.site),{})
                if args.mode:site['mode']=args.mode
                if args.profile:site['profile']=args.profile
                if args.cdn:site['cdn']=args.cdn
                if args.method_override:site['methodOverride']=args.method_override
            else:
                if args.mode:
                    config['mode']=args.mode
                    for item in config['sites'].values():item.pop('mode',None)
                if args.cdn:config['cdn']=args.cdn
                if args.method_override:config['methodOverride']=args.method_override
            config['logTimezone']='UTC'+execute('docker','exec',config['container'],'date','+%z').strip()
        if args.action in {'ban-preflight','ban-install','ban-remove','ban-status','ban-clear','cf-on','cf-off'}:
            import ban
            if args.action=='ban-preflight':result=ban.ban_preflight(root)
            elif args.action=='ban-install':result=ban.install(root)
            elif args.action=='ban-remove':result=ban.remove(root)
            elif args.action=='ban-status':result=ban.status(root)
            elif args.action=='ban-clear':
                ban.clear(root);result=ban.status(root)
            elif args.action=='cf-off':result=ban.configure_cf(root,disable=True)
            else:
                raw=__import__('sys').stdin.read(4097)
                if len(raw)>4096:raise ValueError('Credential input exceeds budget')
                result=ban.configure_cf(root,json.loads(raw))
        elif args.action=='trust-cloudflare':result=trust_cloudflare(root,config,expected)
        elif args.action=='retire-jails':result=fail2ban_update(root,legacy=True)
        elif args.action=='existing-filters':result=fail2ban_update(root)
        elif args.action=='rotation':result=rotation(root,config)
        elif args.action=='plan':
            changes,sites=make_plan(root,config)
            result={'sites':sites,'files':[str(p) for p,c in changes.items() if not p.exists() or p.read_bytes()!=c],'policy':config}
        elif args.action in {'apply','configure'}:result=apply(root,config,expected=expected,respect_native=args.action=='apply')
        elif args.action=='refresh-ips':
            with urllib.request.urlopen('https://api.cloudflare.com/client/v4/ips',timeout=20) as response:raw=response.read(65537)
            if len(raw)>65536:raise ValueError('Cloudflare address response exceeds budget')
            data=json.loads(raw)
            if data.get('success') is not True:raise ValueError('Cloudflare address update failed')
            addresses=data['result']
            policy.networks(addresses)
            result=apply(root,config,{'ipv4_cidrs':addresses['ipv4_cidrs'],'ipv6_cidrs':addresses['ipv6_cidrs']},expected=expected,respect_native=True)
        else:
            if args.action=='doctor':execute('docker','exec',config['container'],'nginx','-t')
            result=configured_status(root,config)
            if args.action=='doctor' and not result['methodOverride']['synchronized']:
                raise ValueError('Gateway capabilities or managed policy changed; apply/refresh the shared WAF configuration before enabling method override compatibility')
            result['syntax']='passed' if args.action=='doctor' else 'not-checked'
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'error':str(error)[:2000]}),file=__import__('sys').stderr)
        raise SystemExit(1)
