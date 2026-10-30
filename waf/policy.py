"""Shared, deterministic policy rendering for the kejilion WAF bundle."""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

VERSION = "1.1.0"
MAX_SITES = 200
MAX_BANS = 10000
MAX_STATE_BYTES = 4 * 1024 * 1024
SCOPE = re.compile(r"(?:\*\.)?[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}\Z")
PROFILES = {"generic", "wordpress", "flarum", "api", "upload", "streaming", "artifact-proxy", "kpanel"}
MODES = {"on", "detect", "off"}
BASE = "/etc/nginx/conf.d/waf"


def scope(value: str) -> str:
    if not isinstance(value, str) or not SCOPE.fullmatch(value):
        raise ValueError("Unsupported site scope; use a canonical server_name")
    return value.lower()


def key(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or value.count("|") != 1:
        raise ValueError("Expected site|IP")
    name, address = value.split("|", 1)
    return scope(name), str(ipaddress.ip_address(address))


def networks(data: dict) -> list[str]:
    result = []
    for entry in data.get("ipv4_cidrs", []) + data.get("ipv6_cidrs", []):
        net = ipaddress.ip_network(entry, strict=True)
        if net.prefixlen < (12 if net.version == 4 else 19) or not net.is_global:
            raise ValueError("Unsafe proxy CIDR")
        result.append(str(net))
    if not 15 <= len(result) <= 128:
        raise ValueError("Incomplete Cloudflare CIDR snapshot")
    if not any(':' in value for value in result) or not any('.' in value for value in result):
        raise ValueError('Both Cloudflare address families are required')
    return result


def validate(config: dict) -> dict:
    allowed = {"schemaVersion", "mode", "cdn", "container", "sites", "trustedProxies", "proxyHeader",
               "rate", "burst", "connections", "attackRetries", "rateRetries", "banSeconds", "banIgnore", "logTimezone", "banBackend", "methodOverride"}
    if set(config) - allowed:
        raise ValueError("Unknown policy fields: " + ", ".join(sorted(set(config) - allowed)))
    if config.get("schemaVersion") != 1:
        raise ValueError("Unsupported WAF policy schema")
    if config.get('banBackend','existing') not in {'none','existing'}:
        raise ValueError('Unsupported existing ban integration')
    ignored=config.get('banIgnore',[])
    if not isinstance(ignored,list) or len(ignored)>128:
        raise ValueError('Invalid ban protection list')
    for entry in ignored:
        ipaddress.ip_network(entry,strict=False)
    if config.get('methodOverride','guarded') not in {'guarded','strict'}:
        raise ValueError('Invalid method override policy')
    if not re.fullmatch(r'UTC(?:[+-](?:0[0-9]|1[0-4])[0-5][0-9])?', config.get('logTimezone','UTC')):
        raise ValueError('Invalid Nginx log timezone')
    if config.get("mode") not in MODES:
        raise ValueError("Invalid mode")
    if config.get("cdn") not in {"direct", "cloudflare", "mixed", "proxy"}:
        raise ValueError("Invalid CDN mode")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", config.get("container", "")):
        raise ValueError("Invalid Nginx container")
    sites = config.get("sites", {})
    if not isinstance(sites, dict) or len(sites) > MAX_SITES:
        raise ValueError("Invalid or excessive sites")
    contract_count=field_count=0
    for name, site in sites.items():
        if set(site) - {"profile", "mode", "exclusions", "cdn", "trustedProxies", "proxyHeader", "methodOverride", "sourceText"}:
            raise ValueError("Unknown site policy fields")
        if scope(name) != name:
            raise ValueError("Site scopes must be normalized")
        if site.get("profile", "generic") not in PROFILES:
            raise ValueError("Invalid profile")
        if site.get("mode", config["mode"]) not in MODES:
            raise ValueError("Invalid site mode")
        if site.get('methodOverride',config.get('methodOverride','guarded')) not in {'guarded','strict'}:
            raise ValueError('Invalid site method override policy')
        for rule in site.get("exclusions", []):
            if not isinstance(rule.get("ruleId"), int) or not 900000 <= rule["ruleId"] <= 999999:
                raise ValueError("Exclusions must identify a CRS rule")
            if not re.fullmatch(r"/[\w./-]{0,250}", rule.get("path", "")):
                raise ValueError("Exclusion requires an exact path")
            if rule.get('target')!='REQUEST_FILENAME' and not re.fullmatch(r"ARGS:[A-Za-z0-9_.\[\]-]{1,100}", rule.get("target", "")):
                raise ValueError("Exclusion requires one named argument or exact filename")
        if len(site.get("exclusions", [])) > 32:
            raise ValueError("Too many exclusions")
        contracts=site.get('sourceText',[])
        if not isinstance(contracts,list) or len(contracts)>16:raise ValueError('Too many source text contracts')
        contract_count+=len(contracts)
        if contract_count>256:raise ValueError('Global source text contract budget exceeded')
        for contract in contracts:
            if not isinstance(contract,dict) or set(contract)!={'method','path','fields'}:raise ValueError('Invalid source text contract')
            if contract['method'] not in {'POST','PUT','PATCH'}:raise ValueError('Invalid source text method')
            if not isinstance(contract['path'],str) or not re.fullmatch(r'/[A-Za-z0-9_/-]{1,200}',contract['path']) or '//' in contract['path']:raise ValueError('Source text requires a literal path')
            fields=contract['fields']
            if not isinstance(fields,list) or not 1<=len(fields)<=8 or any(not isinstance(f,str) for f in fields):raise ValueError('Invalid source text fields')
            if len(set(fields))!=len(fields):raise ValueError('Duplicate source text fields')
            field_count+=len(fields)
            if field_count>1024:raise ValueError('Global source text field budget exceeded')
            if any(not isinstance(field,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:[.][A-Za-z_][A-Za-z0-9_]*){0,7}',field) for field in fields):raise ValueError('Invalid JSON field name')
        if "cdn" in site:
            validate({"schemaVersion": 1, "mode": config["mode"], "cdn": site["cdn"],
                      "container": config["container"], "sites": {},
                      "trustedProxies": site.get("trustedProxies", []),
                      "proxyHeader": site.get("proxyHeader", "X-Forwarded-For")})
    proxies = config.get("trustedProxies", [])
    if not isinstance(proxies, list) or len(proxies) > 128:
        raise ValueError("Invalid proxies")
    for value in proxies:
        net = ipaddress.ip_network(value, strict=True)
        minimum = (12 if net.is_global else 16) if net.version == 4 else 32
        if net.prefixlen < minimum:
            raise ValueError("Proxy CIDR is too broad; declare the actual proxy subnet")
    if config["cdn"] == "proxy" and not proxies:
        raise ValueError("Proxy mode requires explicit trusted proxies")
    header = config.get("proxyHeader", "X-Forwarded-For")
    if header not in {"X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"}:
        raise ValueError("Unsupported proxy header")
    for field, default, low, high in [
        ("rate", 50, 1, 1000), ("burst", 200, 1, 4000),
        ("connections", 256, 16, 2048), ("attackRetries", 20, 10, 1000),
        ("rateRetries", 120, 30, 10000), ("banSeconds", 600, 60, 3600),
    ]:
        value = config.get(field, default)
        if type(value) is not int or not low <= value <= high:
            raise ValueError("Out-of-range policy: " + field)
    return config


def eligible(address: str, proxy_ranges: list[str]) -> bool:
    ip = ipaddress.ip_address(address)
    return ip.is_global and not any(ip in ipaddress.ip_network(net) for net in proxy_ranges)


def render_realip(config: dict, cloudflare: list[str]) -> str:
    lines = ["# Managed WAF proxy trust. Never trust arbitrary private/Docker networks."]
    mode = config["cdn"]
    if mode == "mixed" and config.get("trustedProxies"):
        if config.get("proxyHeader", "X-Forwarded-For") != "X-Forwarded-For":
            raise ValueError("Mixed proxy chains require authoritative X-Forwarded-For, or per-site modes")
        lines += ["set_real_ip_from " + net + ";" for net in cloudflare + config["trustedProxies"]]
        lines += ["real_ip_header X-Forwarded-For;", "real_ip_recursive on;"]
    elif mode in {"cloudflare", "mixed"}:
        lines += ["set_real_ip_from " + net + ";" for net in cloudflare]
        lines += ["real_ip_header CF-Connecting-IP;", "real_ip_recursive off;"]
    elif mode == "proxy":
        lines += ["set_real_ip_from " + net + ";" for net in config["trustedProxies"]]
        lines += ["real_ip_header " + config.get("proxyHeader", "X-Forwarded-For") + ";",
                  "real_ip_recursive on;"]
    return "\n".join(lines) + "\n"


def render_http(config: dict) -> str:
    rate, burst, conn = (config.get("rate", 50), config.get("burst", 200), config.get("connections", 256))
    rendered = f'''# Managed shared WAF. Includes only generated, validated data.
map $server_name $waf_profile {{
    default generic;
{chr(10).join('    "' + name + '" ' + site.get('profile', 'generic') + ';' for name, site in sorted(config['sites'].items()))}
}}
map $waf_profile $waf_normal_key {{ default "$server_name|$binary_remote_addr"; upload ""; streaming ""; }}
map $waf_profile $waf_upload_key {{ default ""; upload "$server_name|$binary_remote_addr"; }}
map $waf_profile $waf_stream_key {{ default ""; streaming "$server_name|$binary_remote_addr"; }}
map "$server_name|$remote_addr" $waf_blocked {{
    default 0;
    include {BASE}/blocked.map;
}}
map "$limit_req_status:$limit_conn_status" $waf_rate_event {{
    default 0;
    ~^(REJECTED:|[^:]*:REJECTED$) 1;
}}
log_format waf_rate escape=json '$time_iso8601 key="$server_name|$remote_addr" event=rate request_limit="$limit_req_status" connection_limit="$limit_conn_status"';
log_format waf_protocol escape=json '{{"time":"$time_iso8601","client":"$remote_addr","method":"$request_method","path":"$uri","status":$status,"upstream":"$upstream_status","duration":$request_time,"id":"$request_id","agent":"$http_user_agent"}}';
access_log /var/log/nginx/waf-rate.log waf_rate if=$waf_rate_event;
limit_req_zone $waf_normal_key zone=waf_requests:20m rate={rate}r/s;
limit_req_zone $waf_upload_key zone=waf_uploads:5m rate={max(1, rate * 2 // 5)}r/s;
limit_req_zone $waf_stream_key zone=waf_streams:5m rate={rate * 2}r/s;
limit_conn_zone $waf_normal_key zone=waf_connections:10m;
limit_conn_zone $waf_upload_key zone=waf_upload_connections:5m;
limit_conn_zone $waf_stream_key zone=waf_stream_connections:5m;
limit_req zone=waf_requests burst={burst} nodelay;
limit_req zone=waf_uploads burst={max(1, burst * 2 // 5)} nodelay;
limit_req zone=waf_streams burst={burst * 2} nodelay;
limit_req_status 429;
limit_conn waf_connections {conn};
limit_conn waf_upload_connections {max(16, conn // 4)};
limit_conn waf_stream_connections {conn * 2};
limit_conn_status 429;
modsecurity_rules_file {BASE}/modsecurity.conf;
modsecurity_transaction_id "$server_name|$remote_addr|$request_id";
'''
    if config.get('banBackend','existing')=='none':
        rendered=rendered.replace(f'map "$server_name|$remote_addr" $waf_blocked {{\n    default 0;\n    include {BASE}/blocked.map;\n}}\n','')
    return rendered


def render_server(realip: str = "realip.conf", existing_bans=True, argument_limit=None, authenticated_proxy=False, cache_conditions=None) -> str:
    cache_conditions=cache_conditions or {}
    cache=''.join(directive+' '+' '.join(cache_conditions.get(directive,[])+['$http_authorization','$http_cookie'])+';\n'
                  for directive in ['proxy_cache_bypass','proxy_no_cache']) if authenticated_proxy else ''
    return ("# Managed per-server configuration; existing ban backend is opt-in.\n"+
            ("if ($waf_blocked) { return 403; }\n" if existing_bans else '')+
            "include " + BASE + "/" + realip + ";\n"+
            ("modsecurity_rules 'SecArgumentsLimit 8192';\n" if argument_limit==8192 else '')+
            cache)


def engine_enabled(config: dict) -> bool:
    return config['mode']!='off' or any(site.get('mode','off')!='off' for site in config.get('sites',{}).values())



CODE_TAGS = ('attack-sqli', 'attack-xss', 'attack-rce', 'attack-lfi', 'attack-rfi', 'attack-injection-php', 'attack-ssti')
PATH_TAGS = ('attack-rce', 'attack-lfi', 'attack-rfi')


def _kpanel_rules(sites, first_id):
    lines = []
    rid = first_id
    names = sorted(name for name, site in sites.items() if site.get('profile') == 'kpanel')
    if not names:
        return lines, rid
    # Emit every trusted server selector before shared rules. Compiling the
    # bounded field lists once avoids multiplying them by the number of sites.
    for name in names:
        lines.append(f'SecRule UNIQUE_ID "@beginsWith {name}|" "id:{rid},phase:1,pass,nolog,t:none,setvar:tx.waf_kpanel_profile=1"')
        rid += 1

    def route(methods, path, controls, json_body=False, media=None):
        nonlocal rid
        lines.extend([
            f'SecRule TX:waf_kpanel_profile "@eq 1" "id:{rid},phase:1,pass,nolog,t:none,chain"',
            '    SecRule &REQUEST_HEADERS:/^(?i:x-(?!method$)(?:http-)?method(?:-override)?)$/ "@eq 0" "t:none,chain"',
            '    SecRule REQUEST_METHOD "@rx ^(?:' + '|'.join(methods) + ')$" "t:none,chain"',
        ])
        if json_body:
            # JSON selectors share ARGS with URL parameters. Do not let an
            # attacker borrow a body exception using ?json.command=... .
            lines.append('    SecRule &ARGS_GET:/^json[.]/ "@eq 0" "t:none,chain"')
            lines.append('    SecRule REQUEST_HEADERS:Content-Type "@rx ^application/(?:[a-z0-9.+-]+\\+)?json(?:;|$)" "t:none,t:lowercase,chain"')
        if media:
            lines.append('    SecRule REQUEST_HEADERS:Content-Type "@rx ^(?:'+media+')(?:;|$)" "t:none,t:lowercase,chain"')
        lines.append('    SecRule REQUEST_FILENAME "@rx ^(?:/[A-Za-z0-9_-]+)?' + path + '$" "t:none,' + ','.join(controls) + '"')
        rid += 1

    def fields(methods, path, targets, tags=CODE_TAGS):
        nonlocal rid
        flag='waf_kpanel_fields_'+str(rid)
        route(methods, path, ['setvar:tx.'+flag+'=1'], json_body=True)
        # Body fields only exist in phase 2. Add literal ctl targets only for
        # fields actually present, not hundreds of absent array slots. This
        # keeps large metadata-only desktop updates from paying a quadratic
        # variable/exclusion matching cost. ctl itself has no regex support.
        for target in targets:
            controls=','.join('ctl:ruleRemoveTargetByTag='+tag+';ARGS:json.'+target for tag in tags)
            if tags==CODE_TAGS:controls+=',setvar:tx.'+flag+'_present=1'
            lines.extend([
                f'SecRule TX:{flag} "@eq 1" "id:{rid},phase:2,pass,nolog,t:none,chain"',
                '    SecRule &ARGS:json.'+target+' "@gt 0" "t:none,'+controls+'"',
            ])
            rid+=1
        # Raw-body Java/SSTI checks duplicate parsed JSON inspection. Retain
        # their ARGS/header/cookie targets, including non-exempt metadata.
        if tags==CODE_TAGS:
            controls=','.join('ctl:ruleRemoveTargetByTag='+tag+';REQUEST_BODY' for tag in tags)
            lines.append(f'SecRule TX:{flag}_present "@eq 1" "id:{rid},phase:2,pass,nolog,t:none,'+controls+'"')
            rid+=1

    for method, path, targets in [
        ('POST', '/api/v1/auth/bootstrap', ['password']),
        ('POST', '/api/v1/auth/login', ['password']),
        ('PUT', '/api/v1/settings/password', ['currentPassword', 'newPassword']),
        ('PUT', '/api/v1/settings/username', ['currentPassword']),
        ('PUT', '/api/v1/files/content', ['content']),
        ('PUT', '/api/v1/terminal-commands', [f'items.array_{i}.command' for i in range(64)]),
        ('POST', '/api/v1/terminal-batches', ['command']),
        ('POST', '/api/v1/terminal-history', [f'items.array_{i}.command' for i in range(64)]),
        ('POST', '/api/v1/terminal-history/remove', ['command']),
        ('POST', r'/api/v1/docker/containers/[a-fA-F0-9]{12,64}/exec', ['command']),
        ('POST', '/api/v1/docker/tasks', ['compose', 'composeEnvironment'] + [f'command.array_{i}' for i in range(64)] + [f'environment.array_{i}.value' for i in range(128)]),
        ('PUT', '/api/v1/settings/preferences', [f'desktop.windows.array_{i}.path' for i in range(8)] + [f'desktop.windowSizes.array_{i}.path' for i in range(32)]),
        ('PUT', '/api/v1/desktop/workspace', [f'shortcuts.array_{i}.{field}' for i in range(64) for field in ['command', 'url']]),
    ]:
        fields([method], path, targets)
    fields(['PUT'], '/api/v1/desktop/workspace', [f'shortcuts.array_{i}.path' for i in range(64)], PATH_TAGS)
    fields(['POST'], '/api/v1/files/entries', [f'paths.array_{i}' for i in range(64)], PATH_TAGS)
    fields(['POST'], r'/api/v1/files/(?:actions|archive-jobs)',
           ['target','name']+[f'sources.array_{i}' for i in range(100)], PATH_TAGS)
    route(['PUT'], '/api/v1/desktop/workspace', ['setvar:tx.waf_argument_limit=8192'], json_body=True)

    session = r'/api/v1/(?:terminal-sessions/[a-f0-9]{64}|job-terminals/(?:app|site|diagnostic|environment)/[a-f0-9]{32})'
    fields(['POST'], session + r'/(?:input|input-batch)', ['data'] + [f'frames.array_{i}.data' for i in range(32)], ('attack-sqli',))
    for prefix in ['/api/v1/app-jobs', '/api/v1/site-installations', '/api/v1/diagnostic-jobs', '/api/v1/web-environment/jobs']:
        fields(['POST'], prefix + r'/[a-fA-F0-9]{32}/input', ['data'], ('attack-sqli',))

    # These v2 envelopes carry authenticated Noise ciphertext, not SQL, HTML or
    # shell input. Metadata and the application cryptographic checks remain on.
    federation = r'/api/v2/federation/(?:pair|commit|revoke|terminal/(?:open|close|capabilities|output|input|resize|relay)|files/(?:open|open-linked|link|relay))'
    fields(['POST'], federation, ['message'], ('attack-sqli',))

    # Authenticated upload handlers consume opaque bytes, not source for an
    # interpreter. Exclude only raw-byte injection targets; phase-2 protocol,
    # headers, cookies and URL parameters still run (body access stays On).
    binary_controls=['ctl:ruleRemoveById=920420']+['ctl:ruleRemoveTargetByTag='+tag+';REQUEST_BODY' for tag in CODE_TAGS]
    route(['POST'], '/api/v1/files/upload', binary_controls+['ctl:ruleRemoveTargetByTag='+tag+';ARGS:'+field for tag in PATH_TAGS for field in ['path','name']], media='application/octet-stream')
    route(['PUT'], '/api/v1/files/transfer/sessions', binary_controls, media='application/octet-stream')
    route(['PUT'], r'/api/v1/desktop/shortcuts/[a-f0-9]{32}/icon', binary_controls, media='image/(?:png|jpeg|webp)')

    # The fixed manage action is a word in the Unix command dictionary. Do not
    # exempt arbitrary app suffixes or any query/body target from this rule.
    route(['POST'], r'/api/v1/apps/(?:builtin|thirdparty|local)-[A-Za-z0-9][A-Za-z0-9_-]{0,63}/manage',
          ['ctl:ruleRemoveTargetById=932260;REQUEST_FILENAME'])
    # Bundled static assets have literal file names, not command arguments.
    # Keep this inside the known application profile, reject traversal/shell
    # syntax and leave query/body/other path rules inspected.
    route(['GET','HEAD'], r'/(?:assets|desktop-icons)/(?:[A-Za-z0-9_-]{1,64}/){0,4}(?![^/]*[.][.])[A-Za-z0-9][A-Za-z0-9_.-]{0,199}[.](?:webp|png|jpe?g|svg|ico|gif|avif|css|js|woff2?)',
          ['ctl:ruleRemoveTargetById=932260;REQUEST_FILENAME'])
    route(['GET', 'PUT'], r'/api/v1/files(?:/(?:entry|content|archive))?',
          ['ctl:ruleRemoveTargetByTag=' + tag + ';ARGS:path' for tag in PATH_TAGS])
    return lines, rid


def _content_application_rules(sites, first_id):
    """Known CMS URL grammar and forum source text, not arbitrary API bypasses."""
    lines=[]
    rid=first_id
    for profile in ['wordpress','flarum']:
        names=sorted(name for name,site in sites.items() if site.get('profile')==profile)
        if not names:continue
        for name in names:
            lines.append(f'SecRule UNIQUE_ID "@beginsWith {name}|" "id:{rid},phase:1,pass,nolog,t:none,setvar:tx.waf_{profile}_profile=1"')
            rid+=1
        if profile=='wordpress':
            # Canonical taxonomy URLs and standard hyphenated post slugs are
            # WordPress route identifiers. Shell syntax and other RCE targets
            # retain inspection, as do plugin/administrative URI families.
            char=r'[\p{L}\p{M}\p{N}_-]'
            slug=char+'{1,200}'
            taxonomy='/(?:category|tag|author)/(?:'+slug+'/){0,8}'+slug+'/?'
            post='/(?:[12][0-9]{3}/(?:0[1-9]|1[0-2])/(?:(?:0[1-9]|[12][0-9]|3[01])/)?)?(?='+char+'{0,199}-)'+slug+'/?'
            lines.extend([
                f'SecRule TX:waf_wordpress_profile "@eq 1" "id:{rid},phase:1,pass,nolog,t:none,chain"',
                '    SecRule &REQUEST_HEADERS:/^(?i:x-(?!method$)(?:http-)?method(?:-override)?)$/ "@eq 0" "t:none,chain"',
                '    SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" "t:none,chain"',
                '    SecRule REQUEST_FILENAME "@rx (*UTF)(*UCP)^(?:'+taxonomy+'|'+post+')$" "t:none,ctl:ruleRemoveTargetById=932260;REQUEST_FILENAME"',
            ])
            rid+=1
            continue
        for methods,path,target in [
            ('POST',r'/api/(?:posts|discussions)','data.attributes.content'),
            ('PATCH',r'/api/posts/[0-9]{1,20}','data.attributes.content'),
            ('POST',r'/(?:api/token|login)','password'),
        ]:
            controls=','.join(['ctl:ruleRemoveTargetByTag='+tag+';ARGS:json.'+target for tag in CODE_TAGS]+
                              ['ctl:ruleRemoveTargetByTag='+tag+';REQUEST_BODY' for tag in CODE_TAGS])
            lines.extend([
                f'SecRule TX:waf_flarum_profile "@eq 1" "id:{rid},phase:1,pass,nolog,t:none,chain"',
                '    SecRule &REQUEST_HEADERS:/^(?i:x-(?!method$)(?:http-)?method(?:-override)?)$/ "@eq 0" "t:none,chain"',
                '    SecRule &ARGS_GET:/^json[.]/ "@eq 0" "t:none,chain"',
                f'    SecRule REQUEST_METHOD "@streq {methods}" "t:none,chain"',
                '    SecRule REQUEST_HEADERS:Content-Type "@rx ^application/(?:[a-z0-9.+-]+\\+)?json(?:;|$)" "t:none,t:lowercase,chain"',
                '    SecRule REQUEST_FILENAME "@rx ^(?:/[A-Za-z0-9_-]+)?'+path+'$" "t:none,'+controls+'"',
            ])
            rid+=1
    return lines,rid


def render_profile_rules(config: dict, method_controls=None, resource_controls=None) -> str:
    # No capability proof means strict. Only the manager's complete Nginx graph
    # can establish absence of method-dependent gateway access controls.
    strict_all,strict_sites=method_controls if method_controls is not None else (True,set())
    guarded=config.get('methodOverride','guarded')=='guarded' and not strict_all
    lines = [
        '# Settings run after vendor setup, before CRS and application exclusions.',
        'SecAction "id:1100,phase:1,pass,nolog,t:none,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4,setvar:tx.blocking_paranoia_level=1,setvar:tx.detection_paranoia_level=1,setvar:tx.wordpress-rule-exclusions-plugin_enabled=0"',
        'SecAction "id:1101,phase:1,pass,nolog,t:none,setvar:\'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE\'"',
        # CRS may reject a phase-1 score before buffering/inspecting the body.
        # DetectionOnly still runs every phase, preserving false-positive tuning.
        'SecAction "id:1102,phase:1,pass,nolog,t:none,setvar:tx.early_blocking=1"',
        'SecAction "id:1103,phase:1,pass,nolog,t:none,setvar:tx.waf_method_override_guarded='+str(int(guarded))+'"',
        'SecAction "id:1104,phase:1,pass,nolog,t:none,setvar:tx.waf_argument_limit=2048"',
    ]
    global_mode = config["mode"]
    # Explicit site settings precede the fallback. Every transaction starts fresh.
    rid = 1200
    exceptions = []
    for name in sorted(config['sites'].keys() | strict_sites):
        site=config['sites'].get(name,{})
        mode = site.get("mode", global_mode)
        # UNIQUE_ID is supplied by the connector from $server_name, not the Host header.
        # Absolute-form requests and aliases must not select a different site's policy.
        actions = []
        site_guarded=site.get('methodOverride',config.get('methodOverride','guarded'))=='guarded' and not strict_all and name not in strict_sites
        if site_guarded!=guarded:
            actions.append('setvar:tx.waf_method_override_guarded='+str(int(site_guarded)))
        if site.get("profile") == "wordpress":
            lines += [f'SecRule UNIQUE_ID "@beginsWith {name}|" "id:{rid},phase:1,pass,nolog,t:none,chain"',
                      '    SecRule &REQUEST_HEADERS:/^(?i:x-(?!method$)(?:http-)?method(?:-override)?)$/ "@eq 0" "t:none,setvar:tx.wordpress-rule-exclusions-plugin_enabled=1"']
            rid += 1
        if mode != global_mode:
            actions.append("setvar:tx.waf_mode_override=1")
            actions.append("ctl:ruleEngine=" + {"on":"On", "off":"Off", "detect":"DetectionOnly"}[mode])
        if actions:
            lines.append(f'SecRule UNIQUE_ID "@beginsWith {name}|" "id:{rid},phase:1,pass,nolog,t:none,' + ','.join(actions) + '"')
            rid += 1
        for item in site.get("exclusions", []):
            exceptions += [
                f'SecRule UNIQUE_ID "@beginsWith {name}|" "id:{rid},phase:1,pass,nolog,t:none,chain"',
                '    SecRule &REQUEST_HEADERS:/^(?i:x-(?!method$)(?:http-)?method(?:-override)?)$/ "@eq 0" "t:none,chain"',
            ]
            if item['target']=='REQUEST_FILENAME':
                exceptions.append('    SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" "t:none,chain"')
            exceptions.append(f'    SecRule REQUEST_FILENAME "@streq {item["path"]}" "t:none,ctl:ruleRemoveTargetById={item["ruleId"]};{item["target"]}"')
            rid += 1
    if global_mode != "on" and engine_enabled(config):
        lines.append('SecRule &TX:waf_mode_override "@eq 0" "id:1190,phase:1,pass,nolog,ctl:ruleEngine=' + {"off":"Off", "detect":"DetectionOnly"}[global_mode] + '"')
    kpanel_lines,rid=_kpanel_rules(config['sites'],rid)
    lines+=kpanel_lines
    content_lines,rid=_content_application_rules(config['sites'],rid)
    lines+=content_lines
    for name,site in sorted(config['sites'].items()):
        if site.get('profile')=='artifact-proxy':
            # Download identifiers may contain command names (e.g. docker-).
            # Only literal, bounded segments are eligible; encoded paths and
            # shell syntax retain the original filename inspection.
            artifact_segment = r'(?![.])[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}'
            artifact_path = (r'^/(?:' +
                r'(?:https?://)?raw[.]githubusercontent[.]com/' +
                artifact_segment + r'(?:/' + artifact_segment + r'){1,15}' +
                r'|v2/' + artifact_segment + r'(?:/' + artifact_segment + r'){0,5}/manifests/(?:' + artifact_segment + r'|sha256:[a-f0-9]{64}))$')
            lines += [f'SecRule UNIQUE_ID "@beginsWith {name}|" "id:{rid},phase:1,pass,nolog,t:none,chain"',
                      '    SecRule &REQUEST_HEADERS:/^(?i:x-(?!method$)(?:http-)?method(?:-override)?)$/ "@eq 0" "t:none,chain"',
                      '    SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" "t:none,chain"',
                      '    SecRule REQUEST_URI_RAW "@rx ^/[^%?]*(?:[?].*)?$" "t:none,chain"',
                      '    SecRule REQUEST_FILENAME "@rx ^(?!.*[.][.])" "t:none,chain"',
                      '    SecRule REQUEST_FILENAME "@rx '+artifact_path+'" "t:none,ctl:ruleRemoveTargetById=932260;REQUEST_FILENAME"']
            rid+=1
            lines += [f'SecRule UNIQUE_ID "@beginsWith {name}|" "id:{rid},phase:1,pass,nolog,t:none,chain"',
                      '    SecRule &REQUEST_HEADERS:/^(?i:x-(?!method$)(?:http-)?method(?:-override)?)$/ "@eq 0" "t:none,chain"',
                      '    SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" "t:none,chain"',
                      '    SecRule REQUEST_FILENAME "@rx ^/(?:https?://)?[A-Za-z0-9-]+(?:[.][A-Za-z0-9-]+)+(?::[0-9]{1,5})?/" "t:none,ctl:ruleRemoveById=920440,ctl:ruleRemoveTargetById=930130;REQUEST_FILENAME"']
            rid+=1
            lines += [f'SecRule UNIQUE_ID "@beginsWith {name}|" "id:{rid},phase:1,pass,nolog,t:none,chain"',
                      '    SecRule &REQUEST_HEADERS:/^(?i:x-(?!method$)(?:http-)?method(?:-override)?)$/ "@eq 0" "t:none,chain"',
                      '    SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD|POST)$" "t:none,chain"',
                      '    SecRule REQUEST_FILENAME "@rx ^/(?:https?://)?[A-Za-z0-9-]+(?:[.][A-Za-z0-9-]+)+(?::[0-9]{1,5})?/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\\.git/(?:info/refs|git-upload-pack)$" "t:none,ctl:ruleRemoveTargetById=930130;REQUEST_FILENAME"']
            rid+=1
            lines += [f'SecRule UNIQUE_ID "@beginsWith {name}|" "id:{rid},phase:1,pass,nolog,t:none,chain"',
                      '    SecRule &REQUEST_HEADERS:/^(?i:x-(?!method$)(?:http-)?method(?:-override)?)$/ "@eq 0" "t:none,chain"',
                      '    SecRule REQUEST_METHOD "@streq POST" "t:none,chain"',
                      '    SecRule REQUEST_FILENAME "@rx ^/(?:https?://)?[A-Za-z0-9-]+(?:[.][A-Za-z0-9-]+)+(?::[0-9]{1,5})?/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\\.git/git-upload-pack$" "t:none,chain"',
                      '    SecRule REQUEST_HEADERS:Content-Type "@streq application/x-git-upload-pack-request" "t:none,t:lowercase,ctl:ruleRemoveById=920420"']
            rid+=1
            lines += [f'SecRule UNIQUE_ID "@beginsWith {name}|" "id:{rid},phase:1,pass,nolog,t:none,chain"',
                      '    SecRule &REQUEST_HEADERS:/^(?i:x-(?!method$)(?:http-)?method(?:-override)?)$/ "@eq 0" "t:none,chain"',
                      '    SecRule REQUEST_METHOD "@streq POST" "t:none,chain"',
                      '    SecRule REQUEST_FILENAME "@rx ^/(?:https?://)?[A-Za-z0-9-]+(?:[.][A-Za-z0-9-]+)+(?::[0-9]{1,5})?/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\\.git/git-upload-pack$" "t:none,chain"',
                      '    SecRule &REQUEST_HEADERS:/^(?i:content-type)$/ "@eq 1" "t:none,chain"',
                      '    SecRule REQUEST_HEADERS:Content-Type "@streq application/x-git-upload-pack-request" "t:none,t:lowercase,chain"',
                      '    SecRule &REQUEST_HEADERS:/^(?i:content-encoding)$/ "@eq 1" "t:none,chain"',
                      '    SecRule REQUEST_HEADERS:Content-Encoding "@streq gzip" "t:none,t:lowercase,ctl:ruleRemoveTargetById=920450;REQUEST_HEADERS_NAMES:Content-Encoding,ctl:ruleRemoveTargetById=920450;REQUEST_HEADERS_NAMES:content-encoding,ctl:ruleRemoveTargetById=920450;REQUEST_HEADERS_NAMES:CONTENT-ENCODING"']
            rid+=1
    # Capabilities come from a complete nginx -T snapshot, never from a client
    # header, extension alone, or an application profile.
    static_names={name for name,state in (resource_controls or {}).items() if state=='file-only' and SCOPE.fullmatch(name) and name==name.lower()}
    for name in sorted(config['sites'].keys() | static_names):
        if (resource_controls or {}).get(name)=='file-only':
            lines += [f'SecRule UNIQUE_ID "@beginsWith {name}|" "id:{rid},phase:1,pass,nolog,t:none,chain"',
                      '    SecRule &REQUEST_HEADERS:/^(?i:x-(?!method$)(?:http-)?method(?:-override)?)$/ "@eq 0" "t:none,chain"',
                      '    SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" "t:none,chain"',
                      '    SecRule REQUEST_URI_RAW "@rx ^/[^%?]*(?:[?].*)?$" "t:none,chain"',
                      '    SecRule REQUEST_FILENAME "@rx ^/(?!.*[.][.])(?:[A-Za-z0-9_-]{1,64}/){0,8}[A-Za-z0-9][A-Za-z0-9_.-]{0,199}[.](?:webp|png|jpe?g|svg|ico|gif|avif|css|js|woff2?)$" "t:none,ctl:ruleRemoveTargetById=932260;REQUEST_FILENAME"']
            rid+=1
        for contract in config['sites'].get(name,{}).get('sourceText',[]):
            flag='waf_source_'+str(rid)
            lines += [f'SecRule UNIQUE_ID "@beginsWith {name}|" "id:{rid},phase:1,pass,nolog,t:none,chain"',
                      '    SecRule &REQUEST_HEADERS:/^(?i:x-(?!method$)(?:http-)?method(?:-override)?)$/ "@eq 0" "t:none,chain"',
                      '    SecRule &REQUEST_HEADERS:Content-Encoding "@eq 0" "t:none,chain"',
                      '    SecRule &REQUEST_HEADERS:Content-Type "@eq 1" "t:none,chain"',
                      '    SecRule &ARGS_GET:/^json[.]/ "@eq 0" "t:none,chain"',
                      '    SecRule REQUEST_METHOD "@streq '+contract['method']+'" "t:none,chain"',
                      '    SecRule REQUEST_HEADERS:Content-Type "@rx ^application/(?:[a-z0-9.+-]+\\+)?json(?:;|$)" "t:none,t:lowercase,chain"',
                      '    SecRule REQUEST_FILENAME "@streq '+contract['path']+'" "t:none,setvar:tx.'+flag+'=1"']
            rid+=1
            for field in contract['fields']:
                controls=','.join('ctl:ruleRemoveTargetByTag='+tag+';ARGS:json.'+field for tag in CODE_TAGS)
                controls+=','+','.join('ctl:ruleRemoveTargetByTag='+tag+';REQUEST_BODY' for tag in CODE_TAGS)
                lines += [f'SecRule TX:{flag} "@eq 1" "id:{rid},phase:2,pass,nolog,t:none,chain"',
                          '    SecRule &ARGS:/(?i:_method)$/ "@eq 0" "t:none,chain"',
                          '    SecRule &ARGS:json.'+field+' "@eq 1" "t:none,'+controls+'"']
                rid+=1
    return "\n".join(lines + exceptions) + "\n"


def render_modsecurity(config: dict) -> str:
    # A single shared CRS ruleset avoids duplicating its memory for every vhost.
    return f'''# Managed engine settings; site limits at Nginx remain authoritative.
SecRuleEngine On
SecRequestBodyAccess On
SecXmlExternalEntity Off
SecRequestBodyLimit 1073741824
SecRequestBodyNoFilesLimit 8388608
SecRequestBodyLimitAction Reject
SecRequestBodyJsonDepthLimit 64
SecArgumentsLimit 2048
SecRule REQUEST_HEADERS:Content-Type "^application/(?:[a-z0-9.+-]+\\+)?json(?:;|$)" "id:200001,phase:1,pass,nolog,t:none,t:lowercase,ctl:requestBodyProcessor=JSON"
SecRule REQUEST_HEADERS:Content-Type "^(?:application/(?:soap\\+)?xml|text/xml)(?:;|$)" "id:200000,phase:1,pass,nolog,t:none,t:lowercase,ctl:requestBodyProcessor=XML"
SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,deny,status:400,nolog,msg:'WAF request body parsing failed'"
SecRule INBOUND_DATA_ERROR "@eq 1" "id:200006,phase:2,deny,status:413,log,msg:'WAF request body limit exceeded'"
SecRule &ARGS "@ge %{{tx.waf_argument_limit}}" "id:200007,phase:2,deny,status:400,log,msg:'WAF argument budget exceeded'"
SecResponseBodyAccess Off
SecTmpDir /tmp/
SecDataDir /tmp/
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^403$"
SecAuditLogType Serial
SecAuditLogFormat JSON
SecAuditLogParts AHZ
SecAuditLogFileMode 0640
SecAuditLog /var/log/nginx/waf-audit.json
SecStatusEngine Off
SecArgumentSeparator &
SecUnicodeMapFile /etc/nginx/modsec/unicode.mapping 20127
Include /etc/nginx/modsec/crs-setup.conf
Include {BASE}/profile-rules.conf
Include /etc/nginx/modsec/plugins/*-config.conf
Include {BASE}/request-guard.conf
Include /etc/nginx/modsec/plugins/wordpress-rule-exclusions-before.conf
Include {BASE}/method-override.conf
Include /etc/nginx/modsec/rules/*.conf
SecRuleUpdateTargetById 920450 "!REQUEST_HEADERS_NAMES:/^(?i:x-(?!method$)(?:http-)?method(?:-override)?)$/"
SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE "@ge 5" "id:1112,phase:5,pass,nolog,ctl:auditEngine=On"
'''


def render_guard() -> str:
    return '''# Protect secret paths, not ordinary application endpoints or documentation.
# Well-known endpoints still pass through CRS; they never disable the rule engine.
SecRule REQUEST_FILENAME "@rx (?i)(?:^|/)\\.(?!well-known(?:/|$))" "id:1110,phase:1,deny,status:403,log,t:none,t:urlDecodeUni,t:normalizePath,msg:'WAF secret dot path'"
SecRule REQUEST_FILENAME "@rx (?i)(?:^|/)wp-config\\.php(?:[.~].*)?$" "id:1111,phase:1,deny,status:403,log,t:none,t:urlDecodeUni,t:normalizePath,msg:'WAF secret application configuration'"
'''


def render_method_override() -> str:
    lines=['''# Framework method tunnelling is compatible only with a proven gateway policy.
# Only canonical override names are removed from the vendor name restriction.
# These phase-2 guards take over their protocol checks after CRS initialization;
# all other restricted names and the complete vendor wildcard stay untouched.
SecRule &REQUEST_HEADERS:/^(?i:x-(?!method$)(?:http-)?method(?:-override)?)$/ "@gt 1" "id:1120,phase:2,pass,log,t:none,msg:'WAF ambiguous method override headers',setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}"
SecRule &REQUEST_HEADERS:/^(?i:x-(?!method$)(?:http-)?method(?:-override)?)$/ "@gt 0" "id:1121,phase:2,pass,log,t:none,msg:'WAF method override requires POST',chain"
    SecRule REQUEST_METHOD "!@streq POST" "t:none,setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}"
SecRule REQUEST_HEADERS:/^(?i:x-(?!method$)(?:http-)?method(?:-override)?)$/ "!@rx ^(?:PUT|PATCH|DELETE)$" "id:1122,phase:2,pass,log,t:none,msg:'WAF invalid method override value',setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}"
SecRule REQUEST_HEADERS_NAMES "@rx (?i)^(?!x-http-method-override$|x-http-method$|x-method-override$)(?:x[-_.]http[-_.]method[-_.]override|x[-_.]http[-_.]method|x[-_.]method[-_.]override)$" "id:1124,phase:2,pass,log,t:none,msg:'WAF ambiguous method override header spelling',setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}"
# Body arguments are unavailable in phase 1. Check all override sources again
# after normal parsing, before CRS phase-2 checks or the upstream application.
SecRule &REQUEST_HEADERS:/^(?i:x-(?!method$)(?:http-)?method(?:-override)?)$/ "@gt 0" "id:1123,phase:2,pass,log,t:none,msg:'WAF mixed header and parameter method override',chain"
    SecRule &ARGS:/^(?i:(?:json[.])?_method(?:[.\\[].*)?)$/ "@gt 0" "t:none,setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}"
SecRule &REQUEST_HEADERS:/^(?i:x-(?!method$)(?:http-)?method(?:-override)?)$/ "@gt 0" "id:1125,phase:2,pass,log,t:none,msg:'WAF method override requires a compatible gateway policy',chain"
    SecRule TX:waf_method_override_guarded "!@eq 1" "t:none,setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}"
''']
    number=1130
    for header in ['x-http-method-override','x-http-method','x-method-override']:
      for method in ['PUT','PATCH','DELETE']:
        lines.append(f'''SecRule REQUEST_HEADERS:{header} "@streq {method}" "id:{number},phase:2,pass,log,t:none,msg:'WAF method override is not allowed by policy',chain"
    SecRule TX:allowed_methods "!@rx (?:^|[ \\t]){method}(?:[ \\t]|$)" "t:none,setvar:tx.inbound_anomaly_score_pl1=+%{{tx.critical_anomaly_score}}"
''')
        number+=1
    return ''.join(lines)


def render_bans(records: dict, now: int) -> str:
    if len(records) > MAX_BANS:
        raise ValueError("Ban record limit exceeded")
    lines = ["# Managed site-scoped bans; expired records are excluded."]
    for raw, item in sorted(records.items()):
        name, address = key(raw)
        if type(item.get("expires")) is not int:
            raise ValueError("Invalid expiration")
        if item["expires"] > now:
            lines.append(f'"{name}|{address}" 1;')
    return "\n".join(lines) + "\n"


def bundle_files(config: dict, cloudflare: list[str], method_controls=None, cache_controls=None, resource_controls=None) -> dict[str, str]:
    validate(config)
    result = {
        "http.conf": render_http(config), "realip.conf": render_realip(config, cloudflare),
        "server-default.inc": render_server(existing_bans=config.get('banBackend','existing')=='existing'), "profile-rules.conf": render_profile_rules(config,method_controls,resource_controls),
        "method-override.conf": render_method_override(),
        "modsecurity.conf": render_modsecurity(config), "request-guard.conf": render_guard(),
        "access-log.inc": 'access_log /var/log/nginx/waf-rate.log waf_rate if=$waf_rate_event;\n',
        "load-module.conf": 'load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;\n',
    }
    import hashlib
    for name, site in config["sites"].items():
        if site.get('profile')=='kpanel' and cache_controls is not None and name in cache_controls and cache_controls[name] is None:
            raise ValueError('Conflicting cache inheritance for same-name application servers: '+name)
        if "cdn" in site or site.get('profile')=='kpanel':
            ident = hashlib.sha256(name.encode()).hexdigest()[:16]
            realip='realip.conf'
            if 'cdn' in site:
                settings = dict(config, cdn=site["cdn"], trustedProxies=site.get("trustedProxies", []),
                                proxyHeader=site.get("proxyHeader", "X-Forwarded-For"))
                realip=f'realip-{ident}.conf'
                result[realip] = render_realip(settings, cloudflare)
            result[f"server-{ident}.inc"] = render_server(realip,config.get('banBackend','existing')=='existing',
                                                        8192 if site.get('profile')=='kpanel' else None,
                                                        authenticated_proxy=site.get('profile')=='kpanel',
                                                        cache_conditions=(cache_controls or {}).get(name))
    return result


def render_filters() -> dict[str, str]:
    # F-ID is intentionally site|IP, so Fail2Ban counters do not cross vhosts.
    identity = r"[A-Za-z0-9_.*-]+\|[0-9a-fA-F:.]+"
    rate = ('[Definition]\n'
            'datepattern = ^%%Y-%%m-%%dT%%H:%%M:%%S%%z\n'
            'failregex = ^\\s*key="<F-ID>' + identity + '</F-ID>" event=rate '
            'request_limit="(?:REJECTED|[A-Z_]*)" connection_limit="(?:REJECTED|[A-Z_]*)"$\n'
            'ignoreregex = request_limit="(?:PASSED|DELAYED|REJECTED_DRY_RUN|DELAYED_DRY_RUN)?" connection_limit="(?:PASSED|REJECTED_DRY_RUN)?"$\n')
    # The connector's serial JSON is not subject to Nginx's 2 KiB error-line
    # truncation. Identity precedes the request; escaped payload fields cannot
    # impersonate these top-level transaction fields or an actual ruleId.
    string=r'"(?:[^"\\\r\n]|\\.)*"'
    structured=(r'^\{"transaction": \{"client_ip": "(?P<client>[0-9a-fA-F:.]+)", '
                r'"time_stamp": '+string+r', "server_id": "[a-f0-9]+", "client_port": [0-9]+, '
                r'"host_ip": '+string+r', "host_port": [0-9]+, "unique_id": "<F-ID>'
                r'[A-Za-z0-9_.*-]+\|(?P=client)</F-ID>\|[a-f0-9]{32}", "is_interrupted": true, '
                r'"request": \{"method": "[A-Z]+", "http_version": "[0-9.]+", "hostname": '+string+r', "uri": '+string+r'\}, '
                r'"response": \{"http_code": 403\}, "producer": \{.*?\}, "messages": \[.*'
                r'(?<!\\)"ruleId": "(?:949110|949111|1110|1111)".*\}\s*$')
    structured=structured.replace(': ',r':\s*').replace(', ',r',\s*')
    attack='[Definition]\ndatepattern = %%a %%b %%d %%H:%%M:%%S %%Y\nfailregex = '+structured+'\nignoreregex =\n'
    return {"waf-rate.conf": rate, "waf-attack.conf": attack}
