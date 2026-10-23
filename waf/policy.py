"""Shared, deterministic policy rendering for the kejilion WAF bundle."""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

VERSION = "1.0.5"
MAX_SITES = 200
MAX_BANS = 10000
MAX_STATE_BYTES = 4 * 1024 * 1024
SCOPE = re.compile(r"(?:\*\.)?[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}\Z")
PROFILES = {"generic", "wordpress", "api", "upload", "streaming", "artifact-proxy", "kpanel"}
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
               "rate", "burst", "connections", "attackRetries", "rateRetries", "banSeconds", "logTimezone", "banBackend"}
    if set(config) - allowed:
        raise ValueError("Unknown policy fields: " + ", ".join(sorted(set(config) - allowed)))
    if config.get("schemaVersion") != 1:
        raise ValueError("Unsupported WAF policy schema")
    if config.get('banBackend','existing') not in {'none','existing'}:
        raise ValueError('Unsupported existing ban integration')
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
    for name, site in sites.items():
        if set(site) - {"profile", "mode", "exclusions", "cdn", "trustedProxies", "proxyHeader"}:
            raise ValueError("Unknown site policy fields")
        if scope(name) != name:
            raise ValueError("Site scopes must be normalized")
        if site.get("profile", "generic") not in PROFILES:
            raise ValueError("Invalid profile")
        if site.get("mode", config["mode"]) not in MODES:
            raise ValueError("Invalid site mode")
        for rule in site.get("exclusions", []):
            if not isinstance(rule.get("ruleId"), int) or not 900000 <= rule["ruleId"] <= 999999:
                raise ValueError("Exclusions must identify a CRS rule")
            if not re.fullmatch(r"/[A-Za-z0-9_./-]{0,250}", rule.get("path", "")):
                raise ValueError("Exclusion requires an exact path")
            if not re.fullmatch(r"ARGS:[A-Za-z0-9_.\[\]-]{1,100}", rule.get("target", "")):
                raise ValueError("Exclusion requires one named argument")
        if len(site.get("exclusions", [])) > 32:
            raise ValueError("Too many exclusions")
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


def render_server(realip: str = "realip.conf", existing_bans=True) -> str:
    return ("# Managed per-server configuration; existing ban backend is opt-in.\n"+
            ("if ($waf_blocked) { return 403; }\n" if existing_bans else '')+
            "include " + BASE + "/" + realip + ";\n")


def engine_enabled(config: dict) -> bool:
    return config['mode']!='off' or any(site.get('mode','off')!='off' for site in config.get('sites',{}).values())


def render_profile_rules(config: dict) -> str:
    lines = [
        '# Settings run after vendor setup, before CRS and application exclusions.',
        'SecAction "id:1100,phase:1,pass,nolog,t:none,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4,setvar:tx.blocking_paranoia_level=1,setvar:tx.detection_paranoia_level=1,setvar:tx.wordpress-rule-exclusions-plugin_enabled=0"',
        'SecAction "id:1101,phase:1,pass,nolog,t:none,setvar:\'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE\'"',
        # CRS may reject a phase-1 score before buffering/inspecting the body.
        # DetectionOnly still runs every phase, preserving false-positive tuning.
        'SecAction "id:1102,phase:1,pass,nolog,t:none,setvar:tx.early_blocking=1"',
    ]
    global_mode = config["mode"]
    # Explicit site settings precede the fallback. Every transaction starts fresh.
    rid = 1200
    exceptions = []
    for name, site in sorted(config["sites"].items()):
        mode = site.get("mode", global_mode)
        # UNIQUE_ID is supplied by the connector from $server_name, not the Host header.
        # Absolute-form requests and aliases must not select a different site's policy.
        actions = []
        if site.get("profile") == "wordpress":
            actions.append("setvar:tx.wordpress-rule-exclusions-plugin_enabled=1")
        if mode != global_mode:
            actions.append("setvar:tx.waf_mode_override=1")
            actions.append("ctl:ruleEngine=" + {"on":"On", "off":"Off", "detect":"DetectionOnly"}[mode])
        if actions:
            lines.append(f'SecRule UNIQUE_ID "@beginsWith {name}|" "id:{rid},phase:1,pass,nolog,t:none,' + ','.join(actions) + '"')
            rid += 1
        for item in site.get("exclusions", []):
            exceptions += [
                f'SecRule UNIQUE_ID "@beginsWith {name}|" "id:{rid},phase:1,pass,nolog,t:none,chain"',
                f'    SecRule REQUEST_FILENAME "@streq {item["path"]}" "t:none,ctl:ruleRemoveTargetById={item["ruleId"]};{item["target"]}"',
            ]
            rid += 1
    if global_mode != "on" and engine_enabled(config):
        lines.append('SecRule &TX:waf_mode_override "@eq 0" "id:1190,phase:1,pass,nolog,ctl:ruleEngine=' + {"off":"Off", "detect":"DetectionOnly"}[global_mode] + '"')
    for name,site in sorted(config['sites'].items()):
        if site.get('profile')=='kpanel':
            # KPanel intentionally accepts passwords and file/code content. Keep
            # exclusions at the exact application endpoint and JSON argument.
            routes=[('POST','/api/v1/auth/bootstrap',['password']),
                    ('POST','/api/v1/auth/login',['password']),
                    ('PUT','/api/v1/settings/password',['currentPassword','newPassword']),
                    ('PUT','/api/v1/settings/username',['currentPassword']),
                    ('PUT','/api/v1/files/content',['content']),
                    ('PUT','/api/v1/terminal-commands',['items.array_'+str(i)+'.command' for i in range(64)])]
            for method,path,targets in routes:
                controls=','.join('ctl:ruleRemoveTargetByTag='+tag+';ARGS:json.'+target
                                  for target in targets for tag in ['attack-sqli','attack-xss','attack-rce','attack-lfi','attack-rfi'])
                lines += [f'SecRule UNIQUE_ID "@beginsWith {name}|" "id:{rid},phase:1,pass,nolog,t:none,chain"',
                          f'    SecRule REQUEST_METHOD "@streq {method}" "t:none,chain"',
                          '    SecRule REQUEST_FILENAME "@rx ^(?:/[A-Za-z0-9_-]+)?'+path+'$" "t:none,'+controls+'"']
                rid+=1
            lines += [f'SecRule UNIQUE_ID "@beginsWith {name}|" "id:{rid},phase:1,pass,nolog,t:none,chain"',
                      '    SecRule REQUEST_METHOD "@rx ^(?:GET|PUT)$" "t:none,chain"',
                      '    SecRule REQUEST_FILENAME "@rx ^(?:/[A-Za-z0-9_-]+)?/api/v1/files(?:/(?:entry|content|archive))?$" "t:none,ctl:ruleRemoveTargetById=930120;ARGS:path,ctl:ruleRemoveTargetById=930130;ARGS:path"']
            rid+=1
        if site.get('profile')=='artifact-proxy':
            lines += [f'SecRule UNIQUE_ID "@beginsWith {name}|" "id:{rid},phase:1,pass,nolog,t:none,chain"',
                      '    SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" "t:none,chain"',
                      '    SecRule REQUEST_FILENAME "@rx ^/(?:https?://)?[A-Za-z0-9-]+(?:[.][A-Za-z0-9-]+)+(?::[0-9]{1,5})?/" "t:none,ctl:ruleRemoveById=920440,ctl:ruleRemoveTargetById=930130;REQUEST_FILENAME"']
            rid+=1
            lines += [f'SecRule UNIQUE_ID "@beginsWith {name}|" "id:{rid},phase:1,pass,nolog,t:none,chain"',
                      '    SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD|POST)$" "t:none,chain"',
                      '    SecRule REQUEST_FILENAME "@rx ^/(?:https?://)?[A-Za-z0-9-]+(?:[.][A-Za-z0-9-]+)+(?::[0-9]{1,5})?/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\\.git/(?:info/refs|git-upload-pack)$" "t:none,ctl:ruleRemoveTargetById=930130;REQUEST_FILENAME"']
            rid+=1
            lines += [f'SecRule UNIQUE_ID "@beginsWith {name}|" "id:{rid},phase:1,pass,nolog,t:none,chain"',
                      '    SecRule REQUEST_METHOD "@streq POST" "t:none,chain"',
                      '    SecRule REQUEST_FILENAME "@rx ^/(?:https?://)?[A-Za-z0-9-]+(?:[.][A-Za-z0-9-]+)+(?::[0-9]{1,5})?/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\\.git/git-upload-pack$" "t:none,chain"',
                      '    SecRule REQUEST_HEADERS:Content-Type "@streq application/x-git-upload-pack-request" "t:none,t:lowercase,ctl:ruleRemoveById=920420"']
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
SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,deny,status:400,log,msg:'WAF request body parsing failed'"
SecRule INBOUND_DATA_ERROR "@eq 1" "id:200006,phase:2,deny,status:413,log,msg:'WAF request body limit exceeded'"
SecRule &ARGS "@ge 2048" "id:200007,phase:2,deny,status:400,log,msg:'WAF argument budget exceeded'"
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
Include /etc/nginx/modsec/rules/*.conf
SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE "@ge 5" "id:1112,phase:5,pass,nolog,ctl:auditEngine=On"
'''


def render_guard() -> str:
    return '''# Protect secret paths, not ordinary application endpoints or documentation.
# Well-known endpoints still pass through CRS; they never disable the rule engine.
SecRule REQUEST_FILENAME "@rx (?i)(?:^|/)\\.(?!well-known(?:/|$))" "id:1110,phase:1,deny,status:403,log,t:none,t:urlDecodeUni,t:normalizePath,msg:'WAF secret dot path'"
SecRule REQUEST_FILENAME "@rx (?i)(?:^|/)wp-config\\.php(?:[.~].*)?$" "id:1111,phase:1,deny,status:403,log,t:none,t:urlDecodeUni,t:normalizePath,msg:'WAF secret application configuration'"
'''


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


def bundle_files(config: dict, cloudflare: list[str]) -> dict[str, str]:
    validate(config)
    result = {
        "http.conf": render_http(config), "realip.conf": render_realip(config, cloudflare),
        "server-default.inc": render_server(existing_bans=config.get('banBackend','existing')=='existing'), "profile-rules.conf": render_profile_rules(config),
        "modsecurity.conf": render_modsecurity(config), "request-guard.conf": render_guard(),
        "access-log.inc": 'access_log /var/log/nginx/waf-rate.log waf_rate if=$waf_rate_event;\n',
        "load-module.conf": 'load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;\n',
    }
    import hashlib
    for name, site in config["sites"].items():
        if "cdn" in site:
            ident = hashlib.sha256(name.encode()).hexdigest()[:16]
            settings = dict(config, cdn=site["cdn"], trustedProxies=site.get("trustedProxies", []),
                            proxyHeader=site.get("proxyHeader", "X-Forwarded-For"))
            result[f"realip-{ident}.conf"] = render_realip(settings, cloudflare)
            result[f"server-{ident}.inc"] = render_server(f"realip-{ident}.conf",config.get('banBackend','existing')=='existing')
    return result


def render_filters() -> dict[str, str]:
    # F-ID is intentionally site|IP, so Fail2Ban counters do not cross vhosts.
    identity = r"[A-Za-z0-9_.*-]+\|[0-9a-fA-F:.]+"
    rate = ('[Definition]\n'
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
    attack='[Definition]\nfailregex = '+structured+'\nignoreregex =\n'
    return {"waf-rate.conf": rate, "waf-attack.conf": attack}
