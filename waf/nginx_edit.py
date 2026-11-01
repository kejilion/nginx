"""Small Nginx lexer for bounded configuration edits, preserving other bytes."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import fnmatch
import posixpath
import re


@dataclass
class Token:
    value: str
    start: int
    end: int
    source: str = ''


def tokens(text: str) -> list[Token]:
    if len(text.encode()) > 2 * 1024 * 1024:
        raise ValueError("Nginx file exceeds edit budget")
    result = []
    i = 0
    while i < len(text):
        if text[i].isspace():
            i += 1
            continue
        if text[i] == '#':
            i = text.find('\n', i)
            if i == -1:
                break
            continue
        start = i
        if text[i] in '{};':
            i += 1
        elif text[i] in '\"\'':
            quote = text[i]
            i += 1
            while i < len(text):
                if text[i] == '\\':
                    i += 2
                elif text[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
            else:
                raise ValueError("Unterminated Nginx string")
        else:
            while i < len(text) and not text[i].isspace() and text[i] not in '{};':
                if text[i] == '\\' and i + 1 < len(text):
                    i += 2
                elif text.startswith('${', i):
                    close = text.find('}', i + 2)
                    if close == -1:
                        raise ValueError("Unterminated variable")
                    i = close + 1
                else:
                    i += 1
        result.append(Token(text[start:i], start, i))
    return result


def server_blocks(text: str) -> list[dict]:
    stream = tokens(text)
    blocks, stack = [], []
    candidate = None
    for i, token in enumerate(stream):
        if token.value == '{':
            name = stream[i-1].value if i else ''
            # Top-level conf.d server blocks only; upstream and location are excluded.
            if not stack and name == 'server':
                candidate = {'open': token.end, 'names': [], 'token': i}
            stack.append(name)
        elif token.value == '}':
            if not stack:
                raise ValueError("Unbalanced Nginx braces")
            stack.pop()
            if not stack and candidate is not None:
                candidate['close'] = token.start
                candidate['end'] = token.end
                blocks.append(candidate)
                candidate = None
        elif token.value == 'server_name' and len(stack) == 1 and candidate is not None:
            j = i + 1
            while j < len(stream) and stream[j].value != ';':
                value = stream[j].value.strip('\"\'')
                if not re.fullmatch(r'(?:\*\.)?[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}', value):
                    raise ValueError("Complex server_name requires explicit integration")
                candidate['names'].append(value.lower())
                j += 1
        if len(stack) > 24:
            raise ValueError("Nginx nesting exceeds edit budget")
    if stack:
        raise ValueError("Unbalanced Nginx braces")
    return blocks


def site_scopes(text: str) -> list[str]:
    return [b['names'][0] for b in server_blocks(text) if b['names']]


def patch_site(text: str, config: dict) -> str:
    # On updates, only our managed hook is replaced. Existing application directives stay.
    removals=[]
    for group in statement_scopes(tokens(text)).values():
        for statement in group['statements']:
            if group['kind'] in {'server','location'} and [t.value for t in statement[:-1]]==['modsecurity','on']:
                removals.append((statement[0].start,statement[-1].end))
            if statement[0].value=='include' and len(statement)==3 and re.fullmatch(r'/etc/nginx/conf\.d/waf/server-(?:default\*|[a-f0-9]{16})\.inc',statement[1].value.strip('\"\'')):
                removals.append((statement[0].start,statement[-1].end))
    text=remove_statements(text,removals)
    insertions = []
    for block in server_blocks(text):
        if not block['names']:
            raise ValueError("Every managed server needs a canonical server_name")
        name = block['names'][0]
        body = text[block['open']:block['close']]
        # A catch-all that only drops unknown hosts does not need an application hook.
        if name == '_' and re.search(r'\breturn\s+444\s*;', body):
            continue
        filename = 'server-default*.inc'
        if 'cdn' in config.get('sites', {}).get(name, {}) or config.get('sites', {}).get(name, {}).get('profile')=='kpanel':
            filename = 'server-' + hashlib.sha256(name.encode()).hexdigest()[:16] + '.inc'
        suffix='' if text[block['open']:].startswith('\n') else '\n'
        insertions.append((block['open'], '\n    include /etc/nginx/conf.d/waf/' + filename + ';'+suffix))
    for offset, addition in reversed(insertions):
        text = text[:offset] + addition + text[offset:]
    return text


def patch_main(text: str, enabled: bool = True) -> str:
    # Only the shipped legacy module/config/rate directives are migrated.
    removals=[]
    for group in statement_scopes(tokens(text)).values():
        for statement in group['statements']:
            values=[token.value.strip('\"\'') for token in statement[:-1]]
            remove=group['kind']=='root' and values==['load_module','/etc/nginx/modules/ngx_http_modsecurity_module.so']
            if group['kind']=='http':
                remove=remove or values in [['modsecurity','on'],['modsecurity','off'],['modsecurity_rules_file','/etc/nginx/modsec/modsecurity.conf']]
                remove=remove or (len(values)>=3 and values[0]=='limit_req_zone' and values[1] in {'$binary_remote_addr','$server_name|$binary_remote_addr'} and values[2].startswith('zone=example_zone:'))
                remove=remove or (len(values)>=2 and values[:2]==['limit_req','zone=example_zone'])
                remove=remove or (len(values)>=3 and values[0]=='limit_conn_zone' and values[1] in {'$binary_remote_addr','$server_name|$binary_remote_addr'} and values[2].startswith('zone=addr:'))
                remove=remove or (len(values)==3 and values[:2]==['limit_conn','addr'] and values[2].isdigit())
                remove=remove or values in [['limit_req_status','429'],['limit_conn_status','429']]
            if remove:removals.append((statement[0].start,statement[-1].end))
    text=remove_statements(text,removals)
    text=re.sub(r'(?m)^[ \t]*# modsecurity on;[ \t]*(?:\r?\n|$)','',text)
    groups=statement_scopes(tokens(text))
    module='/etc/nginx/conf.d/waf/load-module*.conf'
    http_include='/etc/nginx/conf.d/waf/http*.conf'
    def includes(group,target):return any(len(s)==3 and s[0].value=='include' and s[1].value.strip('\"\'')==target for s in group['statements'])
    if not includes(groups[0],module):
        text = 'include /etc/nginx/conf.d/waf/load-module*.conf;\n' + text
    groups=statement_scopes(tokens(text))
    http=[group for group in groups.values() if group['kind']=='http']
    if len(http)!=1:raise ValueError('Expected one HTTP block')
    # Keep the native script's existing engine switch and status readback working.
    # Rules and maps are still provided by the one shared managed bundle.
    pos=http[0]['open']
    addition='\n    '+('modsecurity on;' if enabled else '# modsecurity on;')
    if not includes(http[0],http_include):addition+='\n    include /etc/nginx/conf.d/waf/http*.conf;'
    if not text[pos:].startswith('\n'):addition+='\n'
    text=text[:pos]+addition+text[pos:]
    return text


def remove_statements(text,spans):
    edits=[]
    for start,end in spans:
        left=text.rfind('\n',0,start)+1
        right=text.find('\n',end)
        if right<0:right=len(text)
        # Remove a whole line only when it contains no other active directive.
        if not text[left:start].strip() and (not text[end:right].strip() or text[end:right].lstrip().startswith('#')):
            start,end=left,min(right+1,len(text))
        edits.append((start,end))
    for start,end in sorted(edits,reverse=True):text=text[:start]+text[end:]
    return text


def strip_legacy_default_realip(text: str,known_cidrs=()) -> str:
    # Legacy default10/default11 placed trust at HTTP scope after the catch-all.
    # Fail closed for unfamiliar mixed content instead of rewriting unknown policies.
    blocks = server_blocks(text)
    end = max((b['end'] for b in blocks), default=0)
    prefix, suffix = text[:end], text[end:]
    trusted={'172.0.0.0/8','fd00::/8',*known_cidrs}
    spans=[]
    for group in statement_scopes(tokens(suffix)).values():
        for statement in group['statements']:
            values=[t.value.strip('\"\'') for t in statement[:-1]]
            if len(values)!=2:continue
            if ((values[0]=='set_real_ip_from' and values[1] in trusted) or
                values in [['real_ip_header','X-Forwarded-For'],['real_ip_header','CF-Connecting-IP'],
                           ['real_ip_recursive','on'],['real_ip_recursive','off']]):
                spans.append((statement[0].start,statement[-1].end))
    if tokens(remove_statements(suffix,spans)):
        raise ValueError('Default file contains additional unmanaged directives')
    if any(s[0].value in {'set_real_ip_from','real_ip_header','real_ip_recursive'} for group in statement_scopes(tokens(prefix)).values() for s in group['statements']):
        raise ValueError("Default file has a custom server-level proxy policy")
    return prefix.rstrip() + '\n'


def statement_scopes(stream):
    groups = {0: {'parent': None, 'kind': 'root', 'statements': []}}
    stack, start, serial = [0], 0, 0
    for i, token in enumerate(stream):
        if token.value == '{':
            serial += 1
            groups[serial] = {'parent': stack[-1], 'kind': stream[start].value,
                              'head':[t.value for t in stream[start:i]], 'open':token.end, 'statements': []}
            stack.append(serial)
            start = i + 1
        elif token.value == '}':
            if len(stack) == 1: raise ValueError('Unbalanced Nginx braces')
            stack.pop()
            start = i + 1
        elif token.value == ';':
            if start < i: groups[stack[-1]]['statements'].append(stream[start:i+1])
            start = i + 1
        if len(stack) > 32: raise ValueError('Nginx nesting exceeds edit budget')
    if len(stack) != 1: raise ValueError('Unbalanced Nginx braces')
    return groups


def configuration_scopes(dump):
    """Expand a bounded nginx -T snapshot without losing its source scopes."""
    parts = re.split(r'(?m)^# configuration file ([^\r\n]+):\n', dump)
    files = dict(zip(parts[1::2], parts[2::2]))
    if not files or len(files)>1024 or sum(len(x.encode()) for x in files.values())>2*1024*1024:
        raise ValueError('Invalid or excessive Nginx configuration snapshot')
    count = [0]
    def expand(name, parents=()):
        if name in parents or len(parents)>24: raise ValueError('Recursive Nginx include')
        stream=tokens(files[name])
        for token in stream: token.source=name
        out=[]; i=0
        while i<len(stream):
            token=stream[i]
            if token.value=='include' and (i==0 or stream[i-1].value in {';', '{', '}'}):
                if i+2>=len(stream) or stream[i+2].value!=';':raise ValueError('Unsupported include syntax')
                target=stream[i+1].value.strip('\"\'')
                if '$' in target:raise ValueError('Dynamic Nginx include needs explicit migration')
                if not target.startswith('/'):target=posixpath.join('/etc/nginx',target)
                # Nginx glob '*' does not cross a directory separator.
                matches=sorted(n for n in files if len(n.split('/'))==len(target.split('/')) and all(fnmatch.fnmatchcase(part,pattern) for part,pattern in zip(n.split('/'),target.split('/'))))
                if not matches and not any(c in target for c in '*?['):
                    raise ValueError('Missing include snapshot: '+target)
                for match in matches:out.extend(expand(match,(*parents,name)))
                i+=3
            else:out.append(token); i+=1
            count[0]+=1
            if count[0]>250000:raise ValueError('Expanded Nginx configuration exceeds budget')
        return out
    main='/etc/nginx/nginx.conf'
    if main not in files: raise ValueError('Missing main configuration snapshot')
    return statement_scopes(expand(main))


def candidate_configuration(dump, replacements):
    """Overlay validated candidate bytes without discarding external includes."""
    parts=re.split(r'(?m)^# configuration file ([^\r\n]+):\n',dump)
    files=dict(zip(parts[1::2],parts[2::2]))
    files.update(replacements)
    return ''.join('# configuration file '+name+':\n'+body+'\n' for name,body in files.items())


def static_resource_controls(dump):
    """Prove file-only handlers from the expanded config, independently of app names."""
    groups=configuration_scopes(dump); decisions={}
    allowed=set(('listen server_name root index charset default_type types_hash_max_size '
                 'ssl_certificate ssl_certificate_key ssl_protocols ssl_ciphers ssl_prefer_server_ciphers '
                 'add_header add_header_inherit expires access_log error_log log_not_found '
                 'aio sendfile tcp_nopush tcp_nodelay open_file_cache open_file_cache_valid '
                 'open_file_cache_min_uses open_file_cache_errors client_max_body_size '
                 'limit_req limit_conn limit_req_dry_run limit_conn_dry_run limit_rate '
                 'limit_rate_after allow deny auth_basic auth_basic_user_file satisfy '
                 'gzip gzip_types gzip_vary gzip_static etag if_modified_since '
                 'try_files return disable_symlinks modsecurity').split())
    inherited_allowed=allowed | set(('client_body_buffer_size client_body_timeout client_header_buffer_size client_header_timeout '
        'large_client_header_buffers keepalive_requests keepalive_timeout log_format modsecurity '
        'reset_timedout_connection send_timeout output_buffers server_names_hash_bucket_size server_names_hash_max_size '
        'server_tokens types_hash_bucket_size variables_hash_bucket_size variables_hash_max_size '
        'gzip_buffers gzip_comp_level gzip_min_length http2 http2_body_preread_size http2_chunk_size '
        'http2_max_concurrent_streams http2_recv_buffer_size http3 http3_max_concurrent_streams http3_stream_buffer_size '
        'quic_active_connection_id_limit quic_gso quic_retry ssl_buffer_size ssl_certificate_cache ssl_session_cache ssl_session_timeout ssl_session_tickets gzip_proxied limit_req_zone limit_req_status limit_conn_zone limit_conn_status').split())
    inherited_allowed |= {prefix+suffix for prefix in ['proxy_','fastcgi_'] for suffix in ('buffer_size buffering buffers busy_buffers_size cache_background_update cache_bypass cache_key cache_lock cache_lock_timeout cache_methods cache_path cache_use_stale cache_valid connect_timeout hide_header intercept_errors keep_conn max_temp_file_size no_cache read_timeout send_timeout socket_keepalive headers_hash_bucket_size headers_hash_max_size').split()}
    inherited_reason=''
    for node in groups.values():
        if node['kind']=='http':
            if any(s[0].value not in inherited_allowed and not s[0].source.startswith('/etc/nginx/conf.d/waf/') for s in node['statements']):inherited_reason='unknown inherited handler'
        elif node['parent'] is not None and groups[node['parent']]['kind']=='http' and node['kind'] not in {'server','map','geo','upstream','types','split_clients'}:
            inherited_reason='unknown inherited handler block'
    for ident,group in groups.items():
        if group['kind'].strip('"\'')!='server':continue
        names=[t.value.strip('"\'').lower() for s in group['statements'] if s[0].value=='server_name' for t in s[1:-1]]
        roots=[s[1].value.strip('"\'') for s in group['statements'] if s[0].value=='root' and len(s)==3]
        reason='' if len(roots)==1 and roots[0].startswith('/var/www/html/') and '$' not in roots[0] else 'unproven document root'
        for child,node in groups.items():
            parent=child
            while parent is not None and parent!=ident:parent=groups[parent]['parent']
            if parent!=ident:continue
            if child!=ident and node['kind'].strip('"\'') not in {'location','if','limit_except'}:reason='unknown handler block'
            for s in node['statements']:
                directive=s[0].value.strip('"\''); values=[t.value.strip('"\'') for t in s[1:-1]]
                if s[0].source.startswith('/etc/nginx/conf.d/waf/'):continue
                if directive not in allowed:reason='unsupported handler: '+directive
                elif directive=='root' and (len(values)!=1 or '$' in values[0] or not values[0].startswith('/')):reason='dynamic document root'
                elif directive=='try_files' and (values not in [['$uri','=404'],['$uri','$uri/','=404'],['$uri','$uri/','/index.html']]):reason='dynamic fallback'
                elif directive=='return' and (not values or not values[0].isdigit() or int(values[0]) not in {301,302,303,307,308,400,401,403,404,405,410}):reason='non-file response'
        for name in names:
            value=inherited_reason or reason or 'file-only'
            decisions[name]=value if name not in decisions or decisions[name]==value else 'conflicting server definitions'
    return decisions


def cache_inheritance(dump):
    """Preserve HTTP cache predicates when a managed server adds its own list."""
    groups=configuration_scopes(dump);result={}
    directives=['proxy_cache_bypass','proxy_no_cache']
    for ident,group in groups.items():
        if group['kind'].strip('\"\'')!='server':continue
        names=[t.value.strip('\"\'').lower() for s in group['statements'] if s[0].value.strip('\"\'')=='server_name' for t in s[1:-1]]
        controls={}
        for directive in directives:
            current=ident
            while current is not None:
                statements=[s for s in groups[current]['statements'] if s[0].value.strip('\"\'')==directive and not re.fullmatch(r'/etc/nginx/conf[.]d/waf/server-(?:default|[a-f0-9]{16})[.]inc',s[0].source)]
                if statements:
                    # Existing server predicates are already in that scope;
                    # only inherited parent lists need copying into the hook.
                    controls[directive]=[] if current==ident else [t.value for s in statements for t in s[1:-1]]
                    break
                current=groups[current]['parent']
            else:controls[directive]=[]
        for name in names:
            result[name]=None if name in result and result[name]!=controls else controls
    return result


def method_override_controls(dump):
    """Keep method-dependent gateway authorization stricter than compatibility.

    Follow variables derived from the method, including maps in external files.
    Cache keys and ordinary FastCGI REQUEST_METHOD forwarding are not ACLs.
    Unknown access-code/auth subrequests cannot prove method-independent access.
    """
    groups=configuration_scopes(dump)
    variables={'$request_method','$request'}
    variable=lambda text:{'$'+name.lower() for name in re.findall(r'\$\{?([A-Za-z0-9_]+)',text)}
    for _ in range(len(groups)):
        before=set(variables)
        for group in groups.values():
            if group['kind']=='map' and len(group['head'])>=3:
                inputs=' '.join(group['head'][1:-1]+[t.value for s in group['statements'] for t in s])
                if variable(inputs) & variables: variables.update(variable(group['head'][-1]))
            for statement in group['statements']:
                if statement[0].value=='set' and len(statement)>=4:
                    conditional=group['kind']=='if' and bool(variable(' '.join(group['head'])) & variables)
                    if conditional or variable(' '.join(t.value for t in statement[2:-1])) & variables:
                        variables.update(variable(statement[1].value))
        if variables==before:break
    sites=set(); all_sites=False
    for ident,group in groups.items():
        opaque=('access_by_lua','rewrite_by_lua','set_by_lua','js_','perl')
        sensitive=group['kind']=='limit_except' or group['kind'].startswith(opaque)
        # Whitelist only consumers that cannot authorize another method. Unknown
        # modules, auth_basic realms/files, custom headers and dynamic routing
        # remain strict when they consume a method-derived variable.
        benign={'set','log_format','access_log','fastcgi_cache_key','proxy_cache_key',
                'fastcgi_no_cache','fastcgi_cache_bypass','proxy_no_cache','proxy_cache_bypass'}
        if variable(' '.join(group.get('head',[]))) & variables and group['kind'] not in {'map','if'}:
            sensitive=True
        if group['kind']=='if' and variable(' '.join(group['head'])) & variables:
            if any(s[0].value not in {'set'} for s in group['statements']):sensitive=True
        for statement in group['statements']:
            key=statement[0].value
            if key=='proxy_method' or key.startswith(opaque):
                sensitive=True
            if key=='auth_request' and statement[1].value!='off':sensitive=True
            if key=='underscores_in_headers' and statement[1].value=='on':sensitive=True
            if key in {'proxy_set_header','fastcgi_param','uwsgi_param','scgi_param'} and len(statement)>2:
                target=statement[1].value.strip('\"\'').lower().replace('_','-')
                if target.removeprefix('http-') in {'x-http-method-override','x-http-method','x-method-override'}:sensitive=True
            if key=='modsecurity_rules' and statement[1].value.strip('\"\'')!='SecArgumentsLimit 8192':sensitive=True
            if key=='modsecurity_rules_file' and statement[1].value.strip('\"\'') not in {'/etc/nginx/modsec/modsecurity.conf','/etc/nginx/conf.d/waf/modsecurity.conf'}:sensitive=True
            dependent=variable(' '.join(t.value for t in statement[1:-1])) & variables
            standard_method=(key in {'fastcgi_param','uwsgi_param','scgi_param'} and
                             [t.value.strip('\"\'') for t in statement[1:-1]]==['REQUEST_METHOD','$request_method'])
            if dependent and key not in benign and not standard_method and group['kind']!='map':sensitive=True
        if not sensitive:continue
        owner=ident
        while owner is not None and groups[owner]['kind'] not in {'server','http'}:owner=groups[owner]['parent']
        if owner is None:continue
        if groups[owner]['kind']=='http':all_sites=True;continue
        names=[s for s in groups[owner]['statements'] if s[0].value=='server_name']
        if not names:all_sites=True;continue
        name=names[0][1].value.strip('\"\'').lower()
        if not re.fullmatch(r'(?:\*\.)?[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}',name):all_sites=True
        else:sites.add(name)
    return all_sites,sites


def configuration_headers(dump, managed_sites=None):
    """Evaluate effective proxy headers, retaining offsets for minimal edits."""
    groups=configuration_scopes(dump)
    main='/etc/nginx/nginx.conf'
    if managed_sites is not None:
        for ident, group in groups.items():
            for statement in group['statements']:
                values=[t.value for t in statement[:-1]]
                if not values or values[0]!='modsecurity':continue
                if group['kind']=='http':
                    if statement[0].source!=main:
                        raise ValueError('HTTP WAF switch in an external include needs explicit integration')
                    continue
                if values==['modsecurity','off']:
                    if group['kind']=='server' and statement[0].source not in managed_sites:
                        raise ValueError('Server WAF switch in an external include needs explicit integration')
                    continue
                if values!=['modsecurity','on']:continue
                if group['kind'] not in {'server','location'} or statement[0].source not in managed_sites:
                    raise ValueError('WAF switch outside managed site scopes needs explicit integration')
                parent=group['parent']
                while parent is not None and groups[parent]['kind']!='http':
                    if any([t.value for t in s[:-1]]==['modsecurity','off'] for s in groups[parent]['statements']):
                        raise ValueError('Nested WAF Off/On exception needs explicit integration')
                    parent=groups[parent]['parent']
    result={}
    for ident, group in groups.items():
        ancestor=ident
        while ancestor is not None and groups[ancestor]['kind']!='http':ancestor=groups[ancestor]['parent']
        if ancestor is None:continue
        passes=[s for s in group['statements'] if s[0].value=='proxy_pass']
        if not passes:continue
        owner=ident
        while owner is not None:
            headers=[s for s in groups[owner]['statements'] if s[0].value=='proxy_set_header']
            if headers:break
            owner=groups[owner]['parent']
        for statement in passes:
            result[(statement[0].source,statement[0].start)]={
                'headers':[(s[1].value.strip('\"\''), ' '.join(t.value for t in s[2:-1])) for s in headers],
                'ownScope': owner==ident,
                'externalIdentityAtSameScope': owner==ident and any(
                    s[0].source!=statement[0].source and s[1].value.strip('\"\'').lower() in IDENTITY_HEADERS for s in headers)}
    return result


IDENTITY_HEADERS = {'x-real-ip', 'x-forwarded-for', 'cf-connecting-ip', 'true-client-ip', 'forwarded'}


def migrate_server_off(text):
    """Retire server-level legacy switches without promoting a location exception."""
    stream=tokens(text)
    groups=statement_scopes(stream)
    edits=[]; detected=[]
    for group in groups.values():
        if group['kind']!='server':continue
        names=[s for s in group['statements'] if s[0].value=='server_name']
        switches=[s for s in group['statements'] if s[0].value=='modsecurity' and s[1].value=='off']
        if switches:
            if not names:raise ValueError('Legacy WAF switch without server_name')
            detected.append(names[0][1].value.strip('\"\'').lower())
            edits.extend((s[0].start,s[-1].end) for s in switches)
    for start,end in sorted(edits,reverse=True):text=text[:start]+text[end:]
    return text,detected


def patch_application(text: str, effective_headers=None, filename='', events=True) -> str:
    """Keep trusted identity at the application boundary and retain defence events.

    Nginx does not inherit access_log/proxy_set_header when a child defines any.
    Operate on parsed statement scopes, including locations with access_log off.
    """
    stream = tokens(text)
    groups = statement_scopes(stream)
    edits = []
    for ident, group in groups.items():
        statements=group['statements']
        logs = [s for s in statements if s[0].value == 'access_log'] if events else []
        hook = 'include /etc/nginx/conf.d/waf/access-log*.inc;'
        has_hook = any(s[0].value == 'include' and 'waf/access-log' in s[1].value for s in statements)
        for statement in logs:
            if statement[1].value == 'off':
                edits.append((statement[0].start, statement[-1].end, hook if not has_hook else ''))
                has_hook = True
        if logs and not has_hook:
            pos = logs[-1][-1].end
            edits.append((pos, pos, '\n    ' + hook))
        passes = [s for s in statements if s[0].value == 'proxy_pass']
        if passes:
            own_headers=[s for s in statements if s[0].value=='proxy_set_header']
            owner=ident
            headers=own_headers
            while not headers and groups[owner]['parent'] is not None:
                owner=groups[owner]['parent']
                headers=[s for s in groups[owner]['statements'] if s[0].value=='proxy_set_header']
            inherited=[(s[1].value.strip('\"\''), ' '.join(t.value for t in s[2:-1])) for s in headers]
            copy_parent=not own_headers
            if effective_headers is not None:
                selected=effective_headers.get((filename,passes[0][0].start))
                if selected is None:raise ValueError('Missing effective proxy scope: '+filename)
                if selected['externalIdentityAtSameScope']:
                    raise ValueError('Identity headers in same-scope include need explicit migration: '+filename)
                inherited=selected['headers']
                copy_parent=not selected['ownScope']
            targets = {'X-Real-IP': '$remote_addr', 'X-Forwarded-For': '$remote_addr',
                       'CF-Connecting-IP': '$remote_addr', 'True-Client-IP': '""', 'Forwarded': '""'}
            identity=[s for s in own_headers if s[1].value.strip('\"\'').lower() in IDENTITY_HEADERS]
            current=[(s[1].value.strip('\"\'').lower(),' '.join(t.value for t in s[2:-1])) for s in identity]
            if sorted(current)==sorted((k.lower(),v) for k,v in targets.items()):continue
            for statement in own_headers:
                if statement[1].value.strip('\"\'').lower() in IDENTITY_HEADERS:
                    start,end=statement[0].start,statement[-1].end
                    line=text.rfind('\n',0,start)+1
                    tail=text.find('\n',end)
                    if tail!=-1 and not text[line:start].strip() and not text[end:tail].strip():
                        start,end=line,tail+1
                    edits.append((start,end,''))
            pos = passes[0][0].start
            line=text.rfind('\n',0,pos)+1
            indent=text[line:pos] if not text[line:pos].strip() else '    '
            # Adding any header at this level stops all Nginx header inheritance.
            # Copy the nearest effective parent's non-identity fields as a unit.
            additions=''
            if copy_parent:
                additions=''.join('proxy_set_header '+k+' '+v+';\n'+indent for k,v in inherited if k.lower() not in IDENTITY_HEADERS)
            additions += ''.join('proxy_set_header ' + k + ' ' + v + ';\n'+indent for k,v in targets.items())
            edits.append((pos, pos, additions))
    for start, end, replacement in sorted(edits, reverse=True):
        text = text[:start] + replacement + text[end:]
    return text


def absolute_includes(text: str) -> str:
    stream = tokens(text)
    edits=[]
    for i, token in enumerate(stream[:-2]):
        if token.value=='include' and stream[i+2].value==';':
            path=stream[i+1].value.strip('\"\'')
            if not path.startswith('/'):
                if '$' in path or '..' in path.split('/'):
                    raise ValueError('Dynamic relative include needs explicit integration')
                edits.append((stream[i+1].start,stream[i+1].end,'"/etc/nginx/'+path+'"'))
    for start,end,value in reversed(edits):text=text[:start]+value+text[end:]
    return text
