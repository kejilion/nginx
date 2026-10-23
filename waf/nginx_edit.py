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
    pattern = r'\n[ \t]*include /etc/nginx/conf\.d/waf/server-(?:default\*|[a-f0-9]{16})\.inc;[^\n]*\n'
    text = re.sub(pattern, '', text)
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
        if 'cdn' in config.get('sites', {}).get(name, {}):
            filename = 'server-' + hashlib.sha256(name.encode()).hexdigest()[:16] + '.inc'
        insertions.append((block['open'], '\n    include /etc/nginx/conf.d/waf/' + filename + ';\n'))
    for offset, addition in reversed(insertions):
        text = text[:offset] + addition + text[offset:]
    return text


def patch_main(text: str) -> str:
    # Only the shipped legacy module/config/rate directives are migrated.
    text = re.sub(r'(?m)^\s*(?:#\s*)?load_module /etc/nginx/modules/ngx_http_modsecurity_module\.so;[^\n]*\n', '', text)
    text = re.sub(r'(?m)^\s*(?:#\s*)?modsecurity(?:_rules_file)? (?:on|off|/etc/nginx/modsec/modsecurity\.conf);[^\n]*\n', '', text)
    key=r'(?:\$binary_remote_addr|"\$server_name\|\$binary_remote_addr")'
    text = re.sub(r'(?m)^\s*limit_req_zone '+key+r' zone=example_zone:[^;]+;[^\n]*\n', '', text)
    text = re.sub(r'(?m)^\s*limit_req zone=example_zone[^;]*;[^\n]*\n', '', text)
    text = re.sub(r'(?m)^\s*limit_conn_zone '+key+r' zone=addr:[^;]+;[^\n]*\n', '', text)
    text = re.sub(r'(?m)^\s*limit_conn addr [0-9]+;[^\n]*\n', '', text)
    text = re.sub(r'(?m)^\s*limit_(?:req|conn)_status 429;[^\n]*\n', '', text)
    if 'include /etc/nginx/conf.d/waf/load-module*.conf;' not in text:
        text = 'include /etc/nginx/conf.d/waf/load-module*.conf;\n' + text
    if 'include /etc/nginx/conf.d/waf/http*.conf;' not in text:
        matches = list(re.finditer(r'(?m)^\s*http\s*\{', text))
        if len(matches) != 1:
            raise ValueError("Expected one HTTP block")
        pos = matches[0].end()
        text = text[:pos] + '\n    include /etc/nginx/conf.d/waf/http*.conf;\n' + text[pos:]
    # Keep the native script's existing engine switch and status readback working.
    # Rules and maps are still provided by the one shared managed bundle.
    text=text.replace('    include /etc/nginx/conf.d/waf/http*.conf;',
                      '    modsecurity on;\n    include /etc/nginx/conf.d/waf/http*.conf;')
    return text


def strip_legacy_default_realip(text: str) -> str:
    # Legacy default10/default11 placed trust at HTTP scope after the catch-all.
    # Fail closed for unfamiliar mixed content instead of rewriting unknown policies.
    blocks = server_blocks(text)
    end = max((b['end'] for b in blocks), default=0)
    prefix, suffix = text[:end], text[end:]
    rest = []
    for line in suffix.splitlines():
        if re.match(r'\s*(?:set_real_ip_from|real_ip_header|real_ip_recursive)\s+', line):
            continue
        if line.strip() and not line.lstrip().startswith('#'):
            raise ValueError("Default file contains additional unmanaged directives")
        rest.append(line)
    if any(re.search(r'\b(?:set_real_ip_from|real_ip_header|real_ip_recursive)\s+', line)
           for line in prefix.splitlines() if not line.lstrip().startswith('#')):
        raise ValueError("Default file has a custom server-level proxy policy")
    return prefix.rstrip() + '\n'


def statement_scopes(stream):
    groups = {0: {'parent': None, 'kind': 'root', 'statements': []}}
    stack, start, serial = [0], 0, 0
    for i, token in enumerate(stream):
        if token.value == '{':
            serial += 1
            groups[serial] = {'parent': stack[-1], 'kind': stream[start].value,
                              'head':[t.value for t in stream[start:i]], 'statements': []}
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


def configuration_headers(dump):
    """Evaluate actual include scopes from a bounded nginx -T snapshot.

    Keep source offsets so only directives in the administrator's site file are
    rewritten. An identity header in a same-scope external include needs explicit
    migration; we must not leave a duplicate or mutate a shared external file.
    """
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
                matches=sorted(n for n in files if fnmatch.fnmatchcase(n,target))
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
    groups=statement_scopes(expand(main))
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
