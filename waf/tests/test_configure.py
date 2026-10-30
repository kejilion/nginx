import pathlib
import sys
import unittest
from unittest.mock import patch
import tempfile
import json
import contextlib
import hashlib
import os
import subprocess

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import configure as manage
import ban
import nginx_edit
import policy


class ManagedTrustTests(unittest.TestCase):
    def test_static_first_migration_status_and_second_plan_converge(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);(root/'conf.d').mkdir()
            main='events {} http { modsecurity on; modsecurity_rules_file /etc/nginx/modsec/modsecurity.conf; include conf.d/*.conf; }'
            site='server { server_name static.example; root /var/www/html/static; modsecurity on; location / {try_files $uri =404;} }'
            (root/'nginx.conf').write_text(main);(root/'conf.d/site.conf').write_text(site)
            config=json.loads((manage.BUNDLE/'example-policy.json').read_text());config['mode']='on'
            dump='# configuration file /etc/nginx/nginx.conf:\n'+main+'\n# configuration file /etc/nginx/conf.d/site.conf:\n'+site
            with patch.object(manage,'execute',return_value=dump),patch.object(manage,'kpanel_endpoints',return_value=set()):
                changes,_=manage.make_plan(root,config)
            self.assertIn(b'ruleRemoveTargetById=932260;REQUEST_FILENAME',changes[root/'conf.d/waf/profile-rules.conf'])
            graph={}
            for path,data in changes.items():
                path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
                if path.suffix in {'.conf','.inc','.map'} or path.name=='nginx.conf':graph['/etc/nginx/'+path.relative_to(root).as_posix()]=data.decode()
            installed=nginx_edit.candidate_configuration(dump,graph)
            with patch.object(manage,'execute',return_value=installed),patch.object(manage,'kpanel_endpoints',return_value=set()):
                self.assertTrue(manage.configured_status(root,config)['requestSemantics']['synchronized'])
                second,_=manage.make_plan(root,config)
            self.assertEqual(second[root/'conf.d/waf/profile-rules.conf'],changes[root/'conf.d/waf/profile-rules.conf'])

    def test_cache_predicates_preserve_http_server_and_location_inheritance(self):
        def check(server):
            return nginx_edit.cache_inheritance('# configuration file /etc/nginx/nginx.conf:\nhttp { proxy_cache_bypass $arg_nocache; proxy_no_cache $http_x_private; '+server+' }')['panel.example']
        self.assertEqual(check('server { server_name panel.example; }'),{'proxy_cache_bypass':['$arg_nocache'],'proxy_no_cache':['$http_x_private']})
        self.assertEqual(check('server { server_name panel.example; proxy_cache_bypass $http_x_custom; }'),{'proxy_cache_bypass':[],'proxy_no_cache':['$http_x_private']})
        self.assertEqual(check('server { server_name panel.example; location / { proxy_cache_bypass $http_x_location; proxy_no_cache $http_x_location; } }'),{'proxy_cache_bypass':['$arg_nocache'],'proxy_no_cache':['$http_x_private']})
        dump='# configuration file /etc/nginx/nginx.conf:\nhttp { proxy_cache_bypass $arg_nocache; proxy_no_cache $http_x_private; server { server_name panel.example; include /etc/nginx/conf.d/waf/server-default.inc; } }\n# configuration file /etc/nginx/conf.d/waf/server-default.inc:\nproxy_cache_bypass $http_cookie; proxy_no_cache $http_cookie;\n'
        self.assertEqual(nginx_edit.cache_inheritance(dump)['panel.example'],check('server { server_name panel.example; }'))
        self.assertEqual(nginx_edit.cache_inheritance(dump.replace('panel.example','Panel.Example'))['panel.example'],check('server { server_name panel.example; }'))
        self.assertEqual(check('server { server_name panel.example; }'),nginx_edit.cache_inheritance(dump.replace('proxy_cache_bypass','"proxy_cache_bypass"'))['panel.example'])
        ambiguous='# configuration file /etc/nginx/nginx.conf:\nhttp { proxy_cache_bypass $arg_http; server { server_name panel.example; proxy_cache_bypass $arg_server; } server { server_name panel.example; } }'
        self.assertIsNone(nginx_edit.cache_inheritance(ambiguous)['panel.example'])
        config=json.loads((manage.BUNDLE/'example-policy.json').read_text());config['sites']={'panel.example':{'profile':'kpanel'}}
        with self.assertRaisesRegex(ValueError,'Conflicting cache inheritance'):
            policy.bundle_files(config,[],cache_controls=nginx_edit.cache_inheritance(ambiguous))
        config['sites']['panel.example']['profile']='generic'
        policy.bundle_files(config,[],cache_controls=nginx_edit.cache_inheritance(ambiguous))

    def test_flarum_metadata_and_mixed_application_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);(root/'public').mkdir();(root/'vendor/flarum/core').mkdir(parents=True)
            (root/'composer.json').write_text(json.dumps({'require':{'flarum/core':'^2'}}))
            vendor=root/'vendor/flarum/core/composer.json';vendor.write_text(json.dumps({'name':'flarum/core'}))
            self.assertTrue(manage.app_is_flarum(root/'public'))
            for invalid in [[],42,None,{'require':[]}]:
                (root/'composer.json').write_text(json.dumps(invalid))
                self.assertFalse(manage.app_is_flarum(root/'public'))
        def scope(body):return manage.flarum_scope_is_unmixed(nginx_edit.statement_scopes(nginx_edit.tokens(body)))
        self.assertTrue(scope('root /var/www/html/forum/public; location ~ \\.php$ { include fastcgi_params; fastcgi_pass php:9000; }'))
        for body in ['location /api/posts { proxy_pass http://other; }','include /etc/nginx/business.inc;',
                     'location /other { root /var/www/html/other; }','location /other { alias /var/www/html/other; }',
                     'location /api/posts { fastcgi_param SCRIPT_FILENAME /var/www/html/other/index.php; fastcgi_pass php:9000; }']:
            self.assertFalse(scope(body))
        for quote in ['"',"'"]:
            self.assertFalse(scope('location /api/posts { fastcgi_param '+quote+'SCRIPT_FILENAME'+quote+' /var/www/html/other/index.php; fastcgi_pass php:9000; }'))
            self.assertFalse(scope(quote+'proxy_pass'+quote+' http://other;'))

    def test_native_mixed_case_proxy_upstream_identifies_only_one_application(self):
        text='upstream backend_IycLeFBR { server 127.0.0.1:8080; } server { server_name panel.example; location / { proxy_pass http://backend_IycLeFBR; } }'
        block=nginx_edit.server_blocks(text)[0]
        endpoints={('127.0.0.1','8080')}
        self.assertTrue(manage.app_is_kpanel(text,block,endpoints))
        for candidate in [text.replace('8080','9090'),
                          text.replace('server 127.0.0.1:8080;', 'server 127.0.0.1:8080; server 127.0.0.1:9090;'),
                          text.replace('location / {', 'location /php { include /etc/nginx/php.inc; } location / {'),
                          text.replace('location / {', 'location /other { "proxy_pass" "http://127.0.0.1:9090"; } location / {'),
                          text.replace('location / {', 'location /php { fastcgi_pass unix:/php.sock; } location / {')]:
            with self.subTest(candidate=candidate):
                self.assertFalse(manage.app_is_kpanel(candidate,nginx_edit.server_blocks(candidate)[0],endpoints))

    def test_method_gateway_capabilities_follow_scopes_includes_and_derived_variables(self):
        def check(http,site,expected):
            dump='# configuration file /etc/nginx/nginx.conf:\nhttp { '+http+' include /etc/nginx/site.conf; }\n# configuration file /etc/nginx/site.conf:\n'+site+'\n'
            self.assertEqual(nginx_edit.method_override_controls(dump),expected)
        plain='server { server_name normal.example; location / { proxy_pass http://backend; } }'
        check('fastcgi_cache_key "$request_method$host";',plain,(False,set()))
        check('map $request_method $realm { default off; DELETE admin; }',
              plain.replace('location /','auth_basic $realm; location /'),(False,{'normal.example'}))
        check('',plain.replace('proxy_pass','limit_except POST { deny all; } proxy_pass'),(False,{'normal.example'}))
        check('auth_request /auth;',plain,(True,set()))
        check('underscores_in_headers on;',plain,(True,set()))
        for directive in ['proxy_set_header X-HTTP-Method-Override $arg_method;',
                          'fastcgi_param HTTP_X_HTTP_METHOD_OVERRIDE $arg_method;',
                          'if ($request_method = DELETE) { return 403; }',
                          'modsecurity_rules "SecRule REQUEST_METHOD POST pass";']:
            check('',plain.replace('location /',directive+' location /'),(False,{'normal.example'}))
        check('map $request_method $a { default 0; POST 1; } map $a $b { default 0; 1 1; }',
              plain.replace('location /','if ($b) { return 403; } location /'),(False,{'normal.example'}))
        check('map $request_method $Guard { default off; DELETE admin; }',
              plain.replace('location /','auth_basic $guard; location /'),(False,{'normal.example'}))
        for directive in ['if ($REQUEST_METHOD = DELETE) { return 403; }',
                          'set "$realm" $request_method; auth_basic $realm;',
                          'access_by_lua_block { return 0; }',
                          'set_by_lua $realm code; auth_basic $realm;']:
            check('',plain.replace('location /',directive+' location /'),(False,{'normal.example'}))
        check('map $request $blocked { default 0; ~^DELETE 1; }',
              plain.replace('location /','if ($blocked) { return 403; } location /'),(False,{'normal.example'}))
        check('',plain.replace('proxy_pass','if ($request_method = POST) { set $skip_cache 1; } proxy_pass'),(False,set()))

    def test_native_switch_reconciliation_preserves_profiles_and_trust(self):
        config={'mode':'on','sites':{'api.example':{'profile':'api','mode':'detect','cdn':'cloudflare'}}}
        with patch.object(manage,'read_config',return_value='events {} http { # modsecurity on;\nserver { modsecurity on; } }'):
            changed=manage.reconcile_native_switch(pathlib.Path('/fixture'),config)
        self.assertEqual(changed['mode'],'off')
        self.assertEqual(changed['sites']['api.example'],{'profile':'api','cdn':'cloudflare'})
        self.assertEqual(config['mode'],'on')
        with patch.object(manage,'read_config',return_value='events {} http { modsecurity on; }'):
            restored=manage.reconcile_native_switch(pathlib.Path('/fixture'),changed)
        self.assertEqual(restored['mode'],'on')
        self.assertEqual(restored['sites'],changed['sites'])

    def test_profiles_and_legacy_modes_are_scoped_to_each_server(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            (root/'conf.d').mkdir()
            (root/'html/wp.example/wp-includes').mkdir(parents=True)
            main='events {}\nhttp { include conf.d/*.conf; }\n'
            site='server { server_name wp.example; root /var/www/html/wp.example; modsecurity off; }\nserver { server_name api.example; root /var/www/html/api.example; location /assets { modsecurity off; } }\n'
            (root/'nginx.conf').write_text(main)
            (root/'conf.d/sites.conf').write_text(site)
            config=json.loads((manage.BUNDLE/'example-policy.json').read_text())
            config['mode']='on'
            dump='# configuration file /etc/nginx/nginx.conf:\n'+main+'# configuration file /etc/nginx/conf.d/sites.conf:\n'+site
            with patch.object(manage,'execute',return_value=dump),patch.object(manage,'kpanel_endpoints',return_value=set()):changes,sites=manage.make_plan(root,config)
            self.assertEqual(config['sites']['wp.example'],{'profile':'wordpress','mode':'detect'})
            self.assertNotIn('api.example',config['sites'])
            self.assertIn(b'location /assets { modsecurity off; }',changes[root/'conf.d/sites.conf'])
            off=json.loads((manage.BUNDLE/'example-policy.json').read_text());off['mode']='off'
            with patch.object(manage,'execute',return_value=dump),patch.object(manage,'kpanel_endpoints',return_value=set()):manage.make_plan(root,off)
            self.assertNotIn('mode',off['sites']['wp.example'])
            blocked=root/'conf.d/waf/blocked.map';blocked.parent.mkdir();blocked.write_text('# existing map\n')
            read_config=manage.read_config
            def untrusted(path):
                if path==blocked:raise ValueError('untrusted-existing-map')
                return read_config(path)
            with patch.object(manage,'execute',return_value=dump),patch.object(manage,'kpanel_endpoints',return_value=set()),patch.object(manage,'read_config',side_effect=untrusted),self.assertRaisesRegex(ValueError,'untrusted-existing-map'):
                manage.make_plan(root,config)

    def test_location_off_never_promotes_to_site_off(self):
        text='server { server_name one.example; location /assets { modsecurity off; } }'
        changed,sites=nginx_edit.migrate_server_off(text)
        self.assertEqual(sites,[])
        self.assertEqual(changed,text)
        changed,sites=nginx_edit.migrate_server_off('server { server_name one.example; modsecurity off; location / { return 200; } }')
        self.assertEqual(sites,['one.example'])
        self.assertNotIn('modsecurity off;',changed)

    def test_effective_header_scope_includes_http_and_includes(self):
        main='http { proxy_set_header Host $host; proxy_set_header Upgrade $http_upgrade; include conf.d/site.conf; }'
        site='server { server_name one.example; location / { proxy_pass http://backend; } }'
        dump='# configuration file /etc/nginx/nginx.conf:\n'+main+'\n# configuration file /etc/nginx/conf.d/site.conf:\n'+site+'\n'
        effective=nginx_edit.configuration_headers(dump)
        changed=nginx_edit.patch_application(site,effective,'/etc/nginx/conf.d/site.conf')
        self.assertIn('proxy_set_header Host $host;',changed)
        self.assertIn('proxy_set_header Upgrade $http_upgrade;',changed)
        self.assertEqual(nginx_edit.patch_application(changed),changed)

    def test_identity_headers_are_case_insensitive_and_unique(self):
        text='server { location / { proxy_set_header x-forwarded-for $http_x_forwarded_for; proxy_set_header X-Forwarded-For bad; proxy_set_header Host $host; proxy_pass http://backend; } }'
        changed=nginx_edit.patch_application(text)
        self.assertNotIn('$http_x_forwarded_for',changed)
        self.assertNotIn(' bad;',changed)
        self.assertEqual(changed.lower().count('proxy_set_header x-forwarded-for '),1)
        self.assertIn('proxy_set_header Host $host;',changed)

    def test_nearest_header_scope_replaces_whole_ancestor_set(self):
        text='server { proxy_set_header Host old; proxy_set_header Upgrade old; location / { proxy_set_header Authorization token; location /sub { proxy_pass http://backend; } } }'
        changed=nginx_edit.patch_application(text)
        leaf=changed[changed.index('location /sub'):]
        self.assertIn('proxy_set_header Authorization token;',leaf)
        self.assertNotIn('proxy_set_header Host old;',leaf)
        self.assertNotIn('proxy_set_header Upgrade old;',leaf)

    def test_same_scope_external_identity_include_refused(self):
        site='server { location / { include headers.conf; proxy_pass http://backend; } }'
        dump='# configuration file /etc/nginx/nginx.conf:\nhttp { include conf.d/site.conf; }\n# configuration file /etc/nginx/conf.d/site.conf:\n'+site+'\n# configuration file /etc/nginx/headers.conf:\nproxy_set_header x-forwarded-for $http_x_forwarded_for;\n'
        with self.assertRaises(ValueError):
            nginx_edit.patch_application(site,nginx_edit.configuration_headers(dump),'/etc/nginx/conf.d/site.conf')

    def test_managed_trust_dump(self):
        manage.check_trust_dump('# configuration file /etc/nginx/conf.d/waf/realip.conf:\nset_real_ip_from 104.16.0.0/13;\nreal_ip_header CF-Connecting-IP;\n')

    def test_custom_scoped_trust_dump(self):
        manage.check_trust_dump('# configuration file /etc/nginx/conf.d/waf/realip-1234567890abcdef.conf:\nset_real_ip_from 10.2.3.4/32;\n')

    def test_unmanaged_inherited_or_location_trust_rejected(self):
        for filename in ['nginx.conf','conf.d/default.conf','conf.d/site.conf','conf.d/waf/not-realip.conf']:
            with self.subTest(filename=filename),self.assertRaises(ValueError):
                manage.check_trust_dump('# configuration file /etc/nginx/'+filename+':\nset_real_ip_from 0.0.0.0/0;\n')

    def test_inline_proxy_trust_is_not_missed(self):
        with self.assertRaises(ValueError):
            manage.check_trust_dump('# configuration file /etc/nginx/conf.d/a.conf:\nserver { set_real_ip_from 0.0.0.0/0; }\n')

    def test_existing_authentication_is_preserved(self):
        for directive in ['auth_request /auth;','auth_request off;','satisfy any;']:
            text='server { server_name one.example; '+directive+' }'
            changed=nginx_edit.patch_site(text,{'sites':{}})
            self.assertIn(directive,changed)

    def test_relative_include_normalization_is_idempotent(self):
        before='server { include fastcgi_params; include /root/custom.conf; }'
        after=nginx_edit.absolute_includes(before)
        self.assertIn('include "/etc/nginx/fastcgi_params";',after)
        self.assertIn('include /root/custom.conf;',after)
        self.assertEqual(after,nginx_edit.absolute_includes(after))

    def test_relative_traversal_refused(self):
        with self.assertRaises(ValueError):nginx_edit.absolute_includes('include ../secret;')


class ConfigurationLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=pathlib.Path(self.temporary.name).resolve()
        # OS directory trust is tested separately; these tests isolate transactions.
        self.addCleanup(patch.stopall)
        patch.object(manage,'safe_parent').start()
        patch.object(manage,'locked',side_effect=lambda path:contextlib.nullcontext()).start()
        patch.object(manage,'atomic',side_effect=self.atomic).start()

    def atomic(self,path,data,mode=0o600):
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)

    def test_external_failure_restores_old_files_and_removes_created_files(self):
        old=self.root/'old.conf';old.write_bytes(b'user custom config\n')
        new=self.root/'new.conf'
        def rejected():raise RuntimeError('validation failed')
        with self.assertRaisesRegex(RuntimeError,'validation failed'):
            manage.external_update(self.root,{old:b'candidate',new:b'candidate'},'fixture',rejected)
        self.assertEqual(old.read_bytes(),b'user custom config\n')
        self.assertFalse(new.exists())
        self.assertEqual(len(list((self.root/'backups/waf-managed').glob('*/preimage.json'))),1)

    def test_existing_fail2ban_log_migration_preserves_actions_and_thresholds(self):
        text='# Managed shared WAF; existing integration\n[waf-attack]\nlogpath = '+str(self.root/'log/nginx/error.log')+'\naction = existing-ban[source=attack,notify='+str(self.root/'log/nginx/error.log')+']\nmaxretry = 20\n[waf-rate]\nlogpath = '+str(self.root/'log/nginx/waf-rate.log')+'\naction = existing-ban[source=rate]\n'
        changed=manage.migrate_existing_jail(self.root,text)
        self.assertEqual(changed,text.replace('error.log','waf-audit.json',1))
        self.assertEqual(manage.migrate_existing_jail(self.root,changed),changed)
        with self.assertRaisesRegex(ValueError,'explicit migration'):
            manage.migrate_existing_jail(self.root,text.replace('error.log','custom.log'))

    def test_existing_fail2ban_migration_accepts_old_headers_inherited_rotated_logs_and_tail(self):
        old=str(self.root/'log/nginx/error.log');new=str(self.root/'log/nginx/waf-audit.json')
        text='\ufeff# Operator note\r\n# Managed Shared WAF: historical config\r\n'
        text+='[DEFAULT]\r\nlogpath = '+old+'.* '+old+'.1.gz tail\r\n'
        text+='[waf-attack]\r\naction = existing-ban[notify='+old+']\r\nmaxretry = 20\r\n'
        changed=manage.migrate_existing_jail(self.root,text)
        expected='logpath = '+new+'.* '+new+'.1.gz tail\r\n'
        self.assertIn(expected,changed)
        self.assertIn('logpath = '+old+'.* '+old+'.1.gz tail\r\n',changed)
        self.assertIn('action = existing-ban[notify='+old+']\r\n',changed)
        self.assertIn('[waf-attack]\r\nlogpath = '+new+'.* '+new+'.1.gz tail\r\n',changed)
        self.assertEqual(manage.migrate_existing_jail(self.root,changed),changed)

    def test_existing_fail2ban_refresh_accepts_rate_only_case_variant(self):
        text='# Managed shared WAF; historical config\n[WAF-RATE]\nenabled = true\n'
        text+='findtime = 120\nmaxretry = 120\nbantime = 600\n'
        text+='logpath = '+str(self.root/'log/nginx/waf-rate.log')+'\n'
        text+='action = waf-local[reason=rate]\n'
        changed=manage.migrate_existing_jail(self.root,text)
        self.assertIn('[waf-rate]\n',changed)
        self.assertNotIn('[WAF-RATE]',changed)
        self.assertNotIn('[waf-attack]',changed)

    def test_existing_fail2ban_migration_rejects_marker_after_jail_data(self):
        text='[waf-attack]\nlogpath = '+str(self.root/'log/nginx/error.log')+'\n'
        text+='# Managed shared WAF; too late\n'
        with self.assertRaisesRegex(ValueError,'explicit migration'):
            manage.migrate_existing_jail(self.root,text)

    def test_unmarked_legacy_waf_jail_can_move_from_error_log_on_first_enable(self):
        old=str(self.root/'log/nginx/error.log')
        rate=str(self.root/'log/nginx/waf-rate.log')
        text='''[DEFAULT]
action = waf-local[reason=attack]
logpath = '''+old+''' tail
[waf-attack]
enabled = true
findtime = 120
maxretry = 20
bantime = 600
[waf-rate]
enabled = true
findtime = 120
maxretry = 120
bantime = 600
logpath = '''+rate+'''
action = waf-local[reason=rate]
'''
        action_dir=self.root/'f2b/action.d';action_dir.mkdir(parents=True)
        (action_dir/'waf-local.conf').write_text('''[Definition]
actionban = <python> <runtime> --root <root> ban --key "<ip>" --ttl <bantime> --reason <reason>
actionunban = <python> <runtime> --root <root> unban --key "<ip>" --reason <reason>
[Init]
python = /usr/bin/python3
runtime = /home/web/conf.d/waf/wafctl.py
root = /home/web
reason = attack
''')
        with patch.object(ban,'F2B',self.root/'f2b'):
            changed=manage.migrate_existing_jail(self.root,text)
        self.assertIn('[DEFAULT]\naction = waf-local[reason=attack]\nlogpath = '+old+' tail\n',changed)
        self.assertIn('[waf-attack]\nlogpath = '+str(self.root/'log/nginx/waf-audit.json')+' tail\n',changed)

    def test_policy_concurrency_conflict_does_not_write_any_configuration(self):
        state=self.root/'config/waf/policy.json';self.atomic(state,b'newer policy')
        with patch.object(manage,'make_plan') as plan,self.assertRaisesRegex(ValueError,'concurrently'):
            manage.apply(self.root,{},expected=hashlib.sha256(b'old policy').hexdigest())
        plan.assert_not_called()
        self.assertEqual(state.read_bytes(),b'newer policy')

    def test_status_counts_unlisted_sites_using_the_global_mode(self):
        (self.root/'conf.d').mkdir()
        (self.root/'conf.d/sites.conf').write_text('server { server_name one.example; } server { server_name two.example; }')
        (self.root/'nginx.conf').write_text('http {\n modsecurity on;\n}')
        config={'mode':'detect','sites':{'one.example':{'mode':'on'}}}
        dump='# configuration file /etc/nginx/nginx.conf:\nhttp {modsecurity on;}'
        with patch.object(manage,'execute',return_value=dump):status=manage.configured_status(self.root,config)
        self.assertEqual(status['mode'],'mixed')
        self.assertEqual(status['siteCount'],2)
        config['sites']['two.example']={'mode':'on'}
        with patch.object(manage,'execute',return_value=dump):self.assertEqual(manage.configured_status(self.root,config)['mode'],'on')
        profile=self.root/'conf.d/waf/profile-rules.conf'
        self.atomic(profile,policy.render_profile_rules(config,(False,set())).encode())
        with patch.object(manage,'execute',return_value=dump):self.assertTrue(manage.configured_status(self.root,config)['methodOverride']['synchronized'])
        changed='# configuration file /etc/nginx/nginx.conf:\nhttp {modsecurity on; auth_request /auth;}'
        with patch.object(manage,'execute',return_value=changed):
            status=manage.configured_status(self.root,config)
        self.assertTrue(status['methodOverride']['gatewayStrictAll'])
        self.assertFalse(status['methodOverride']['synchronized'])

    def test_status_rejects_external_http_switch_instead_of_false_off(self):
        (self.root/'conf.d').mkdir()
        (self.root/'conf.d/site.conf').write_text('server { server_name one.example; }',encoding='utf-8')
        main='http { # modsecurity on;\n include /etc/nginx/custom.inc; }'
        (self.root/'nginx.conf').write_text(main,encoding='utf-8')
        for mode in ['on','off']:
            dump='# configuration file /etc/nginx/nginx.conf:\n'+main+'\n# configuration file /etc/nginx/custom.inc:\nmodsecurity '+mode+';\n'
            with self.subTest(mode=mode),patch.object(manage,'execute',return_value=dump),self.assertRaisesRegex(ValueError,'HTTP WAF switch'):
                manage.configured_status(self.root,{'mode':'off','sites':{}})

    def test_identical_apply_reloads_without_growing_backups(self):
        path=self.root/'site.conf';path.write_bytes(b'unchanged')
        with patch.object(manage,'make_plan',return_value=({path:b'unchanged'},['one.example'])),patch.object(manage,'execute',return_value='# configuration file /etc/nginx/nginx.conf:\nhttp {}'),patch.object(manage,'reload_nginx') as reload:
            result=manage.apply(self.root,{'mode':'on','container':'nginx'})
        self.assertFalse(result['applied'])
        reload.assert_called_once_with('nginx')
        self.assertFalse((self.root/'backups').exists())

    def test_identical_apply_rejects_unmanaged_trust_before_reload(self):
        path=self.root/'site.conf';path.write_bytes(b'unchanged')
        dump='# configuration file /etc/nginx/nginx.conf:\nhttp { set_real_ip_from 0.0.0.0/0; }'
        with patch.object(manage,'make_plan',return_value=({path:b'unchanged'},['one.example'])),patch.object(manage,'execute',return_value=dump),patch.object(manage,'reload_nginx') as reload:
            with self.assertRaisesRegex(ValueError,'Unmanaged proxy trust'):
                manage.apply(self.root,{'mode':'on','container':'nginx'})
        reload.assert_not_called()

    def test_backup_limit_preserves_existing_recovery_points(self):
        directory=self.root/'backups/waf-managed';directory.mkdir(parents=True)
        for index in range(3):
            item=directory/str(index);item.mkdir();(item/'manifest.json').write_text('{}')
        with patch.object(manage,'MAX_BACKUPS',3),self.assertRaisesRegex(ValueError,'count limit'):
            manage.snapshot(self.root,{},'fixture')
        self.assertEqual(len(list(directory.iterdir())),3)

    def test_rollback_refuses_changed_or_missing_owned_files(self):
        path=self.root/'site.conf';path.write_bytes(b'before')
        backup=manage.snapshot(self.root,{path:b'after'},'fixture')
        for value in [b'user later edit',None]:
            if value is None:path.unlink()
            else:path.write_bytes(value)
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'changed since'):
                manage.restore(self.root,backup)

    @unittest.skipUnless(os.name=='posix','Linux cron paths')
    def test_rotation_bounds_normal_logs_and_preserves_unrelated_jobs(self):
        legacy='0 2 * * * docker exec nginx apk add logrotate && docker exec nginx logrotate -f /etc/logrotate.conf'
        custom='17 3 * * * /usr/local/bin/user-logrotate --custom'
        before=custom+'\n'+legacy+'\n'
        installed=[]
        def run(args,**kwargs):
            if args==['crontab','-l']:return subprocess.CompletedProcess(args,0,before,'')
            installed.append(kwargs['input'])
            return subprocess.CompletedProcess(args,0,'','')
        with patch.object(manage.shutil,'which',side_effect=lambda name:'/usr/sbin/'+name),patch.object(manage,'execute'),patch.object(manage.subprocess,'run',side_effect=run):
            manage.rotation(self.root,{})
            before=installed[-1]
            manage.rotation(self.root,{})
        text=(self.root/'config/waf/logrotate.conf').read_text()
        for name in ['waf-rate.log','waf-audit.json','error.log','access.log']:
            self.assertIn(str(self.root/'log/nginx'/name),text)
        self.assertIn('maxsize 50M',text)
        self.assertEqual(installed[-1].count('# kejilion-waf-logrotate'),1)
        self.assertIn(custom,installed[-1])
        self.assertNotIn(legacy,installed[-1])
        self.assertEqual(installed[-1],installed[-2])

    @unittest.skipUnless(os.name=='posix','Linux cron paths')
    def test_cron_install_failure_restores_preexisting_cron_and_configuration(self):
        path=self.root/'config/waf/logrotate.conf';self.atomic(path,b'old rotation')
        before='17 3 * * * /usr/local/bin/user-backup\n'
        calls=[]
        def run(args,**kwargs):
            calls.append((args,kwargs.get('input')))
            if args==['crontab','-l']:return subprocess.CompletedProcess(args,0,before,'')
            if len(calls)==2:raise subprocess.CalledProcessError(1,args)
            return subprocess.CompletedProcess(args,0,'','')
        with patch.object(manage.shutil,'which',side_effect=lambda name:'/usr/sbin/'+name),patch.object(manage,'execute'),patch.object(manage.subprocess,'run',side_effect=run):
            with self.assertRaises(subprocess.CalledProcessError):manage.rotation(self.root,{})
        self.assertEqual(calls[-1],(['crontab','-'],before))
        self.assertEqual(path.read_bytes(),b'old rotation')

    def test_cloudflare_trust_preserves_existing_inspection_profiles_and_backend(self):
        self.atomic(self.root/'config/waf/policy.json',b'{}')
        config={'mode':'on','banBackend':'existing','sites':{'one.example':{'profile':'api','mode':'detect'}}}
        with patch.object(manage,'apply',return_value={'applied':True}) as apply:
            manage.trust_cloudflare(self.root,config,'exact-policy-hash')
        self.assertEqual(config['mode'],'on')
        self.assertEqual(config['banBackend'],'existing')
        self.assertEqual(config['sites']['one.example'],{'profile':'api','mode':'detect'})
        self.assertEqual(apply.call_args.kwargs['expected'],'exact-policy-hash')
        self.assertTrue(apply.call_args.kwargs['respect_native'])

    def test_cloudflare_trust_obeys_legacy_switch_in_both_directions(self):
        state=self.root/'config/waf/policy.json';self.atomic(state,b'{}')
        for native,mode,wanted in [('off','on','off'),('on','off','on')]:
            config={'mode':mode,'container':'nginx','banBackend':'existing','trustedProxies':['10.20.0.0/16'],'sites':{'one.example':{'profile':'api','mode':'detect','cdn':'direct'}}}
            if mode=='off':config['sites']['one.example'].pop('mode')
            (self.root/'nginx.conf').write_text('events {} http { modsecurity '+native+'; }',encoding='utf-8')
            def plan(root,changed,cfdata=None):
                self.assertEqual(changed['mode'],wanted)
                self.assertEqual(changed['banBackend'],'existing')
                self.assertEqual(changed['trustedProxies'],['10.20.0.0/16'])
                self.assertEqual(changed['sites']['one.example'],{'profile':'api','cdn':'direct'})
                self.assertEqual(changed['cdn'],'mixed')
                return {},['one.example']
            with self.subTest(native=native),patch.object(manage,'make_plan',side_effect=plan),patch.object(manage,'execute',return_value='# configuration file /etc/nginx/nginx.conf:\nhttp {}'),patch.object(manage,'reload_nginx'):
                result=manage.trust_cloudflare(self.root,config,hashlib.sha256(state.read_bytes()).hexdigest())
            self.assertEqual(result['mode'],wanted)

    def test_status_refuses_false_off_with_unmigrated_child_on(self):
        (self.root/'conf.d').mkdir()
        (self.root/'conf.d/site.conf').write_text('server { server_name one.example; modsecurity on; }',encoding='utf-8')
        (self.root/'nginx.conf').write_text('events {} http { # modsecurity on;\n}',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'conflicts'):
            manage.configured_status(self.root,{'mode':'off','sites':{}})


@unittest.skipUnless(os.name=='posix','POSIX ownership and symlink checks')
class DirectoryTrustTests(unittest.TestCase):
    def test_dangling_parent_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            parent=pathlib.Path(directory)/'parent'
            parent.symlink_to(pathlib.Path(directory)/'absent',target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'Unsafe parent'):manage.safe_parent(parent/'file')
