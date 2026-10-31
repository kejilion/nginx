import copy
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import policy


class PolicyTests(unittest.TestCase):
    def test_authenticated_application_profile_does_not_share_proxy_cache(self):
        self.assertNotIn('proxy_cache_bypass',policy.render_server())
        import hashlib
        self.config['sites']={'panel.example':{'profile':'kpanel'}}
        files=policy.bundle_files(self.config,policy.networks(json.loads((self.root/'cloudflare-ips.json').read_text())))
        hook=files['server-'+hashlib.sha256(b'panel.example').hexdigest()[:16]+'.inc']
        self.assertIn('proxy_cache_bypass $http_authorization $http_cookie;',hook)
        self.assertIn('proxy_no_cache $http_authorization $http_cookie;',hook)

    def test_kpanel_typed_rules_are_shared_without_cross_site_activation(self):
        self.config['sites']={f'panel{i}.example':{'profile':'kpanel'} for i in range(200)}
        text=policy.render_profile_rules(self.config)
        self.assertEqual(text.count('setvar:tx.waf_kpanel_profile=1'),200)
        self.assertLess(len(text.encode()),512*1024)
        self.assertEqual(text.count('ruleRemoveTargetByTag=attack-rce;ARGS:json.desktop.windows.array_0.path'),1)
        self.assertLess(text.rfind('setvar:tx.waf_kpanel_profile=1'),text.index('SecRule TX:waf_kpanel_profile'))
        self.assertIn('ARGS:json.frames.array_31.data',text)
        self.assertNotIn('ruleEngine=Off',text)
        self.assertNotIn('ctl:requestBodyAccess=Off',text)

    def test_full_off_keeps_the_native_global_switch_authoritative(self):
        config={'mode':'off','sites':{'wp.example':{'profile':'wordpress'}}}
        self.assertFalse(policy.engine_enabled(config))
        self.assertNotIn('ctl:ruleEngine=Off',policy.render_profile_rules(config))
        config['sites']['api.example']={'mode':'on'}
        self.assertTrue(policy.engine_enabled(config))
        self.assertIn('ctl:ruleEngine=Off',policy.render_profile_rules(config))

    def setUp(self):
        self.root = pathlib.Path(__file__).resolve().parents[1]
        self.config = json.loads((self.root / 'example-policy.json').read_text())
        self.cloudflare = policy.networks(json.loads((self.root / 'cloudflare-ips.json').read_text()))

    def test_official_ranges_have_both_families(self):
        self.assertTrue(any(':' in net for net in self.cloudflare))
        self.assertTrue(any('.' in net for net in self.cloudflare))

    def test_direct_never_trusts_headers(self):
        self.config['cdn'] = 'direct'
        self.assertNotIn('set_real_ip_from', policy.render_realip(self.config, self.cloudflare))

    def test_configuration_only_default_has_no_new_ban_or_authorization_backend(self):
        rendered='\n'.join(policy.bundle_files(self.config,self.cloudflare).values())
        self.assertNotIn('auth_request',rendered)
        self.assertNotIn('upstream waf',rendered)
        self.assertNotIn('unix:',rendered)
        self.assertNotIn('if ($waf_blocked)',rendered)
        self.config['banBackend']='existing'
        rendered='\n'.join(policy.bundle_files(self.config,self.cloudflare).values())
        self.assertIn('include /etc/nginx/conf.d/waf/blocked.map;',rendered)
        self.assertIn('if ($waf_blocked)',rendered)

    def test_incomplete_cloudflare_snapshot_is_rejected(self):
        data=json.loads((self.root/'cloudflare-ips.json').read_text())
        data['ipv6_cidrs']=[]
        with self.assertRaisesRegex(ValueError,'families'):policy.networks(data)

    def test_cloudflare_does_not_trust_arbitrary_docker_ranges(self):
        rendered = policy.render_realip(self.config, self.cloudflare)
        self.assertNotIn('172.0.0.0/8', rendered)
        self.assertNotIn('fd00::/8', rendered)
        self.assertIn('real_ip_recursive off', rendered)

    def test_explicit_custom_proxy(self):
        self.config.update(cdn='proxy', trustedProxies=['10.2.3.0/24'])
        policy.validate(self.config)
        rendered = policy.render_realip(self.config, self.cloudflare)
        self.assertIn('10.2.3.0/24', rendered)
        self.assertNotIn('CF-Connecting-IP', rendered)

    def test_broad_proxy_trust_rejected(self):
        for network in ['0.0.0.0/0', '172.0.0.0/8', 'fd00::/8', '::/0']:
            with self.subTest(network=network), self.assertRaises(ValueError):
                policy.validate(dict(self.config, cdn='proxy', trustedProxies=[network]))

    def test_mixed_chain_uses_authoritative_xff(self):
        self.config['trustedProxies'] = ['10.2.3.4/32']
        self.assertIn('real_ip_header X-Forwarded-For', policy.render_realip(self.config, self.cloudflare))

    def test_scope_and_ip_are_both_required(self):
        self.assertNotEqual(policy.key('one.example|1.1.1.1'), policy.key('two.example|1.1.1.1'))
        self.assertEqual(policy.key('one.example|2606:4700:4700:0::1111')[1], '2606:4700:4700::1111')

    def test_invalid_identity_cannot_inject_config(self):
        for value in ['one.example|1.1.1.1";include /tmp/bad', 'one.example|host.example', '../bad|1.1.1.1', 'one.example|1.1.1.1|x']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                policy.key(value)

    def test_private_and_proxy_addresses_not_banned(self):
        for address in ['127.0.0.1', '::1', '10.1.1.1', '104.16.0.1', '2606:4700::1']:
            self.assertFalse(policy.eligible(address, self.cloudflare), address)
        self.assertTrue(policy.eligible('8.8.8.8', self.cloudflare))

    def test_bans_expire_and_are_scoped(self):
        rendered = policy.render_bans({'one.example|8.8.8.8': {'expires': 200}, 'two.example|8.8.8.8': {'expires': 99}}, 100)
        self.assertIn('"one.example|8.8.8.8" 1;', rendered)
        self.assertNotIn('two.example', rendered)

    def test_unknown_fields_and_profiles_are_rejected(self):
        with self.assertRaises(ValueError):
            policy.validate(dict(self.config, accidentalBypass=True))
        self.config['sites'] = {'one.example': {'profile': 'everything-trusted'}}
        with self.assertRaises(ValueError):
            policy.validate(self.config)

    def test_exclusions_require_exact_path_and_one_argument(self):
        self.config['sites'] = {'one.example': {'exclusions': [{'ruleId': 942100, 'path': '/api/query', 'target': 'ARGS:query'}]}}
        policy.validate(self.config)
        rendered = policy.render_profile_rules(self.config)
        self.assertIn('@streq /api/query', rendered)
        self.assertIn('ruleRemoveTargetById=942100;ARGS:query', rendered)
        self.assertNotIn('ruleRemoveByTag', rendered)
        self.config['sites']['one.example']['exclusions'][0]['target'] = 'ARGS'
        with self.assertRaises(ValueError):
            policy.validate(self.config)

    def test_dot_guard_exclusion_is_exact_filename_only(self):
        entry={'ruleId':1110,'path':'/raw.example/repo/main/.env','target':'REQUEST_FILENAME'}
        self.config['sites']={'one.example':{'exclusions':[entry]}}
        policy.validate(self.config)
        rendered=policy.render_profile_rules(self.config)
        self.assertIn('REQUEST_URI_RAW "@rx ^/raw\\.example/repo/main/\\.env(?:[?].*)?$',rendered)
        self.assertIn('ruleRemoveTargetById=1110;REQUEST_FILENAME',rendered)
        self.assertNotIn('ruleRemoveById=1110',rendered)
        for field,value in [('ruleId',1111),('target','ARGS:file'),('path','/x/../.env'),('path','//.env'),('path','/x/%2eenv'),('path','/x/./.env'),('path','/例/.env')]:
            bad=dict(entry);bad[field]=value
            self.config['sites']['one.example']['exclusions']=[bad]
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):policy.validate(self.config)

    def test_no_global_business_path_blacklist_or_acme_bypass(self):
        rendered = policy.render_guard()
        for path in ['/feed', '/readme.html', '/xmlrpc.php', 'allow,', 'ruleEngine=Off']:
            self.assertNotIn(path, rendered)

    def test_unicode_filename_exclusion_keeps_exact_site_path_and_target(self):
        entry={'ruleId':932260,'path':'/category/docker-项目/','target':'REQUEST_FILENAME'}
        self.config['sites']={'one.example':{'exclusions':[entry]}}
        policy.validate(self.config)
        rendered=policy.render_profile_rules(self.config)
        self.assertIn('@beginsWith one.example|',rendered)
        self.assertIn('@streq /category/docker-项目/',rendered)
        self.assertIn('ruleRemoveTargetById=932260;REQUEST_FILENAME',rendered)
        self.assertIn('REQUEST_METHOD "@rx ^(?:GET|HEAD)$"',rendered)
        self.assertNotIn('ruleRemoveById=932260',rendered)
        for path in ['/bad"path','/bad\npath','/bad;path']:
            entry['path']=path
            with self.subTest(path=path),self.assertRaises(ValueError):policy.validate(self.config)

    def test_headroom_does_not_raise_crs_threshold(self):
        self.config.update(burst=400, connections=512)
        self.assertIn('inbound_anomaly_score_threshold=5', policy.render_profile_rules(self.config))
        self.assertIn('burst=400', policy.render_http(self.config))

    def test_early_blocking_keeps_scoring_and_auditable_rule_ids(self):
        rendered = policy.render_profile_rules(self.config)
        self.assertIn('setvar:tx.early_blocking=1', rendered)
        self.assertIn('inbound_anomaly_score_threshold=5', rendered)
        self.assertIn('outbound_anomaly_score_threshold=4', rendered)
        self.assertIn('949111', policy.render_filters()['waf-attack.conf'])

    def test_events_use_engine_signals_not_response_status(self):
        rendered = policy.render_http(self.config)
        self.assertIn('$limit_req_status:$limit_conn_status', rendered)
        # Optional access observability must not become a ban input.
        event_config='\n'.join(line for line in rendered.splitlines() if not line.startswith('log_format waf_protocol '))
        self.assertNotIn('$status', event_config)
        self.assertNotIn('$http_', event_config)
        self.assertIn('"upstream":"$upstream_status"',rendered)

    def test_method_compatibility_needs_proof_and_preserves_all_other_restrictions(self):
        self.assertIn('waf_method_override_guarded=0',policy.render_profile_rules(self.config))
        self.assertIn('waf_method_override_guarded=1',policy.render_profile_rules(self.config,(False,set())))
        self.config['sites']={'locked.example':{'methodOverride':'strict'}}
        rules=policy.render_profile_rules(self.config,(False,{'acl.example'}))
        self.assertIn('@beginsWith acl.example|',rules)
        self.assertIn('@beginsWith locked.example|',rules)
        guard=policy.render_method_override()
        self.assertNotIn('ruleRemoveById=920450',guard)
        self.assertNotIn('ruleEngine=Off',guard)
        self.assertIn('requires a compatible gateway policy',guard)
        self.assertNotIn('@within',guard)
        self.assertIn('])PATCH(?:[',guard)
        self.assertIn('phase:2',guard)
        self.config['methodOverride']='off'
        with self.assertRaisesRegex(ValueError,'method override'):policy.validate(self.config)

    def test_method_compatibility_preserves_vendor_wildcard_and_removes_only_header_name_targets(self):
        rendered=policy.render_modsecurity(self.config)
        self.assertIn('Include /etc/nginx/modsec/rules/*.conf',rendered)
        self.assertIn('SecRuleUpdateTargetById 920450 "!REQUEST_HEADERS_NAMES:',rendered)
        self.assertNotIn('ruleRemoveById=920450',rendered)

    def test_bounded_resources(self):
        for field, value in [('connections', 100000), ('burst', 0), ('attackRetries', 1), ('banSeconds', 999999)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                policy.validate(dict(self.config, **{field: value}))

    def test_body_parser_errors_remain_denied_without_duplicate_full_logs(self):
        rendered=policy.render_modsecurity(self.config)
        rule=next(line for line in rendered.splitlines() if 'id:200002,' in line)
        self.assertIn('deny,status:400,nolog',rule)
        self.assertIn('SecRequestBodyAccess On',rendered)
        self.assertIn('SecAuditLogRelevantStatus "^403$"',rendered)
        self.assertIn('ctl:auditEngine=On',rendered)


if __name__ == '__main__':
    unittest.main()
