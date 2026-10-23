import copy
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import policy


class PolicyTests(unittest.TestCase):
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

    def test_no_global_business_path_blacklist_or_acme_bypass(self):
        rendered = policy.render_guard()
        for path in ['/feed', '/readme.html', '/xmlrpc.php', 'allow,', 'ruleEngine=Off']:
            self.assertNotIn(path, rendered)

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
        self.assertNotIn('$status', rendered)
        self.assertNotIn('$http_', rendered)

    def test_bounded_resources(self):
        for field, value in [('connections', 100000), ('burst', 0), ('attackRetries', 1), ('banSeconds', 999999)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                policy.validate(dict(self.config, **{field: value}))


if __name__ == '__main__':
    unittest.main()
