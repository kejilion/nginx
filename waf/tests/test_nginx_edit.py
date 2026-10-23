import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import nginx_edit


class ApplicationBoundaryTests(unittest.TestCase):
    def test_identity_and_event_logging_survive_child_overrides(self):
        original = 'server { server_name one.example;\nlocation / { access_log off; proxy_set_header Host $host; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; proxy_pass http://app; }\n}'
        changed = nginx_edit.patch_application(original)
        self.assertNotIn('access_log off', changed)
        self.assertIn('waf/access-log*.inc', changed)
        self.assertNotIn('$proxy_add_x_forwarded_for', changed)
        self.assertIn('proxy_set_header X-Real-IP $remote_addr;', changed)
        self.assertEqual(changed, nginx_edit.patch_application(changed))

    def test_existing_application_log_is_preserved(self):
        changed = nginx_edit.patch_application('server { access_log /log/app.log combined; location / { proxy_pass http://app; } }')
        self.assertIn('access_log /log/app.log combined;', changed)
        self.assertEqual(changed.count('waf/access-log*.inc'), 1)


class NginxEditTests(unittest.TestCase):
    def test_two_servers_comments_and_nested_locations(self):
        text = '''# server { ignored }
upstream demo { server 127.0.0.1:8000; }
server {
  server_name one.example www.one.example;
  location ~ "^/a/[a-z]{2}/$" { add_header Cache-Control "public; max-age=1"; }
}
server { server_name two.example; if ($scheme = http) { return 301 https://$host$request_uri; } }
'''
        self.assertEqual(nginx_edit.site_scopes(text), ['one.example', 'two.example'])
        updated = nginx_edit.patch_site(text, {'sites': {}})
        self.assertEqual(updated.count('server-default*.inc;'), 2)
        self.assertIn('Cache-Control "public; max-age=1"', updated)

    def test_site_patch_is_idempotent(self):
        text = 'server {\n    server_name one.example;\n    root /a;\n}\n'
        first = nginx_edit.patch_site(text, {'sites': {}})
        self.assertEqual(nginx_edit.patch_site(first, {'sites': {}}), first)

    def test_custom_cdn_has_one_scoped_hook(self):
        text = 'server { server_name one.example; }\nserver { server_name two.example; }\n'
        updated = nginx_edit.patch_site(text, {'sites': {'one.example': {'cdn': 'direct'}}})
        self.assertEqual(updated.count('server-default*.inc;'), 1)
        self.assertEqual(updated.count('/waf/server-'), 2)

    def test_drop_only_catchall_is_preserved(self):
        text = 'server { server_name _; return 444; }\n'
        self.assertEqual(nginx_edit.patch_site(text, {'sites': {}}), text)

    def test_unknown_server_name_fails_closed(self):
        with self.assertRaises(ValueError):
            nginx_edit.patch_site('server { server_name ~^api\\d+\\.example$; }', {'sites': {}})

    def test_main_patch_removes_only_known_legacy_limits(self):
        text = '''load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;
events {}
http {
 modsecurity on;
 modsecurity_rules_file /etc/nginx/modsec/modsecurity.conf;
 limit_req_zone $binary_remote_addr zone=example_zone:50m rate=50r/s;
 limit_req zone=example_zone burst=150 nodelay;
 limit_conn_zone $binary_remote_addr zone=addr:20m;
 limit_conn addr 200;
 limit_req zone=custom_login burst=10;
}
'''
        updated = nginx_edit.patch_main(text)
        self.assertNotIn('zone=example_zone', updated)
        self.assertIn('zone=custom_login', updated)
        self.assertEqual(nginx_edit.patch_main(updated), updated)

    def test_legacy_default_migration(self):
        text = 'server { server_name _; return 444; }\n# Old trust\nset_real_ip_from 172.0.0.0/8;\nreal_ip_header CF-Connecting-IP;\n'
        self.assertNotIn('set_real_ip_from', nginx_edit.strip_legacy_default_realip(text))
        with self.assertRaises(ValueError):
            nginx_edit.strip_legacy_default_realip(text + 'map $x $y { default 1; }\n')


if __name__ == '__main__':
    unittest.main()
