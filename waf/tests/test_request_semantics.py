import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import nginx_edit
import policy

class SemanticsTests(unittest.TestCase):
    def controls(self,body='',parent=''):
        return nginx_edit.static_resource_controls('# configuration file /etc/nginx/nginx.conf:\nhttp { '+parent+' server { server_name any.example; root /var/www/html/any; '+body+' }}')['any.example']

    def test_file_only_is_independent_of_application(self):
        self.assertEqual(self.controls('location / { try_files $uri =404; }'),'file-only')
        self.assertEqual(self.controls('location / { try_files $uri $uri/ /index.html; }'),'file-only')

    def test_public_templates_are_recognized(self):
        root=Path(__file__).resolve().parents[2]
        import re
        for template in ['nginx.conf','nginx10.conf']:
            main=(root/template).read_text()
            # Supply the complete include snapshot as nginx -T would. Managed
            # optional globs are absent on a fresh install; MIME data is passive.
            includes=re.findall(r'(?m)^\s*include\s+([^;]+);',main)
            files={'/etc/nginx/nginx.conf':main,'/etc/nginx/conf.d/example.conf':(root/'html.conf').read_text()}
            for target in includes:
                target=target.strip().strip('"\'')
                if not any(c in target for c in '*?['):
                    if not target.startswith('/'):target='/etc/nginx/'+target
                    files.setdefault(target,'')
            dump=''.join('# configuration file '+name+':\n'+body+'\n' for name,body in files.items())
            with self.subTest(template=template):self.assertEqual(nginx_edit.static_resource_controls(dump)['yuming.com'],'file-only')

    def test_dynamic_or_uncertain_handlers_never_inherit_static_exception(self):
        for body in ['location / { proxy_pass http://backend; }','location ~ \\.php$ { fastcgi_pass unix:/run/php; }',
                     'location / { try_files $uri /index.php; }','location / { alias /tmp; }',
                     'location / { custom_handler on; }','rewrite ^ /index.html last;',
                     'root $arg_root;','location / { js_content handler; }']:
            with self.subTest(body=body):self.assertNotEqual(self.controls(body),'file-only')

    def test_inherited_execution_and_unknown_modules_fail_closed(self):
        for parent in ['access_by_lua_file /test.lua;','rewrite_by_lua_block { return; }','custom_handler on;']:
            self.assertNotEqual(self.controls(parent=parent),'file-only')

    def test_conflicting_same_name_servers_fail_closed(self):
        dump='# configuration file /etc/nginx/nginx.conf:\nhttp { server { server_name any.example; root /var/www/html/any; } server { server_name any.example; root /var/www/html/any; location / {proxy_pass http://backend;} }}'
        self.assertNotEqual(nginx_edit.static_resource_controls(dump)['any.example'],'file-only')

    def test_unconfigured_file_site_gets_default_exception(self):
        config={'schemaVersion':1,'mode':'on','cdn':'direct','container':'nginx','sites':{}}
        rendered=policy.render_profile_rules(config,resource_controls={'any.example':'file-only'})
        self.assertIn('@beginsWith any.example|',rendered)
        self.assertIn('ruleRemoveTargetById=932260;REQUEST_FILENAME',rendered)
        self.assertNotIn('@beginsWith unsafe.example|',policy.render_profile_rules(config,resource_controls={'unsafe.example':'unsupported handler'}))

    def test_legacy_native_switch_does_not_change_file_capability(self):
        self.assertEqual(self.controls('modsecurity on; location / { modsecurity on; try_files $uri =404; }'),'file-only')

    def test_global_legacy_migration_uses_candidate_capability(self):
        main='http { modsecurity_rules_file /etc/nginx/modsec/modsecurity.conf; include /etc/nginx/conf.d/*.conf; }'
        site='server {server_name any.example;root /var/www/html/any;}'
        dump='# configuration file /etc/nginx/nginx.conf:\n'+main+'\n# configuration file /etc/nginx/conf.d/site.conf:\n'+site
        self.assertNotEqual(nginx_edit.static_resource_controls(dump)['any.example'],'file-only')
        replacements={'/etc/nginx/nginx.conf':nginx_edit.patch_main(main),'/etc/nginx/conf.d/site.conf':site}
        candidate=nginx_edit.candidate_configuration(dump,replacements)
        self.assertEqual(nginx_edit.static_resource_controls(candidate)['any.example'],'file-only')

    def test_include_glob_never_includes_nested_unloaded_handlers(self):
        dump='# configuration file /etc/nginx/nginx.conf:\nhttp {include /etc/nginx/conf.d/*.conf;}\n# configuration file /etc/nginx/conf.d/site.conf:\nserver {server_name any.example;root /var/www/html/any;}\n# configuration file /etc/nginx/conf.d/nested/unused.conf:\nserver {server_name any.example;location / {proxy_pass http://backend;}}'
        self.assertEqual(nginx_edit.static_resource_controls(dump)['any.example'],'file-only')

    def test_source_contract_validation_and_no_implicit_exemptions(self):
        base={'schemaVersion':1,'mode':'on','cdn':'direct','container':'nginx','sites':{'any.example':{'profile':'generic'}}}
        contract={'method':'POST','path':'/api/note','fields':['content']}
        self.assertNotIn('waf_source_',policy.render_profile_rules(base))
        for bad in [dict(contract,path='/.*'),dict(contract,method='GET'),dict(contract,fields=['a;deny']),dict(contract,fields=['content','content'])]:
            value=copy.deepcopy(base);value['sites']['any.example']['sourceText']=[bad]
            with self.assertRaises(ValueError):policy.validate(value)
        base['sites']['any.example']['sourceText']=[contract]
        policy.validate(base)
        self.assertIn('waf_source_',policy.render_profile_rules(base))

if __name__=='__main__':unittest.main()
