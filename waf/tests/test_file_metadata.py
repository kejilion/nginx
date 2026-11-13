import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import policy


class FileMetadataPolicyTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((Path(policy.__file__).parent / 'example-policy.json').read_text())
        self.contract = {'method': 'POST', 'path': '/api/upload-meta', 'fields': ['file.name']}
        self.config['sites'] = {'files.example': {'fileMetadata': [self.contract]}}

    def test_arbitrary_application_can_declare_literal_filename_contract(self):
        policy.validate(self.config)
        rendered = policy.render_profile_rules(self.config)
        self.assertIn('@beginsWith files.example|', rendered)
        self.assertIn('ruleRemoveTargetById=942100;ARGS:json.file.name', rendered)
        self.assertIn('SecRule REQBODY_PROCESSOR "@streq JSON"', rendered)
        self.assertNotIn('ruleRemoveById=942100', rendered)
        self.assertNotIn('ruleRemoveTargetByTag=attack-sqli;ARGS:json.file.name', rendered)

    def test_no_field_name_or_application_name_implies_trust(self):
        self.config['sites'] = {'files.example': {}}
        self.assertNotIn('waf_filename_', policy.render_profile_rules(self.config))

    def test_configuration_cannot_inject_waf_targets_or_routes(self):
        for field, value in [('method', 'GET'), ('path', '/api/.*'), ('path', '/api//upload'),
                             ('fields', ['file.*']), ('fields', ['name;REQUEST_BODY']),
                             ('fields', ['file.name', 'file.name']), ('fields', []),
                             ('fields', ['field' + str(i) for i in range(9)])]:
            with self.subTest(field=field, value=value):
                config = copy.deepcopy(self.config)
                config['sites']['files.example']['fileMetadata'][0][field] = value
                with self.assertRaises(ValueError):
                    policy.validate(config)

    def test_source_and_filename_contracts_share_bounded_global_budget(self):
        self.config['sites'] = {f's{i}.example': {'sourceText': [copy.deepcopy(self.contract)],
                                                'fileMetadata': [copy.deepcopy(self.contract)]}
                                for i in range(129)}
        with self.assertRaisesRegex(ValueError, 'budget'):
            policy.validate(self.config)

    def test_kpanel_filename_rules_are_shared_across_sites(self):
        self.config['sites'] = {f'panel{i}.example': {'profile': 'kpanel'} for i in range(200)}
        rendered = policy.render_profile_rules(self.config)
        self.assertEqual(rendered.count('ruleRemoveTargetById=942100;ARGS:json.input.name'), 2)
        self.assertEqual(rendered.count('ruleRemoveTargetById=942100;ARGS:json.name'), 1)


if __name__ == '__main__':
    unittest.main()
