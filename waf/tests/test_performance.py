import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from performance import assess


class ResponseValidationTests(unittest.TestCase):
    def fixture(self, codes, **extra):
        return dict(codes=codes, requests=sum(codes.values()), elapsedSeconds=10,
                    networkErrors=extra.get('networkErrors', 0), skipped=extra.get('skipped', 0))

    def test_business_denials_and_errors_never_count_as_success(self):
        for code in (403, 429, 500, 502):
            result = assess(self.fixture({200: 90, code: 10}), 'candidate', 'json')
            self.assertFalse(result['responseValidationPassed'])
            self.assertEqual(result['expectedRps'], 9)

    def test_only_explicit_limit_boundary_accepts_rate_denials(self):
        result = assess(self.fixture({'200': 500, '429': 100}), 'candidate', 'static', True)
        self.assertTrue(result['responseValidationPassed'])
        self.assertEqual(result['expectedRps'], 50)
        self.assertFalse(assess(self.fixture({200: 600}), 'candidate', 'static', True)['responseValidationPassed'])

    def test_disabled_engine_attack_is_baseline_not_a_protection_claim(self):
        self.assertTrue(assess(self.fixture({200: 100}), 'off', 'attack')['responseValidationPassed'])
        self.assertFalse(assess(self.fixture({200: 100}), 'candidate', 'attack')['responseValidationPassed'])
        self.assertTrue(assess(self.fixture({403: 100}), 'candidate', 'attack')['responseValidationPassed'])

    def test_missing_requests_and_network_failures_cannot_pass(self):
        for extra in ({'skipped': 1}, {'networkErrors': 1}):
            self.assertFalse(assess(self.fixture({200: 99}, **extra), 'candidate', 'static')['responseValidationPassed'])
        self.assertFalse(assess(self.fixture({}), 'candidate', 'static')['responseValidationPassed'])
