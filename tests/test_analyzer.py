
import unittest

from api_sentry.analyzer import analyze_spec


class TestAnalyzer(unittest.TestCase):
    def test_http_server_is_detected(self):
        findings = analyze_spec({
            "openapi": "3.0.3",
            "servers": [{"url": "http://example.test"}],
            "paths": {},
        })

        self.assertIn(
            "AS001",
            {finding.rule_id for finding in findings}
        )

    def test_missing_security_is_detected(self):
        findings = analyze_spec({
            "openapi": "3.0.3",
            "paths": {
                "/profile": {
                    "get": {
                        "responses": {
                            "200": {"description": "OK"}
                        }
                    }
                }
            }
        })

        rules = {finding.rule_id for finding in findings}
        self.assertIn("AS002", rules)
        self.assertIn("AS004", rules)

    def test_explicit_empty_security_is_detected(self):
        findings = analyze_spec({
            "openapi": "3.0.3",
            "security": [{"bearerAuth": []}],
            "paths": {
                "/public": {
                    "get": {
                        "security": [],
                        "responses": {
                            "200": {"description": "OK"}
                        }
                    }
                }
            }
        })

        self.assertIn(
            "AS003",
            {finding.rule_id for finding in findings}
        )


if __name__ == "__main__":
    unittest.main()
