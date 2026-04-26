#!/usr/bin/env python3
"""
Unit tests for API Hardening Checker.
"""
import json
import sys
import unittest
from datetime import datetime
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from api_hardening import APIHardeningChecker, APIHardeningResult


class TestAPIHardeningResult(unittest.TestCase):
    """Tests for APIHardeningResult dataclass."""

    def test_result_creation(self):
        """Test creating a result object."""
        result = APIHardeningResult(
            endpoint="https://api.example.com",
            is_hardened=True,
            security_score=85,
            issues=[],
            recommendations=[],
            headers_present={"x-content-type-options": True},
            tls_verified=True,
            timestamp="2026-04-26T18:00:00Z"
        )
        self.assertEqual(result.endpoint, "https://api.example.com")
        self.assertTrue(result.is_hardened)
        self.assertEqual(result.security_score, 85)


class TestAPIHardeningCheckerInit(unittest.TestCase):
    """Tests for APIHardeningChecker initialization."""

    def test_default_init(self):
        """Test default initialization."""
        checker = APIHardeningChecker()
        self.assertEqual(checker.config, {})
        self.assertEqual(len(checker.required_headers), 4)

    def test_custom_config(self):
        """Test initialization with custom config."""
        config = {"timeout": 30}
        checker = APIHardeningChecker(config)
        self.assertEqual(checker.config, config)

    def test_security_checks_initialized(self):
        """Test that all security checks are initialized."""
        checker = APIHardeningChecker()
        self.assertIn("tls", checker.security_checks)
        self.assertIn("headers", checker.security_checks)
        self.assertIn("rate_limiting", checker.security_checks)
        self.assertIn("auth", checker.security_checks)
        self.assertIn("cors", checker.security_checks)
        self.assertIn("input_validation", checker.security_checks)


class TestAPICheckTLS(unittest.TestCase):
    """Tests for TLS checking."""

    def test_https_endpoint(self):
        """Test HTTPS endpoint passes TLS check."""
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com")
        self.assertTrue(result.tls_verified)
        # HTTPS with empty config still gets deductions for missing headers/auth/etc
        self.assertLess(result.security_score, 100)
        self.assertGreaterEqual(result.security_score, 0)
        self.assertTrue(any(i["type"] == "missing_header" for i in result.issues))

    def test_http_endpoint(self):
        """Test HTTP endpoint fails TLS check."""
        checker = APIHardeningChecker()
        result = checker.check("http://api.example.com")
        self.assertFalse(result.tls_verified)
        self.assertTrue(any(i["type"] == "insecure_transport" for i in result.issues))
        self.assertIn("Migrate to HTTPS immediately", result.recommendations)

    def test_non_url_endpoint(self):
        """Test non-URL endpoint defaults to TLS verified."""
        checker = APIHardeningChecker()
        result = checker.check("my-api-service")
        self.assertTrue(result.tls_verified)


class TestAPICheckHeaders(unittest.TestCase):
    """Tests for security headers checking."""

    def test_all_headers_present(self):
        """Test that all required headers present increases score."""
        config = {
            "headers": {
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'"
            }
        }
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", config)
        # All headers present so no missing_header issues
        self.assertFalse(any(i["type"] == "missing_header" for i in result.issues))
        # But still deductions for other missing controls
        self.assertLess(result.security_score, 100)

    def test_missing_headers(self):
        """Test missing headers are detected."""
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", {})
        missing_headers = [i for i in result.issues if i["type"] == "missing_header"]
        self.assertEqual(len(missing_headers), 4)

    def test_partial_headers(self):
        """Test with some headers present."""
        config = {"headers": {"x-content-type-options": "nosniff"}}
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", config)
        missing_headers = [i for i in result.issues if i["type"] == "missing_header"]
        self.assertEqual(len(missing_headers), 3)


class TestAPICheckRateLimiting(unittest.TestCase):
    """Tests for rate limiting checks."""

    def test_no_rate_limiting(self):
        """Test detection of missing rate limiting."""
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", {})
        self.assertTrue(any(i["type"] == "no_rate_limiting" for i in result.issues))
        self.assertIn("Implement rate limiting (requests/minute)", result.recommendations)

    def test_disabled_rate_limiting(self):
        """Test detection of disabled rate limiting."""
        config = {"rate_limiting": {"enabled": False}}
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", config)
        self.assertTrue(any(i["type"] == "rate_limiting_disabled" for i in result.issues))

    def test_enabled_rate_limiting(self):
        """Test enabled rate limiting passes."""
        config = {"rate_limiting": {"enabled": True, "requests_per_minute": 100}}
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", config)
        self.assertFalse(any(i["type"] == "no_rate_limiting" for i in result.issues))
        self.assertFalse(any(i["type"] == "rate_limiting_disabled" for i in result.issues))


class TestAPICheckAuthentication(unittest.TestCase):
    """Tests for authentication checks."""

    def test_no_authentication(self):
        """Test detection of missing authentication."""
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", {})
        self.assertTrue(any(i["type"] == "no_authentication" for i in result.issues))
        self.assertIn("Implement API key authentication", result.recommendations)

    def test_disabled_authentication(self):
        """Test detection of disabled authentication."""
        config = {"authentication": {"enabled": False}}
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", config)
        self.assertTrue(any(i["type"] == "auth_disabled" for i in result.issues))

    def test_enabled_authentication(self):
        """Test enabled authentication passes."""
        config = {"authentication": {"enabled": True, "type": "api_key"}}
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", config)
        self.assertFalse(any(i["type"] == "no_authentication" for i in result.issues))


class TestAPICheckCORS(unittest.TestCase):
    """Tests for CORS checks."""

    def test_no_cors_policy(self):
        """Test detection of missing CORS policy."""
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", {})
        self.assertTrue(any(i["type"] == "no_cors_policy" for i in result.issues))

    def test_wildcard_cors(self):
        """Test detection of wildcard CORS origin."""
        config = {"cors": {"allow_origins": "*"}}
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", config)
        self.assertTrue(any(i["type"] == "wildcard_cors" for i in result.issues))
        self.assertIn("Remove wildcard CORS origin", result.recommendations)

    def test_restricted_cors(self):
        """Test restricted CORS passes."""
        config = {"cors": {"allow_origins": ["https://app.example.com"]}}
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", config)
        self.assertFalse(any(i["type"] == "wildcard_cors" for i in result.issues))


class TestAPICheckInputValidation(unittest.TestCase):
    """Tests for input validation checks."""

    def test_no_input_validation(self):
        """Test detection of missing input validation."""
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", {})
        self.assertTrue(any(i["type"] == "no_input_validation" for i in result.issues))
        self.assertIn("Implement input length limits and sanitization", result.recommendations)

    def test_enabled_input_validation(self):
        """Test enabled input validation passes."""
        config = {"input_validation": {"enabled": True, "max_input_length": 4096}}
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", config)
        self.assertFalse(any(i["type"] == "no_input_validation" for i in result.issues))


class TestAPICheckDebugMode(unittest.TestCase):
    """Tests for debug mode checks."""

    def test_debug_enabled(self):
        """Test detection of debug mode in production."""
        config = {"debug_mode": True}
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", config)
        self.assertTrue(any(i["type"] == "debug_enabled" for i in result.issues))
        self.assertIn("Disable debug/verbose mode", result.recommendations)

    def test_debug_disabled(self):
        """Test debug disabled passes."""
        config = {"debug_mode": False}
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", config)
        self.assertFalse(any(i["type"] == "debug_enabled" for i in result.issues))


class TestAPICheckAuditLogging(unittest.TestCase):
    """Tests for audit logging checks."""

    def test_no_audit_logging(self):
        """Test detection of missing audit logging."""
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", {})
        self.assertTrue(any(i["type"] == "no_audit_logging" for i in result.issues))
        self.assertIn("Enable security audit logging", result.recommendations)

    def test_audit_logging_enabled(self):
        """Test enabled audit logging passes."""
        config = {"audit_logging": True}
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", config)
        self.assertFalse(any(i["type"] == "no_audit_logging" for i in result.issues))


class TestAPIIsHardened(unittest.TestCase):
    """Tests for is_hardened determination."""

    def test_fully_hardened(self):
        """Test fully hardened endpoint."""
        config = {
            "headers": {
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'"
            },
            "rate_limiting": {"enabled": True},
            "authentication": {"enabled": True, "type": "api_key"},
            "cors": {"allow_origins": ["https://app.example.com"]},
            "input_validation": {"enabled": True},
            "audit_logging": True
        }
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", config)
        self.assertTrue(result.is_hardened)
        self.assertEqual(result.security_score, 100)

    def test_not_hardened_low_score(self):
        """Test endpoint with low security score."""
        checker = APIHardeningChecker()
        result = checker.check("http://api.example.com", {})
        self.assertFalse(result.is_hardened)

    def test_not_hardened_critical_issue(self):
        """Test endpoint with critical issue."""
        checker = APIHardeningChecker()
        result = checker.check("http://api.example.com", {})
        self.assertFalse(result.is_hardened)


class TestAPIHelperMethods(unittest.TestCase):
    """Tests for helper methods."""

    def test_get_header_recommendation(self):
        """Test getting header recommendations."""
        checker = APIHardeningChecker()
        rec = checker._get_header_recommendation("x-content-type-options")
        self.assertIn("nosniff", rec)

    def test_get_header_recommendation_unknown(self):
        """Test recommendation for unknown header."""
        checker = APIHardeningChecker()
        rec = checker._get_header_recommendation("unknown-header")
        self.assertIn("unknown-header", rec)

    def test_check_tls_method(self):
        """Test _check_tls method."""
        checker = APIHardeningChecker()
        self.assertTrue(checker._check_tls("https://api.example.com"))
        self.assertFalse(checker._check_tls("http://api.example.com"))

    def test_check_security_headers(self):
        """Test _check_security_headers method."""
        checker = APIHardeningChecker()
        headers = {
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'"
        }
        self.assertTrue(checker._check_security_headers(headers))
        self.assertFalse(checker._check_security_headers({}))

    def test_check_rate_limiting(self):
        """Test _check_rate_limiting method."""
        checker = APIHardeningChecker()
        self.assertTrue(checker._check_rate_limiting({"rate_limiting": {"enabled": True, "requests_per_minute": 100}}))
        self.assertFalse(checker._check_rate_limiting({}))

    def test_check_authentication(self):
        """Test _check_authentication method."""
        checker = APIHardeningChecker()
        self.assertTrue(checker._check_authentication({"authentication": {"enabled": True, "type": "api_key"}}))
        self.assertFalse(checker._check_authentication({}))

    def test_check_cors(self):
        """Test _check_cors method."""
        checker = APIHardeningChecker()
        self.assertTrue(checker._check_cors({"cors": {"allow_origins": ["https://app.example.com"]}}))
        self.assertFalse(checker._check_cors({"cors": {"allow_origins": "*"}}))
        self.assertFalse(checker._check_cors({}))

    def test_check_input_validation(self):
        """Test _check_input_validation method."""
        checker = APIHardeningChecker()
        self.assertTrue(checker._check_input_validation({"input_validation": {"enabled": True, "max_input_length": 100}}))
        self.assertFalse(checker._check_input_validation({}))

    def test_get_timestamp(self):
        """Test timestamp generation."""
        checker = APIHardeningChecker()
        ts = checker._get_timestamp()
        self.assertTrue(ts.endswith("Z"))
        # Should be parseable
        datetime.strptime(ts.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S.%f%z")


class TestAPICheckMultiple(unittest.TestCase):
    """Tests for check_multiple method."""

    def test_check_multiple_endpoints(self):
        """Test checking multiple endpoints."""
        checker = APIHardeningChecker()
        endpoints = [
            {"url": "https://api1.example.com", "config": {"authentication": {"enabled": True}}},
            {"url": "https://api2.example.com", "config": {"authentication": {"enabled": False}}}
        ]
        results = checker.check_multiple(endpoints)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].endpoint, "https://api1.example.com")
        self.assertEqual(results[1].endpoint, "https://api2.example.com")

    def test_check_multiple_empty(self):
        """Test checking empty endpoint list."""
        checker = APIHardeningChecker()
        results = checker.check_multiple([])
        self.assertEqual(len(results), 0)


class TestAPIMain(unittest.TestCase):
    """Tests for main() CLI entry point."""

    @patch("builtins.open", mock_open(read_data='{"authentication": {"enabled": true}}'))
    @patch("json.load")
    def test_main_json_output(self, mock_json_load):
        """Test main with JSON output."""
        mock_json_load.return_value = {"authentication": {"enabled": True}}
        captured = StringIO()
        with patch("sys.stdout", captured):
            with patch("sys.argv", ["api_hardening.py", "https://api.example.com", "--config", "config.json", "--json"]):
                with patch.object(APIHardeningChecker, "check", return_value=APIHardeningResult(
                    endpoint="https://api.example.com", is_hardened=True, security_score=100,
                    issues=[], recommendations=[], headers_present={}, tls_verified=True,
                    timestamp="2026-04-26T18:00:00Z"
                )):
                    from src import api_hardening
                    api_hardening.main()
        output = captured.getvalue()
        self.assertIn("https://api.example.com", output)


class TestAPIScoreBounds(unittest.TestCase):
    """Tests for score boundary conditions."""

    def test_score_never_negative(self):
        """Test that security score never goes below 0."""
        checker = APIHardeningChecker()
        # Apply every possible deduction
        config = {
            "debug_mode": True,
            "cors": {"allow_origins": "*"}
        }
        result = checker.check("http://api.example.com", config)
        self.assertGreaterEqual(result.security_score, 0)

    def test_score_max_100(self):
        """Test that security score maxes at 100."""
        config = {
            "headers": {
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'"
            },
            "rate_limiting": {"enabled": True},
            "authentication": {"enabled": True, "type": "api_key"},
            "cors": {"allow_origins": ["https://app.example.com"]},
            "input_validation": {"enabled": True},
            "audit_logging": True
        }
        checker = APIHardeningChecker()
        result = checker.check("https://api.example.com", config)
        self.assertEqual(result.security_score, 100)


if __name__ == "__main__":
    unittest.main()
