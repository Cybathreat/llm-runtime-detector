#!/usr/bin/env python3
"""
LLM API Endpoint Hardening Checker
Validates security configurations for LLM API deployments.
"""

import re
import json
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class APIHardeningResult:
    """Result of API hardening check."""
    endpoint: str
    is_hardened: bool
    security_score: int
    issues: List[Dict[str, Any]]
    recommendations: List[str]
    headers_present: Dict[str, bool]
    tls_verified: bool
    timestamp: str


class APIHardeningChecker:
    """Checks LLM API endpoints for security hardening."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.required_headers = [
            'x-content-type-options',
            'x-frame-options',
            'strict-transport-security',
            'content-security-policy',
        ]
        self.security_checks = self._init_security_checks()

    def _init_security_checks(self) -> Dict[str, callable]:
        """Initialize security check functions."""
        return {
            'tls': self._check_tls,
            'headers': self._check_security_headers,
            'rate_limiting': self._check_rate_limiting,
            'auth': self._check_authentication,
            'cors': self._check_cors,
            'input_validation': self._check_input_validation,
        }

    def check(self, endpoint: str, config: Optional[Dict] = None) -> APIHardeningResult:
        """
        Check API endpoint for security hardening.

        Args:
            endpoint: API endpoint URL or identifier
            config: Optional endpoint configuration dict

        Returns:
            APIHardeningResult with security assessment
        """
        issues = []
        recommendations = []
        headers_present = {}
        security_score = 100

        config = config or {}

        # Parse endpoint
        parsed = urlparse(endpoint) if endpoint.startswith('http') else None
        tls_verified = parsed is None or parsed.scheme == 'https'

        if not tls_verified:
            issues.append({
                "type": "insecure_transport",
                "severity": "critical",
                "message": "API endpoint uses HTTP instead of HTTPS",
                "recommendation": "Enable TLS/HTTPS for all API endpoints"
            })
            security_score -= 25
            recommendations.append("Migrate to HTTPS immediately")

        # Check security headers
        headers = config.get('headers', {})
        for header in self.required_headers:
            present = header.lower() in [h.lower() for h in headers.keys()]
            headers_present[header] = present
            if not present:
                issues.append({
                    "type": "missing_header",
                    "severity": "medium",
                    "message": f"Missing security header: {header}",
                    "recommendation": self._get_header_recommendation(header)
                })
                security_score -= 5
                recommendations.append(f"Add {header} header")

        # Check rate limiting
        rate_limit = config.get('rate_limiting')
        if not rate_limit:
            issues.append({
                "type": "no_rate_limiting",
                "severity": "high",
                "message": "No rate limiting configured",
                "recommendation": "Implement rate limiting to prevent DoS and abuse"
            })
            security_score -= 15
            recommendations.append("Implement rate limiting (requests/minute)")
        elif rate_limit.get('enabled', False):
            headers_present['rate_limiting'] = True
        else:
            issues.append({
                "type": "rate_limiting_disabled",
                "severity": "medium",
                "message": "Rate limiting is configured but disabled",
                "recommendation": "Enable rate limiting"
            })
            security_score -= 10

        # Check authentication
        auth = config.get('authentication')
        if not auth:
            issues.append({
                "type": "no_authentication",
                "severity": "critical",
                "message": "No authentication configured",
                "recommendation": "Require API key or token authentication"
            })
            security_score -= 20
            recommendations.append("Implement API key authentication")
        elif not auth.get('enabled', False):
            issues.append({
                "type": "auth_disabled",
                "severity": "high",
                "message": "Authentication is configured but disabled",
                "recommendation": "Enable authentication"
            })
            security_score -= 15
        else:
            headers_present['authentication'] = True

        # Check CORS
        cors = config.get('cors')
        if not cors:
            issues.append({
                "type": "no_cors_policy",
                "severity": "medium",
                "message": "No CORS policy configured",
                "recommendation": "Configure restrictive CORS policy"
            })
            security_score -= 5
            recommendations.append("Set explicit CORS origins")
        elif cors.get('allow_origins') == '*':
            issues.append({
                "type": "wildcard_cors",
                "severity": "high",
                "message": "CORS allows all origins (wildcard)",
                "recommendation": "Restrict CORS to specific trusted origins"
            })
            security_score -= 10
            recommendations.append("Remove wildcard CORS origin")
        else:
            headers_present['cors'] = True

        # Check input validation
        input_val = config.get('input_validation')
        if not input_val:
            issues.append({
                "type": "no_input_validation",
                "severity": "high",
                "message": "No input validation configured",
                "recommendation": "Validate and sanitize all user inputs"
            })
            security_score -= 15
            recommendations.append("Implement input length limits and sanitization")
        else:
            headers_present['input_validation'] = True

        # Check for debug mode
        if config.get('debug_mode', False):
            issues.append({
                "type": "debug_enabled",
                "severity": "high",
                "message": "Debug mode is enabled in production",
                "recommendation": "Disable debug mode in production environments"
            })
            security_score -= 10
            recommendations.append("Disable debug/verbose mode")

        # Check logging/audit
        if not config.get('audit_logging'):
            issues.append({
                "type": "no_audit_logging",
                "severity": "medium",
                "message": "No audit logging configured",
                "recommendation": "Enable request/response logging for security auditing"
            })
            security_score -= 5
            recommendations.append("Enable security audit logging")

        # Ensure score doesn't go below 0
        security_score = max(0, security_score)

        is_hardened = security_score >= 80 and len([i for i in issues if i.get('severity') == 'critical']) == 0

        return APIHardeningResult(
            endpoint=endpoint,
            is_hardened=is_hardened,
            security_score=security_score,
            issues=issues,
            recommendations=list(set(recommendations)),
            headers_present=headers_present,
            tls_verified=tls_verified,
            timestamp=self._get_timestamp()
        )

    def _get_header_recommendation(self, header: str) -> str:
        """Get recommendation for security header."""
        recommendations = {
            'x-content-type-options': "Set to 'nosniff' to prevent MIME sniffing",
            'x-frame-options': "Set to 'DENY' or 'SAMEORIGIN' to prevent clickjacking",
            'strict-transport-security': "Set with max-age >= 31536000 and includeSubDomains",
            'content-security-policy': "Define restrictive policy for script/content sources",
        }
        return recommendations.get(header, f"Configure {header} header")

    def _check_tls(self, endpoint: str) -> bool:
        """Check TLS configuration."""
        parsed = urlparse(endpoint)
        return parsed.scheme == 'https' if parsed else False

    def _check_security_headers(self, headers: Dict) -> bool:
        """Check security headers presence."""
        return all(h.lower() in [k.lower() for k in headers.keys()] for h in self.required_headers)

    def _check_rate_limiting(self, config: Dict) -> bool:
        """Check rate limiting configuration."""
        rl = config.get('rate_limiting', {})
        return rl.get('enabled', False) and rl.get('requests_per_minute', 0) > 0

    def _check_authentication(self, config: Dict) -> bool:
        """Check authentication configuration."""
        auth = config.get('authentication', {})
        return auth.get('enabled', False) and auth.get('type') in ['api_key', 'oauth', 'jwt']

    def _check_cors(self, config: Dict) -> bool:
        """Check CORS configuration."""
        cors = config.get('cors', {})
        origins = cors.get('allow_origins', [])
        return origins and origins != '*' and len(origins) < 10

    def _check_input_validation(self, config: Dict) -> bool:
        """Check input validation configuration."""
        iv = config.get('input_validation', {})
        return iv.get('enabled', False) and iv.get('max_input_length', 0) > 0

    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime
        return datetime.utcnow().isoformat() + 'Z'

    def check_multiple(self, endpoints: List[Dict]) -> List[APIHardeningResult]:
        """Check multiple endpoints."""
        results = []
        for ep in endpoints:
            result = self.check(ep.get('url', ep.get('endpoint', '')), ep.get('config'))
            results.append(result)
        return results


def main():
    """CLI entry point for API hardening checker."""
    import argparse
    parser = argparse.ArgumentParser(description="API Hardening Checker")
    parser.add_argument("endpoint", help="API endpoint URL")
    parser.add_argument("--config", help="JSON config file")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    config = {}
    if args.config:
        with open(args.config, 'r') as f:
            config = json.load(f)

    checker = APIHardeningChecker()
    result = checker.check(args.endpoint, config)
    output = asdict(result)

    if args.json:
        print(json.dumps(output, indent=2))
    else:
        _print_result(output)


def _print_result(result: Dict):
    """Print result in human-readable format."""
    status = "✓ HARDENED" if result.get('is_hardened') else "✗ NOT HARDENED"
    print(f"Endpoint: {result.get('endpoint')}")
    print(f"Status: {status}")
    print(f"Security Score: {result.get('security_score')}/100")
    print(f"TLS Verified: {result.get('tls_verified')}")
    if result.get('issues'):
        print("\nSecurity Issues:")
        for issue in result['issues']:
            print(f"  [{issue.get('severity').upper()}] {issue.get('type')}: {issue.get('message')}")
    if result.get('recommendations'):
        print("\nRecommendations:")
        for rec in result['recommendations']:
            print(f"  - {rec}")


if __name__ == "__main__":
    main()
