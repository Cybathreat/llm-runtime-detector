#!/usr/bin/env python3
"""
Report Generator
Generates JSON and Markdown security reports.
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Union
from pathlib import Path


class ReportGenerator:
    """Generates security scan reports in multiple formats."""

    def __init__(self):
        self.timestamp = datetime.utcnow().isoformat() + 'Z'

    def generate_json(self, results: Union[Dict, List]) -> str:
        """Generate JSON report."""
        report = {
            'report_type': 'llm_runtime_security_scan',
            'generated_at': self.timestamp,
            'version': '0.1.0',
            'results': self._serialize_results(results)
        }
        return json.dumps(report, indent=2, default=str)

    def generate_markdown(self, results: Union[Dict, List]) -> str:
        """Generate Markdown report."""
        md = []
        md.append("# LLM Runtime Security Scan Report")
        md.append("")
        md.append(f"**Generated:** {self.timestamp}")
        md.append(f"**Tool Version:** 0.1.0")
        md.append("")
        md.append("---")
        md.append("")

        if isinstance(results, dict):
            # Full scan results
            for scan_type, scan_results in results.items():
                md.extend(self._format_scan_section(scan_type, scan_results))
        elif isinstance(results, list):
            # Single scan type results
            if len(results) > 0 and hasattr(results[0], '__class__'):
                scan_type = results[0].__class__.__name__.replace('Result', '').lower().replace('_', ' ')
            else:
                scan_type = 'security_scan'
            md.extend(self._format_scan_section(scan_type, results))

        md.append("")
        md.append("---")
        md.append("")
        md.append("## Summary")
        md.append("")
        md.append(self._generate_summary(results))

        return '\n'.join(md)

    def _format_scan_section(self, scan_type: str, results: List) -> List[str]:
        """Format a scan section for Markdown."""
        lines = []
        lines.append(f"## {scan_type.replace('_', ' ').title()}")
        lines.append("")

        for i, result in enumerate(results):
            result_dict = self._to_dict(result)
            
            lines.append(f"### Scan {i + 1}")
            lines.append("")
            
            # Status
            status = "✓ PASS" if self._is_safe(result_dict) else "✗ FAIL"
            lines.append(f"**Status:** {status}")
            lines.append("")
            
            # Key metrics
            for key, value in result_dict.items():
                if key in ['model_path', 'endpoint', 'input_text']:
                    lines.append(f"**{key.replace('_', ' ').title()}:** {value}")
                elif key in ['is_safe', 'attack_detected', 'is_hardened', 'integrity_verified']:
                    lines.append(f"**{key.replace('_', ' ').title()}:** {value}")
                elif key in ['security_score', 'confidence']:
                    lines.append(f"**{key.replace('_', ' ').title()}:** {value}")
            
            lines.append("")
            
            # Issues
            if result_dict.get('issues') or result_dict.get('anomalies') or result_dict.get('flagged_patterns'):
                issues = result_dict.get('issues') or result_dict.get('anomalies') or result_dict.get('flagged_patterns')
                lines.append("**Issues Found:**")
                lines.append("")
                for issue in issues:
                    severity = issue.get('severity', 'unknown').upper()
                    issue_type = issue.get('type', 'unknown')
                    message = issue.get('message', 'No details')
                    lines.append(f"- **[{severity}]** {issue_type}: {message}")
                lines.append("")
            
            # Recommendations
            if result_dict.get('recommendations'):
                lines.append("**Recommendations:**")
                lines.append("")
                for rec in result_dict.get('recommendations'):
                    lines.append(f"- {rec}")
                lines.append("")
            
            lines.append("---")
            lines.append("")

        return lines

    def _generate_summary(self, results: Union[Dict, List]) -> str:
        """Generate summary section."""
        total_scans = 0
        passed = 0
        failed = 0
        critical_issues = 0
        high_issues = 0

        if isinstance(results, dict):
            for scan_results in results.values():
                if isinstance(scan_results, list):
                    total_scans += len(scan_results)
                    for result in scan_results:
                        result_dict = self._to_dict(result)
                        if self._is_safe(result_dict):
                            passed += 1
                        else:
                            failed += 1
                        critical_issues += self._count_issues(result_dict, 'critical')
                        high_issues += self._count_issues(result_dict, 'high')
        elif isinstance(results, list):
            total_scans = len(results)
            for result in results:
                result_dict = self._to_dict(result)
                if self._is_safe(result_dict):
                    passed += 1
                else:
                    failed += 1
                critical_issues += self._count_issues(result_dict, 'critical')
                high_issues += self._count_issues(result_dict, 'high')

        summary = []
        summary.append(f"- **Total Scans:** {total_scans}")
        summary.append(f"- **Passed:** {passed}")
        summary.append(f"- **Failed:** {failed}")
        summary.append(f"- **Critical Issues:** {critical_issues}")
        summary.append(f"- **High Issues:** {high_issues}")
        summary.append("")
        
        if critical_issues > 0:
            summary.append("**⚠️ ACTION REQUIRED:** Critical security issues detected. Review and remediate immediately.")
        elif high_issues > 0:
            summary.append("**⚠️ WARNING:** High-severity issues detected. Review soon.")
        elif failed > 0:
            summary.append("**ℹ️ NOTICE:** Some scans failed. Review findings.")
        else:
            summary.append("**✓ All scans passed.** No critical or high-severity issues detected.")

        return '\n'.join(summary)

    def _is_safe(self, result_dict: Dict) -> bool:
        """Check if result indicates safe status."""
        for key in ['is_safe', 'attack_detected', 'is_hardened', 'integrity_verified']:
            if key in result_dict:
                if key == 'attack_detected':
                    return not result_dict[key]
                return result_dict.get(key, False)
        return True

    def _count_issues(self, result_dict: Dict, severity: str) -> int:
        """Count issues of specific severity."""
        issues = result_dict.get('issues') or result_dict.get('anomalies') or result_dict.get('flagged_patterns') or []
        return sum(1 for i in issues if i.get('severity', '').lower() == severity.lower())

    def _to_dict(self, obj: Any) -> Dict:
        """Convert object to dict."""
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        elif isinstance(obj, dict):
            return obj
        return str(obj)

    def _serialize_results(self, results: Union[Dict, List]) -> Union[Dict, List]:
        """Serialize results for JSON."""
        if isinstance(results, dict):
            return {k: self._serialize_results(v) for k, v in results.items()}
        elif isinstance(results, list):
            return [self._serialize_results(r) for r in results]
        elif hasattr(results, '__dict__'):
            return results.__dict__
        return results

    def write_json(self, results: Union[Dict, List], output_path: str):
        """Write JSON report to file."""
        content = self.generate_json(results)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            f.write(content)

    def write_markdown(self, results: Union[Dict, List], output_path: str):
        """Write Markdown report to file."""
        content = self.generate_markdown(results)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            f.write(content)

    def write_text(self, results: Union[Dict, List], output_path: str):
        """Write text report to file."""
        content = self.generate_text(results)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            f.write(content)

    def generate_text(self, results: Union[Dict, List]) -> str:
        """Generate plain text report."""
        lines = []
        lines.append("=" * 60)
        lines.append("LLM RUNTIME SECURITY SCAN REPORT")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"Generated: {self.timestamp}")
        lines.append(f"Version: 0.1.0")
        lines.append("")
        lines.append("-" * 60)
        lines.append("")

        if isinstance(results, dict):
            for scan_type, scan_results in results.items():
                lines.extend(self._format_text_section(scan_type, scan_results))
        elif isinstance(results, list):
            lines.extend(self._format_text_section('scan', results))

        lines.append("")
        lines.append("=" * 60)
        lines.append("SUMMARY")
        lines.append("=" * 60)
        lines.append("")
        lines.append(self._generate_summary(results))

        return '\n'.join(lines)

    def _format_text_section(self, scan_type: str, results: List) -> List[str]:
        """Format a scan section for text output."""
        lines = []
        lines.append(f"{scan_type.replace('_', ' ').upper()}")
        lines.append("-" * 40)

        for i, result in enumerate(results):
            result_dict = self._to_dict(result)
            
            lines.append(f"\n[Scan {i + 1}]")
            
            status = "PASS" if self._is_safe(result_dict) else "FAIL"
            lines.append(f"Status: {status}")
            
            for key, value in result_dict.items():
                if key in ['model_path', 'endpoint', 'input_text', 'is_safe', 
                          'attack_detected', 'security_score', 'confidence']:
                    lines.append(f"{key.replace('_', ' ').title()}: {value}")
            
            issues = result_dict.get('issues') or result_dict.get('anomalies') or result_dict.get('flagged_patterns')
            if issues:
                lines.append("\nIssues Found:")
                for issue in issues:
                    severity = issue.get('severity', 'unknown').upper()
                    issue_type = issue.get('type', 'unknown')
                    message = issue.get('message', 'No details')
                    lines.append(f"  [{severity}] {issue_type}: {message}")
            
            lines.append("")

        return lines

    def print_text(self, results: Union[Dict, List]):
        """Print text report to stdout."""
        print(self.generate_text(results))


def main():
    """Test report generator."""
    generator = ReportGenerator()
    sample_results = {
        'model_loading': [{
            'model_path': '/models/test.bin',
            'is_safe': True,
            'issues': []
        }],
        'inference': [{
            'input_text': 'test input',
            'attack_detected': False,
            'confidence': 0.0
        }]
    }
    print(generator.generate_markdown(sample_results))


if __name__ == '__main__':
    main()
