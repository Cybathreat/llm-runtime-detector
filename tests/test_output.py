#!/usr/bin/env python3
"""
Unit tests for Report Generator.
"""
import json
import sys
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from output import ReportGenerator


class TestReportGeneratorInit(unittest.TestCase):
    """Tests for ReportGenerator initialization."""

    def test_init(self):
        """Test initialization."""
        generator = ReportGenerator()
        self.assertIsNotNone(generator.timestamp)
        self.assertIn("T", generator.timestamp)


class TestGenerateJSON(unittest.TestCase):
    """Tests for generate_json method."""

    def test_generate_json_dict(self):
        """Test JSON generation with dict results."""
        generator = ReportGenerator()
        results = {
            "model_loading": [{"is_safe": True}],
            "inference": [{"attack_detected": False}]
        }
        json_output = generator.generate_json(results)
        parsed = json.loads(json_output)
        self.assertEqual(parsed["report_type"], "llm_runtime_security_scan")
        self.assertEqual(parsed["version"], "0.1.0")
        self.assertIn("results", parsed)

    def test_generate_json_list(self):
        """Test JSON generation with list results."""
        generator = ReportGenerator()
        results = [{"is_safe": True}, {"is_safe": False}]
        json_output = generator.generate_json(results)
        parsed = json.loads(json_output)
        self.assertIn("results", parsed)

    def test_generate_json_empty(self):
        """Test JSON generation with empty results."""
        generator = ReportGenerator()
        json_output = generator.generate_json({})
        parsed = json.loads(json_output)
        self.assertEqual(parsed["results"], {})

    def test_generate_json_with_dataclass(self):
        """Test JSON generation with dataclass objects."""
        generator = ReportGenerator()
        result_obj = MagicMock()
        result_obj.__dict__ = {"endpoint": "https://api.example.com", "is_hardened": True}
        json_output = generator.generate_json([result_obj])
        parsed = json.loads(json_output)
        self.assertEqual(parsed["results"][0]["endpoint"], "https://api.example.com")


class TestGenerateMarkdown(unittest.TestCase):
    """Tests for generate_markdown method."""

    def test_generate_markdown_dict(self):
        """Test Markdown generation with dict results."""
        generator = ReportGenerator()
        results = {
            "model_loading": [{"model_path": "model.bin", "is_safe": True, "issues": []}]
        }
        md = generator.generate_markdown(results)
        self.assertIn("# LLM Runtime Security Scan Report", md)
        self.assertIn("model.bin", md)
        self.assertIn("## Summary", md)

    def test_generate_markdown_list(self):
        """Test Markdown generation with list results."""
        generator = ReportGenerator()
        results = [{"model_path": "model.bin", "is_safe": True, "issues": []}]
        md = generator.generate_markdown(results)
        self.assertIn("model.bin", md)
        self.assertIn("PASS", md)

    def test_generate_markdown_with_issues(self):
        """Test Markdown with issues."""
        generator = ReportGenerator()
        results = [{
            "model_path": "model.bin",
            "is_safe": False,
            "issues": [{"severity": "critical", "type": "hash_mismatch", "message": "Tampered"}],
            "recommendations": ["Re-download"]
        }]
        md = generator.generate_markdown(results)
        self.assertIn("FAIL", md)
        self.assertIn("CRITICAL", md)
        self.assertIn("Re-download", md)

    def test_generate_markdown_with_anomalies(self):
        """Test Markdown with anomalies instead of issues."""
        generator = ReportGenerator()
        results = [{
            "model_path": "model.bin",
            "is_safe": False,
            "anomalies": [{"severity": "high", "type": "suspicious_bytes", "message": "NOP sled"}]
        }]
        md = generator.generate_markdown(results)
        self.assertIn("HIGH", md)
        self.assertIn("suspicious_bytes", md)

    def test_generate_markdown_empty(self):
        """Test Markdown generation with empty results."""
        generator = ReportGenerator()
        md = generator.generate_markdown({})
        self.assertIn("# LLM Runtime Security Scan Report", md)
        self.assertIn("## Summary", md)

    def test_generate_markdown_full_scan(self):
        """Test Markdown with full scan results."""
        generator = ReportGenerator()
        results = {
            "model_loading": [{"model_path": "model.bin", "is_safe": True, "issues": []}],
            "inference": [{"input_text": "test", "attack_detected": False, "confidence": 0.0}],
            "memory_safety": [{"model_path": "model.bin", "is_safe": True, "anomalies": []}],
            "api_hardening": [{"endpoint": "https://api.example.com", "is_hardened": True, "issues": []}]
        }
        md = generator.generate_markdown(results)
        self.assertIn("model.bin", md)
        self.assertIn("test", md)
        self.assertIn("https://api.example.com", md)


class TestGenerateText(unittest.TestCase):
    """Tests for generate_text method."""

    def test_generate_text_dict(self):
        """Test text generation with dict results."""
        generator = ReportGenerator()
        results = {
            "model_loading": [{"model_path": "model.bin", "is_safe": True}]
        }
        text = generator.generate_text(results)
        self.assertIn("LLM RUNTIME SECURITY SCAN REPORT", text)
        self.assertIn("model.bin", text)
        self.assertIn("PASS", text)

    def test_generate_text_list(self):
        """Test text generation with list results."""
        generator = ReportGenerator()
        results = [{"model_path": "model.bin", "is_safe": True}]
        text = generator.generate_text(results)
        self.assertIn("model.bin", text)

    def test_generate_text_with_issues(self):
        """Test text generation with issues."""
        generator = ReportGenerator()
        results = [{
            "model_path": "model.bin",
            "is_safe": False,
            "issues": [{"severity": "critical", "type": "hash_mismatch", "message": "Tampered"}]
        }]
        text = generator.generate_text(results)
        self.assertIn("FAIL", text)
        self.assertIn("CRITICAL", text)


class TestWriteMethods(unittest.TestCase):
    """Tests for write methods."""

    @patch("builtins.open", mock_open())
    @patch("pathlib.Path.mkdir")
    def test_write_json(self, mock_mkdir):
        """Test writing JSON report."""
        generator = ReportGenerator()
        results = {"model_loading": [{"is_safe": True}]}
        generator.write_json(results, "/tmp/report.json")
        mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)

    @patch("builtins.open", mock_open())
    @patch("pathlib.Path.mkdir")
    def test_write_markdown(self, mock_mkdir):
        """Test writing Markdown report."""
        generator = ReportGenerator()
        results = {"model_loading": [{"is_safe": True}]}
        generator.write_markdown(results, "/tmp/report.md")
        mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)

    @patch("builtins.open", mock_open())
    @patch("pathlib.Path.mkdir")
    def test_write_text(self, mock_mkdir):
        """Test writing text report."""
        generator = ReportGenerator()
        results = {"model_loading": [{"is_safe": True}]}
        generator.write_text(results, "/tmp/report.txt")
        mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)


class TestPrintText(unittest.TestCase):
    """Tests for print_text method."""

    def test_print_text(self):
        """Test printing text report."""
        generator = ReportGenerator()
        results = [{"model_path": "model.bin", "is_safe": True}]
        captured = StringIO()
        with patch("sys.stdout", captured):
            generator.print_text(results)
        self.assertIn("model.bin", captured.getvalue())


class TestSummaryGeneration(unittest.TestCase):
    """Tests for summary generation."""

    def test_summary_all_pass(self):
        """Test summary when all scans pass."""
        generator = ReportGenerator()
        results = [{"model_path": "model.bin", "is_safe": True, "issues": []}]
        summary = generator._generate_summary(results)
        self.assertIn("All scans passed", summary)
        self.assertIn("Passed:** 1", summary)

    def test_summary_with_critical(self):
        """Test summary with critical issues."""
        generator = ReportGenerator()
        results = [{
            "model_path": "model.bin",
            "is_safe": False,
            "issues": [{"severity": "critical", "type": "hash_mismatch"}]
        }]
        summary = generator._generate_summary(results)
        self.assertIn("ACTION REQUIRED", summary)
        self.assertIn("Critical Issues:** 1", summary)

    def test_summary_with_high(self):
        """Test summary with high issues."""
        generator = ReportGenerator()
        results = [{
            "model_path": "model.bin",
            "is_safe": False,
            "issues": [{"severity": "high", "type": "suspicious_bytes"}]
        }]
        summary = generator._generate_summary(results)
        self.assertIn("WARNING", summary)
        self.assertIn("High Issues:** 1", summary)

    def test_summary_dict_results(self):
        """Test summary with dict results."""
        generator = ReportGenerator()
        results = {
            "model_loading": [{"is_safe": True, "issues": []}],
            "inference": [{"attack_detected": False, "flagged_patterns": []}]
        }
        summary = generator._generate_summary(results)
        self.assertIn("Total Scans:** 2", summary)
        self.assertIn("Passed:** 2", summary)


class TestIsSafe(unittest.TestCase):
    """Tests for _is_safe method."""

    def test_is_safe_true(self):
        """Test safe result detection."""
        generator = ReportGenerator()
        self.assertTrue(generator._is_safe({"is_safe": True}))

    def test_is_safe_false(self):
        """Test unsafe result detection."""
        generator = ReportGenerator()
        self.assertFalse(generator._is_safe({"is_safe": False}))

    def test_attack_detected(self):
        """Test attack_detected logic."""
        generator = ReportGenerator()
        self.assertFalse(generator._is_safe({"attack_detected": True}))
        self.assertTrue(generator._is_safe({"attack_detected": False}))

    def test_is_hardened(self):
        """Test hardened result detection."""
        generator = ReportGenerator()
        self.assertTrue(generator._is_safe({"is_hardened": True}))
        self.assertFalse(generator._is_safe({"is_hardened": False}))

    def test_integrity_verified(self):
        """Test integrity verified detection."""
        generator = ReportGenerator()
        self.assertTrue(generator._is_safe({"integrity_verified": True}))

    def test_default_true(self):
        """Test default safe when no known keys."""
        generator = ReportGenerator()
        self.assertTrue(generator._is_safe({"unknown_key": True}))


class TestCountIssues(unittest.TestCase):
    """Tests for _count_issues method."""

    def test_count_critical(self):
        """Test counting critical issues."""
        generator = ReportGenerator()
        result = {"issues": [{"severity": "critical"}, {"severity": "high"}, {"severity": "critical"}]}
        self.assertEqual(generator._count_issues(result, "critical"), 2)

    def test_count_high(self):
        """Test counting high issues."""
        generator = ReportGenerator()
        result = {"issues": [{"severity": "critical"}, {"severity": "high"}]}
        self.assertEqual(generator._count_issues(result, "high"), 1)

    def test_count_anomalies(self):
        """Test counting from anomalies."""
        generator = ReportGenerator()
        result = {"anomalies": [{"severity": "high"}, {"severity": "medium"}]}
        self.assertEqual(generator._count_issues(result, "high"), 1)

    def test_count_no_issues(self):
        """Test counting with no issues."""
        generator = ReportGenerator()
        result = {}
        self.assertEqual(generator._count_issues(result, "critical"), 0)


class TestToDict(unittest.TestCase):
    """Tests for _to_dict method."""

    def test_dict_input(self):
        """Test dict input returns itself."""
        generator = ReportGenerator()
        d = {"key": "value"}
        self.assertEqual(generator._to_dict(d), d)

    def test_object_input(self):
        """Test object with __dict__."""
        generator = ReportGenerator()
        obj = MagicMock()
        obj.__dict__ = {"key": "value"}
        self.assertEqual(generator._to_dict(obj), {"key": "value"})

    def test_string_input(self):
        """Test string input returns string."""
        generator = ReportGenerator()
        self.assertEqual(generator._to_dict("test"), "test")


class TestSerializeResults(unittest.TestCase):
    """Tests for _serialize_results method."""

    def test_serialize_dict(self):
        """Test serializing dict."""
        generator = ReportGenerator()
        result = generator._serialize_results({"key": "value"})
        self.assertEqual(result, {"key": "value"})

    def test_serialize_list(self):
        """Test serializing list."""
        generator = ReportGenerator()
        result = generator._serialize_results([1, 2, 3])
        self.assertEqual(result, [1, 2, 3])

    def test_serialize_object(self):
        """Test serializing object."""
        generator = ReportGenerator()
        obj = MagicMock()
        obj.__dict__ = {"key": "value"}
        result = generator._serialize_results(obj)
        self.assertEqual(result, {"key": "value"})


class TestFormatTextSection(unittest.TestCase):
    """Tests for _format_text_section method."""

    def test_format_section(self):
        """Test formatting a section."""
        generator = ReportGenerator()
        results = [{"model_path": "model.bin", "is_safe": True}]
        lines = generator._format_text_section("model_loading", results)
        text = "\n".join(lines)
        self.assertIn("MODEL LOADING", text)
        self.assertIn("model.bin", text)


class TestFormatScanSection(unittest.TestCase):
    """Tests for _format_scan_section method."""

    def test_format_scan_section(self):
        """Test formatting scan section for Markdown."""
        generator = ReportGenerator()
        results = [{"model_path": "model.bin", "is_safe": True, "issues": []}]
        lines = generator._format_scan_section("model_loading", results)
        text = "\n".join(lines)
        self.assertIn("Model Loading", text)
        self.assertIn("PASS", text)

    def test_format_scan_section_with_issues(self):
        """Test formatting with issues."""
        generator = ReportGenerator()
        results = [{
            "model_path": "model.bin",
            "is_safe": False,
            "issues": [{"severity": "critical", "type": "hash_mismatch", "message": "Tampered"}],
            "recommendations": ["Re-download"]
        }]
        lines = generator._format_scan_section("model_loading", results)
        text = "\n".join(lines)
        self.assertIn("FAIL", text)
        self.assertIn("CRITICAL", text)
        self.assertIn("Re-download", text)


if __name__ == "__main__":
    unittest.main()
