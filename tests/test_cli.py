#!/usr/bin/env python3
"""
Unit tests for LLM Runtime Detector CLI.
"""
import json
import sys
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

import cli


class TestLoadConfig(unittest.TestCase):
    """Tests for load_config function."""

    def test_load_config_none_returns_empty(self):
        """Test that None config path returns empty dict."""
        result = cli.load_config(None)
        self.assertEqual(result, {})

    def test_load_config_missing_file_returns_empty(self):
        """Test that missing config file returns empty dict with warning."""
        with patch("pathlib.Path.exists", return_value=False):
            with patch("logging.Logger.warning") as mock_warn:
                result = cli.load_config("nonexistent.yaml")
                self.assertEqual(result, {})
                mock_warn.assert_called_once()

    def test_load_config_yaml_success(self):
        """Test successful YAML config loading."""
        yaml_content = "key: value\nnum: 42"
        with patch("pathlib.Path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=yaml_content)):
                with patch("yaml.safe_load", return_value={"key": "value", "num": 42}):
                    result = cli.load_config("config.yaml")
                    self.assertEqual(result, {"key": "value", "num": 42})

    def test_load_config_json_success(self):
        """Test successful JSON config loading."""
        json_content = '{"key": "value", "num": 42}'
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.suffix", ".json"):
                with patch("builtins.open", mock_open(read_data=json_content)):
                    with patch("json.load", return_value={"key": "value", "num": 42}):
                        result = cli.load_config("config.json")
                        self.assertEqual(result, {"key": "value", "num": 42})

    def test_load_config_yaml_error_returns_empty(self):
        """Test that YAML parse error returns empty dict."""
        with patch("pathlib.Path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data="bad yaml")):
                with patch("yaml.safe_load", side_effect=Exception("parse error")):
                    with patch("logging.Logger.error") as mock_error:
                        result = cli.load_config("config.yaml")
                        self.assertEqual(result, {})
                        mock_error.assert_called_once()


class TestRunModelScan(unittest.TestCase):
    """Tests for run_model_scan function."""

    @patch("cli.ModelLoadingScanner")
    @patch("cli.load_config")
    @patch("pathlib.Path.is_dir", return_value=False)
    def test_run_model_scan_single_file(self, mock_is_dir, mock_load_config, mock_scanner_cls):
        """Test scanning a single model file."""
        mock_scanner = MagicMock()
        mock_scanner_cls.return_value = mock_scanner
        mock_scanner.scan_model_path.return_value = {"is_safe": True}

        args = MagicMock()
        args.config = None
        args.model_path = "model.bin"
        args.hash = "abc123"

        result = cli.run_model_scan(args)
        self.assertEqual(result, [{"is_safe": True}])
        mock_scanner.scan_model_path.assert_called_once_with("model.bin", "abc123")

    @patch("cli.ModelLoadingScanner")
    @patch("cli.load_config")
    @patch("pathlib.Path.is_dir", return_value=True)
    def test_run_model_scan_directory(self, mock_is_dir, mock_load_config, mock_scanner_cls):
        """Test scanning a directory of models."""
        mock_scanner = MagicMock()
        mock_scanner_cls.return_value = mock_scanner
        mock_scanner.scan_directory.return_value = [{"is_safe": True}, {"is_safe": False}]

        args = MagicMock()
        args.config = "config.yaml"
        args.model_path = "./models"
        args.hash = None

        result = cli.run_model_scan(args)
        self.assertEqual(len(result), 2)
        mock_scanner.scan_directory.assert_called_once_with("./models")


class TestRunInferenceScan(unittest.TestCase):
    """Tests for run_inference_scan function."""

    @patch("cli.InferenceAttackDetector")
    @patch("cli.load_config")
    def test_run_inference_scan_single_input(self, mock_load_config, mock_detector_cls):
        """Test scanning a single input."""
        mock_detector = MagicMock()
        mock_detector_cls.return_value = mock_detector
        mock_detector.detect.return_value = {"attack_detected": False}

        args = MagicMock()
        args.config = None
        args.input = "test prompt"
        args.batch_file = None

        result = cli.run_inference_scan(args)
        self.assertEqual(result, [{"attack_detected": False}])
        mock_detector.detect.assert_called_once_with("test prompt")

    @patch("cli.InferenceAttackDetector")
    @patch("cli.load_config")
    def test_run_inference_scan_batch(self, mock_load_config, mock_detector_cls):
        """Test scanning a batch of inputs from file."""
        mock_detector = MagicMock()
        mock_detector_cls.return_value = mock_detector
        mock_detector.analyze_batch.return_value = [{"attack_detected": False}, {"attack_detected": True}]

        args = MagicMock()
        args.config = None
        args.input = None
        args.batch_file = "prompts.txt"

        with patch("builtins.open", mock_open(read_data="prompt1\nprompt2\n")):
            result = cli.run_inference_scan(args)
            self.assertEqual(len(result), 2)
            mock_detector.analyze_batch.assert_called_once()


class TestRunMemoryScan(unittest.TestCase):
    """Tests for run_memory_scan function."""

    @patch("cli.MemorySafetyValidator")
    @patch("cli.load_config")
    def test_run_memory_scan_single_file(self, mock_load_config, mock_validator_cls):
        """Test validating a single model file."""
        mock_validator = MagicMock()
        mock_validator_cls.return_value = mock_validator
        mock_validator.validate.return_value = {"is_safe": True}

        args = MagicMock()
        args.config = None
        args.model_path = "model.bin"
        args.hash = "hash123"
        args.batch_file = None

        result = cli.run_memory_scan(args)
        self.assertEqual(result, [{"is_safe": True}])
        mock_validator.validate.assert_called_once_with("model.bin", "hash123")

    @patch("cli.MemorySafetyValidator")
    @patch("cli.load_config")
    def test_run_memory_scan_batch(self, mock_load_config, mock_validator_cls):
        """Test validating a batch of models from file."""
        mock_validator = MagicMock()
        mock_validator_cls.return_value = mock_validator
        mock_validator.validate_batch.return_value = [{"is_safe": True}]

        args = MagicMock()
        args.config = None
        args.model_path = None
        args.hash = None
        args.batch_file = "models.txt"

        with patch("builtins.open", mock_open(read_data="model1.bin\nmodel2.bin\n")):
            result = cli.run_memory_scan(args)
            self.assertEqual(len(result), 1)
            mock_validator.validate_batch.assert_called_once()


class TestRunApiScan(unittest.TestCase):
    """Tests for run_api_scan function."""

    @patch("cli.APIHardeningChecker")
    @patch("cli.load_config")
    def test_run_api_scan_single_endpoint(self, mock_load_config, mock_checker_cls):
        """Test scanning a single API endpoint."""
        mock_checker = MagicMock()
        mock_checker_cls.return_value = mock_checker
        mock_checker.check.return_value = {"is_hardened": True}

        args = MagicMock()
        args.config = None
        args.endpoint = "https://api.example.com"
        args.batch_file = None

        result = cli.run_api_scan(args)
        self.assertEqual(result, [{"is_hardened": True}])
        mock_checker.check.assert_called_once_with("https://api.example.com")

    @patch("cli.APIHardeningChecker")
    @patch("cli.load_config")
    def test_run_api_scan_batch_json(self, mock_load_config, mock_checker_cls):
        """Test scanning batch endpoints with JSON lines."""
        mock_checker = MagicMock()
        mock_checker_cls.return_value = mock_checker
        mock_checker.check_multiple.return_value = [{"is_hardened": True}]

        args = MagicMock()
        args.config = None
        args.endpoint = None
        args.batch_file = "endpoints.txt"

        with patch("builtins.open", mock_open(read_data='{"url": "https://api.example.com"}\n')):
            result = cli.run_api_scan(args)
            self.assertEqual(len(result), 1)
            mock_checker.check_multiple.assert_called_once()

    @patch("cli.APIHardeningChecker")
    @patch("cli.load_config")
    def test_run_api_scan_batch_plain_url(self, mock_load_config, mock_checker_cls):
        """Test scanning batch endpoints with plain URLs."""
        mock_checker = MagicMock()
        mock_checker_cls.return_value = mock_checker
        mock_checker.check_multiple.return_value = [{"is_hardened": True}]

        args = MagicMock()
        args.config = None
        args.endpoint = None
        args.batch_file = "endpoints.txt"

        with patch("builtins.open", mock_open(read_data="https://api.example.com\n")):
            result = cli.run_api_scan(args)
            self.assertEqual(len(result), 1)
            mock_checker.check_multiple.assert_called_once()


class TestRunFullScan(unittest.TestCase):
    """Tests for run_full_scan function."""

    @patch("cli.APIHardeningChecker")
    @patch("cli.MemorySafetyValidator")
    @patch("cli.InferenceAttackDetector")
    @patch("cli.ModelLoadingScanner")
    @patch("cli.load_config")
    def test_run_full_scan_all_modules(self, mock_load_config, mock_scanner_cls, mock_detector_cls,
                                       mock_validator_cls, mock_checker_cls):
        """Test full scan with all modules enabled."""
        mock_scanner = MagicMock()
        mock_scanner_cls.return_value = mock_scanner
        mock_scanner.scan_model_path.return_value = {"is_safe": True}

        mock_detector = MagicMock()
        mock_detector_cls.return_value = mock_detector
        mock_detector.detect.return_value = {"attack_detected": False}

        mock_validator = MagicMock()
        mock_validator_cls.return_value = mock_validator
        mock_validator.validate.return_value = {"is_safe": True}

        mock_checker = MagicMock()
        mock_checker_cls.return_value = mock_checker
        mock_checker.check.return_value = {"is_hardened": True}

        args = MagicMock()
        args.config = None
        args.model_path = "model.bin"
        args.hash = "hash123"
        args.input = "test prompt"
        args.endpoint = "https://api.example.com"
        args.batch_file = None

        result = cli.run_full_scan(args)
        self.assertIn("model_loading", result)
        self.assertIn("inference", result)
        self.assertIn("memory_safety", result)
        self.assertIn("api_hardening", result)


class TestMain(unittest.TestCase):
    """Tests for main() function."""

    @patch("sys.argv", ["cli.py", "--help"])
    def test_main_help(self):
        """Test that --help exits cleanly."""
        with self.assertRaises(SystemExit) as cm:
            cli.main()
        self.assertEqual(cm.exception.code, 0)

    @patch("sys.argv", ["cli.py"])
    def test_main_no_command(self):
        """Test that no command exits with code 1."""
        with self.assertRaises(SystemExit) as cm:
            cli.main()
        self.assertEqual(cm.exception.code, 1)

    @patch("sys.argv", ["cli.py", "model-scan", "model.bin"])
    @patch("cli.ModelLoadingScanner")
    def test_main_model_scan_text_output(self, mock_scanner_cls):
        """Test model-scan command with text output."""
        mock_scanner = MagicMock()
        mock_scanner_cls.return_value = mock_scanner
        mock_scanner.scan_model_path.return_value = {"is_safe": True}

        captured = StringIO()
        with patch("sys.stdout", captured):
            cli.main()
        output = captured.getvalue()
        self.assertIn("Is Safe", output)
        self.assertIn("PASS", output)

    @patch("sys.argv", ["cli.py", "--version"])
    def test_main_version(self):
        """Test --version flag."""
        with self.assertRaises(SystemExit) as cm:
            cli.main()
        self.assertEqual(cm.exception.code, 0)

    @patch("sys.argv", ["cli.py", "--verbose", "model-scan", "model.bin"])
    @patch("cli.ModelLoadingScanner")
    def test_main_verbose(self, mock_scanner_cls):
        """Test verbose mode sets logging level."""
        mock_scanner = MagicMock()
        mock_scanner_cls.return_value = mock_scanner
        mock_scanner.scan_model_path.return_value = {"is_safe": True}

        with patch("logging.getLogger") as mock_get_logger:
            with patch("sys.stdout", StringIO()):
                cli.main()
            mock_get_logger.return_value.setLevel.assert_called()


class TestCLIEdgeCases(unittest.TestCase):
    """Edge case tests for CLI."""

    @patch("sys.argv", ["cli.py", "inference-scan", "--input", ""])
    @patch("cli.InferenceAttackDetector")
    def test_empty_input(self, mock_detector_cls):
        """Test empty string input handling."""
        mock_detector = MagicMock()
        mock_detector_cls.return_value = mock_detector
        mock_detector.detect.return_value = {"attack_detected": False}

        with patch("sys.stdout", StringIO()):
            cli.main()
        mock_detector.detect.assert_called_once_with("")

    @patch("sys.argv", ["cli.py", "api-scan", "http://insecure.example.com"])
    @patch("cli.APIHardeningChecker")
    def test_insecure_http_endpoint(self, mock_checker_cls):
        """Test scanning HTTP endpoint (not HTTPS)."""
        mock_checker = MagicMock()
        mock_checker_cls.return_value = mock_checker
        mock_checker.check.return_value = {"is_hardened": False}

        with patch("sys.stdout", StringIO()):
            cli.main()
        mock_checker.check.assert_called_once_with("http://insecure.example.com")


if __name__ == "__main__":
    unittest.main()
