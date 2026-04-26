#!/usr/bin/env python3
"""
Unit tests for Memory Safety Validator.
"""
import hashlib
import sys
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from memory_safety import MemorySafetyValidator, MemorySafetyResult, main as memory_safety_main


class TestMemorySafetyResult(unittest.TestCase):
    """Tests for MemorySafetyResult dataclass."""

    def test_result_creation(self):
        """Test creating a result object."""
        result = MemorySafetyResult(
            model_path="model.bin",
            is_safe=True,
            integrity_verified=True,
            tampering_detected=False,
            anomalies=[],
            weight_hash="abc123",
            expected_hash="abc123",
            timestamp="2026-04-26T18:00:00Z"
        )
        self.assertEqual(result.model_path, "model.bin")
        self.assertTrue(result.is_safe)
        self.assertTrue(result.integrity_verified)
        self.assertFalse(result.tampering_detected)


class TestMemorySafetyValidatorInit(unittest.TestCase):
    """Tests for MemorySafetyValidator initialization."""

    def test_default_init(self):
        """Test default initialization."""
        validator = MemorySafetyValidator()
        self.assertEqual(validator.config, {})
        self.assertEqual(validator.chunk_size, 1024 * 1024)
        self.assertIn(".bin", validator.supported_formats)
        self.assertIn(".safetensors", validator.supported_formats)

    def test_custom_config(self):
        """Test initialization with custom config."""
        config = {"read_chunk_size": 512 * 1024}
        validator = MemorySafetyValidator(config)
        self.assertEqual(validator.chunk_size, 512 * 1024)


class TestMemorySafetyValidate(unittest.TestCase):
    """Tests for validate method."""

    def test_file_not_found(self):
        """Test validation of non-existent file."""
        validator = MemorySafetyValidator()
        result = validator.validate("nonexistent.bin")
        self.assertFalse(result.is_safe)
        self.assertFalse(result.integrity_verified)
        self.assertTrue(any(a["type"] == "file_not_found" for a in result.anomalies))
        self.assertEqual(result.weight_hash, None)

    def test_unsupported_format(self):
        """Test validation of unsupported file format."""
        validator = MemorySafetyValidator()
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.suffix", ".unknown"):
                with patch.object(validator, "_compute_file_hash", return_value="hash123"):
                    result = validator.validate("model.unknown")
                    self.assertTrue(any(a["type"] == "unsupported_format" for a in result.anomalies))

    @patch("pathlib.Path.stat", return_value=MagicMock(st_size=2048))
    @patch("pathlib.Path.exists", return_value=True)
    @patch("memory_safety.MemorySafetyValidator._compute_file_hash", return_value="abc123")
    @patch("memory_safety.MemorySafetyValidator._is_truncated", return_value=False)
    @patch("memory_safety.MemorySafetyValidator._scan_for_suspicious_bytes", return_value=[])
    @patch("memory_safety.MemorySafetyValidator._validate_structure", return_value=[])
    def test_valid_file(self, mock_structure, mock_suspicious, mock_truncated, mock_hash, mock_exists, mock_stat):
        """Test validation of a valid file."""
        validator = MemorySafetyValidator()
        result = validator.validate("model.bin", expected_hash="abc123")
        self.assertTrue(result.is_safe)
        self.assertTrue(result.integrity_verified)
        self.assertFalse(result.tampering_detected)
        self.assertEqual(result.weight_hash, "abc123")

    @patch("pathlib.Path.stat", return_value=MagicMock(st_size=2048))
    @patch("pathlib.Path.exists", return_value=True)
    @patch("memory_safety.MemorySafetyValidator._compute_file_hash", return_value="wrong_hash")
    @patch("memory_safety.MemorySafetyValidator._is_truncated", return_value=False)
    @patch("memory_safety.MemorySafetyValidator._scan_for_suspicious_bytes", return_value=[])
    @patch("memory_safety.MemorySafetyValidator._validate_structure", return_value=[])
    def test_hash_mismatch(self, mock_structure, mock_suspicious, mock_truncated, mock_hash, mock_exists, mock_stat):
        """Test detection of hash mismatch."""
        validator = MemorySafetyValidator()
        result = validator.validate("model.bin", expected_hash="abc123")
        self.assertFalse(result.is_safe)
        self.assertFalse(result.integrity_verified)
        self.assertTrue(result.tampering_detected)
        self.assertTrue(any(a["type"] == "hash_mismatch" for a in result.anomalies))

    @patch("pathlib.Path.stat", return_value=MagicMock(st_size=2048))
    @patch("pathlib.Path.exists", return_value=True)
    @patch("memory_safety.MemorySafetyValidator._compute_file_hash", return_value="hash123")
    @patch("memory_safety.MemorySafetyValidator._is_truncated", return_value=True)
    @patch("memory_safety.MemorySafetyValidator._scan_for_suspicious_bytes", return_value=[])
    @patch("memory_safety.MemorySafetyValidator._validate_structure", return_value=[])
    def test_truncated_file(self, mock_structure, mock_suspicious, mock_truncated, mock_hash, mock_exists, mock_stat):
        """Test detection of truncated file."""
        validator = MemorySafetyValidator()
        result = validator.validate("model.bin")
        self.assertTrue(any(a["type"] == "file_truncation" for a in result.anomalies))

    @patch("pathlib.Path.stat", return_value=MagicMock(st_size=2048))
    @patch("pathlib.Path.exists", return_value=True)
    @patch("memory_safety.MemorySafetyValidator._compute_file_hash", return_value="hash123")
    @patch("memory_safety.MemorySafetyValidator._is_truncated", return_value=False)
    @patch("memory_safety.MemorySafetyValidator._scan_for_suspicious_bytes", return_value=[{
        "type": "suspicious_bytes", "severity": "high", "message": "NOP sled detected"
    }])
    @patch("memory_safety.MemorySafetyValidator._validate_structure", return_value=[])
    def test_suspicious_bytes(self, mock_structure, mock_suspicious, mock_truncated, mock_hash, mock_exists, mock_stat):
        """Test detection of suspicious byte patterns."""
        validator = MemorySafetyValidator()
        result = validator.validate("model.bin")
        # suspicious_bytes anomaly is severity=high but type does NOT contain 'tampering'
        # so tampering_detected remains False per source logic
        self.assertFalse(result.tampering_detected)
        self.assertTrue(any(a["type"] == "suspicious_bytes" for a in result.anomalies))
        # is_safe is True because no tampering detected and no critical severity anomalies
        self.assertTrue(result.is_safe)

    @patch("pathlib.Path.stat", return_value=MagicMock(st_size=2048))
    @patch("pathlib.Path.exists", return_value=True)
    @patch("memory_safety.MemorySafetyValidator._compute_file_hash", return_value="hash123")
    @patch("memory_safety.MemorySafetyValidator._is_truncated", return_value=False)
    @patch("memory_safety.MemorySafetyValidator._scan_for_suspicious_bytes", return_value=[])
    @patch("memory_safety.MemorySafetyValidator._validate_structure", return_value=[{
        "type": "parse_error", "severity": "medium", "message": "Error parsing"
    }])
    def test_structure_issues(self, mock_structure, mock_suspicious, mock_truncated, mock_hash, mock_exists, mock_stat):
        """Test detection of structure issues."""
        validator = MemorySafetyValidator()
        result = validator.validate("model.bin")
        self.assertTrue(any(a["type"] == "parse_error" for a in result.anomalies))

    @patch("pathlib.Path.stat", return_value=MagicMock(st_size=2048))
    @patch("pathlib.Path.exists", return_value=True)
    @patch("memory_safety.MemorySafetyValidator._compute_file_hash", return_value="hash123")
    @patch("memory_safety.MemorySafetyValidator._is_truncated", return_value=False)
    @patch("memory_safety.MemorySafetyValidator._scan_for_suspicious_bytes", return_value=[])
    @patch("memory_safety.MemorySafetyValidator._validate_structure", return_value=[])
    def test_no_expected_hash(self, mock_structure, mock_suspicious, mock_truncated, mock_hash, mock_exists, mock_stat):
        """Test validation without expected hash."""
        validator = MemorySafetyValidator()
        result = validator.validate("model.bin")
        self.assertTrue(result.is_safe)
        self.assertFalse(result.integrity_verified)  # No hash to verify against
        self.assertFalse(result.tampering_detected)


class TestMemorySafetyComputeHash(unittest.TestCase):
    """Tests for _compute_file_hash method."""

    def test_compute_hash(self):
        """Test hash computation of a file."""
        validator = MemorySafetyValidator()
        test_data = b"test model data"
        expected_hash = hashlib.sha256(test_data).hexdigest()

        with patch("builtins.open", mock_open(read_data=test_data)):
            result = validator._compute_file_hash(Path("model.bin"))
            self.assertEqual(result, expected_hash)

    def test_compute_hash_large_file(self):
        """Test hash computation with large file (chunked reading)."""
        validator = MemorySafetyValidator(config={"read_chunk_size": 8})
        test_data = b"a" * 100
        expected_hash = hashlib.sha256(test_data).hexdigest()

        # Use a real BytesIO wrapped in a context manager mock
        from io import BytesIO
        byte_stream = BytesIO(test_data)
        
        class MockFile:
            def __enter__(self):
                return byte_stream
            def __exit__(self, *args):
                pass
        
        with patch("builtins.open", return_value=MockFile()):
            result = validator._compute_file_hash(Path("model.bin"))
            self.assertEqual(result, expected_hash)


class TestMemorySafetyIsTruncated(unittest.TestCase):
    """Tests for _is_truncated method."""

    def test_truncated_file(self):
        """Test detection of truncated file."""
        validator = MemorySafetyValidator()
        result = validator._is_truncated(Path("model.bin"), ".bin", 512)
        self.assertTrue(result)

    def test_normal_file(self):
        """Test normal file size passes."""
        validator = MemorySafetyValidator()
        result = validator._is_truncated(Path("model.bin"), ".bin", 2048)
        self.assertFalse(result)

    def test_unknown_format(self):
        """Test unknown format uses default minimum."""
        validator = MemorySafetyValidator()
        result = validator._is_truncated(Path("model.unknown"), ".unknown", 512)
        self.assertTrue(result)
        result = validator._is_truncated(Path("model.unknown"), ".unknown", 2048)
        self.assertFalse(result)


class TestMemorySafetyScanSuspiciousBytes(unittest.TestCase):
    """Tests for _scan_for_suspicious_bytes method."""

    def test_nop_sled_detected(self):
        """Test detection of NOP sled pattern."""
        validator = MemorySafetyValidator()
        data = b"\x00" * 100 + b"\x90" * 20 + b"\x00" * 100
        with patch("builtins.open", mock_open(read_data=data)):
            result = validator._scan_for_suspicious_bytes(Path("model.bin"))
            self.assertTrue(any(a["type"] == "suspicious_bytes" and "NOP sled" in a["message"] for a in result))

    def test_null_bytes_detected(self):
        """Test detection of large null byte run."""
        validator = MemorySafetyValidator()
        data = b"\x00" * 300
        with patch("builtins.open", mock_open(read_data=data)):
            result = validator._scan_for_suspicious_bytes(Path("model.bin"))
            self.assertTrue(any(a["type"] == "suspicious_bytes" and "null byte" in a["message"] for a in result))

    def test_no_suspicious_bytes(self):
        """Test clean file passes."""
        validator = MemorySafetyValidator()
        data = b"normal model data here"
        with patch("builtins.open", mock_open(read_data=data)):
            result = validator._scan_for_suspicious_bytes(Path("model.bin"))
            self.assertEqual(len(result), 0)

    def test_oserror_handling(self):
        """Test OSError handling during scan."""
        validator = MemorySafetyValidator()
        with patch("builtins.open", side_effect=OSError("Permission denied")):
            result = validator._scan_for_suspicious_bytes(Path("model.bin"))
            self.assertEqual(len(result), 0)


class TestMemorySafetyValidateStructure(unittest.TestCase):
    """Tests for _validate_structure method."""

    def test_safetensors_valid(self):
        """Test valid safetensors structure."""
        validator = MemorySafetyValidator()
        # Header size = 8 bytes (little-endian uint64) = 100
        data = (100).to_bytes(8, "little") + b"a" * 100
        with patch("builtins.open", mock_open(read_data=data)):
            result = validator._validate_structure(Path("model.safetensors"), ".safetensors")
            self.assertEqual(len(result), 0)

    def test_safetensors_too_small(self):
        """Test safetensors file too small for header."""
        validator = MemorySafetyValidator()
        data = b"\x00" * 4  # Less than 8 bytes
        with patch("builtins.open", mock_open(read_data=data)):
            result = validator._validate_structure(Path("model.safetensors"), ".safetensors")
            self.assertTrue(any(a["type"] == "invalid_header" for a in result))

    def test_safetensors_large_header(self):
        """Test abnormally large safetensors header."""
        validator = MemorySafetyValidator()
        # Header size = 200MB
        data = (200 * 1024 * 1024).to_bytes(8, "little")
        with patch("builtins.open", mock_open(read_data=data)):
            result = validator._validate_structure(Path("model.safetensors"), ".safetensors")
            self.assertTrue(any(a["type"] == "suspicious_header" for a in result))

    def test_safetensors_zero_header(self):
        """Test zero-size safetensors header."""
        validator = MemorySafetyValidator()
        data = (0).to_bytes(8, "little")
        with patch("builtins.open", mock_open(read_data=data)):
            result = validator._validate_structure(Path("model.safetensors"), ".safetensors")
            self.assertTrue(any(a["type"] == "invalid_header" for a in result))

    def test_pytorch_valid(self):
        """Test valid PyTorch file."""
        validator = MemorySafetyValidator()
        data = b"PK" + b"\x00" * 100
        with patch("builtins.open", mock_open(read_data=data)):
            result = validator._validate_structure(Path("model.pt"), ".pt")
            self.assertEqual(len(result), 0)

    def test_pytorch_invalid_magic(self):
        """Test invalid PyTorch magic bytes."""
        validator = MemorySafetyValidator()
        data = b"XX" + b"\x00" * 100
        with patch("builtins.open", mock_open(read_data=data)):
            result = validator._validate_structure(Path("model.pt"), ".pt")
            self.assertTrue(any(a["type"] == "invalid_magic" for a in result))

    def test_gguf_valid(self):
        """Test valid GGUF file."""
        validator = MemorySafetyValidator()
        data = b"GGUF" + b"\x00" * 100
        with patch("builtins.open", mock_open(read_data=data)):
            result = validator._validate_structure(Path("model.gguf"), ".gguf")
            self.assertEqual(len(result), 0)

    def test_gguf_invalid_magic(self):
        """Test invalid GGUF magic."""
        validator = MemorySafetyValidator()
        data = b"WRNG" + b"\x00" * 100
        with patch("builtins.open", mock_open(read_data=data)):
            result = validator._validate_structure(Path("model.gguf"), ".gguf")
            self.assertTrue(any(a["type"] == "invalid_magic" for a in result))

    def test_unsupported_format(self):
        """Test unsupported format returns no structure issues."""
        validator = MemorySafetyValidator()
        result = validator._validate_structure(Path("model.unknown"), ".unknown")
        self.assertEqual(len(result), 0)

    def test_parse_error_handling(self):
        """Test exception handling during structure validation."""
        validator = MemorySafetyValidator()
        # _validate_pytorch catches its own exceptions, so we need to patch it to raise
        with patch.object(validator, "_validate_pytorch", side_effect=Exception("Parse error")):
            result = validator._validate_structure(Path("model.pt"), ".pt")
            self.assertTrue(any(a["type"] == "parse_error" for a in result))


class TestMemorySafetyGetTimestamp(unittest.TestCase):
    """Tests for _get_timestamp method."""

    def test_timestamp_format(self):
        """Test timestamp format."""
        validator = MemorySafetyValidator()
        ts = validator._get_timestamp()
        self.assertTrue(ts.endswith("Z"))
        self.assertIn("T", ts)


class TestMemorySafetyValidateBatch(unittest.TestCase):
    """Tests for validate_batch method."""

    @patch("pathlib.Path.stat", return_value=MagicMock(st_size=2048))
    @patch("pathlib.Path.exists", return_value=True)
    @patch("memory_safety.MemorySafetyValidator._compute_file_hash", return_value="hash123")
    @patch("memory_safety.MemorySafetyValidator._is_truncated", return_value=False)
    @patch("memory_safety.MemorySafetyValidator._scan_for_suspicious_bytes", return_value=[])
    @patch("memory_safety.MemorySafetyValidator._validate_structure", return_value=[])
    def test_validate_batch(self, mock_structure, mock_suspicious, mock_truncated, mock_hash, mock_exists, mock_stat):
        """Test batch validation."""
        validator = MemorySafetyValidator()
        results = validator.validate_batch(["model1.bin", "model2.bin"])
        self.assertEqual(len(results), 2)

    @patch("pathlib.Path.stat", return_value=MagicMock(st_size=2048))
    @patch("pathlib.Path.exists", return_value=True)
    @patch("memory_safety.MemorySafetyValidator._compute_file_hash", return_value="hash123")
    @patch("memory_safety.MemorySafetyValidator._is_truncated", return_value=False)
    @patch("memory_safety.MemorySafetyValidator._scan_for_suspicious_bytes", return_value=[])
    @patch("memory_safety.MemorySafetyValidator._validate_structure", return_value=[])
    def test_validate_batch_with_hashes(self, mock_structure, mock_suspicious, mock_truncated, mock_hash, mock_exists, mock_stat):
        """Test batch validation with expected hashes."""
        validator = MemorySafetyValidator()
        hashes = {"model1.bin": "hash123", "model2.bin": "wrong_hash"}
        results = validator.validate_batch(["model1.bin", "model2.bin"], hashes)
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0].integrity_verified)
        self.assertFalse(results[1].integrity_verified)

    def test_validate_batch_empty(self):
        """Test empty batch."""
        validator = MemorySafetyValidator()
        results = validator.validate_batch([])
        self.assertEqual(len(results), 0)


class TestMemorySafetyMain(unittest.TestCase):
    """Tests for main() CLI entry point."""

    @patch("builtins.open", mock_open(read_data=b"fake model data"))
    @patch("sys.argv", ["memory_safety.py", "model.bin", "--json"])
    @patch("pathlib.Path.stat", return_value=MagicMock(st_size=2048))
    @patch("pathlib.Path.exists", return_value=True)
    @patch("memory_safety.MemorySafetyValidator._compute_file_hash", return_value="hash123")
    @patch("memory_safety.MemorySafetyValidator._is_truncated", return_value=False)
    @patch("memory_safety.MemorySafetyValidator._scan_for_suspicious_bytes", return_value=[])
    @patch("memory_safety.MemorySafetyValidator._validate_structure", return_value=[])
    def test_main_json_output(self, mock_structure, mock_suspicious, mock_truncated, mock_hash, mock_exists, mock_stat):
        """Test main with JSON output."""
        captured = StringIO()
        with patch("sys.stdout", captured):
            memory_safety_main()
        output = captured.getvalue()
        self.assertIn("model.bin", output)
        self.assertIn("hash123", output)


if __name__ == "__main__":
    unittest.main()
