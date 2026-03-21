#!/usr/bin/env python3
"""
Unit tests for Model Loading Security Scanner
"""

import unittest
import tempfile
import os
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from model_loading import ModelLoadingScanner, ModelLoadingResult


class TestModelLoadingScanner(unittest.TestCase):
    """Test cases for model loading security scanner."""

    def setUp(self):
        """Set up test fixtures."""
        self.scanner = ModelLoadingScanner()
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_scan_nonexistent_path(self):
        """Test scanning a path that doesn't exist."""
        result = self.scanner.scan_model_path('/nonexistent/path/model.bin')
        self.assertFalse(result.is_safe)
        self.assertEqual(len(result.issues), 1)
        self.assertEqual(result.issues[0]['type'], 'path_not_found')
        self.assertEqual(result.issues[0]['severity'], 'critical')

    def test_scan_valid_model_file(self):
        """Test scanning a valid model file."""
        model_path = Path(self.test_dir) / 'test_model.bin'
        model_path.write_bytes(b'test model content')
        
        result = self.scanner.scan_model_path(str(model_path))
        self.assertTrue(result.is_safe)
        self.assertEqual(len(result.issues), 0)
        self.assertFalse(result.symlink_detected)
        self.assertTrue(result.permissions_ok)

    def test_scan_symlink(self):
        """Test scanning a symlink."""
        target = Path(self.test_dir) / 'target.bin'
        target.write_bytes(b'target content')
        
        link_path = Path(self.test_dir) / 'link.bin'
        os.symlink(str(target), str(link_path))
        
        result = self.scanner.scan_model_path(str(link_path))
        self.assertTrue(result.symlink_detected)
        self.assertGreater(len(result.issues), 0)
        self.assertEqual(result.issues[0]['type'], 'symlink_detected')

    def test_hash_verification_success(self):
        """Test hash verification with matching hash."""
        import hashlib
        model_path = Path(self.test_dir) / 'test.bin'
        content = b'test content for hashing'
        model_path.write_bytes(content)
        
        expected_hash = hashlib.sha256(content).hexdigest()
        result = self.scanner.scan_model_path(str(model_path), expected_hash)
        self.assertTrue(result.hash_verified)
        self.assertTrue(result.is_safe)

    def test_hash_verification_failure(self):
        """Test hash verification with mismatched hash."""
        model_path = Path(self.test_dir) / 'test.bin'
        model_path.write_bytes(b'test content')
        
        wrong_hash = 'a' * 64  # Invalid hash
        result = self.scanner.scan_model_path(str(model_path), wrong_hash)
        self.assertFalse(result.hash_verified)
        self.assertFalse(result.is_safe)
        self.assertEqual(result.issues[0]['type'], 'hash_mismatch')

    def test_path_traversal_detection(self):
        """Test detection of path traversal attempts."""
        model_path = '../../../etc/passwd'
        result = self.scanner.scan_model_path(model_path)
        self.assertFalse(result.is_safe)
        self.assertTrue(any(i['type'] == 'path_traversal' for i in result.issues))

    def test_unknown_extension_warning(self):
        """Test warning for unknown file extension."""
        model_path = Path(self.test_dir) / 'test.xyz'
        model_path.write_bytes(b'unknown format')
        
        result = self.scanner.scan_model_path(str(model_path))
        self.assertTrue(result.is_safe)  # Still safe, just warning
        self.assertTrue(any(i['type'] == 'unknown_extension' for i in result.issues))

    def test_scan_directory(self):
        """Test scanning a directory with multiple models."""
        # Create multiple model files
        for ext in ['.bin', '.pt', '.safetensors']:
            model_path = Path(self.test_dir) / f'model{ext}'
            model_path.write_bytes(b'model content')
        
        results = self.scanner.scan_directory(self.test_dir)
        self.assertEqual(len(results), 3)
        self.assertTrue(all(r.is_safe for r in results))

    def test_insecure_permissions(self):
        """Test detection of insecure file permissions."""
        model_path = Path(self.test_dir) / 'test.bin'
        model_path.write_bytes(b'test')
        os.chmod(str(model_path), 0o777)  # World-writable
        
        result = self.scanner.scan_model_path(str(model_path))
        self.assertFalse(result.permissions_ok)
        self.assertTrue(any(i['type'] == 'insecure_permissions' for i in result.issues))

    def test_result_serialization(self):
        """Test that result can be serialized to dict."""
        from dataclasses import asdict
        model_path = Path(self.test_dir) / 'test.bin'
        model_path.write_bytes(b'test')
        
        result = self.scanner.scan_model_path(str(model_path))
        result_dict = asdict(result)
        
        self.assertIn('model_path', result_dict)
        self.assertIn('is_safe', result_dict)
        self.assertIn('issues', result_dict)
        self.assertIn('timestamp', result_dict)


if __name__ == '__main__':
    unittest.main()
