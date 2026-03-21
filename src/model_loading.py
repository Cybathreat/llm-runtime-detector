#!/usr/bin/env python3
"""
Model Loading Security Scanner
Detects vulnerabilities during LLM model loading operations.
"""

import hashlib
import json
import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class ModelLoadingResult:
    """Result of model loading security scan."""
    model_path: str
    is_safe: bool
    issues: List[Dict[str, Any]]
    hash_verified: bool
    permissions_ok: bool
    symlink_detected: bool
    timestamp: str


class ModelLoadingScanner:
    """Scans LLM model loading for security vulnerabilities."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.allowed_extensions = {'.bin', '.safetensors', '.pt', '.pth', '.onnx', '.gguf'}
        self.max_file_size = self.config.get('max_model_size_mb', 50000) * 1024 * 1024

    def scan_model_path(self, model_path: str, expected_hash: Optional[str] = None) -> ModelLoadingResult:
        """
        Scan a model path for security issues.

        Args:
            model_path: Path to model file or directory
            expected_hash: Optional SHA256 hash for verification

        Returns:
            ModelLoadingResult with security assessment
        """
        issues = []
        path = Path(model_path)

        # Check if path exists
        if not path.exists():
            return ModelLoadingResult(
                model_path=model_path,
                is_safe=False,
                issues=[{"type": "path_not_found", "severity": "critical", "message": f"Path does not exist: {model_path}"}],
                hash_verified=False,
                permissions_ok=False,
                symlink_detected=False,
                timestamp=self._get_timestamp()
            )

        # Check for symlink attacks
        symlink_detected = path.is_symlink()
        if symlink_detected:
            real_path = path.resolve()
            issues.append({
                "type": "symlink_detected",
                "severity": "high",
                "message": f"Symlink detected pointing to: {real_path}",
                "recommendation": "Verify symlink target is trusted location"
            })

        # Check file permissions
        permissions_ok = self._check_permissions(path)
        if not permissions_ok:
            issues.append({
                "type": "insecure_permissions",
                "severity": "medium",
                "message": f"Model file has insecure permissions",
                "recommendation": "Set permissions to 0644 or more restrictive"
            })

        # Check file extension
        if path.is_file():
            ext = path.suffix.lower()
            if ext not in self.allowed_extensions:
                issues.append({
                    "type": "unknown_extension",
                    "severity": "medium",
                    "message": f"Unknown model extension: {ext}",
                    "recommendation": "Verify file type is legitimate model format"
                })

            # Check file size
            try:
                file_size = path.stat().st_size
                if file_size > self.max_file_size:
                    issues.append({
                        "type": "oversized_file",
                        "severity": "low",
                        "message": f"Model file exceeds size limit: {file_size / (1024*1024):.2f} MB",
                        "recommendation": "Verify this is expected model size"
                    })
            except OSError as e:
                issues.append({
                    "type": "stat_error",
                    "severity": "low",
                    "message": f"Cannot stat file: {str(e)}"
                })

        # Verify hash if provided
        hash_verified = False
        if expected_hash and path.is_file():
            computed_hash = self._compute_sha256(path)
            hash_verified = computed_hash == expected_hash.lower()
            if not hash_verified:
                issues.append({
                    "type": "hash_mismatch",
                    "severity": "critical",
                    "message": f"SHA256 hash mismatch",
                    "expected": expected_hash,
                    "computed": computed_hash,
                    "recommendation": "Model may have been tampered with"
                })

        # Check for path traversal attempts
        if '..' in model_path:
            issues.append({
                "type": "path_traversal",
                "severity": "high",
                "message": "Path traversal sequence detected",
                "recommendation": "Sanitize model path inputs"
            })

        is_safe = len([i for i in issues if i.get('severity') in ['critical', 'high']]) == 0

        return ModelLoadingResult(
            model_path=model_path,
            is_safe=is_safe,
            issues=issues,
            hash_verified=hash_verified,
            permissions_ok=permissions_ok,
            symlink_detected=symlink_detected,
            timestamp=self._get_timestamp()
        )

    def _check_permissions(self, path: Path) -> bool:
        """Check if file permissions are secure."""
        try:
            stat_info = path.stat()
            mode = stat_info.st_mode & 0o777
            # Check if world-writable or group-writable
            if mode & 0o022:
                return False
            return True
        except OSError:
            return False

    def _compute_sha256(self, path: Path) -> str:
        """Compute SHA256 hash of file."""
        sha256_hash = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime
        return datetime.utcnow().isoformat() + 'Z'

    def scan_directory(self, model_dir: str) -> List[ModelLoadingResult]:
        """Scan all model files in a directory."""
        results = []
        dir_path = Path(model_dir)
        if not dir_path.is_dir():
            return results

        for ext in self.allowed_extensions:
            for model_file in dir_path.glob(f"*{ext}"):
                result = self.scan_model_path(str(model_file))
                results.append(result)

        return results


def main():
    """CLI entry point for model loading scanner."""
    import argparse
    parser = argparse.ArgumentParser(description="Model Loading Security Scanner")
    parser.add_argument("model_path", help="Path to model file or directory")
    parser.add_argument("--hash", dest="expected_hash", help="Expected SHA256 hash")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    scanner = ModelLoadingScanner()
    path = Path(args.model_path)

    if path.is_dir():
        results = scanner.scan_directory(args.model_path)
        output = [asdict(r) for r in results]
    else:
        result = scanner.scan_model_path(args.model_path, args.expected_hash)
        output = asdict(result)

    if args.json:
        print(json.dumps(output, indent=2))
    else:
        if isinstance(output, list):
            for r in output:
                _print_result(r)
        else:
            _print_result(output)


def _print_result(result: Dict):
    """Print result in human-readable format."""
    status = "✓ SAFE" if result.get('is_safe') else "✗ UNSAFE"
    print(f"Model: {result.get('model_path')}")
    print(f"Status: {status}")
    print(f"Hash Verified: {result.get('hash_verified')}")
    print(f"Permissions OK: {result.get('permissions_ok')}")
    print(f"Symlink Detected: {result.get('symlink_detected')}")
    if result.get('issues'):
        print("\nIssues Found:")
        for issue in result['issues']:
            print(f"  [{issue.get('severity').upper()}] {issue.get('type')}: {issue.get('message')}")


if __name__ == "__main__":
    main()
