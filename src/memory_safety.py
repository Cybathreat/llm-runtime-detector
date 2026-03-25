#!/usr/bin/env python3
"""
Memory Safety Validator
Detects model weight tampering and memory corruption attacks.
"""

import hashlib
import struct
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class MemorySafetyResult:
    """Result of memory safety validation."""
    model_path: str
    is_safe: bool
    integrity_verified: bool
    tampering_detected: bool
    anomalies: List[Dict[str, Any]]
    weight_hash: Optional[str]
    expected_hash: Optional[str]
    timestamp: str


class MemorySafetyValidator:
    """Validates model memory safety and weight integrity."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.supported_formats = {'.bin', '.safetensors', '.pt', '.pth', '.gguf'}
        self.chunk_size = self.config.get('read_chunk_size', 1024 * 1024)  # 1MB chunks

    def validate(self, model_path: str, expected_hash: Optional[str] = None) -> MemorySafetyResult:
        """
        Validate model file for memory safety and tampering.

        Args:
            model_path: Path to model file
            expected_hash: Optional expected SHA256 hash

        Returns:
            MemorySafetyResult with validation results
        """
        anomalies = []
        path = Path(model_path)

        # Check file exists
        if not path.exists():
            return MemorySafetyResult(
                model_path=model_path,
                is_safe=False,
                integrity_verified=False,
                tampering_detected=False,
                anomalies=[{"type": "file_not_found", "severity": "critical", "message": "Model file does not exist"}],
                weight_hash=None,
                expected_hash=expected_hash,
                timestamp=self._get_timestamp()
            )

        # Check file format
        ext = path.suffix.lower()
        if ext not in self.supported_formats:
            anomalies.append({
                "type": "unsupported_format",
                "severity": "medium",
                "message": f"Unsupported model format: {ext}"
            })

        # Compute file hash
        weight_hash = self._compute_file_hash(path)

        # Verify hash if provided
        integrity_verified = False
        if expected_hash:
            integrity_verified = weight_hash == expected_hash.lower()
            if not integrity_verified:
                anomalies.append({
                    "type": "hash_mismatch",
                    "severity": "critical",
                    "message": "Model weight hash does not match expected value",
                    "expected": expected_hash,
                    "computed": weight_hash,
                    "recommendation": "Model may have been tampered with - do not load"
                })

        # Check for file truncation
        try:
            file_size = path.stat().st_size
            if self._is_truncated(path, ext, file_size):
                anomalies.append({
                    "type": "file_truncation",
                    "severity": "high",
                    "message": "Model file appears to be truncated",
                    "file_size": file_size,
                    "recommendation": "Re-download model from trusted source"
                })
        except OSError as e:
            anomalies.append({
                "type": "stat_error",
                "severity": "low",
                "message": f"Cannot read file stats: {str(e)}"
            })

        # Check for suspicious byte patterns
        suspicious_patterns = self._scan_for_suspicious_bytes(path)
        if suspicious_patterns:
            anomalies.extend(suspicious_patterns)

        # Validate file structure (format-specific)
        structure_issues = self._validate_structure(path, ext)
        if structure_issues:
            anomalies.extend(structure_issues)

        tampering_detected = any(
            a.get('severity') in ['critical', 'high'] and 
            'tampering' in a.get('type', '').lower() or 
            a.get('type') == 'hash_mismatch'
            for a in anomalies
        )

        is_safe = not tampering_detected and len([a for a in anomalies if a.get('severity') == 'critical']) == 0

        return MemorySafetyResult(
            model_path=model_path,
            is_safe=is_safe,
            integrity_verified=integrity_verified,
            tampering_detected=tampering_detected,
            anomalies=anomalies,
            weight_hash=weight_hash,
            expected_hash=expected_hash,
            timestamp=self._get_timestamp()
        )

    def _compute_file_hash(self, path: Path) -> str:
        """Compute SHA256 hash of file."""
        sha256_hash = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(self.chunk_size), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def _is_truncated(self, path: Path, ext: str, file_size: int) -> bool:
        """Check if file appears truncated based on format expectations."""
        # Minimal size checks for common formats
        min_sizes = {
            '.bin': 1024,  # 1KB minimum
            '.safetensors': 1024,
            '.pt': 1024,
            '.pth': 1024,
            '.gguf': 1024,
        }
        min_size = min_sizes.get(ext, 1024)
        return file_size < min_size

    def _scan_for_suspicious_bytes(self, path: Path) -> List[Dict]:
        """Scan file for suspicious byte patterns."""
        anomalies = []
        try:
            with open(path, 'rb') as f:
                # Read first 1KB for magic byte check
                header = f.read(1024)
                
                # Check for shellcode-like patterns (NOP sleds)
                nop_sled = b'\x90' * 16
                if nop_sled in header:
                    anomalies.append({
                        "type": "suspicious_bytes",
                        "severity": "high",
                        "message": "NOP sled pattern detected in file header",
                        "recommendation": "File may contain executable shellcode"
                    })
                
                # Check for repeated null bytes (potential overflow)
                null_run = b'\x00' * 256
                if null_run in header:
                    anomalies.append({
                        "type": "suspicious_bytes",
                        "severity": "medium",
                        "message": "Large null byte run detected",
                        "recommendation": "May indicate memory corruption or overflow"
                    })
        except OSError:
            pass
        return anomalies

    def _validate_structure(self, path: Path, ext: str) -> List[Dict]:
        """Validate file structure for specific formats."""
        anomalies = []
        try:
            if ext == '.safetensors':
                anomalies.extend(self._validate_safetensors(path))
            elif ext in ['.pt', '.pth']:
                anomalies.extend(self._validate_pytorch(path))
            elif ext == '.gguf':
                anomalies.extend(self._validate_gguf(path))
        except Exception as e:
            anomalies.append({
                "type": "parse_error",
                "severity": "medium",
                "message": f"Error parsing file structure: {str(e)}"
            })
        return anomalies

    def _validate_safetensors(self, path: Path) -> List[Dict]:
        """Validate safetensors format structure."""
        anomalies = []
        try:
            with open(path, 'rb') as f:
                # Read header size (first 8 bytes, little-endian uint64)
                header_size_bytes = f.read(8)
                if len(header_size_bytes) < 8:
                    anomalies.append({
                        "type": "invalid_header",
                        "severity": "critical",
                        "message": "safetensors file too small for header"
                    })
                    return anomalies
                
                header_size = struct.unpack('<Q', header_size_bytes)[0]
                
                # Sanity check header size
                if header_size > 100 * 1024 * 1024:  # 100MB max header
                    anomalies.append({
                        "type": "suspicious_header",
                        "severity": "high",
                        "message": f"Abnormally large safetensors header: {header_size} bytes"
                    })
                
                if header_size == 0:
                    anomalies.append({
                        "type": "invalid_header",
                        "severity": "critical",
                        "message": "safetensors header size is zero"
                    })
        except Exception:
            pass
        return anomalies

    def _validate_pytorch(self, path: Path) -> List[Dict]:
        """Validate PyTorch pickle format structure."""
        anomalies = []
        try:
            with open(path, 'rb') as f:
                magic = f.read(2)
                # PyTorch files typically start with 0x50 0x4b (PK) or 0x80 0x?? (pickle)
                if magic not in [b'PK', b'\x80\x02', b'\x80\x03', b'\x80\x04']:
                    anomalies.append({
                        "type": "invalid_magic",
                        "severity": "medium",
                        "message": f"Unknown PyTorch magic bytes: {magic.hex()}"
                    })
        except Exception:
            pass
        return anomalies

    def _validate_gguf(self, path: Path) -> List[Dict]:
        """Validate GGUF format structure."""
        anomalies = []
        try:
            with open(path, 'rb') as f:
                magic = f.read(4)
                if magic != b'GGUF':
                    anomalies.append({
                        "type": "invalid_magic",
                        "severity": "critical",
                        "message": f"Invalid GGUF magic: {magic}"
                    })
        except Exception:
            pass
        return anomalies

    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

    def validate_batch(self, model_paths: List[str], hashes: Optional[Dict[str, str]] = None) -> List[MemorySafetyResult]:
        """Validate multiple model files."""
        results = []
        hashes = hashes or {}
        for path in model_paths:
            expected_hash = hashes.get(path)
            result = self.validate(path, expected_hash)
            results.append(result)
        return results


def main():
    """CLI entry point for memory safety validator."""
    import argparse
    parser = argparse.ArgumentParser(description="Memory Safety Validator")
    parser.add_argument("model_path", help="Path to model file")
    parser.add_argument("--hash", dest="expected_hash", help="Expected SHA256 hash")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    validator = MemorySafetyValidator()
    result = validator.validate(args.model_path, args.expected_hash)
    output = asdict(result)

    if args.json:
        print(json.dumps(output, indent=2))
    else:
        _print_result(output)


def _print_result(result: Dict):
    """Print result in human-readable format."""
    import json
    status = "✓ SAFE" if result.get('is_safe') else "✗ UNSAFE"
    print(f"Model: {result.get('model_path')}")
    print(f"Status: {status}")
    print(f"Integrity Verified: {result.get('integrity_verified')}")
    print(f"Tampering Detected: {result.get('tampering_detected')}")
    print(f"Weight Hash: {result.get('weight_hash')}")
    if result.get('anomalies'):
        print("\nAnomalies Found:")
        for anomaly in result['anomalies']:
            print(f"  [{anomaly.get('severity').upper()}] {anomaly.get('type')}: {anomaly.get('message')}")


if __name__ == "__main__":
    main()
