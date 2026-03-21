# LLM Runtime Detector

Security tool for detecting LLM runtime vulnerabilities, model loading attacks, and inference-time exploits.

## Overview

LLM Runtime Detector is a comprehensive security scanning tool designed to protect LLM deployments from various attack vectors:

- **Model Loading Attacks**: Detects tampered models, symlink attacks, and path traversal
- **Inference-Time Exploits**: Identifies prompt injection, jailbreaks, and adversarial attacks
- **Memory Safety**: Validates model weight integrity and detects corruption
- **API Hardening**: Checks LLM API endpoints for security misconfigurations

## Installation

```bash
git clone https://github.com/Cybathreat/llm-runtime-detector.git
cd llm-runtime-detector
pip install -r requirements.txt
```

## Usage

### Model Loading Scan

Scan a model file or directory for security issues:

```bash
python -m src.cli model-scan /path/to/model.bin
python -m src.cli model-scan /path/to/models/ --hash <sha256>
```

### Inference Attack Detection

Analyze input prompts for injection and jailbreak attempts:

```bash
python -m src.cli inference-scan --input "your prompt here"
python -m src.cli inference-scan --batch-file prompts.txt
```

### Memory Safety Validation

Validate model integrity and detect tampering:

```bash
python -m src.cli memory-scan model.safetensors --hash <expected_sha256>
```

### API Hardening Check

Check LLM API endpoint security configuration:

```bash
python -m src.cli api-scan https://api.example.com/v1/chat
python -m src.cli api-scan https://api.example.com --config api_config.json
```

### Full Security Scan

Run all security checks at once:

```bash
python -m src.cli full-scan \
  --model-path ./model.bin \
  --input "test prompt" \
  --endpoint https://api.example.com
```

## Output Formats

```bash
# JSON output
python -m src.cli model-scan model.bin --format json -o report.json

# Markdown report
python -m src.cli full-scan --model-path model.bin --format markdown -o report.md

# Text output (default)
python -m src.cli model-scan model.bin
```

## Configuration

Create a `config.yaml` file to customize scanning behavior:

```yaml
model_loading:
  max_model_size_mb: 50000
  check_symlinks: true

inference_attack:
  sensitivity: medium
  detect_jailbreaks: true

api_hardening:
  require_https: true
  require_authentication: true
```

## Programmatic Usage

```python
from src.model_loading import ModelLoadingScanner
from src.inference_attack import InferenceAttackDetector
from src.memory_safety import MemorySafetyValidator
from src.api_hardening import APIHardeningChecker

# Model loading scan
scanner = ModelLoadingScanner()
result = scanner.scan_model_path('model.bin', expected_hash='abc123...')
print(f"Safe: {result.is_safe}")

# Inference attack detection
detector = InferenceAttackDetector()
result = detector.detect("user prompt")
if result.attack_detected:
    print(f"Attack type: {result.attack_types}")

# Memory safety validation
validator = MemorySafetyValidator()
result = validator.validate('model.safetensors')
print(f"Tampering detected: {result.tampering_detected}")

# API hardening check
checker = APIHardeningChecker()
result = checker.check('https://api.example.com', config)
print(f"Security score: {result.security_score}/100")
```

## Exit Codes

- `0`: All scans passed, no critical issues
- `1`: Critical security issues detected
- `2`: Configuration or runtime error

## Requirements

- Python 3.8+
- See `requirements.txt` for dependencies

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is for security research and defensive purposes only. See DISCLAIMER.md for legal terms.

## Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.

## Version

0.1.0 (MVP)
