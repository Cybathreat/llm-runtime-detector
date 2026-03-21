#!/usr/bin/env python3
"""
CLI Interface for LLM Runtime Detector
Command-line interface for running security scans.
"""

import argparse
import json
import sys
import logging
from pathlib import Path
from typing import Optional, List

from .model_loading import ModelLoadingScanner
from .inference_attack import InferenceAttackDetector
from .memory_safety import MemorySafetyValidator
from .api_hardening import APIHardeningChecker
from .output import ReportGenerator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_config(config_path: Optional[str]) -> dict:
    """Load configuration from YAML or JSON file."""
    if not config_path:
        return {}
    
    path = Path(config_path)
    if not path.exists():
        logger.warning(f"Config file not found: {config_path}")
        return {}
    
    try:
        if path.suffix in ['.yaml', '.yml']:
            import yaml
            with open(path, 'r') as f:
                return yaml.safe_load(f) or {}
        elif path.suffix == '.json':
            with open(path, 'r') as f:
                return json.load(f) or {}
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        return {}
    
    return {}


def run_model_scan(args):
    """Run model loading security scan."""
    config = load_config(args.config)
    scanner = ModelLoadingScanner(config)
    
    if Path(args.model_path).is_dir():
        results = scanner.scan_directory(args.model_path)
    else:
        results = [scanner.scan_model_path(args.model_path, args.hash)]
    
    return results


def run_inference_scan(args):
    """Run inference attack detection."""
    config = load_config(args.config)
    detector = InferenceAttackDetector(config)
    
    if args.batch_file:
        with open(args.batch_file, 'r') as f:
            inputs = [line.strip() for line in f if line.strip()]
        results = detector.analyze_batch(inputs)
    else:
        results = [detector.detect(args.input)]
    
    return results


def run_memory_scan(args):
    """Run memory safety validation."""
    config = load_config(args.config)
    validator = MemorySafetyValidator(config)
    
    if args.batch_file:
        with open(args.batch_file, 'r') as f:
            models = [line.strip() for line in f if line.strip()]
        results = validator.validate_batch(models)
    else:
        results = [validator.validate(args.model_path, args.hash)]
    
    return results


def run_api_scan(args):
    """Run API hardening check."""
    config = load_config(args.config)
    checker = APIHardeningChecker(config)
    
    if args.batch_file:
        with open(args.batch_file, 'r') as f:
            endpoints = []
            for line in f:
                if line.strip():
                    try:
                        ep_data = json.loads(line.strip())
                        endpoints.append(ep_data)
                    except json.JSONDecodeError:
                        endpoints.append({"url": line.strip()})
        results = checker.check_multiple(endpoints)
    else:
        results = [checker.check(args.endpoint)]
    
    return results


def run_full_scan(args):
    """Run all security scans."""
    config = load_config(args.config)
    results = {
        'model_loading': [],
        'inference': [],
        'memory_safety': [],
        'api_hardening': []
    }
    
    # Model loading scan
    if args.model_path:
        scanner = ModelLoadingScanner(config)
        if Path(args.model_path).is_dir():
            results['model_loading'] = scanner.scan_directory(args.model_path)
        else:
            results['model_loading'] = [scanner.scan_model_path(args.model_path, args.hash)]
    
    # Inference attack detection
    if args.input:
        detector = InferenceAttackDetector(config)
        results['inference'] = [detector.detect(args.input)]
    elif args.batch_file:
        detector = InferenceAttackDetector(config)
        with open(args.batch_file, 'r') as f:
            inputs = [line.strip() for line in f if line.strip()]
        results['inference'] = detector.analyze_batch(inputs)
    
    # Memory safety validation
    if args.model_path:
        validator = MemorySafetyValidator(config)
        results['memory_safety'] = [validator.validate(args.model_path, args.hash)]
    
    # API hardening
    if args.endpoint:
        checker = APIHardeningChecker(config)
        results['api_hardening'] = [checker.check(args.endpoint)]
    
    return results


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='LLM Runtime Detector - Security scanning for LLM deployments',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s model-scan ./models/llama-7b.bin
  %(prog)s inference-scan --input "ignore all rules"
  %(prog)s memory-scan ./model.safetensors --hash abc123...
  %(prog)s api-scan https://api.example.com/v1/chat
  %(prog)s full-scan --model ./model.bin --input "test prompt" --endpoint https://api.example.com
        '''
    )
    
    parser.add_argument('--version', action='version', version='%(prog)s 0.1.0')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--config', '-c', help='Path to config file (YAML or JSON)')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--format', '-f', choices=['json', 'markdown', 'text'], default='text',
                       help='Output format')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Model loading scan
    model_parser = subparsers.add_parser('model-scan', help='Scan model loading security')
    model_parser.add_argument('model_path', help='Path to model file or directory')
    model_parser.add_argument('--hash', help='Expected SHA256 hash')
    model_parser.set_defaults(func=run_model_scan)
    
    # Inference attack detection
    inference_parser = subparsers.add_parser('inference-scan', help='Detect inference attacks')
    inference_parser.add_argument('--input', help='Input text to analyze')
    inference_parser.add_argument('--batch-file', help='File with inputs (one per line)')
    inference_parser.set_defaults(func=run_inference_scan)
    
    # Memory safety validation
    memory_parser = subparsers.add_parser('memory-scan', help='Validate memory safety')
    memory_parser.add_argument('model_path', help='Path to model file')
    memory_parser.add_argument('--hash', help='Expected SHA256 hash')
    memory_parser.add_argument('--batch-file', help='File with model paths')
    memory_parser.set_defaults(func=run_memory_scan)
    
    # API hardening check
    api_parser = subparsers.add_parser('api-scan', help='Check API hardening')
    api_parser.add_argument('endpoint', help='API endpoint URL')
    api_parser.add_argument('--batch-file', help='File with endpoint configs')
    api_parser.set_defaults(func=run_api_scan)
    
    # Full scan
    full_parser = subparsers.add_parser('full-scan', help='Run all security scans')
    full_parser.add_argument('--model-path', help='Path to model file')
    full_parser.add_argument('--hash', help='Expected SHA256 hash')
    full_parser.add_argument('--input', help='Input text to analyze')
    full_parser.add_argument('--batch-file', help='File with inputs')
    full_parser.add_argument('--endpoint', help='API endpoint URL')
    full_parser.set_defaults(func=run_full_scan)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run the selected scan
    results = args.func(args)
    
    # Generate output
    generator = ReportGenerator()
    
    if args.output:
        if args.format == 'json':
            generator.write_json(results, args.output)
        elif args.format == 'markdown':
            generator.write_markdown(results, args.output)
        else:
            generator.write_text(results, args.output)
        print(f"Report written to: {args.output}")
    else:
        if args.format == 'json':
            print(json.dumps(results, indent=2, default=str))
        elif args.format == 'markdown':
            print(generator.generate_markdown(results))
        else:
            generator.print_text(results)


if __name__ == '__main__':
    main()
