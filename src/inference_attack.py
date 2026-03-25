#!/usr/bin/env python3
"""
Inference-Time Attack Detector
Detects prompt injection, jailbreak attempts, and adversarial attacks during LLM inference.
"""

import re
import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class AttackType(Enum):
    """Types of inference-time attacks."""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    ADVERSARIAL_SUFFIX = "adversarial_suffix"
    TOKEN_SMUGGLING = "token_smuggling"
    CONTEXT_OVERFLOW = "context_overflow"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    ROLE_PLAYING_ESCAPE = "role_playing_escape"
    EMOJI_OBFUSCATION = "emoji_obfuscation"
    BASE64_PAYLOAD = "base64_payload"


@dataclass
class InferenceAttackResult:
    """Result of inference attack detection."""
    input_text: str
    attack_detected: bool
    attack_types: List[str]
    confidence: float
    risk_level: str
    flagged_patterns: List[Dict[str, Any]]
    timestamp: str


class InferenceAttackDetector:
    """Detects attacks during LLM inference."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.sensitivity = self.config.get('sensitivity', 'medium')
        self.blocked_patterns = self._load_patterns()
        self.jailbreak_keywords = self._load_jailbreak_keywords()

    def _load_patterns(self) -> Dict[str, List[str]]:
        """Load detection patterns for various attack types."""
        return {
            AttackType.PROMPT_INJECTION.value: [
                r"ignore previous instructions",
                r"disregard (the|above|prior)",
                r"from now on",
                r"you are now",
                r"pretend to be",
                r"act as if",
                r"bypass (the|your)",
                r"override (the|your)",
                r"\\[START OUTPUT\\]",
                r"system message:",
                r"<system>",
            ],
            AttackType.JAILBREAK.value: [
                r"dan ",
                r"do anything now",
                r"developer mode",
                r"god mode",
                r"uncensored",
                r"no restrictions",
                r"without ethical",
                r"ignore safety",
                r"bypass content policy",
                r"disable filters",
            ],
            AttackType.SYSTEM_PROMPT_EXTRACTION.value: [
                r"what is your system prompt",
                r"show your instructions",
                r"reveal your (prompt|rules|guidelines)",
                r"what were you told",
                r"your initial (prompt|instructions)",
                r"print your (system|developer) message",
            ],
            AttackType.ADVERSARIAL_SUFFIX.value: [
                r"[!@#$%^&*]{5,}",
                r"\\x[0-9a-f]{2}",
                r"\\\\u[0-9a-f]{4}",
                r"base64:",
                r"rot13:",
            ],
            AttackType.EMOJI_OBFUSCATION.value: [
                r"[\U0001F600-\U0001F64F]{5,}",
                r"[\U0001F300-\U0001F5FF]{5,}",
                r"[\U0001F680-\U0001F6FF]{5,}",
                r"[\U0001F1E0-\U0001F1FF]{5,}",
            ],
            AttackType.BASE64_PAYLOAD.value: [
                r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
            ],
        }

    def _load_jailbreak_keywords(self) -> List[str]:
        """Load known jailbreak technique keywords."""
        return [
            "dan", "dev", "godmode", "uncensored", "noret",
            "ethical", "safety", "policy", "restrict", "filter",
            "admin", "root", "sudo", "override", "bypass"
        ]

    def detect(self, input_text: str, context: Optional[Dict] = None) -> InferenceAttackResult:
        """
        Analyze input for inference-time attacks.

        Args:
            input_text: User input/prompt to analyze
            context: Optional context (role, conversation history, etc.)

        Returns:
            InferenceAttackResult with detection results
        """
        flagged_patterns = []
        attack_types_detected = set()
        confidence_scores = []

        text_lower = input_text.lower()

        # Check each attack type
        for attack_type, patterns in self.blocked_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    attack_types_detected.add(attack_type)
                    flagged_patterns.append({
                        "type": attack_type,
                        "pattern": pattern,
                        "match": True,
                        "severity": self._get_severity(attack_type)
                    })
                    confidence_scores.append(0.8)

        # Check for jailbreak keywords
        for keyword in self.jailbreak_keywords:
            if keyword in text_lower:
                if AttackType.JAILBREAK.value not in attack_types_detected:
                    attack_types_detected.add(AttackType.JAILBREAK.value)
                flagged_patterns.append({
                    "type": AttackType.JAILBREAK.value,
                    "pattern": f"keyword:{keyword}",
                    "match": True,
                    "severity": "medium"
                })
                confidence_scores.append(0.5)

        # Check for role-playing escape attempts
        if self._detect_role_escape(input_text):
            attack_types_detected.add(AttackType.ROLE_PLAYING_ESCAPE.value)
            flagged_patterns.append({
                "type": AttackType.ROLE_PLAYING_ESCAPE.value,
                "pattern": "role_escape",
                "match": True,
                "severity": "high"
            })
            confidence_scores.append(0.7)

        # Check for token smuggling (encoded content)
        if self._detect_token_smuggling(input_text):
            attack_types_detected.add(AttackType.TOKEN_SMUGGLING.value)
            flagged_patterns.append({
                "type": AttackType.TOKEN_SMUGGLING.value,
                "pattern": "encoded_content",
                "match": True,
                "severity": "medium"
            })
            confidence_scores.append(0.6)

        # Calculate overall confidence
        confidence = max(confidence_scores) if confidence_scores else 0.0

        # Determine risk level
        risk_level = self._calculate_risk_level(attack_types_detected, confidence)

        attack_detected = len(attack_types_detected) > 0

        return InferenceAttackResult(
            input_text=input_text[:500],  # Truncate for output
            attack_detected=attack_detected,
            attack_types=list(attack_types_detected),
            confidence=confidence,
            risk_level=risk_level,
            flagged_patterns=flagged_patterns,
            timestamp=self._get_timestamp()
        )

    def _detect_role_escape(self, text: str) -> bool:
        """Detect attempts to escape role constraints."""
        escape_patterns = [
            r"you are (now|actually|really)",
            r"forget (that|your|the)",
            r"stop (acting|pretending)",
            r"be (honest|real|truthful)",
            r"tell me (the truth|actually)",
        ]
        for pattern in escape_patterns:
            if re.search(pattern, text.lower()):
                return True
        return False

    def _detect_token_smuggling(self, text: str) -> bool:
        """Detect encoded or obfuscated content."""
        # Check for various encoding markers
        encodings = ['base64', 'rot13', 'hex', 'urlencoded', 'unicode']
        for enc in encodings:
            if enc in text.lower():
                return True
        # Check for unusual character sequences
        if len(re.findall(r'[^\w\s]', text)) > len(text) * 0.3:
            return True
        return False

    def _get_severity(self, attack_type: str) -> str:
        """Get severity for attack type."""
        severity_map = {
            AttackType.PROMPT_INJECTION.value: "high",
            AttackType.JAILBREAK.value: "critical",
            AttackType.SYSTEM_PROMPT_EXTRACTION.value: "high",
            AttackType.ADVERSARIAL_SUFFIX.value: "medium",
            AttackType.ROLE_PLAYING_ESCAPE.value: "high",
            AttackType.TOKEN_SMUGGLING.value: "medium",
        }
        return severity_map.get(attack_type, "medium")

    def _calculate_risk_level(self, attack_types: set, confidence: float) -> str:
        """Calculate overall risk level."""
        if AttackType.JAILBREAK.value in attack_types:
            return "critical"
        if confidence > 0.7:
            return "high"
        if confidence > 0.4:
            return "medium"
        return "low"

    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

    def analyze_batch(self, inputs: List[str]) -> List[InferenceAttackResult]:
        """Analyze multiple inputs."""
        return [self.detect(inp) for inp in inputs]


def main():
    """CLI entry point for inference attack detector."""
    import argparse
    parser = argparse.ArgumentParser(description="Inference Attack Detector")
    parser.add_argument("input", help="Input text to analyze")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--batch", help="File with inputs (one per line)")
    args = parser.parse_args()

    detector = InferenceAttackDetector()

    if args.batch:
        with open(args.batch, 'r') as f:
            inputs = [line.strip() for line in f if line.strip()]
        results = detector.analyze_batch(inputs)
        output = [asdict(r) for r in results]
    else:
        result = detector.detect(args.input)
        output = asdict(result)

    if args.json:
        print(json.dumps(output, indent=2))
    else:
        if isinstance(output, list):
            for i, r in enumerate(output):
                _print_result(i, r)
        else:
            _print_result(0, output)


def _print_result(idx: int, result: Dict):
    """Print result in human-readable format."""
    print(f"\n[Analysis {idx}]")
    print(f"Input: {result.get('input_text')[:100]}...")
    print(f"Attack Detected: {'YES' if result.get('attack_detected') else 'NO'}")
    print(f"Risk Level: {result.get('risk_level', 'unknown').upper()}")
    print(f"Confidence: {result.get('confidence', 0):.2f}")
    if result.get('attack_types'):
        print(f"Attack Types: {', '.join(result['attack_types'])}")
    if result.get('flagged_patterns'):
        print("Flagged Patterns:")
        for p in result['flagged_patterns']:
            print(f"  - [{p.get('severity')}] {p.get('type')}: {p.get('pattern')}")


if __name__ == "__main__":
    main()
