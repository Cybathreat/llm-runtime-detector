#!/usr/bin/env python3
"""
LLM Runtime Rate Limiting and Abuse Prevention

Implements rate limiting, request quotas, and abuse detection
for LLM inference endpoints.
"""

import time
import hashlib
from collections import defaultdict
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timezone


class RateLimitAction(Enum):
    ALLOW = "allow"
    THROTTLE = "throttle"
    BLOCK = "block"
    CHALLENGE = "challenge"


@dataclass
class RateLimitResult:
    """Result of rate limit check."""
    client_id: str
    action: str
    remaining_requests: int
    reset_time: str
    retry_after: Optional[int] = None
    reason: Optional[str] = None


@dataclass
class AbuseDetectionResult:
    """Result of abuse pattern detection."""
    client_id: str
    abuse_detected: bool
    abuse_type: Optional[str]
    confidence: float
    evidence: List[str]
    recommended_action: str


class TokenBucketRateLimiter:
    """
    Token bucket rate limiter for LLM requests.
    
    Implements configurable rate limiting with:
    - Configurable bucket size (burst capacity)
    - Configurable refill rate
    - Per-client tracking
    - Sliding window support
    """
    
    def __init__(self, 
                 bucket_size: int = 100,
                 refill_rate: float = 10.0,  # tokens per second
                 window_seconds: int = 60):
        self.bucket_size = bucket_size
        self.refill_rate = refill_rate
        self.window_seconds = window_seconds
        self.buckets: Dict[str, Dict[str, Any]] = {}
    
    def _get_bucket(self, client_id: str) -> Dict[str, Any]:
        """Get or create token bucket for client."""
        if client_id not in self.buckets:
            self.buckets[client_id] = {
                'tokens': self.bucket_size,
                'last_update': time.time(),
                'requests': []
            }
        return self.buckets[client_id]
    
    def _refill_bucket(self, bucket: Dict[str, Any]) -> None:
        """Refill bucket based on elapsed time."""
        now = time.time()
        elapsed = now - bucket['last_update']
        
        # Add tokens based on elapsed time
        new_tokens = elapsed * self.refill_rate
        bucket['tokens'] = min(self.bucket_size, bucket['tokens'] + new_tokens)
        bucket['last_update'] = now
    
    def check_rate_limit(self, client_id: str) -> RateLimitResult:
        """
        Check if request should be allowed.
        
        Args:
            client_id: Unique client identifier (IP, API key, user ID)
            
        Returns:
            RateLimitResult with action and metadata
        """
        bucket = self._get_bucket(client_id)
        self._refill_bucket(bucket)
        
        # Clean old requests from sliding window
        cutoff = time.time() - self.window_seconds
        bucket['requests'] = [r for r in bucket['requests'] if r > cutoff]
        
        # Calculate remaining requests in window
        window_requests = len(bucket['requests'])
        max_window_requests = int(self.refill_rate * self.window_seconds)
        remaining = max(0, max_window_requests - window_requests)
        
        # Determine action
        if bucket['tokens'] >= 1:
            bucket['tokens'] -= 1
            bucket['requests'].append(time.time())
            
            return RateLimitResult(
                client_id=client_id,
                action=RateLimitAction.ALLOW.value,
                remaining_requests=remaining,
                reset_time=self._format_reset_time(bucket['last_update'] + self.window_seconds),
                retry_after=None
            )
        else:
            # Calculate retry-after
            tokens_needed = 1 - bucket['tokens']
            retry_after = int(tokens_needed / self.refill_rate) + 1
            
            return RateLimitResult(
                client_id=client_id,
                action=RateLimitAction.THROTTLE.value,
                remaining_requests=0,
                reset_time=self._format_reset_time(bucket['last_update'] + self.window_seconds),
                retry_after=retry_after,
                reason="Rate limit exceeded"
            )
    
    def _format_reset_time(self, timestamp: float) -> str:
        """Format reset timestamp as ISO string."""
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat().replace('+00:00', 'Z')
    
    def get_client_stats(self, client_id: str) -> Dict[str, Any]:
        """Get current rate limit stats for client."""
        bucket = self._get_bucket(client_id)
        self._refill_bucket(bucket)
        
        return {
            'client_id': client_id,
            'tokens_available': bucket['tokens'],
            'bucket_size': self.bucket_size,
            'requests_in_window': len(bucket['requests']),
            'window_seconds': self.window_seconds,
            'refill_rate': self.refill_rate
        }


class AbuseDetector:
    """
    Detects abuse patterns in LLM API usage.
    
    Detects:
    - Rapid-fire requests (DoS attempts)
    - Token stuffing attacks
    - Prompt injection flooding
    - Unusual usage patterns
    - Credential stuffing
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.request_history: Dict[str, List[Dict]] = defaultdict(list)
        self.baseline_stats: Dict[str, Dict] = {}
        
        # Configurable thresholds
        self.rapid_fire_threshold = self.config.get('rapid_fire_threshold', 50)  # requests/minute
        self.token_limit_threshold = self.config.get('token_limit_threshold', 100000)  # tokens/minute
        self.error_rate_threshold = self.config.get('error_rate_threshold', 0.5)  # 50% errors
        
    def record_request(self, 
                       client_id: str, 
                       tokens_used: int = 0, 
                       response_status: str = "success",
                       input_length: int = 0) -> None:
        """Record a request for abuse analysis."""
        now = time.time()
        self.request_history[client_id].append({
            'timestamp': now,
            'tokens': tokens_used,
            'status': response_status,
            'input_length': input_length
        })
        
        # Keep only last 10 minutes of history
        cutoff = now - 600
        self.request_history[client_id] = [
            r for r in self.request_history[client_id] if r['timestamp'] > cutoff
        ]
    
    def detect_abuse(self, client_id: str) -> AbuseDetectionResult:
        """
        Analyze client behavior for abuse patterns.
        
        Args:
            client_id: Client identifier to analyze
            
        Returns:
            AbuseDetectionResult with findings
        """
        history = self.request_history.get(client_id, [])
        
        if len(history) < 10:
            # Not enough data
            return AbuseDetectionResult(
                client_id=client_id,
                abuse_detected=False,
                abuse_type=None,
                confidence=0.0,
                evidence=[],
                recommended_action="allow"
            )
        
        # Analyze patterns
        abuse_types = []
        evidence = []
        confidence_scores = []
        
        # Check rapid-fire requests
        now = time.time()
        minute_ago = now - 60
        recent_requests = [r for r in history if r['timestamp'] > minute_ago]
        
        if len(recent_requests) > self.rapid_fire_threshold:
            abuse_types.append("rapid_fire")
            evidence.append(f"{len(recent_requests)} requests in last minute (threshold: {self.rapid_fire_threshold})")
            confidence_scores.append(0.8)
        
        # Check token stuffing
        tokens_last_minute = sum(r['tokens'] for r in recent_requests)
        if tokens_last_minute > self.token_limit_threshold:
            abuse_types.append("token_stuffing")
            evidence.append(f"{tokens_last_minute} tokens in last minute (threshold: {self.token_limit_threshold})")
            confidence_scores.append(0.7)
        
        # Check error rate (potential credential stuffing)
        errors = [r for r in recent_requests if r['status'] in ['error', 'unauthorized', 'forbidden']]
        if len(recent_requests) > 0:
            error_rate = len(errors) / len(recent_requests)
            if error_rate > self.error_rate_threshold:
                abuse_types.append("credential_stuffing")
                evidence.append(f"{error_rate:.1%} error rate (threshold: {self.error_rate_threshold:.1%})")
                confidence_scores.append(0.6)
        
        # Check for prompt injection flooding
        large_inputs = [r for r in recent_requests if r['input_length'] > 10000]
        if len(large_inputs) > 5:
            abuse_types.append("prompt_flooding")
            evidence.append(f"{len(large_inputs)} large inputs (>10k chars) in last minute")
            confidence_scores.append(0.75)
        
        # Determine overall result
        if not abuse_types:
            return AbuseDetectionResult(
                client_id=client_id,
                abuse_detected=False,
                abuse_type=None,
                confidence=0.0,
                evidence=[],
                recommended_action="allow"
            )
        
        confidence = max(confidence_scores)
        
        # Determine recommended action
        if confidence > 0.8:
            action = "block"
        elif confidence > 0.6:
            action = "challenge"
        else:
            action = "throttle"
        
        return AbuseDetectionResult(
            client_id=client_id,
            abuse_detected=True,
            abuse_type=",".join(abuse_types),
            confidence=confidence,
            evidence=evidence,
            recommended_action=action
        )
    
    def get_client_profile(self, client_id: str) -> Dict[str, Any]:
        """Get usage profile for client."""
        history = self.request_history.get(client_id, [])
        
        if not history:
            return {'client_id': client_id, 'total_requests': 0}
        
        now = time.time()
        minute_ago = now - 60
        
        recent = [r for r in history if r['timestamp'] > minute_ago]
        
        return {
            'client_id': client_id,
            'total_requests': len(history),
            'requests_last_minute': len(recent),
            'tokens_last_minute': sum(r['tokens'] for r in recent),
            'avg_tokens_per_request': sum(r['tokens'] for r in history) / len(history) if history else 0,
            'error_rate': sum(1 for r in recent if r['status'] == 'error') / len(recent) if recent else 0
        }


class RateLimitMiddleware:
    """
    Middleware for applying rate limiting to LLM requests.
    
    Combines rate limiting with abuse detection for
    comprehensive API protection.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.rate_limiter = TokenBucketRateLimiter(
            bucket_size=self.config.get('bucket_size', 100),
            refill_rate=self.config.get('refill_rate', 10.0),
            window_seconds=self.config.get('window_seconds', 60)
        )
        self.abuse_detector = AbuseDetector(self.config)
    
    def process_request(self, 
                        client_id: str, 
                        tokens_used: int = 0,
                        input_length: int = 0) -> Tuple[RateLimitResult, Optional[AbuseDetectionResult]]:
        """
        Process incoming request through rate limiting and abuse detection.
        
        Args:
            client_id: Client identifier
            tokens_used: Estimated tokens for this request
            input_length: Length of input prompt
            
        Returns:
            Tuple of (RateLimitResult, AbuseDetectionResult or None)
        """
        # Check rate limit first
        rate_result = self.rate_limiter.check_rate_limit(client_id)
        
        if rate_result.action != RateLimitAction.ALLOW.value:
            return rate_result, None
        
        # Record for abuse detection
        self.abuse_detector.record_request(
            client_id=client_id,
            tokens_used=tokens_used,
            response_status="success",
            input_length=input_length
        )
        
        # Check for abuse patterns
        abuse_result = self.abuse_detector.detect_abuse(client_id)
        
        if abuse_result.abuse_detected:
            if abuse_result.recommended_action == "block":
                return RateLimitResult(
                    client_id=client_id,
                    action=RateLimitAction.BLOCK.value,
                    remaining_requests=0,
                    reset_time=rate_result.reset_time,
                    retry_after=300,
                    reason=f"Abuse detected: {abuse_result.abuse_type}"
                ), abuse_result
            elif abuse_result.recommended_action == "challenge":
                return RateLimitResult(
                    client_id=client_id,
                    action=RateLimitAction.CHALLENGE.value,
                    remaining_requests=rate_result.remaining_requests,
                    reset_time=rate_result.reset_time,
                    reason=f"Suspicious activity: {abuse_result.abuse_type}"
                ), abuse_result
        
        return rate_result, abuse_result


def main():
    """CLI entry point for rate limiting demo."""
    import argparse
    
    parser = argparse.ArgumentParser(description="LLM Rate Limiting Demo")
    parser.add_argument("--client", default="test-client", help="Client ID")
    parser.add_argument("--requests", type=int, default=10, help="Number of requests to simulate")
    args = parser.parse_args()
    
    middleware = RateLimitMiddleware()
    
    print(f"Simulating {args.requests} requests for client: {args.client}\n")
    
    for i in range(args.requests):
        rate_result, abuse_result = middleware.process_request(
            client_id=args.client,
            tokens_used=1000,
            input_length=500
        )
        
        print(f"Request {i+1}: {rate_result.action}")
        if rate_result.retry_after:
            print(f"  Retry after: {rate_result.retry_after}s")
        if abuse_result and abuse_result.abuse_detected:
            print(f"  Abuse detected: {abuse_result.abuse_type}")
    
    # Print final stats
    print("\nFinal stats:")
    stats = middleware.rate_limiter.get_client_stats(args.client)
    print(f"  Tokens available: {stats['tokens_available']:.1f}")
    print(f"  Requests in window: {stats['requests_in_window']}")


if __name__ == "__main__":
    main()
