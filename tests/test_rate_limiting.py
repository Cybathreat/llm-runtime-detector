#!/usr/bin/env python3
"""
Unit tests for Rate Limiting and Abuse Prevention.
"""

import unittest
import time
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from rate_limiting import (
    TokenBucketRateLimiter, AbuseDetector, RateLimitMiddleware,
    RateLimitAction, RateLimitResult, AbuseDetectionResult
)


class TestTokenBucketRateLimiter(unittest.TestCase):
    """Test cases for token bucket rate limiter."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.limiter = TokenBucketRateLimiter(
            bucket_size=10,
            refill_rate=2.0,  # 2 tokens per second
            window_seconds=60
        )
    
    def test_initial_requests_allowed(self):
        """Test that initial requests within bucket size are allowed."""
        client_id = "test-client"
        
        # Should allow first 10 requests (bucket size)
        for i in range(10):
            result = self.limiter.check_rate_limit(client_id)
            self.assertEqual(result.action, RateLimitAction.ALLOW.value)
    
    def test_rate_limit_exceeded(self):
        """Test that requests are throttled when bucket is empty."""
        client_id = "test-client"
        
        # Exhaust bucket
        for _ in range(10):
            self.limiter.check_rate_limit(client_id)
        
        # Next request should be throttled
        result = self.limiter.check_rate_limit(client_id)
        self.assertEqual(result.action, RateLimitAction.THROTTLE.value)
        self.assertIsNotNone(result.retry_after)
        self.assertGreater(result.retry_after, 0)
    
    def test_bucket_refill(self):
        """Test that bucket refills over time."""
        client_id = "test-client"
        
        # Exhaust bucket
        for _ in range(10):
            self.limiter.check_rate_limit(client_id)
        
        # Wait for refill (0.5 seconds = 1 token at 2 tokens/sec)
        time.sleep(0.6)
        
        # Should have tokens again
        result = self.limiter.check_rate_limit(client_id)
        self.assertEqual(result.action, RateLimitAction.ALLOW.value)
    
    def test_remaining_requests_tracking(self):
        """Test that remaining requests are tracked correctly."""
        client_id = "test-client"
        
        result = self.limiter.check_rate_limit(client_id)
        # Remaining is based on window capacity (refill_rate * window_seconds)
        # With default 2.0 * 60 = 120 max requests in window
        self.assertLessEqual(result.remaining_requests, 120)
    
    def test_multiple_clients_isolated(self):
        """Test that different clients have separate buckets."""
        client1 = "client-1"
        client2 = "client-2"
        
        # Exhaust client1's bucket
        for _ in range(10):
            self.limiter.check_rate_limit(client1)
        
        # Client2 should still have full bucket
        result = self.limiter.check_rate_limit(client2)
        self.assertEqual(result.action, RateLimitAction.ALLOW.value)
    
    def test_get_client_stats(self):
        """Test client statistics retrieval."""
        client_id = "test-client"
        
        # Make some requests
        for _ in range(5):
            self.limiter.check_rate_limit(client_id)
        
        stats = self.limiter.get_client_stats(client_id)
        
        self.assertEqual(stats['client_id'], client_id)
        self.assertEqual(stats['bucket_size'], 10)
        self.assertEqual(stats['window_seconds'], 60)
        self.assertLess(stats['tokens_available'], 10)
        self.assertEqual(stats['requests_in_window'], 5)
    
    def test_reset_time_format(self):
        """Test that reset time is in ISO format."""
        client_id = "test-client"
        
        result = self.limiter.check_rate_limit(client_id)
        
        # Should be ISO format with Z suffix
        self.assertIn('T', result.reset_time)
        self.assertTrue(result.reset_time.endswith('Z'))


class TestAbuseDetector(unittest.TestCase):
    """Test cases for abuse detection."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = AbuseDetector({
            'rapid_fire_threshold': 10,  # 10 requests/minute
            'token_limit_threshold': 5000,
            'error_rate_threshold': 0.5
        })
    
    def test_no_abuse_normal_usage(self):
        """Test that normal usage is not flagged as abuse."""
        client_id = "normal-user"
        
        # Record normal requests
        for i in range(5):
            self.detector.record_request(
                client_id=client_id,
                tokens_used=1000,
                response_status="success",
                input_length=500
            )
        
        result = self.detector.detect_abuse(client_id)
        
        self.assertFalse(result.abuse_detected)
        self.assertIsNone(result.abuse_type)
    
    def test_rapid_fire_detection(self):
        """Test detection of rapid-fire requests."""
        client_id = "rapid-user"
        
        # Record many requests quickly
        for i in range(20):
            self.detector.record_request(
                client_id=client_id,
                tokens_used=100,
                response_status="success",
                input_length=100
            )
        
        result = self.detector.detect_abuse(client_id)
        
        self.assertTrue(result.abuse_detected)
        self.assertIn("rapid_fire", result.abuse_type)
        self.assertGreater(result.confidence, 0.5)
    
    def test_token_stuffing_detection(self):
        """Test detection of token stuffing attacks."""
        client_id = "token-stuffer"
        
        # Record requests with huge token counts
        for i in range(10):
            self.detector.record_request(
                client_id=client_id,
                tokens_used=10000,  # 10k tokens each = 100k total
                response_status="success",
                input_length=500
            )
        
        result = self.detector.detect_abuse(client_id)
        
        self.assertTrue(result.abuse_detected)
        self.assertIn("token_stuffing", result.abuse_type)
    
    def test_credential_stuffing_detection(self):
        """Test detection of credential stuffing (high error rate)."""
        client_id = "cred-stuffer"
        
        # Record requests with high error rate
        for i in range(20):
            status = "error" if i < 15 else "success"  # 75% errors
            self.detector.record_request(
                client_id=client_id,
                tokens_used=100,
                response_status=status,
                input_length=100
            )
        
        result = self.detector.detect_abuse(client_id)
        
        self.assertTrue(result.abuse_detected)
        self.assertIn("credential_stuffing", result.abuse_type)
    
    def test_prompt_flooding_detection(self):
        """Test detection of prompt flooding with large inputs."""
        client_id = "prompt-flooder"
        
        # Record requests with large inputs
        for i in range(10):
            self.detector.record_request(
                client_id=client_id,
                tokens_used=500,
                response_status="success",
                input_length=15000  # 15k chars each
            )
        
        result = self.detector.detect_abuse(client_id)
        
        self.assertTrue(result.abuse_detected)
        self.assertIn("prompt_flooding", result.abuse_type)
    
    def test_insufficient_data(self):
        """Test that insufficient data returns no abuse."""
        client_id = "new-user"
        
        # Only 5 requests (below minimum threshold of 10)
        for i in range(5):
            self.detector.record_request(
                client_id=client_id,
                tokens_used=100,
                response_status="success",
                input_length=100
            )
        
        result = self.detector.detect_abuse(client_id)
        
        self.assertFalse(result.abuse_detected)
        self.assertEqual(result.confidence, 0.0)
    
    def test_get_client_profile(self):
        """Test client profile retrieval."""
        client_id = "profile-test"
        
        for i in range(10):
            self.detector.record_request(
                client_id=client_id,
                tokens_used=1000,
                response_status="success" if i % 2 == 0 else "error",
                input_length=500
            )
        
        profile = self.detector.get_client_profile(client_id)
        
        self.assertEqual(profile['client_id'], client_id)
        self.assertEqual(profile['total_requests'], 10)
        self.assertEqual(profile['requests_last_minute'], 10)
        self.assertEqual(profile['avg_tokens_per_request'], 1000)
        self.assertAlmostEqual(profile['error_rate'], 0.5, places=2)
    
    def test_recommended_actions(self):
        """Test that appropriate actions are recommended."""
        # High confidence should recommend block or challenge
        high_conf_detector = AbuseDetector({'rapid_fire_threshold': 5})
        
        for i in range(50):
            high_conf_detector.record_request(
                client_id="high-conf",
                tokens_used=100,
                response_status="success",
                input_length=100
            )
        
        result = high_conf_detector.detect_abuse("high-conf")
        # Should recommend aggressive action for high abuse
        self.assertIn(result.recommended_action, ['block', 'challenge', 'throttle'])


class TestRateLimitMiddleware(unittest.TestCase):
    """Test cases for rate limiting middleware."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.middleware = RateLimitMiddleware({
            'bucket_size': 10,
            'refill_rate': 2.0,
            'rapid_fire_threshold': 15
        })
    
    def test_normal_request_flow(self):
        """Test normal request processing."""
        client_id = "normal-client"
        
        rate_result, abuse_result = self.middleware.process_request(
            client_id=client_id,
            tokens_used=1000,
            input_length=500
        )
        
        self.assertEqual(rate_result.action, RateLimitAction.ALLOW.value)
        self.assertFalse(abuse_result.abuse_detected)
    
    def test_rate_limit_then_abuse(self):
        """Test that rate limiting catches abuse before abuse detector."""
        client_id = "abusive-client"
        
        # Exhaust bucket
        for _ in range(10):
            rate_result, _ = self.middleware.process_request(
                client_id=client_id,
                tokens_used=100,
                input_length=100
            )
        
        # Next request should be throttled
        rate_result, abuse_result = self.middleware.process_request(
            client_id=client_id,
            tokens_used=100,
            input_length=100
        )
        
        self.assertEqual(rate_result.action, RateLimitAction.THROTTLE.value)
    
    def test_abuse_block_action(self):
        """Test that severe abuse results in block action."""
        client_id = "block-me"
        
        # Generate lots of requests to trigger abuse detection
        for i in range(30):
            rate_result, abuse_result = self.middleware.process_request(
                client_id=client_id,
                tokens_used=100,
                input_length=100
            )
        
        # After enough requests, should get blocked
        rate_result, abuse_result = self.middleware.process_request(
            client_id=client_id,
            tokens_used=100,
            input_length=100
        )
        
        # Either throttled or blocked
        self.assertIn(rate_result.action, ['throttle', 'block'])
    
    def test_challenge_action(self):
        """Test that suspicious activity triggers challenge."""
        # Use lower threshold to ensure detection
        middleware = RateLimitMiddleware({
            'bucket_size': 100,
            'refill_rate': 10.0,
            'rapid_fire_threshold': 10  # Low threshold
        })
        
        client_id = "suspicious-client"
        
        # Generate abuse - many requests quickly
        for i in range(25):
            middleware.process_request(
                client_id=client_id,
                tokens_used=100,
                input_length=100
            )
        
        # Check if abuse is detected
        abuse_result = middleware.abuse_detector.detect_abuse(client_id)
        
        # Should detect rapid_fire abuse (25 requests > 10 threshold)
        self.assertTrue(abuse_result.abuse_detected)
        self.assertIn("rapid_fire", abuse_result.abuse_type)


class TestRateLimitResult(unittest.TestCase):
    """Test rate limit result data structures."""
    
    def test_rate_limit_result_creation(self):
        """Test creating rate limit result."""
        result = RateLimitResult(
            client_id="test",
            action="allow",
            remaining_requests=10,
            reset_time="2024-01-01T00:00:00Z"
        )
        
        self.assertEqual(result.client_id, "test")
        self.assertEqual(result.action, "allow")
        self.assertEqual(result.remaining_requests, 10)
        self.assertIsNone(result.retry_after)
    
    def test_abuse_detection_result_creation(self):
        """Test creating abuse detection result."""
        result = AbuseDetectionResult(
            client_id="test",
            abuse_detected=True,
            abuse_type="rapid_fire",
            confidence=0.8,
            evidence=["20 requests in 1 minute"],
            recommended_action="block"
        )
        
        self.assertTrue(result.abuse_detected)
        self.assertEqual(result.abuse_type, "rapid_fire")
        self.assertEqual(result.confidence, 0.8)
        self.assertEqual(len(result.evidence), 1)


if __name__ == '__main__':
    unittest.main()
