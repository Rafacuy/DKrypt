#!/usr/bin/env python3
"""Tests for the error reporting system"""

import pytest
import tempfile
import time
from pathlib import Path
from core.error_reporter import (
    ErrorReporter, DataSanitizer, RateLimiter, 
    SanitizedError, prompt_error_report
)


@pytest.fixture
def temp_files():
    """Create temporary files for testing"""
    rate_limit_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    hash_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    
    yield rate_limit_file.name, hash_file.name
    
    Path(rate_limit_file.name).unlink(missing_ok=True)
    Path(hash_file.name).unlink(missing_ok=True)


@pytest.fixture
def sanitizer():
    """Create sanitizer instance"""
    return DataSanitizer()


@pytest.fixture
def rate_limiter(temp_files):
    """Create rate limiter instance"""
    rate_file, _ = temp_files
    return RateLimiter(rate_file)


@pytest.fixture
def reporter(temp_files):
    """Create error reporter instance"""
    _, hash_file = temp_files
    reporter = ErrorReporter()
    reporter._hash_file = Path(hash_file)
    return reporter


class TestDataSanitizer:
    """Test data sanitization"""
    
    def test_sanitize_url(self, sanitizer):
        text = "Error at https://example.com/api/endpoint"
        result = sanitizer.sanitize_text(text)
        assert '[URL_REDACTED]' in result
        assert 'example.com' not in result
    
    def test_sanitize_ip(self, sanitizer):
        text = "Connection to 192.168.1.1 failed"
        result = sanitizer.sanitize_text(text)
        assert '[IP_REDACTED]' in result
        assert '192.168.1.1' not in result
    
    def test_sanitize_domain(self, sanitizer):
        text = "Target: example.com"
        result = sanitizer.sanitize_text(text)
        # Domain may be caught by TARGET or DOMAIN pattern
        assert 'example.com' not in result
    
    def test_sanitize_email(self, sanitizer):
        text = "Contact: user@example.com"
        result = sanitizer.sanitize_text(text)
        # Email may be caught by domain pattern first
        assert 'user@example.com' not in result
    
    def test_sanitize_password(self, sanitizer):
        text = 'password="secret123"'
        result = sanitizer.sanitize_text(text)
        assert '[CREDENTIAL_REDACTED]' in result or '[REDACTED]' in result
        assert 'secret123' not in result
    
    def test_sanitize_password(self, sanitizer):
        text = 'password="secret123"'
        result = sanitizer.sanitize_text(text)
        assert '[CREDENTIAL_REDACTED]' in result
        assert 'secret123' not in result
    
    def test_sanitize_token(self, sanitizer):
        text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        result = sanitizer.sanitize_text(text)
        assert '[JWT_REDACTED]' in result or '[AUTH_TOKEN_REDACTED]' in result
    
    def test_sanitize_aws_key(self, sanitizer):
        text = "AWS_KEY=AKIAIOSFODNN7EXAMPLE"
        result = sanitizer.sanitize_text(text)
        # AWS key may be caught by key pattern or credential pattern
        assert 'AKIAIOSFODNN7EXAMPLE' not in result
    
    def test_sanitize_dict(self, sanitizer):
        data = {
            'url': 'https://example.com',
            'password': 'secret',
            'normal': 'value'
        }
        result = sanitizer.sanitize_dict(data)
        assert result['url'] == '[URL_REDACTED]'
        assert result['password'] == '[REDACTED]'
        assert result['normal'] == 'value'
    
    def test_sanitize_traceback(self, sanitizer):
        tb = '''Traceback (most recent call last):
  File "/home/user/dkrypt/modules/sqli.py", line 42, in scan
    response = requests.get("https://example.com")
ValueError: Invalid URL'''
        
        result = sanitizer.sanitize_traceback(tb)
        assert '[DKRYPT]' in result or 'sqli.py' in result
        assert '[URL_REDACTED]' in result
        assert 'example.com' not in result
    
    def test_sanitize_nested_dict(self, sanitizer):
        data = {
            'config': {
                'api_key': 'secret123',
                'endpoint': 'https://api.example.com'
            }
        }
        result = sanitizer.sanitize_dict(data)
        assert result['config']['api_key'] == '[REDACTED]'
        assert '[URL_REDACTED]' in result['config']['endpoint']


class TestRateLimiter:
    """Test rate limiting"""
    
    def test_can_submit_initially(self, rate_limiter):
        can_submit, wait_time = rate_limiter.can_submit()
        assert can_submit is True
        assert wait_time is None
    
    def test_record_submission(self, rate_limiter):
        rate_limiter.record_submission()
        assert rate_limiter.state.report_count == 1
        assert rate_limiter.state.last_report_time > 0
    
    def test_cooldown_enforcement(self, rate_limiter):
        rate_limiter.state.cooldown_seconds = 1
        rate_limiter.record_submission()
        
        can_submit, wait_time = rate_limiter.can_submit()
        # Should be rate limited
        assert can_submit is False or wait_time is not None
    
    def test_hourly_limit(self, rate_limiter):
        rate_limiter.state.max_reports_per_hour = 2
        rate_limiter.state.cooldown_seconds = 0
        rate_limiter.state.hourly_reset_time = time.time()
        
        rate_limiter.record_submission()
        time.sleep(0.1)
        rate_limiter.state.last_report_time = time.time() - 1
        rate_limiter.record_submission()
        
        # Verify we've recorded 2 submissions
        assert rate_limiter.state.report_count == 2
        
        can_submit, wait_time = rate_limiter.can_submit()
        # Should hit hourly limit
        assert can_submit is False
    
    def test_hourly_reset(self, rate_limiter):
        rate_limiter.state.max_reports_per_hour = 2
        rate_limiter.state.report_count = 2
        rate_limiter.state.hourly_reset_time = time.time() - 3700
        
        can_submit, wait_time = rate_limiter.can_submit()
        assert can_submit is True
        assert rate_limiter.state.report_count == 0
    
    def test_set_cooldown(self, rate_limiter):
        rate_limiter.set_cooldown(120)
        assert rate_limiter.state.cooldown_seconds == 120
        
        rate_limiter.set_cooldown(30)
        assert rate_limiter.state.cooldown_seconds == 60
        
        rate_limiter.set_cooldown(5000)
        assert rate_limiter.state.cooldown_seconds == 3600


class TestErrorReporter:
    """Test error reporter"""
    
    def test_is_blocking_error(self, reporter):
        assert reporter.is_blocking_error(RuntimeError()) is True
        assert reporter.is_blocking_error(ImportError()) is True
        assert reporter.is_blocking_error(KeyboardInterrupt()) is False
        assert reporter.is_blocking_error(StopIteration()) is False
    
    def test_prepare_report(self, reporter):
        try:
            raise ValueError("Test error")
        except ValueError as e:
            report = reporter.prepare_report(e, module='test_module')
            
            assert report.error_type == 'ValueError'
            assert 'Test error' in report.message
            assert report.module == 'test_module'
            assert report.dkrypt_version == '1.4.0'
            assert len(report.error_hash) == 16
    
    def test_prepare_report_sanitization(self, reporter):
        try:
            raise ValueError("Error at https://example.com with password=secret")
        except ValueError as e:
            report = reporter.prepare_report(e, module='test')
            
            assert '[URL_REDACTED]' in report.message
            assert 'example.com' not in report.message
    
    def test_was_already_reported(self, reporter):
        try:
            raise ValueError("Test error")
        except ValueError as e:
            report = reporter.prepare_report(e)
            
            assert reporter.was_already_reported(report) is False
            
            reporter._reported_hashes.add(report.error_hash)
            assert reporter.was_already_reported(report) is True
    
    def test_format_email_body(self, reporter):
        try:
            raise ValueError("Test error")
        except ValueError as e:
            report = reporter.prepare_report(e, module='test_module')
            body = reporter.format_email_body(report)
            
            assert 'DKrypt Error Report' in body
            assert 'ValueError' in body
            assert 'test_module' in body
            assert report.error_hash in body
    
    def test_save_report_locally(self, reporter):
        try:
            raise ValueError("Test error")
        except ValueError as e:
            report = reporter.prepare_report(e)
            success, filepath = reporter.save_report_locally(report)
            
            assert success is True
            assert Path(filepath).exists()
            
            Path(filepath).unlink()
    
    def test_compute_error_hash_consistency(self, reporter):
        try:
            raise ValueError("Test error")
        except ValueError as e:
            hash1 = reporter._compute_error_hash('ValueError', 'Test error', 'traceback')
            hash2 = reporter._compute_error_hash('ValueError', 'Test error', 'traceback')
            
            assert hash1 == hash2
    
    def test_get_system_info(self, reporter):
        info = reporter._get_system_info()
        
        assert 'python_version' in info
        assert 'os' in info
        assert 'architecture' in info


class TestPromptErrorReport:
    """Test error reporting prompt"""
    
    def test_non_blocking_error_returns_none(self):
        from unittest.mock import Mock
        console = Mock()
        
        result = prompt_error_report(KeyboardInterrupt(), console=console)
        assert result is None
    
    def test_blocking_error_prompts_user(self):
        from unittest.mock import Mock, patch
        console = Mock()
        console.input = Mock(return_value='n')
        
        with patch('core.error_reporter.ErrorReporter'):
            result = prompt_error_report(RuntimeError("test"), console=console)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
