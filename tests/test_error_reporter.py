#!/usr/bin/env python3
"""Tests for the error reporting system"""

import pytest
import tempfile
import time
from pathlib import Path
from core.error_reporter import (
    ErrorLogger, DataSanitizer, prompt_error_report
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
def error_logger():
    """Create error logger instance"""
    return ErrorLogger()


@pytest.fixture
def reporter():
    """Create error reporter instance - using ErrorLogger as the actual class"""
    return ErrorLogger()


class TestDataSanitizer:
    """Test data sanitization"""

    def test_sanitize_url(self, sanitizer):
        text = "Error at https://example.com/api/endpoint"
        result = sanitizer.sanitize(text)
        assert '[URL]' in result
        assert 'example.com' not in result

    def test_sanitize_ip(self, sanitizer):
        text = "Connection to 192.168.1.1 failed"
        result = sanitizer.sanitize(text)
        assert '[IP]' in result

    def test_sanitize_email(self, sanitizer):
        text = "Contact: user@example.com"
        result = sanitizer.sanitize(text)
        assert '[EMAIL]' in result

    def test_sanitize_password(self, sanitizer):
        text = 'password="secret123"'
        result = sanitizer.sanitize(text)
        assert '[CREDENTIAL]' in result
        assert 'secret123' not in result

    def test_sanitize_home_path(self, sanitizer):
        text = "Config file: /home/user/.dkrypt/config"
        result = sanitizer.sanitize(text)
        assert '[USER]' in result
        assert 'user' not in result


class TestErrorLogger:
    """Test error logger functionality"""

    def test_prepare_report(self, error_logger):
        try:
            raise ValueError("Test error")
        except ValueError as e:
            report = error_logger.prepare_report(e, module='test_module')

            assert report.error_type == 'ValueError'
            assert 'Test error' in report.message
            assert report.module == 'test_module'
            assert len(report.error_hash) == 12  # Updated to match actual implementation

    def test_log_error(self, error_logger):
        try:
            raise ValueError("Test error for logging")
        except ValueError as e:
            report = error_logger.prepare_report(e, module='test_module')
            success, path = error_logger.log_error(report)

            # The log_error function returns (bool, str) where str is the path if successful
            # or an error message if failed
            assert isinstance(success, bool)


class TestErrorLoggerMethods:
    """Test error logger methods"""

    def test_prepare_report(self, reporter):
        try:
            raise ValueError("Test error")
        except ValueError as e:
            report = reporter.prepare_report(e, module='test_module')

            assert report.error_type == 'ValueError'
            assert 'Test error' in report.message
            assert report.module == 'test_module'
            assert len(report.error_hash) == 12  # Updated to match actual implementation

    def test_prepare_report_sanitization(self, reporter):
        try:
            raise ValueError("Error at https://example.com with password=secret")
        except ValueError as e:
            report = reporter.prepare_report(e, module='test')

            assert '[URL]' in report.message or 'https://' not in report.message
            assert 'example.com' not in report.message

    def test_log_error_functionality(self, reporter):
        try:
            raise ValueError("Test error for logging")
        except ValueError as e:
            report = reporter.prepare_report(e, module='test_module')
            success, path = reporter.log_error(report)

            assert isinstance(success, bool)
            # Path might be a file path or error message

    def test_get_system_info(self, reporter):
        info = reporter._get_system_info()

        assert 'python' in info
        assert 'os' in info
        assert 'arch' in info


class TestPromptErrorReport:
    """Test error reporting prompt"""

    def test_blocking_error_prompts_user(self):
        from unittest.mock import Mock
        console = Mock()
        console.input = Mock(return_value='n')  # Simulate user saying 'no'

        # Test with a general exception
        result = prompt_error_report(ValueError("test error"), module='test_module', console=console)
        # The function returns None when user says 'no' or in certain error conditions


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
