#!/usr/bin/env python3
"""
Tests for Interactive CLI fixes
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from core.cli.interactive_cli import InteractiveCLI
from core.cli.suggestor import EnhancedSuggester
from core.error_reporter import ErrorLogger, DataSanitizer, prompt_error_report


class TestUnpackingFixes:
    """Test unpacking error fixes"""
    
    @pytest.fixture
    def cli(self):
        with patch('core.cli.interactive_cli.display_header'):
            cli = InteractiveCLI()
            cli.ui_formatter = Mock()
            return cli
    
    def test_do_use_with_typo(self, cli):
        """Test 'use' command with typo doesn't crash"""
        cli.do_use("sli")
        cli.ui_formatter.print_status.assert_called()
        assert "not found" in str(cli.ui_formatter.print_status.call_args)
    
    def test_do_use_with_incomplete(self, cli):
        """Test 'use' command with incomplete input"""
        cli.do_use("us")
        cli.ui_formatter.print_status.assert_called()
    
    def test_do_use_with_valid_module(self, cli):
        """Test 'use' command with valid module"""
        if 'sqli' in cli.module_list:
            cli.do_use("sqli")
            assert cli.module == "sqli"
    
    def test_do_search_with_typo(self, cli):
        """Test 'search' command with typo"""
        cli.do_search("sli")
        assert cli.ui_formatter.print_status.called or cli.ui_formatter.print_suggestion_box.called
    
    def test_default_with_typo(self, cli):
        """Test unknown command with typo"""
        cli.default("us sqli")
        cli.ui_formatter.print_status.assert_called()
    
    def test_complete_use_with_partial(self, cli):
        """Test tab completion for 'use' with partial input"""
        result = cli.complete_use("sq", "use sq", 4, 6)
        assert isinstance(result, list)
    
    def test_complete_search_with_partial(self, cli):
        """Test tab completion for 'search' with partial input"""
        result = cli.complete_search("xss", "search xss", 7, 10)
        assert isinstance(result, list)


class TestSuggesterRobustness:
    """Test suggester handles edge cases"""
    
    @pytest.fixture
    def suggester(self):
        modules = {
            'sqli': {'name': 'SQL Injection', 'description': 'Test', 'options': {}},
            'xss': {'name': 'XSS Scanner', 'description': 'Test', 'options': {}},
        }
        return EnhancedSuggester(modules)
    
    def test_suggest_module_returns_tuples(self, suggester):
        """Test suggest_module always returns list of tuples"""
        result = suggester.suggest_module("sli")
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, tuple)
            assert len(item) == 2
    
    def test_suggest_command_returns_tuples(self, suggester):
        """Test suggest_command always returns list of tuples"""
        result = suggester.suggest_command("us")
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, tuple)
            assert len(item) == 2
    
    def test_suggest_module_empty_input(self, suggester):
        """Test suggest_module with empty input"""
        result = suggester.suggest_module("")
        assert isinstance(result, list)
    
    def test_suggest_module_no_matches(self, suggester):
        """Test suggest_module with no matches"""
        result = suggester.suggest_module("zzzzz", threshold=0.9)
        assert isinstance(result, list)


class TestErrorLogger:
    """Test local error logging system"""
    
    @pytest.fixture
    def logger(self, tmp_path):
        return ErrorLogger(log_dir=str(tmp_path / "logs"))
    
    def test_prepare_report(self, logger):
        """Test error report preparation"""
        try:
            raise ValueError("Test error")
        except ValueError as e:
            report = logger.prepare_report(e, "test_module")
            assert report.error_type == "ValueError"
            assert report.module == "test_module"
            assert report.error_hash
    
    def test_log_error(self, logger):
        """Test error logging"""
        try:
            raise RuntimeError("Test error")
        except RuntimeError as e:
            report = logger.prepare_report(e)
            success, path = logger.log_error(report)
            assert success
            assert "error_" in path
    
    def test_duplicate_error_not_logged(self, logger):
        """Test duplicate errors are not logged twice"""
        try:
            raise RuntimeError("Duplicate error")
        except RuntimeError as e:
            report = logger.prepare_report(e)
            success1, _ = logger.log_error(report)
            success2, msg = logger.log_error(report)
            assert success1
            assert not success2
            assert "Already logged" in msg
    
    def test_list_errors(self, logger):
        """Test listing error logs"""
        try:
            raise ValueError("Error 1")
        except ValueError as e:
            report = logger.prepare_report(e)
            logger.log_error(report)
        
        logs = logger.list_errors()
        assert len(logs) >= 1
    
    def test_view_error(self, logger):
        """Test viewing specific error"""
        try:
            raise ValueError("View test")
        except ValueError as e:
            report = logger.prepare_report(e)
            logger.log_error(report)
            content = logger.view_error(report.error_hash)
            assert content
            assert "ValueError" in content


class TestDataSanitizer:
    """Test data sanitization"""
    
    @pytest.fixture
    def sanitizer(self):
        return DataSanitizer()
    
    def test_sanitize_url(self, sanitizer):
        """Test URL sanitization"""
        text = "Error at https://example.com/path"
        result = sanitizer.sanitize(text)
        assert "https://example.com" not in result
        assert "[URL]" in result
    
    def test_sanitize_ip(self, sanitizer):
        """Test IP sanitization"""
        text = "Connection to 192.168.1.1 failed"
        result = sanitizer.sanitize(text)
        assert "192.168.1.1" not in result
        assert "[IP]" in result
    
    def test_sanitize_email(self, sanitizer):
        """Test email sanitization"""
        text = "Contact user@example.com"
        result = sanitizer.sanitize(text)
        assert "user@example.com" not in result
        assert "[EMAIL]" in result
    
    def test_sanitize_password(self, sanitizer):
        """Test password sanitization"""
        text = "password=secret123"
        result = sanitizer.sanitize(text)
        assert "secret123" not in result
        assert "[CREDENTIAL]" in result


class TestErrorReportPrompt:
    """Test error reporting prompt"""
    
    def test_prompt_saves_on_yes(self):
        """Test prompt saves error when user says yes"""
        mock_console = Mock()
        mock_console.input.return_value = "y"
        
        try:
            raise ValueError("Test error")
        except ValueError as e:
            result = prompt_error_report(e, "test", mock_console)
            assert result is True
    
    def test_prompt_skips_on_no(self):
        """Test prompt skips when user says no"""
        mock_console = Mock()
        mock_console.input.return_value = "n"
        
        try:
            raise ValueError("Test error")
        except ValueError as e:
            result = prompt_error_report(e, "test", mock_console)
            assert result is False


class TestInteractiveCLIErrorCommand:
    """Test error management command in CLI"""
    
    @pytest.fixture
    def cli(self):
        with patch('core.cli.interactive_cli.display_header'):
            return InteractiveCLI()
    
    def test_errors_list_command(self, cli):
        """Test 'errors list' command"""
        with patch('core.cli.interactive_cli.ErrorLogger') as mock_logger:
            mock_logger.return_value.list_errors.return_value = []
            cli.do_errors("list")
            mock_logger.return_value.list_errors.assert_called_once()
    
    def test_errors_view_command(self, cli):
        """Test 'errors view' command"""
        with patch('core.cli.interactive_cli.ErrorLogger') as mock_logger:
            mock_logger.return_value.view_error.return_value = "Error content"
            cli.do_errors("view abc123")
            mock_logger.return_value.view_error.assert_called_with("abc123")
    
    def test_errors_clear_command(self, cli):
        """Test 'errors clear' command"""
        with patch('core.cli.interactive_cli.ErrorLogger') as mock_logger:
            cli.do_errors("clear")
            mock_logger.return_value.clear_old_logs.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
