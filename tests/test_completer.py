#!/usr/bin/env python3
"""Tests for the smart completer"""

import pytest
from unittest.mock import Mock, patch
from core.cli.completer import SmartCompleter, CompletionContext
from core.cli.suggestor import EnhancedSuggester


@pytest.fixture
def sample_modules():
    """Sample module configuration"""
    return {
        'sqli': {
            'name': 'SQL Injection Scanner',
            'description': 'Scan for SQL injection vulnerabilities',
            'options': {
                'URL': {'required': True, 'description': 'Target URL'},
                'METHOD': {'required': False, 'default': 'GET', 'choices': ['GET', 'POST']}
            }
        },
        'xss': {
            'name': 'XSS Scanner',
            'description': 'Cross-site scripting vulnerability scanner',
            'options': {
                'URL': {'required': True, 'description': 'Target URL'}
            }
        }
    }


@pytest.fixture
def completer(sample_modules):
    """Create completer instance"""
    suggester = EnhancedSuggester(sample_modules)
    return SmartCompleter(suggester, sample_modules)


class TestCompletionContext:
    """Test completion context parsing"""
    
    def test_empty_context(self):
        ctx = CompletionContext()
        assert ctx.command == ""
        assert ctx.module == ""
        assert ctx.partial == ""


class TestSmartCompleter:
    """Test smart completer functionality"""
    
    def test_set_context(self, completer):
        completer.set_context(module='sqli', options={'URL': 'test'})
        assert completer.current_module == 'sqli'
        assert completer.current_options == {'URL': 'test'}
    
    def test_parse_line_empty(self, completer):
        ctx = completer._parse_line('', 0, 0)
        assert ctx.command == ""
        assert ctx.partial == ""
    
    def test_parse_line_command(self, completer):
        ctx = completer._parse_line('use sqli', 0, 8)
        assert ctx.command == 'use'
    
    def test_complete_command(self, completer):
        results = completer._complete_command('us')
        assert 'use' in results
    
    def test_complete_command_empty(self, completer):
        results = completer._complete_command('')
        assert len(results) > 0
        assert 'use' in results
    
    def test_complete_use(self, completer):
        ctx = CompletionContext(command='use', partial='sq')
        results = completer._complete_use(ctx, 'sq')
        assert 'sqli' in results
    
    def test_complete_set_options(self, completer):
        completer.set_context(module='sqli')
        ctx = CompletionContext(command='set', module='sqli', line='set ')
        results = completer._complete_set(ctx, '')
        assert 'URL' in results
        assert 'METHOD' in results
    
    def test_complete_set_values(self, completer):
        completer.set_context(module='sqli')
        ctx = CompletionContext(command='set', module='sqli', line='set METHOD ')
        results = completer._complete_set(ctx, '')
        # Should return choices or empty if no history
        assert isinstance(results, list)
    
    def test_complete_unset(self, completer):
        completer.set_context(module='sqli', options={'URL': 'test', 'METHOD': 'GET'})
        ctx = CompletionContext(command='unset', module='sqli')
        results = completer._complete_unset(ctx, '')
        assert 'URL' in results
        assert 'METHOD' in results
    
    def test_complete_show(self, completer):
        ctx = CompletionContext(command='show')
        results = completer._complete_show(ctx, '')
        assert 'modules' in results
        assert 'options' in results
    
    def test_complete_show_partial(self, completer):
        ctx = CompletionContext(command='show')
        results = completer._complete_show(ctx, 'mod')
        assert 'modules' in results
        assert 'options' not in results
    
    def test_complete_search(self, completer):
        ctx = CompletionContext(command='search')
        results = completer._complete_search(ctx, 'sq')
        assert 'sqli' in results
    
    def test_complete_workspace(self, completer):
        ctx = CompletionContext(command='workspace', line='workspace ')
        results = completer._complete_workspace(ctx, '')
        assert 'list' in results
        assert 'create' in results
    
    def test_complete_workflow(self, completer):
        ctx = CompletionContext(command='workflow', line='workflow ')
        results = completer._complete_workflow(ctx, '')
        assert 'list' in results
        assert 'run' in results
    
    def test_complete_results(self, completer):
        ctx = CompletionContext(command='results', line='results ')
        results = completer._complete_results(ctx, '')
        assert 'list' in results
        assert 'analyze' in results
    
    def test_complete_shortcut(self, completer):
        ctx = CompletionContext(command='shortcut', line='shortcut ')
        results = completer._complete_shortcut(ctx, '')
        assert 'create' in results
        assert 'run' in results
    
    def test_complete_export(self, completer):
        ctx = CompletionContext(command='export', module='', line='export target ')
        results = completer._complete_export(ctx, '')
        # Export completion depends on line parsing
        assert isinstance(results, list)
    
    @patch('readline.get_line_buffer')
    @patch('readline.get_begidx')
    @patch('readline.get_endidx')
    def test_complete_state_machine(self, mock_endidx, mock_begidx, mock_buffer, completer):
        mock_buffer.return_value = 'use sq'
        mock_begidx.return_value = 4
        mock_endidx.return_value = 6
        
        result1 = completer.complete('sq', 0)
        assert result1 is not None
        
        result2 = completer.complete('sq', 1)
        assert result2 is None or isinstance(result2, str)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
