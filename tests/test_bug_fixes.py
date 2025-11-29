# tests/test_bug_fixes.py
import pytest
import argparse
from unittest.mock import MagicMock, patch

from core.interactive_cli import InteractiveCLI
from modules import sqli_scan, dir_bruteforcer

@pytest.fixture
def interactive_cli_instance():
    """Fixture to create an instance of the InteractiveCLI."""
    cli = InteractiveCLI()
    return cli

def test_sqli_scan_arg_fix(interactive_cli_instance):
    """
    Tests the fix for the sqli_scan module call.
    Verifies that the module can be called with the 'export' argument without a TypeError.
    """
    cli = interactive_cli_instance
    cli.module = 'sqli'
    cli.options = {
        'URL': 'http://test.com',
        'EXPORT': 'csv'
    }

    # Mock the actual scanning function to prevent network calls
    with patch('modules.sqli_scan.SQLiScanner.run_comprehensive_scan') as mock_run:
        # The do_run method should now execute without raising a TypeError
        cli.do_run('')

        # Check that the underlying function was called with the correct 'export' argument
        mock_run.assert_called_once()
        call_args, call_kwargs = mock_run.call_args
        # The 'export' argument is the 5th positional argument (index 4)
        assert len(call_args) > 4
        assert call_args[4] == 'csv'
        assert 'export' not in call_kwargs
        assert 'export_format' not in call_kwargs

def test_dirbrute_arg_fix(interactive_cli_instance):
    """
    Tests the fix for the dir_bruteforcer module call.
    Verifies that the 'export' argument is correctly passed.
    """
    cli = interactive_cli_instance
    cli.module = 'dirbrute'
    cli.options = {
        'URL': 'http://test.com',
        'EXPORT': 'my_report.txt'
    }

    # Mock the main function of the module
    with patch('modules.dir_bruteforcer.main') as mock_main:
        cli.do_run('')

        # Verify that the main function was called with a namespace object
        # that has the 'export' attribute.
        mock_main.assert_called_once()
        call_args = mock_main.call_args[0][0] # The 'args' object is the first positional argument
        
        assert isinstance(call_args, argparse.Namespace)
        assert hasattr(call_args, 'export')
        assert call_args.export == 'my_report.txt'
        assert not hasattr(call_args, 'output')
        assert not hasattr(call_args, 'report')

def test_do_run_arg_object_completeness(interactive_cli_instance):
    """
    Tests the core fix in the do_run method.
    Verifies that the 'args' object passed to the module function is complete,
    containing the command, user-set options, and default values.
    """
    cli = interactive_cli_instance
    cli.module = 'sqli'
    # User only sets the required URL
    cli.options = {
        'URL': 'http://test.com'
    }

    # Mock the module's lambda function to inspect the args it receives
    mock_lambda_func = MagicMock()
    cli.module_list['sqli']['function'] = mock_lambda_func
    
    cli.do_run('')

    # Assert that the function was called exactly once
    mock_lambda_func.assert_called_once()
    
    # Inspect the 'args' object that the function was called with
    call_args = mock_lambda_func.call_args[0][0]

    assert isinstance(call_args, argparse.Namespace)
    
    # 1. Check for the command name
    assert hasattr(call_args, 'command')
    assert call_args.command == 'sqli'

    # 2. Check for the user-set value
    assert hasattr(call_args, 'url')
    assert call_args.url == 'http://test.com'

    # 3. Check for default values that the user did not set
    assert hasattr(call_args, 'export')
    assert call_args.export == 'html'  # Default value from module_list
    assert hasattr(call_args, 'test_forms')
    assert call_args.test_forms is False # Default value
