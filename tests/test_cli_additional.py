"""
Additional tests for CLI and Interactive CLI functionality to ensure comprehensive coverage.
"""
import unittest
from unittest.mock import patch, MagicMock
import sys
import io
from core.cli import run_cli


class TestCLIFunctionality(unittest.TestCase):
    """Additional tests for CLI functionality"""

    def test_cli_with_no_args_shows_help(self):
        """Test CLI shows help when no arguments provided."""
        raise unittest.SkipTest("Legacy argparse CLI - Typer-based tests in test_typer_migration.py")

    def test_cli_with_interactive_flag(self):
        """Test CLI behavior with interactive flag."""
        with patch('sys.argv', ['dkrypt.py', '-i']):
            # This should trigger the interactive mode path
            # Since we can't easily test the interactive mode directly in unit tests,
            # we'll just ensure it doesn't crash
            try:
                # This would normally call run_interactive_cli, which we'll test separately
                # For now, let's just ensure no immediate errors
                from core.interactive_cli import run_interactive_cli
                self.assertTrue(callable(run_interactive_cli))
            except Exception as e:
                self.fail(f"run_interactive_cli is not properly defined: {e}")

    def test_cli_invalid_module_error_handling(self):
        """Test CLI handles invalid modules gracefully."""
        raise unittest.SkipTest("Legacy argparse CLI - Typer-based tests in test_typer_migration.py")


class TestInteractiveCLIEnhanced(unittest.TestCase):
    """Additional tests for Interactive CLI functionality"""

    def test_run_command_without_module(self):
        """Test running without selecting a module."""
        from core.interactive_cli import InteractiveCLI
        cli = InteractiveCLI()
        
        # Capture output
        captured_output = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            cli.onecmd("run")  # Try to run without selecting a module
        finally:
            sys.stdout = old_stdout
        
        output = captured_output.getvalue()
        self.assertIn("No module selected", output)

    def test_run_command_with_mock_module(self):
        """Test run command with a mock module."""
        from core.interactive_cli import InteractiveCLI
        cli = InteractiveCLI()
        
        # Select a module
        cli.onecmd("use sqli")
        cli.options['URL'] = 'http://test.com'
        
        # Verify the options were set correctly
        self.assertEqual(cli.options.get('URL'), 'http://test.com')

    @patch('core.interactive_cli.display_header')
    @patch('builtins.input', return_value='exit')
    def test_interactive_cli_init(self, mock_input, mock_display_header):
        """Test the Interactive CLI initialization."""
        from core.interactive_cli import InteractiveCLI
        
        # Just confirm it initializes without error
        cli = InteractiveCLI()
        self.assertIsNotNone(cli)
        self.assertEqual(cli.prompt, '(dkrypt) ')
        self.assertIsNone(cli.module)
        self.assertEqual(cli.options, {})

    def test_module_list_completeness(self):
        """Test that all expected modules are in the interactive CLI."""
        from core.interactive_cli import InteractiveCLI
        
        cli = InteractiveCLI()
        
        # Verify that expected modules exist in the module list
        expected_modules = [
            'sqli', 'xss', 'graphql', 'portscanner', 'subdomain', 'crawler',
            'headers', 'dirbrute', 'sslinspect', 'corstest', 'smuggler',
            'tracepulse', 'js-crawler', 'py-obfuscator', 'waftester'
        ]
        
        for module in expected_modules:
            self.assertIn(module, cli.module_list)


if __name__ == '__main__':
    unittest.main()