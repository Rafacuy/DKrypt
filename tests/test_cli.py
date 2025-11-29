"""
Tests for the CLI module to ensure proper functionality and identify bugs.
"""
import sys
import io
import unittest
from unittest.mock import patch, MagicMock
import argparse
from core.cli import run_cli
from core.interactive_cli import InteractiveCLI, run_interactive_cli
from core.parsers import create_parser


class TestCLI(unittest.TestCase):
    """Test cases for the CLI module"""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.parser = create_parser()

    def test_parser_creation(self):
        """Test that the parser is created without errors."""
        parser = create_parser()
        self.assertIsNotNone(parser)
        self.assertIsInstance(parser, argparse.ArgumentParser)

    @patch('sys.argv', ['dkrypt.py', '--help'])
    def test_help_output(self):
        """Test help output is generated without errors."""
        raise unittest.SkipTest("Legacy argparse CLI - Typer-based tests in test_typer_migration.py")

    def test_sqli_module_execution(self):
        """Test SQLI module execution (legacy argparse)."""
        raise unittest.SkipTest("Legacy argparse CLI - use Typer-based tests instead")

    def test_xss_module_execution(self):
        """Test XSS module execution (legacy argparse)."""
        raise unittest.SkipTest("Legacy argparse CLI - use Typer-based tests instead")

    def test_unknown_module(self):
        """Test unknown module handling."""
        raise unittest.SkipTest("Legacy argparse CLI - Typer-based tests in test_typer_migration.py")

    def test_no_arguments_shows_help(self):
        """Test that no arguments shows help."""
        raise unittest.SkipTest("Legacy argparse CLI - Typer-based tests in test_typer_migration.py")

    def test_interactive_flag_handling(self):
        """Test that interactive flag is handled properly in CLI."""
        raise unittest.SkipTest("Legacy argparse CLI - Typer-based tests in test_typer_migration.py")
        
        with patch('core.cli.create_parser') as mock_parser:
            mock_parser.return_value.parse_args.return_value = test_args
            mock_parser.return_value.print_help = MagicMock()
            
            # This should return early when interactive flag is True
            result = None
            try:
                run_cli()
            except SystemExit:
                # This might happen if no module is provided
                pass


class TestInteractiveCLI(unittest.TestCase):
    """Test cases for the Interactive CLI module"""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.interactive_cli = InteractiveCLI()

    def test_initial_state(self):
        """Test initial state of Interactive CLI."""
        self.assertIsNone(self.interactive_cli.module)
        self.assertEqual(self.interactive_cli.options, {})
        self.assertEqual(self.interactive_cli.prompt, '(dkrypt) ')

    def test_do_use_with_valid_module(self):
        """Test 'use' command with a valid module."""
        self.interactive_cli.onecmd("use sqli")
        self.assertEqual(self.interactive_cli.module, 'sqli')
        self.assertEqual(self.interactive_cli.prompt, '(dkrypt:sqli) ')

    def test_do_use_with_invalid_module(self):
        """Test 'use' command with an invalid module."""
        # Capture stdout to verify error message
        captured_output = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            self.interactive_cli.onecmd("use invalid_module")
        finally:
            sys.stdout = old_stdout
        
        output = captured_output.getvalue()
        self.assertIn("not found", output)

    def test_do_show_modules(self):
        """Test 'show modules' command."""
        # Capture stdout to verify output
        captured_output = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            self.interactive_cli.onecmd("show modules")
        finally:
            sys.stdout = old_stdout
        
        output = captured_output.getvalue()
        self.assertIn("Available Modules", output)
        # Module display uses key 'sqli' not full name 'SQLI Scanner'
        self.assertIn("sqli", output)

    def test_do_set_option(self):
        """Test 'set' command when a module is selected."""
        self.interactive_cli.onecmd("use sqli")
        self.interactive_cli.onecmd("set URL http://example.com")
        
        self.assertEqual(self.interactive_cli.options.get('URL'), 'http://example.com')

    def test_do_set_without_module(self):
        """Test 'set' command without selecting a module."""
        captured_output = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            self.interactive_cli.onecmd("set URL http://example.com")
        finally:
            sys.stdout = old_stdout
        
        output = captured_output.getvalue()
        self.assertIn("No module selected", output)

    def test_do_unset_option(self):
        """Test 'unset' command."""
        self.interactive_cli.onecmd("use sqli")
        self.interactive_cli.onecmd("set URL http://example.com")
        self.interactive_cli.onecmd("unset URL")
        
        self.assertNotIn('URL', self.interactive_cli.options)

    def test_do_show_options(self):
        """Test 'show options' command."""
        self.interactive_cli.onecmd("use sqli")
        self.interactive_cli.onecmd("set URL http://example.com")
        
        captured_output = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            self.interactive_cli.onecmd("show options")
        finally:
            sys.stdout = old_stdout
        
        output = captured_output.getvalue()
        self.assertIn("URL", output)
        self.assertIn("http://example.com", output)

    def test_do_back_command(self):
        """Test 'back' command."""
        self.interactive_cli.onecmd("use sqli")
        self.interactive_cli.onecmd("set URL http://example.com")
        
        self.interactive_cli.onecmd("back")
        
        self.assertIsNone(self.interactive_cli.module)
        self.assertEqual(self.interactive_cli.options, {})
        self.assertEqual(self.interactive_cli.prompt, '(dkrypt) ')

    def test_do_search_command(self):
        """Test 'search' command functionality."""
        captured_output = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            self.interactive_cli.onecmd("search sqli")
        finally:
            sys.stdout = old_stdout
        
        output = captured_output.getvalue()
        self.assertIn("SQLI Scanner", output)

    def test_do_exit_command(self):
        """Test 'exit' command."""
        # The cmdloop usually handles exit differently, so testing the do_exit method directly
        result = self.interactive_cli.do_exit("")
        self.assertTrue(result)

    def test_do_quit_command(self):
        """Test 'quit' command."""
        result = self.interactive_cli.do_quit("")
        self.assertTrue(result)

    def test_empty_line_handling(self):
        """Test handling of empty lines."""
        # Should not raise an exception
        result = self.interactive_cli.emptyline()
        self.assertIsNone(result)

    def test_default_command_handler(self):
        """Test handler for unknown commands."""
        captured_output = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            self.interactive_cli.default("unknown_command")
        finally:
            sys.stdout = old_stdout
        
        output = captured_output.getvalue()
        self.assertIn("Unknown command", output)


if __name__ == '__main__':
    unittest.main()