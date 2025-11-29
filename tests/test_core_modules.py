"""
Tests for core modules to ensure proper functionality and identify bugs.
"""
import unittest
from unittest.mock import patch, MagicMock
import argparse
from core.parsers import create_parser
from core.utils import header_banner
from core.banner import display_header


class TestCoreModules(unittest.TestCase):
    """Test cases for core modules"""

    def test_parser_creation_completeness(self):
        """Test that all expected modules are available in parser."""
        parser = create_parser()
        
        # Check that subparsers exist
        self.assertIsNotNone(parser._subparsers)
        
        # Check for a few key modules
        # Note: We can't easily test the actual subparsers action directly
        # but we can verify the parser creation doesn't fail
        
        # The parser should not be None and should contain the expected structure
        self.assertIn('description', vars(parser))

    def test_header_banner_function(self):
        """Test the header_banner utility function."""
        # Test with a simple tool name
        try:
            header_banner(tool_name="Test Tool")
            # If this doesn't raise an exception, the function works
            self.assertTrue(True)
        except Exception as e:
            self.fail(f"header_banner raised {type(e).__name__} unexpectedly: {e}")

    @patch('rich.console.Console.print')
    def test_display_header(self, mock_print):
        """Test the display header function."""
        try:
            display_header()
            # Verify that print was called (indicating the function executed)
            mock_print.assert_called()
        except Exception as e:
            self.fail(f"display_header raised {type(e).__name__} unexpectedly: {e}")

    def test_parser_arguments_structure(self):
        """Test that parser arguments have the expected structure."""
        parser = create_parser()
        
        # Check for the interactive flag
        # We can't directly check the arguments without parsing, but we can verify
        # that the parser has been created with subparsers
        self.assertTrue(hasattr(parser, '_subparsers'))
        
    def test_all_modules_in_parser(self):
        """Test that all expected modules are registered in the parser."""
        parser = create_parser()
        
        # Get the subparsers action
        subparsers_action = None
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                subparsers_action = action
                break
        
        self.assertIsNotNone(subparsers_action)
        
        # Check for some expected modules by name
        expected_modules = [
            'sqli', 'xss', 'portscanner', 'subdomain', 'crawler', 
            'headers', 'dirbrute', 'sslinspect', 'corstest', 'waftester',
            'smuggler', 'tracepulse', 'js-crawler', 'py-obfuscator', 'graphql'
        ]
        
        # The choices should contain all our expected modules
        actual_choices = list(subparsers_action.choices.keys())
        
        for module in expected_modules:
            self.assertIn(module, actual_choices, 
                         f"Module '{module}' not found in parser choices. Available: {actual_choices}")


class TestModuleIntegration(unittest.TestCase):
    """Test cases for module integration aspects"""

    def test_module_imports(self):
        """Test that all module imports in cli.py work properly."""
        try:
            from modules import (
                subdomain, ssl_inspector,
                dir_bruteforcer, header_audit, port_scanner,
                cors_scan, sqli_scan, tracepulse,
                jscrawler, py_obfuscator, graphql_introspect
            )
            from modules.crawler_engine import crawler_utils
            from modules.waf_bypass import tui
            from modules.http_desync import main_runner
            from modules.xss import scanner
            
            # Verify that the modules have the expected attributes
            self.assertTrue(hasattr(sqli_scan, 'run_sqli_scan'))
            self.assertTrue(hasattr(scanner, 'run_xss_scan'))
            self.assertTrue(hasattr(port_scanner, 'main_menu'))
            self.assertTrue(hasattr(subdomain, 'main_menu'))
            self.assertTrue(hasattr(crawler_utils, 'main'))
            self.assertTrue(hasattr(header_audit, 'HeaderAuditor'))
            self.assertTrue(hasattr(graphql_introspect, 'run_cli'))
            self.assertTrue(hasattr(dir_bruteforcer, 'main'))
            self.assertTrue(hasattr(ssl_inspector, 'run_ssl_inspector'))
            self.assertTrue(hasattr(cors_scan, 'main'))
            self.assertTrue(hasattr(main_runner, 'run'))
            self.assertTrue(hasattr(tracepulse, 'main'))
            self.assertTrue(hasattr(jscrawler, 'main'))
            self.assertTrue(hasattr(py_obfuscator, 'main'))
            
        except ImportError as e:
            self.fail(f"Module import failed: {e}")

    def test_interactive_cli_module_structure(self):
        """Test the structure of modules in Interactive CLI."""
        from core.interactive_cli import InteractiveCLI
        
        cli = InteractiveCLI()
        
        # Check that the module list has expected structure
        self.assertIsInstance(cli.module_list, dict)
        self.assertGreater(len(cli.module_list), 0)
        
        # Check that each module in the list has required attributes
        for module_key, module_info in cli.module_list.items():
            self.assertIn('name', module_info)
            self.assertIn('description', module_info)
            self.assertIn('function', module_info)
            self.assertIsInstance(module_info['name'], str)
            self.assertIsInstance(module_info['description'], str)
            # The function should be callable
            self.assertTrue(callable(module_info['function']))


if __name__ == '__main__':
    unittest.main()