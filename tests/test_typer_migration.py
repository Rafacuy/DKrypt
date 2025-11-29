"""
Comprehensive tests for Typer migration from Argparse
Tests all 15+ module commands for proper functionality and error handling
"""

import unittest
import sys
from unittest.mock import patch, MagicMock
from io import StringIO
import typer
from typer.testing import CliRunner

# Import the Typer app
from dkrypt_main import app


class TestTyperMigration(unittest.TestCase):
    """Test Typer command registration and execution"""

    def setUp(self):
        """Set up test runner"""
        self.runner = CliRunner()

    def test_app_exists(self):
        """Test that main app is properly configured"""
        self.assertIsNotNone(app)
        self.assertIsInstance(app, typer.Typer)

    def test_version_command(self):
        """Test version command"""
        result = self.runner.invoke(app, ["version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("DKrypt", result.stdout)

    def test_diagnostic_command(self):
        """Test diagnostic command"""
        result = self.runner.invoke(app, ["diagnostic"])
        self.assertEqual(result.exit_code, 0)

    def test_list_modules_command(self):
        """Test list-modules command"""
        result = self.runner.invoke(app, ["list-modules"])
        self.assertEqual(result.exit_code, 0)

    def test_help_output(self):
        """Test help output"""
        result = self.runner.invoke(app, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("DKrypt", result.stdout)

    def test_sqli_command_exists(self):
        """Test SQLI command is registered"""
        result = self.runner.invoke(app, ["sqli", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("SQL Injection", result.stdout)

    def test_xss_command_exists(self):
        """Test XSS command is registered"""
        result = self.runner.invoke(app, ["xss", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("XSS", result.stdout)

    def test_graphql_command_exists(self):
        """Test GraphQL command is registered"""
        result = self.runner.invoke(app, ["graphql", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("GraphQL", result.stdout)

    def test_portscanner_command_exists(self):
        """Test Port Scanner command is registered"""
        result = self.runner.invoke(app, ["portscanner", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Port Scanner", result.stdout)

    def test_subdomain_command_exists(self):
        """Test Subdomain command is registered"""
        result = self.runner.invoke(app, ["subdomain", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Subdomain", result.stdout)

    def test_crawler_command_exists(self):
        """Test Crawler command is registered"""
        result = self.runner.invoke(app, ["crawler", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Crawler", result.stdout)

    def test_headers_command_exists(self):
        """Test Headers command is registered"""
        result = self.runner.invoke(app, ["headers", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Header", result.stdout)

    def test_dirbrute_command_exists(self):
        """Test Dirbrute command is registered"""
        result = self.runner.invoke(app, ["dirbrute", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Directory", result.stdout)

    def test_sslinspect_command_exists(self):
        """Test SSL Inspect command is registered"""
        result = self.runner.invoke(app, ["sslinspect", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("SSL", result.stdout)

    def test_corstest_command_exists(self):
        """Test CORS Test command is registered"""
        result = self.runner.invoke(app, ["corstest", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("CORS", result.stdout)

    def test_smuggler_command_exists(self):
        """Test Smuggler command is registered"""
        result = self.runner.invoke(app, ["smuggler", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Smuggling", result.stdout)

    def test_tracepulse_command_exists(self):
        """Test Tracepulse command is registered"""
        result = self.runner.invoke(app, ["tracepulse", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Tracepulse", result.stdout)

    def test_jscrawler_command_exists(self):
        """Test JS Crawler command is registered"""
        result = self.runner.invoke(app, ["js-crawler", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("JS", result.stdout)

    def test_pyobfuscator_command_exists(self):
        """Test Python Obfuscator command is registered"""
        result = self.runner.invoke(app, ["py-obfuscator", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Obfuscator", result.stdout)

    def test_waftester_command_exists(self):
        """Test WAF Tester command is registered"""
        result = self.runner.invoke(app, ["waftester", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("WAF", result.stdout)

    def test_interactive_command_exists(self):
        """Test interactive command is registered"""
        result = self.runner.invoke(app, ["interactive", "--help"])
        self.assertEqual(result.exit_code, 0)

    def test_interactive_shortcut_exists(self):
        """Test interactive shortcut 'i' is registered"""
        result = self.runner.invoke(app, ["i", "--help"])
        self.assertEqual(result.exit_code, 0)


class TestTyperParameterValidation(unittest.TestCase):
    """Test parameter validation for Typer commands"""

    def setUp(self):
        """Set up test runner"""
        self.runner = CliRunner()

    @patch('modules.sqli_scan.run_sqli_scan')
    def test_sqli_required_url_parameter(self, mock_sqli):
        """Test SQLI command requires URL"""
        # Missing --url should fail
        result = self.runner.invoke(app, ["sqli"])
        # Should fail or show error about missing URL
        self.assertTrue(
            result.exit_code != 0 or "--url" in result.stdout.lower(),
            f"Expected error or help text, got: {result.stdout}"
        )

    @patch('modules.xss.scanner.run_xss_scan')
    def test_xss_required_url_parameter(self, mock_xss):
        """Test XSS command requires URL"""
        result = self.runner.invoke(app, ["xss"])
        self.assertNotEqual(result.exit_code, 0)

    @patch('modules.dir_bruteforcer.main')
    def test_dirbrute_required_url_parameter(self, mock_dirbrute):
        """Test Dirbrute command requires URL"""
        result = self.runner.invoke(app, ["dirbrute"])
        self.assertNotEqual(result.exit_code, 0)

    @patch('modules.ssl_inspector.run_ssl_inspector')
    def test_sslinspect_required_target_parameter(self, mock_ssl):
        """Test SSL Inspect command requires target"""
        result = self.runner.invoke(app, ["sslinspect"])
        self.assertNotEqual(result.exit_code, 0)

    @patch('modules.cors_scan.main')
    def test_corstest_required_url_parameter(self, mock_cors):
        """Test CORS Test command requires URL"""
        result = self.runner.invoke(app, ["corstest"])
        self.assertNotEqual(result.exit_code, 0)

    @patch('modules.tracepulse.main')
    def test_tracepulse_required_destination_parameter(self, mock_tracepulse):
        """Test Tracepulse command requires destination"""
        result = self.runner.invoke(app, ["tracepulse"])
        self.assertNotEqual(result.exit_code, 0)


class TestTyperTypeCoercion(unittest.TestCase):
    """Test type coercion for Typer options"""

    def setUp(self):
        """Set up test runner"""
        self.runner = CliRunner()

    @patch('modules.subdomain.main_menu')
    def test_integer_type_coercion(self, mock_subdomain):
        """Test integer parameters are properly coerced"""
        # rate-limit expects int
        result = self.runner.invoke(app, [
            "subdomain", "single",
            "--target", "example.com",
            "--rate-limit", "500"
        ])
        # Should not fail on type conversion
        self.assertNotIn("invalid", result.stdout.lower())

    @patch('modules.crawler_engine.crawler_utils.main')
    def test_float_type_coercion(self, mock_crawler):
        """Test float parameters are properly coerced"""
        # delay should accept float
        result = self.runner.invoke(app, [
            "dirbrute",
            "--url", "https://example.com",
            "--delay", "0.5"
        ])
        self.assertNotIn("type", result.stdout.lower())

    @patch('modules.port_scanner.main_menu')
    def test_boolean_flag_parsing(self, mock_portscanner):
        """Test boolean flags are properly parsed"""
        result = self.runner.invoke(app, [
            "portscanner", "single",
            "--target", "example.com",
            "--service-detection"
        ])
        # Flag should be recognized
        self.assertNotIn("unrecognized", result.stdout.lower())


class TestTyperCommandIntegration(unittest.TestCase):
    """Test integration with actual modules"""

    def setUp(self):
        """Set up test runner"""
        self.runner = CliRunner()

    @patch('modules.graphql_introspect.run_cli')
    def test_graphql_json_headers_parsing(self, mock_graphql):
        """Test JSON headers parsing in GraphQL command"""
        headers_json = '{"Authorization": "Bearer token"}'
        result = self.runner.invoke(app, [
            "graphql",
            "--url", "https://api.example.com/graphql",
            "--headers", headers_json
        ])
        # Should not fail on JSON parsing
        self.assertNotIn("json", result.stdout.lower())

    @patch('modules.subdomain.main_menu')
    def test_subdomain_api_keys_json_parsing(self, mock_subdomain):
        """Test JSON API keys parsing in Subdomain command"""
        api_keys = '{"virustotal": "test_key"}'
        result = self.runner.invoke(app, [
            "subdomain", "single",
            "--target", "example.com",
            "--api-keys", api_keys
        ])
        # Should not fail on JSON parsing
        self.assertNotIn("json", result.stdout.lower())


class TestTyperErrorHandling(unittest.TestCase):
    """Test error handling in Typer commands"""

    def setUp(self):
        """Set up test runner"""
        self.runner = CliRunner()

    def test_invalid_command_error(self):
        """Test invalid command returns error"""
        result = self.runner.invoke(app, ["invalid-command"])
        self.assertNotEqual(result.exit_code, 0)

    def test_no_arguments_shows_help(self):
        """Test no arguments shows help (callback behavior)"""
        result = self.runner.invoke(app, [])
        # Should either show help or start interactive mode
        self.assertIn("DKrypt", result.stdout)

    @patch('modules.sqli_scan.run_sqli_scan')
    def test_missing_required_option(self, mock_sqli):
        """Test missing required option returns error"""
        result = self.runner.invoke(app, ["sqli", "--export", "html"])
        # Should fail because --url is required
        self.assertNotEqual(result.exit_code, 0)


class TestTyperOptionAliases(unittest.TestCase):
    """Test option aliases and shortcuts"""

    def setUp(self):
        """Set up test runner"""
        self.runner = CliRunner()

    def test_option_naming_consistency(self):
        """Test all options use consistent naming conventions"""
        # Check help for consistency
        result = self.runner.invoke(app, ["sqli", "--help"])
        self.assertEqual(result.exit_code, 0)
        # All options should use --hyphenated-names
        self.assertIn("--url", result.stdout)
        self.assertIn("--test-forms", result.stdout)

    def test_command_naming_consistency(self):
        """Test all commands use consistent naming"""
        result = self.runner.invoke(app, ["--help"])
        self.assertEqual(result.exit_code, 0)
        # Commands should be lowercase
        self.assertIn("sqli", result.stdout)
        self.assertIn("xss", result.stdout)
        self.assertIn("portscanner", result.stdout)


if __name__ == "__main__":
    unittest.main()
