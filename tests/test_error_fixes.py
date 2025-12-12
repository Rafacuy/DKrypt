"""
Unit tests to verify fixes for the error log issues identified in the debugging process.

These tests ensure that the TypeErrors and RuntimeErrors found in error logs are properly resolved.
"""
import unittest
from unittest.mock import patch, MagicMock, Mock
from typing import Dict, Any
from core.cli.module_registry import (
    run_smuggler,
    run_tracepulse,
    run_py_obfuscator,
    run_waftester
)


class TestErrorFixes(unittest.TestCase):
    """Test class to verify fixes for common DKrypt module errors"""

    def test_run_smuggler_with_args_object(self):
        """Test that run_smuggler properly creates and passes an args object to main_runner.run()"""
        # Mock the main_runner module
        with patch('core.cli.module_registry.main_runner') as mock_main_runner:
            mock_main_runner.run = Mock()
            
            # Test values that would come from CLI
            values = {
                "url": "https://example.com",
                "port": 443,
                "method": "GET",
                "verbose": True,
                "headers": "User-Agent: test"
            }
            
            # This should not raise a TypeError about argument counts
            run_smuggler(values)
            
            # Verify that main_runner.run was called with an Args object
            self.assertTrue(mock_main_runner.run.called)
            args_passed = mock_main_runner.run.call_args[0][0]
            self.assertTrue(hasattr(args_passed, 'url'))
            self.assertTrue(hasattr(args_passed, 'port'))
            self.assertTrue(hasattr(args_passed, 'headers'))
            self.assertEqual(args_passed.url, "https://example.com")
            self.assertEqual(args_passed.port, 443)
            self.assertEqual(args_passed.headers, "User-Agent: test")

    def test_run_tracepulse_with_args_object(self):
        """Test that run_tracepulse properly creates and passes an args object to tracepulse.main()"""
        # Mock the tracepulse module
        with patch('core.cli.module_registry.tracepulse') as mock_tracepulse:
            mock_tracepulse.main = Mock()
            
            # Test values that would come from CLI
            values = {
                "destination": "8.8.8.8",
                "protocol": "icmp",
                "max_hops": 30,
                "port": 33434,
                "timeout": 2,
                "probe_delay": 0.1,
                "save": False,
                "output": "results.json",
                "allow_private": False
            }
            
            # This should not raise a TypeError about argument counts
            run_tracepulse(values)
            
            # Verify that tracepulse.main was called with an Args object
            self.assertTrue(mock_tracepulse.main.called)
            args_passed = mock_tracepulse.main.call_args[0][0]
            self.assertTrue(hasattr(args_passed, 'destination'))
            self.assertTrue(hasattr(args_passed, 'protocol'))
            self.assertTrue(hasattr(args_passed, 'max_hops'))
            self.assertTrue(hasattr(args_passed, 'port'))
            self.assertEqual(args_passed.destination, "8.8.8.8")
            self.assertEqual(args_passed.protocol, "icmp")
            self.assertEqual(args_passed.max_hops, 30)
            self.assertEqual(args_passed.port, 33434)

    def test_run_py_obfuscator_with_args_object(self):
        """Test that run_py_obfuscator properly creates and passes an args object to py_obfuscator.main()"""
        # Mock the py_obfuscator module
        with patch('core.cli.module_registry.py_obfuscator') as mock_py_obfuscator:
            mock_py_obfuscator.main = Mock()
            
            # Test values that would come from CLI
            values = {
                "input": "input.py",
                "output": "output.py",
                "level": 2,
                "rename_vars": True,
                "rename_funcs": True,
                "flow_obfuscation": True
            }
            
            # This should not raise a TypeError about argument counts
            run_py_obfuscator(values)
            
            # Verify that py_obfuscator.main was called with an Args object
            self.assertTrue(mock_py_obfuscator.main.called)
            args_passed = mock_py_obfuscator.main.call_args[0][0]
            self.assertTrue(hasattr(args_passed, 'input'))
            self.assertTrue(hasattr(args_passed, 'output'))
            self.assertTrue(hasattr(args_passed, 'level'))
            self.assertTrue(hasattr(args_passed, 'rename_vars'))
            self.assertTrue(hasattr(args_passed, 'rename_funcs'))
            self.assertTrue(hasattr(args_passed, 'flow_obfuscation'))
            self.assertEqual(args_passed.input, "input.py")
            self.assertEqual(args_passed.output, "output.py")
            self.assertEqual(args_passed.level, 2)
            self.assertEqual(args_passed.rename_vars, True)
            self.assertEqual(args_passed.rename_funcs, True)
            self.assertEqual(args_passed.flow_obfuscation, True)

    @patch('modules.waf_bypass.tui.WAFTUI')
    def test_run_waftester_avoids_asyncio_conflicts(self, mock_waftui_class):
        """Test that run_waftester does not raise asyncio runtime errors"""
        import asyncio

        # Create a mock WAFTUI instance that correctly mocks the async run method
        async def mock_run_method(**kwargs):
            # Simulate the async behavior of the real method
            await asyncio.sleep(0.01)  # Simulate some async work
            return "completed"

        mock_waftui_instance = Mock()
        mock_waftui_instance.run = mock_run_method
        mock_waftui_class.return_value = mock_waftui_instance

        # Test values that would come from CLI
        values = {
            "url": "https://example.com",
            "method": "GET",
            "packs": "test",
            "custom_headers": '{"X-Test": "value"}',
            "concurrency": 10,
            "timeout": 10,
            "jitter": 0.1,
            "verify_tls": True,
            "profile": None,
            "export": "json"
        }

        # This should not raise a RuntimeError about asyncio
        try:
            run_waftester(values)
            # The function should run without throwing asyncio-related errors
            self.assertTrue(True)  # This confirms no exception was raised during the call
        except RuntimeError as e:
            if "asyncio.run() cannot be called from a running event loop" in str(e):
                self.fail(f"run_waftester still raises asyncio runtime error: {e}")
            else:
                # Re-raise if it's a different RuntimeError
                raise e


if __name__ == '__main__':
    unittest.main()