#!/usr/bin/env python3
"""
Tests for the DKrypt prompt-toolkit completer.
"""

import pytest
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import to_plain_text

from core.cli.completer import SmartCompleter
from core.cli.suggestor import EnhancedSuggester
from core.cli.prompt_completer import DKryptCompleter

@pytest.fixture
def modules_config():
    """Fixture for modules configuration."""
    return {
        "sqli_scan": {
            "name": "SQL Injection Scanner",
            "description": "Scans for SQL injection vulnerabilities.",
            "options": {
                "URL": {"required": True, "description": "Target URL"},
                "METHOD": {"required": False, "default": "GET", "choices": ["GET", "POST"]},
            },
        },
        "xss_scan": {
            "name": "XSS Scanner",
            "description": "Scans for Cross-Site Scripting vulnerabilities.",
            "options": {
                "URL": {"required": True, "description": "Target URL"},
                "PAYLOAD": {"required": False, "default": "default_payload"},
            },
        },
    }

@pytest.fixture
def suggester(modules_config):
    """Fixture for EnhancedSuggester."""
    return EnhancedSuggester(modules_config)

@pytest.fixture
def smart_completer(suggester, modules_config):
    """Fixture for SmartCompleter."""
    return SmartCompleter(suggester, modules_config)

@pytest.fixture
def dkrypt_completer(smart_completer):
    """Fixture for DKryptCompleter."""
    return DKryptCompleter(smart_completer)

def get_completions(completer, text, cursor_offset=None):
    """Helper function to get completions from the completer."""
    if cursor_offset is None:
        cursor_offset = len(text)
    doc = Document(text, cursor_position=cursor_offset)
    return list(completer.get_completions(doc, None))

def test_complete_base_commands(dkrypt_completer):
    """Test completion of base commands."""
    completions = get_completions(dkrypt_completer, "sho")
    assert "show" in [c.text for c in completions]

def test_complete_use_command(dkrypt_completer):
    """Test completion of the 'use' command."""
    completions = get_completions(dkrypt_completer, "use sqli")
    assert "sqli_scan" in [c.text for c in completions]
    assert "xss_scan" not in [c.text for c in completions]

def test_complete_set_command_options(dkrypt_completer):
    """Test completion of options for the 'set' command."""
    dkrypt_completer.smart_completer.set_context(module="sqli_scan")
    completions = get_completions(dkrypt_completer, "set UR")
    assert "URL" in [c.text for c in completions]

def test_complete_set_command_values(dkrypt_completer):
    """Test completion of values for the 'set' command."""
    dkrypt_completer.smart_completer.set_context(module="sqli_scan")
    completions = get_completions(dkrypt_completer, "set METHOD ")
    assert "GET" in [c.text for c in completions]
    assert "POST" in [c.text for c in completions]

def test_completion_metadata(dkrypt_completer):
    """Test that completions have the correct metadata."""
    completions = get_completions(dkrypt_completer, "use sqli")
    for comp in completions:
        if comp.text == "sqli_scan":
            assert to_plain_text(comp.display_meta) == "Scans for SQL injection vulnerabilities."
            return
    assert False, "Completion for sqli_scan not found"
def test_set_option_completion_metadata(dkrypt_completer):
    """Test metadata for set option completions."""
    dkrypt_completer.smart_completer.set_context(module="sqli_scan")
    completions = get_completions(dkrypt_completer, "set UR")
    for comp in completions:
        if comp.text == "URL":
            assert to_plain_text(comp.display_meta) == "Target URL"
            return
    assert False, "Completion for URL option not found"
