"""
Compatibility shim for parsers imports
Redirects to new location: core.cli.parsers
"""

from core.cli.parsers import *

__all__ = ['create_parser', 'register_commands', 'ArgumentValidator']
