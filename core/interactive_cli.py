"""
Compatibility shim for interactive_cli imports
Redirects to new location: core.cli.interactive_cli
"""

from core.cli.interactive_cli import *

__all__ = ['InteractiveCLI', 'run_interactive_cli']
