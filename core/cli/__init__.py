"""CLI components"""

from .interactive_cli import run_interactive_cli

# Backward compatibility
def run_cli():
    """Deprecated: Use run_interactive_cli instead"""
    return run_interactive_cli()

__all__ = ['run_interactive_cli', 'run_cli']
