"""
Compatibility shim for cli imports
Note: run_cli is deprecated, use interactive_cli instead
"""

# For backward compatibility with tests
def run_cli():
    """Deprecated: Use run_interactive_cli instead"""
    from core.cli.interactive_cli import run_interactive_cli
    return run_interactive_cli()

__all__ = ['run_cli']
