#!/usr/bin/env python3
"""
Simplified parsers module - delegates to central module registry.
All module definitions are now in core/cli/module_registry.py
"""

import typer


def create_parser():
    """
    Create argparse parser for backward compatibility with interactive CLI.
    Delegates to module_registry for actual module definitions.
    """
    from core.cli.module_registry import registry
    return registry.create_argparse_parser()


def register_commands(app: typer.Typer):
    """Register all module commands dynamically from the central registry"""
    from core.cli.module_registry import registry
    registry.register_with_typer(app)
