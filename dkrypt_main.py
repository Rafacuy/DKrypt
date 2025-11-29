#!/usr/bin/env python3
"""
DKrypt - Advanced Penetration Testing Framework
Modern main entry point using Typer for improved CLI experience
"""

import typer
from typing import Optional
from rich.console import Console
from core.cli.interactive_cli import run_interactive_cli
from core.logger import logger
from core.exceptions import DKryptException, UserCancelledError
from core.config import config
from core.diagnostics import run_diagnostics
from core.utils.help import show_help
from core.ui.banner import display_header

console = Console()

__version__ = "1.4.0"
__status__ = "STABLE"

app = typer.Typer(
    name="dkrypt",
    help="DKrypt - Advanced Penetration Testing Framework",
    no_args_is_help=True,
    add_completion=False
)

def show_version():
    """Show version information"""
    console.print(f"[bold cyan]DKrypt[/bold cyan] v{__version__} ({__status__})")
    console.print("[dim]Advanced Penetration Testing Framework[/dim]")
    console.print("[dim]Developed by Rafacuy (arazz.)[/dim]")


@app.command("version", help="Show version information")
def version():
    """Show version information"""
    show_version()


@app.command("diagnostic", help="Run system diagnostics and exit")
def diagnostic():
    """Run system diagnostics and exit"""
    run_diagnostics()


@app.command("list-modules", help="List all available modules and exit")
def list_modules():
    """List all available modules and exit"""
    show_help(topic="modules")


@app.command("quick-start", help="Show quick start guide")
def quick_start():
    """Show quick start guide"""
    show_help(topic="quick-start")


@app.command("tips", help="Show tips and tricks")
def tips():
    """Show tips and tricks"""
    show_help(topic="tips")


@app.command("interactive", help="Start the interactive CLI shell")
def interactive_cmd():
    """Start the interactive CLI shell"""
    run_interactive_cli()

@app.command("i", help="Start the interactive CLI shell (shorthand)")
def interactive_shortcut():
    """Start the interactive CLI shell (shorthand)"""
    run_interactive_cli()

@app.callback(invoke_without_command=True, help="DKrypt - Advanced Penetration Testing Framework")
def callback(ctx: typer.Context):
    """Main callback to handle the default case when no command is provided"""
    if ctx.invoked_subcommand is None:
        run_interactive_cli()


# Import and register all module commands
from core.cli.parsers import register_commands
register_commands(app)

def main():
    """
    Main entry point for DKrypt.
    Parses arguments using Typer and routes to appropriate functionality.
    """
    try:
        # Initialize configuration
        config.validate()
        logger.info("DKrypt started")

        # Run Typer app
        app()

    except UserCancelledError:
        console.print("\n[bold yellow]Operation cancelled by user[/bold yellow]")
        logger.info("User cancelled operation")
        raise typer.Exit(code=0)

    except DKryptException as e:
        console.print(f"\n[bold red]Error: {e.message}[/bold red]")
        if e.details:
            console.print(f"[dim]Details: {e.details}[/dim]")
        logger.error(f"{e.code}: {e.message}", extra={"details": e.details})
        raise typer.Exit(code=1)

    except KeyboardInterrupt:
        console.print("\n[bold yellow]Operation cancelled by user[/bold yellow]")
        logger.info("User interrupted operation (Ctrl+C)")
        raise typer.Exit(code=0)

    except Exception as e:
        console.print(f"\n[bold red]Unexpected error: {str(e)}[/bold red]")
        logger.critical(f"Unexpected error: {str(e)}", exc_info=True)
        console.print("[dim]Check logs for more details: .dkrypt/logs/[/dim]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    main()
