# main_runner.py
import h2.events
import sys
from typing import Dict
from enum import Enum
import os

from rich.console import Console

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Imports from other modules
from engine.payload_generator import ModernPayloadGenerator, TargetValidator
from engine.smuggler import RequestSmuggler
from core.utils import clear_console, header_banner

# Import the randomizer module for stealth headers
try:
    from core.randomizer import HeaderFactory
    RANDOMIZER_AVAILABLE = True
except ImportError:
    RANDOMIZER_AVAILABLE = False




# ============================================================================
# UTILITIES & MAIN RUNNER
# ============================================================================

VERSION = "1.0.0"

def parse_headers(header_str: str) -> Dict[str, str]:
    if not header_str:
        return {}
    headers = {}
    for part in header_str.split(','):
        if ':' in part:
            key, val = part.split(':', 1)
            headers[key.strip()] = val.strip()
    return headers

def run(args=None):
    """
    Main execution function with CLI-focused interface and error handling.
    """
    console = Console()

    try:
        if args:
            target_url = args.url
            port = args.port if hasattr(args, 'port') else None
            headers = args.headers if hasattr(args, 'headers') else None
        else:
            # In non-interactive mode, we should have URL passed via args
            console.print("[red]Error: URL must be provided via arguments in CLI mode[/red]")
            sys.exit(1)

        # Validate inputs
        if not target_url:
            console.print("[red]Error: Target URL is required[/red]")
            sys.exit(1)

        if not (target_url.startswith("http://") or target_url.startswith("https://")):
            target_url = "https://" + target_url

        if not port:
            port = 443 if target_url.startswith("https://") else 80

        if isinstance(headers, str):
            headers = parse_headers(headers)

        # Display settings
        console.print(f"[bold]Target URL:[/bold] {target_url}")
        console.print(f"[bold]Target Port:[/bold] {port}")
        if headers:
            console.print(f"[bold]Custom Headers:[/bold] {headers}")

        if RANDOMIZER_AVAILABLE:
            console.print("[green]✅ Stealth headers: Available[/green]")
        else:
            console.print("[yellow]⚠️ Stealth headers: Not available (randomizer.py not found)[/yellow]")

        # Create and run scanner
        smuggler = RequestSmuggler(target_url, port, headers)
        smuggler.run_full_scan()

    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Scan cancelled by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]❌ Fatal error: {e}[/red]")
        sys.exit(1)
