# main_runner.py
import h2.events
import sys
from typing import Dict
from enum import Enum
import os

from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.panel import Panel

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Imports from other modules
from engine.payload_generator import ModernPayloadGenerator, TargetValidator
from engine.smuggler import RequestSmuggler

# Import the randomizer module for stealth headers
try:
    from core.randomizer import HeaderFactory
    RANDOMIZER_AVAILABLE = True
except ImportError:
    RANDOMIZER_AVAILABLE = False

try:
    from core.utils import clear_console
except ImportError:
    def clear_console():
        import os
        os.system('cls' if os.name == 'nt' else 'clear')

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

def run():
    """
    Main execution function with enhanced user interface and error handling.
    """
    console = Console()
    
    try:
        clear_console()
        # Display welcome and gather target information
        console.print(Panel(
            "[bold green]HTTP Desync Tester - Configuration[/bold green]\n\n",
            border_style="green"
        ))

        # Target URL input with validation
        while True:
            target_url = Prompt.ask(
                "[bold cyan]Enter target URL[/bold cyan]",
                default="https://example.com"
            ).strip()

            if not target_url:
                console.print("[red]URL cannot be empty[/red]")
                continue

            if not (target_url.startswith("http://") or target_url.startswith("https://")):
                console.print("[red]URL must start with http:// or https://[/red]")
                continue

            break

        # Port input with smart defaults
        default_port = 443 if target_url.startswith("https://") else 80
        port = IntPrompt.ask(
            "[bold cyan]Enter port[/bold cyan]",
            default=default_port,
            show_default=True
        )

        # Custom headers (optional)
        headers = Prompt.ask(
            "[bold cyan]Custom headers[/bold cyan] (optional, format: key1:val1,key2:val2)",
            default="",
            show_default=False
        )

        # Advanced options
        console.print("\n[bold]Advanced Options:[/bold]")
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

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    # Verify dependencies
    required_modules = ['httpx', 'rich']
    missing_modules = []

    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)

    if missing_modules:
        print(f"Missing required modules: {', '.join(missing_modules)}")
        print("Install them with: pip install " + " ".join(missing_modules))
        sys.exit(1)

    run()
