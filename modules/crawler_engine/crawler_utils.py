# utils_main.py
"""
This module serves as the main entry point and contains utility functions,
validation logic, and the primary application control flow.
- GracefulShutdownHandler: Manages Ctrl+C and other termination signals.
- CrawlStatistics: Tracks metrics about a crawl session.
- Validation functions: Check for dependencies and browser driver availability.
- Main application loop and entry point.
"""
import asyncio
import signal
import sys
import time
import traceback
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from rich.panel import Panel
from rich.table import Table
from rich.prompt import IntPrompt, Prompt, Confirm

from core.randomizer import HeaderFactory
from core.utils import clear_console

from .config_ui import (console, get_crawl_config, get_output_choice,
                        display_results, save_to_file)
from .core_crawler import EnhancedWebCrawler


# --- Signal Handling for Graceful Shutdown ---

class GracefulShutdownHandler:
    """Handle graceful shutdown on signals."""

    def __init__(self):
        self.shutdown_event = asyncio.Event()
        self.crawlers: List[EnhancedWebCrawler] = []

    def register_crawler(self, crawler: EnhancedWebCrawler):
        """Register a crawler for shutdown handling."""
        self.crawlers.append(crawler)

    def signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        console.print(f"\n[yellow]Received signal {signum}. Initiating graceful shutdown...[/yellow]")
        self.shutdown_event.set()

        # Mark all crawlers as closed
        for crawler in self.crawlers:
            crawler._closed = True

    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        if sys.platform != 'win32':
            signal.signal(signal.SIGTERM, self.signal_handler)
            signal.signal(signal.SIGINT, self.signal_handler)


shutdown_handler = GracefulShutdownHandler()


# --- Enhanced Error Handling and Validation ---

def validate_requirements():
    """Validate that required dependencies are available."""
    missing_deps = []

    dependencies = [
        ("selenium", "selenium"),
        ("appium.webdriver", "appium-python-client"),
        ("aiohttp", "aiohttp"),
        ("phonenumbers", "phonenumbers"),
        ("bs4", "beautifulsoup4"),
        ("rich", "rich")
    ]

    for module_name, package_name in dependencies:
        try:
            # Handle nested modules like appium.webdriver
            if '.' in module_name:
                __import__(module_name)
            else:
                __import__(module_name)
        except ImportError:
            missing_deps.append(package_name)

    if missing_deps:
        console.print(f"[bold red]Missing required dependencies:[/bold red]")
        for dep in missing_deps:
            console.print(f"  • {dep}")
        console.print(f"\n[yellow]Install with: pip install {' '.join(missing_deps)}[/yellow]")
        return False

    return True


def check_browser_availability():
    """Check if browser drivers are available."""
    chrome_available = False

    try:
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')

        driver = webdriver.Chrome(options=options)
        driver.quit()
        chrome_available = True
    except Exception:
        pass

    if not chrome_available:
        console.print("[yellow]⚠️  Chrome/Chromium driver not found. JavaScript rendering will be disabled.[/yellow]")
        console.print("[dim]To enable JavaScript rendering, install ChromeDriver:[/dim]")
        console.print("[dim]  • Download from: https://chromedriver.chromium.org/[/dim]")
        console.print("[dim]  • Or use: pip install webdriver-manager[/dim]")

    return chrome_available


# --- Advanced Features ---

class CrawlStatistics:
    """Track and display crawling statistics."""

    def __init__(self):
        self.start_time = time.time()
        self.pages_crawled = 0
        self.pages_failed = 0
        self.total_emails = 0
        self.total_phones = 0
        self.domains_visited: Set[str] = set()
        self._stats_lock = asyncio.Lock()

    async def update_from_results(self, results: List[Dict[str, Any]]):
        """Update statistics from crawl results."""
        async with self._stats_lock:
            self.pages_crawled = len(results)

            for result in results:
                try:
                    domain = urlparse(result['final_url']).netloc
                    self.domains_visited.add(domain)
                    self.total_emails += len(result.get('contacts', {}).get('emails', []))
                    self.total_phones += len(result.get('contacts', {}).get('phones', []))
                except Exception:
                    continue

    async def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics."""
        async with self._stats_lock:
            elapsed_time = time.time() - self.start_time
            return {
                'elapsed_time': elapsed_time,
                'pages_crawled': self.pages_crawled,
                'pages_failed': self.pages_failed,
                'total_emails': self.total_emails,
                'total_phones': self.total_phones,
                'domains_visited': len(self.domains_visited),
                'pages_per_second': self.pages_crawled / elapsed_time if elapsed_time > 0 else 0
            }


def display_startup_info():
    """Display startup information and system check."""
    console.print(Panel.fit(
        '[bold magenta] Web Crawler Engine [/bold magenta]\n\n',
        padding=(0, 1)
    ))

    console.print("\n[bold]System Check:[/bold]")

    # Check dependencies
    if not validate_requirements():
        console.print("\n[bold red]❌ Missing dependencies. Please install required packages.[/bold red]")
        return False
    else:
        console.print("[green]✓ All Python dependencies available[/green]")

    # Check browser availability
    browser_ok = check_browser_availability()
    if browser_ok:
        console.print("[green]✓ Chrome/Chromium driver available[/green]")

    console.print("[green]✓ System ready for crawling[/green]")

    try:
        Prompt.ask("\nPress Enter to continue to main menu...")
    except KeyboardInterrupt:
        return False

    return True


# --- Main Application Logic ---

async def main_menu():
    """Display the main menu and handle user choices."""
    header_factory = HeaderFactory()

    while True:
        if shutdown_handler.shutdown_event.is_set():
            break

        clear_console()
        console.print(Panel.fit(
            '[bold magenta]🚀 Web Crawler Engine 🚀[/bold magenta]\n\n'
            'Select an option to begin:',
            padding=(1, 2),
            title="Main Menu"
        ))

        console.print("\n[bold]1.[/bold] Crawl a single URL")
        console.print("[bold]2.[/bold] Crawl URLs from a file (Batch Mode)")
        console.print("[bold]3.[/bold] Exit")

        try:
            choice = IntPrompt.ask("\nEnter your choice", choices=["1", "2", "3"], default=1)
        except KeyboardInterrupt:
            break

        if choice == 3:
            console.print("\n[bold blue]Goodbye![/bold blue]")
            break

        # Get crawler configuration
        try:
            config = get_crawl_config()
        except KeyboardInterrupt:
            continue

        urls_to_crawl = []
        if choice == 1:
            try:
                url = Prompt.ask("\n[cyan]Enter the URL to crawl[/cyan]")
                urls_to_crawl.append(url)
            except KeyboardInterrupt:
                continue
        elif choice == 2:
            try:
                file_path = Prompt.ask("\n[cyan]Enter the path to the file containing URLs[/cyan]")
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        urls_to_crawl = [line.strip() for line in f if line.strip()]
                    if not urls_to_crawl:
                        console.print("[yellow]File is empty or contains no valid URLs.[/yellow]")
                        Prompt.ask("\nPress Enter to continue...")
                        continue
                except FileNotFoundError:
                    console.print(f"[bold red]Error: File not found at '{file_path}'[/bold red]")
                    Prompt.ask("\nPress Enter to continue...")
                    continue
                except Exception as e:
                    console.print(f"[bold red]Error reading file: {e}[/bold red]")
                    Prompt.ask("\nPress Enter to continue...")
                    continue
            except KeyboardInterrupt:
                continue

        if urls_to_crawl:
            console.print(f"\n[bold]Starting crawl with the following settings:[/bold]")
            console.print(f"• URLs to crawl: {len(urls_to_crawl)}")
            console.print(f"• Maximum depth: {config.max_depth}")
            console.print(f"• Concurrent requests: {config.max_concurrent}")
            console.print(f"• Maximum total URLs: {config.max_urls_per_crawl}")
            console.print(f"• JavaScript rendering: {'Enabled' if config.use_javascript else 'Disabled'}")
            console.print(f"• Robots.txt compliance: {'Enabled' if config.respect_robots else 'Disabled'}")

            if config.use_javascript:
                console.print("[yellow]⚠️  JavaScript rendering is enabled. This may take significantly longer.[/yellow]")

            try:
                if not Confirm.ask("\nProceed with crawling?", default=True):
                    continue
            except KeyboardInterrupt:
                continue

            # Start crawling with proper resource management
            try:
                async with EnhancedWebCrawler(config, header_factory) as crawler:
                    shutdown_handler.register_crawler(crawler)
                    results = await crawler.crawl_urls(urls_to_crawl)

                    if results:
                        console.print(f"\n[bold green]✓ Crawling completed! Found {len(results)} pages.[/bold green]")
                        stats = CrawlStatistics()
                        await stats.update_from_results(results)
                        summary = await stats.get_summary()

                        summary_table = Table(title="Crawl Summary", box=None)
                        summary_table.add_column("Metric", style="cyan")
                        summary_table.add_column("Value", style="magenta", justify="right")
                        summary_table.add_row("Pages Crawled", str(summary['pages_crawled']))
                        summary_table.add_row("Total Emails Found", str(summary['total_emails']))
                        summary_table.add_row("Total Phones Found", str(summary['total_phones']))
                        console.print(Panel(summary_table, title="[b green]Summary[/b green]", border_style="green"))

                        try:
                            output_choice, filename = get_output_choice()
                            if output_choice == 1:
                                display_results(results)
                            elif output_choice == 2 and filename:
                                save_to_file(results, filename, 'json')
                            elif output_choice == 3 and filename:
                                save_to_file(results, filename, 'csv')
                        except KeyboardInterrupt:
                            console.print("\n[yellow]Output selection cancelled.[/yellow]")
                    else:
                        console.print("\n[yellow]Could not retrieve any data from the provided URL(s).[/yellow]")

            except KeyboardInterrupt:
                console.print("\n[bold yellow]Crawling interrupted by user.[/bold yellow]")
            except Exception as e:
                console.print(f"\n[bold red]An error occurred during crawling: {e}[/bold red]")
                console.print(f"[dim]Traceback: {traceback.format_exc()}[/dim]")

            try:
                Prompt.ask("\nPress Enter to return to the main menu...")
            except KeyboardInterrupt:
                break


async def main():
    """Main application entry point."""
    shutdown_handler.setup_signal_handlers()
    try:
        # Display startup info and check system
        if not display_startup_info():
            return

        # Run main menu loop
        await main_menu()

    except KeyboardInterrupt:
        console.print("\n[bold yellow]Program interrupted by user. Exiting.[/bold yellow]")
    except Exception as e:
        console.print(f"\n[bold red]A critical error occurred: {e}[/bold red]")
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
    finally:
        # Ensure cleanup
        console.print("\n[dim]Cleaning up resources...[/dim]")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Program terminated.[/bold yellow]")
    except Exception as e:
        console.print(f"\n[bold red]Fatal error: {e}[/bold red]")
