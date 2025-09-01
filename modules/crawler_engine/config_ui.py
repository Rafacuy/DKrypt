# config_ui.py
"""
This module handles all user-facing components, including:
- Configuration data classes (AndroidConfig, CrawlConfig).
- User input prompts for setting up the crawl (get_crawl_config).
- Functions for displaying and saving results (display_results, save_to_file).
- The main menu interface (main_menu).
- A shared Rich Console instance.
"""
import os
import json
import csv
from dataclasses import dataclass, field
from typing import List, Dict, Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt, Confirm

# --- Global Console Instance ---
console = Console()


# --- Configuration Dataclasses ---

@dataclass
class AndroidConfig:
    """Configuration for Android/Appium driver."""
    platform_name: str = "Android"
    browser_name: str = "Chrome"
    device_name: str = "Android Emulator"
    platform_version: str = "11.0"
    appium_server_url: str = "http://localhost:4723/wd/hub"
    new_command_timeout: int = 300
    implicit_wait: int = 10


@dataclass
class CrawlConfig:
    """Configuration class for crawler settings."""
    max_depth: int = 1
    max_concurrent: int = 20
    request_timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0
    use_javascript: bool = False
    respect_robots: bool = True
    android_mode: bool = False
    android_config: AndroidConfig = field(default_factory=AndroidConfig)
    max_urls_per_crawl: int = 1000
    semaphore_timeout: int = 60


# --- User Interface and Prompts ---

def get_crawl_config() -> CrawlConfig:
    """Get crawler configuration from user input."""
    console.print(Panel(
        "[bold]Crawler Configuration[/bold]\n"
        "Configure the crawling behavior and options.",
        title="Settings",
        border_style="blue"
    ))

    config = CrawlConfig()

    # Crawl depth
    config.max_depth = IntPrompt.ask(
        "[cyan]Maximum crawl depth[/cyan] (0=single page, 1=links from seed URLs, etc.)",
        default=config.max_depth,
        show_default=True
    )

    # Concurrency
    config.max_concurrent = IntPrompt.ask(
        "[cyan]Maximum concurrent requests[/cyan]",
        default=config.max_concurrent,
        show_default=True
    )

    # Max URLs limit
    config.max_urls_per_crawl = IntPrompt.ask(
        "[cyan]Maximum URLs to crawl[/cyan] (prevents memory overflow)",
        default=config.max_urls_per_crawl,
        show_default=True
    )

    # JavaScript rendering
    config.use_javascript = Confirm.ask(
        "[cyan]Enable JavaScript rendering?[/cyan] (Slower but can handle dynamic content)",
        default=config.use_javascript
    )

    if config.use_javascript:
        config.android_mode = Confirm.ask(
            "[cyan]Use Android/Appium mode?[/cyan] (For mobile testing)",
            default=config.android_mode
        )

        if config.android_mode:
            # Configure Android settings
            android_config = AndroidConfig()

            configure_android = Confirm.ask(
                "[cyan]Configure Android settings?[/cyan] (Use defaults otherwise)",
                default=False
            )

            if configure_android:
                android_config.device_name = Prompt.ask(
                    "[cyan]Android device name[/cyan]",
                    default=android_config.device_name
                )
                android_config.platform_version = Prompt.ask(
                    "[cyan]Android platform version[/cyan]",
                    default=android_config.platform_version
                )
                android_config.appium_server_url = Prompt.ask(
                    "[cyan]Appium server URL[/cyan]",
                    default=android_config.appium_server_url
                )

            config.android_config = android_config

    # Robots.txt compliance
    config.respect_robots = Confirm.ask(
        "[cyan]Respect robots.txt?[/cyan] (Recommended for ethical crawling)",
        default=config.respect_robots
    )

    # Advanced settings
    configure_advanced = Confirm.ask(
        "[cyan]Configure advanced settings?[/cyan] (timeouts, retries)",
        default=False
    )

    if configure_advanced:
        config.request_timeout = IntPrompt.ask(
            "[cyan]Request timeout (seconds)[/cyan]",
            default=config.request_timeout,
            show_default=True
        )
        config.max_retries = IntPrompt.ask(
            "[cyan]Maximum retries per URL[/cyan]",
            default=config.max_retries,
            show_default=True
        )
        config.semaphore_timeout = IntPrompt.ask(
            "[cyan]Semaphore timeout (seconds)[/cyan]",
            default=config.semaphore_timeout,
            show_default=True
        )

    return config


def get_output_choice():
    """Prompt user for how to handle the output."""
    console.print("\n[bold]How would you like to receive the results?[/bold]")
    console.print("1. Display in console")
    console.print("2. Save to JSON file")
    console.print("3. Save to CSV file")
    choice = IntPrompt.ask("Enter your choice", choices=["1", "2", "3"], default=1)

    filename = None
    if choice == 2:
        filename = Prompt.ask("Enter JSON filename", default="crawler_report.json")
        if not filename.endswith('.json'):
            filename += '.json'
    elif choice == 3:
        filename = Prompt.ask("Enter CSV filename", default="crawler_report.csv")
        if not filename.endswith('.csv'):
            filename += '.csv'

    return choice, filename


# --- Output & Presentation Modules ---

def display_results(results: List[Dict[str, Any]]):
    """Display the scraped results in a rich TUI format."""
    if not results:
        console.print("\n[yellow]No data was successfully scraped.[/yellow]")
        return

    # Group results by depth
    by_depth: Dict[int, List[Dict[str, Any]]] = {}
    for result in results:
        depth = result.get('crawl_depth', 0)
        if depth not in by_depth:
            by_depth[depth] = []
        by_depth[depth].append(result)

    for depth in sorted(by_depth.keys()):
        console.print(f"\n[bold blue]╔══ Crawl Depth {depth} ══╗[/bold blue]")

        for result in by_depth[depth]:
            try:
                console.print(Panel(
                    f"[bold cyan]{result['source_url']}[/bold cyan]"
                    + (f"\n→ [dim]{result['final_url']}[/dim]" if result['source_url'] != result['final_url'] else ""),
                    title="[bold]Scrape Result[/bold]",
                    expand=False
                ))

                meta_table = Table(show_header=False, box=None, padding=(0, 1))
                meta_table.add_row("[bold]Title[/bold]:", result.get('metadata', {}).get('title', 'N/A'))
                meta_table.add_row("[bold]Description[/bold]:", result.get('metadata', {}).get('description', 'N/A') or "N/A")
                console.print(Panel(meta_table, title="[b green]Metadata[/b green]", border_style="green"))

                # Enhanced contact display
                contacts = result.get('contacts', {})
                if contacts.get('emails') or contacts.get('phones'):
                    contact_table = Table(show_header=False, box=None, padding=(0, 1))
                    if contacts.get('emails'):
                        contact_table.add_row("[bold]Emails[/bold]:", "\n".join(contacts['emails']))
                    if contacts.get('phones'):
                        contact_table.add_row("[bold]Phones[/bold]:", "\n".join(contacts['phones']))
                    console.print(Panel(contact_table, title="[b magenta]Contacts[/b magenta]", border_style="magenta"))

                link_table = Table(title="Link Details", box=None)
                link_table.add_column("Type", style="cyan")
                link_table.add_column("Count", style="magenta", justify="right")
                link_table.add_column("Examples", style="green")

                links = result.get('links', {})
                for link_type, urls in links.items():
                    examples = '\n'.join(urls[:3]) + ('\n...' if len(urls) > 3 else '')
                    link_table.add_row(link_type.capitalize(), str(len(urls)), examples)

                console.print(Panel(link_table, title="[b blue]Links[/b blue]", border_style="blue"))
                console.print("-" * 80)
            except Exception as e:
                console.log(f"[yellow]Error displaying result: {e}[/yellow]")


def save_to_file(data: List[Dict[str, Any]], filename: str, format_type: str):
    """Save results to the specified file format with enhanced error handling."""
    if not data:
        console.print("[yellow]No data to save.[/yellow]")
        return

    output_dir = "reports/crawler_results"
    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        console.print(f"[red]Error creating output directory: {e}[/red]")
        return

    full_path = os.path.join(output_dir, filename)

    try:
        if format_type == 'json':
            with open(full_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False, sort_keys=True)
        elif format_type == 'csv':
            flat_data = []
            for item in data:
                if not item:
                    continue

                try:
                    flat_item = {
                        "source_url": item.get("source_url", ""),
                        "final_url": item.get("final_url", ""),
                        "crawl_depth": item.get("crawl_depth", 0),
                        "title": item.get("metadata", {}).get("title", ""),
                        "description": item.get("metadata", {}).get("description", ""),
                        "keywords": item.get("metadata", {}).get("keywords", ""),
                        "emails": ", ".join(item.get("contacts", {}).get("emails", [])),
                        "phones": ", ".join(item.get("contacts", {}).get("phones", [])),
                        "internal_links_count": item.get("link_counts", {}).get("internal", 0),
                        "external_links_count": item.get("link_counts", {}).get("external", 0),
                        "asset_links_count": item.get("link_counts", {}).get("assets", 0),
                    }

                    # Add OG properties safely
                    og_properties = item.get("metadata", {}).get("og_properties", {})
                    for key, value in og_properties.items():
                        flat_item[f"og_{key}"] = str(value) if value else ""

                    flat_data.append(flat_item)
                except Exception as e:
                    console.log(f"[yellow]Error processing item for CSV: {e}[/yellow]")
                    continue

            if flat_data:
                with open(full_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=flat_data[0].keys())
                    writer.writeheader()
                    writer.writerows(flat_data)
            else:
                console.print("[yellow]No valid data to save to CSV.[/yellow]")
                return

        console.print(f"\n[bold green]✓ Results successfully saved to {full_path}[/bold green]")

    except IOError as e:
        console.print(f"\n[bold red]Error: Could not write to file {full_path}. {e}[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red]Unexpected error writing file: {e}[/bold red]")
