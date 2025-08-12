# scraper_tui.py
import asyncio
import csv
import json
import re
import sys
import os
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse, urljoin

import aiohttp
import phonenumbers
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.prompt import Prompt, IntPrompt
from core.randomizer import HeaderFactory
from core.utils import clear_console

# --- Setup ---
console = Console()

# --- Data Extraction Modules (Modified for async) ---

def _extract_metadata(soup: BeautifulSoup) -> Dict[str, Any]:
    """
    Extracts key metadata from a BeautifulSoup object.
    """
    title_tag = soup.find('title')
    title = title_tag.string.strip() if title_tag and title_tag.string else "No Title Found"

    metadata = {
        'title': title,
        'description': '',
        'keywords': '',
        'og_properties': {},
        'other_meta': []
    }

    for tag in soup.find_all('meta'):
        name = tag.get('name', '').lower()
        prop = tag.get('property', '').lower()
        content = tag.get('content', '')

        if name == 'description':
            metadata['description'] = content
        elif name == 'keywords':
            metadata['keywords'] = content
        elif prop.startswith('og:'):
            metadata['og_properties'][prop[3:]] = content
        else:
            if name or prop:
                metadata['other_meta'].append({'name': name or prop, 'content': content})
    return metadata


def _extract_contacts(text: str) -> Dict[str, List[str]]:
    """
    Extracts email addresses and international phone numbers from text content.
    """
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = set(re.findall(email_regex, text))

    found_numbers = set()
    try:
        for match in phonenumbers.PhoneNumberMatcher(text, "ZZ"):
            formatted_number = phonenumbers.format_number(
                match.number, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            )
            found_numbers.add(formatted_number)
    except Exception:
        # Ignore phonenumbers parsing errors on non-phone number text
        pass


    return {
        'emails': sorted(list(emails)),
        'phones': sorted(list(found_numbers))
    }


def _extract_links(soup: BeautifulSoup, base_url: str) -> Dict[str, List[str]]:
    """
    Extracts and categorizes all links from a page.
    """
    links: Dict[str, Set[str]] = {'internal': set(), 'external': set(), 'assets': set()}
    parsed_base = urlparse(base_url)

    for tag in soup.find_all(['a', 'link', 'img', 'script', 'source']):
        url = tag.get('href') or tag.get('src')
        if not url or url.startswith(('mailto:', 'tel:')):
            continue

        absolute_url = urljoin(base_url, url)
        parsed_url = urlparse(absolute_url)

        if any(absolute_url.endswith(ext) for ext in ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp')):
            links['assets'].add(absolute_url)
        elif parsed_url.netloc == parsed_base.netloc:
            links['internal'].add(absolute_url)
        else:
            links['external'].add(absolute_url)

    return {key: sorted(list(value)) for key, value in links.items()}


# --- Core Scraping Function (Async) ---

async def scrape_url_async(url: str, session: aiohttp.ClientSession, header_factory: HeaderFactory) -> Optional[Dict[str, Any]]:
    """
    Performs the full scraping process for a single URL asynchronously.
    """
    try:
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        headers = header_factory.get_headers()
        async with session.get(url, headers=headers, timeout=30, allow_redirects=True) as response:
            if response.status == 403:
                console.log(f"[bold yellow]Access to {url} is forbidden (403). The site is likely blocking scrapers.[/bold yellow]")
                return None
            if response.status == 404:
                console.log(f"[yellow]URL not found (404): {url}[/yellow]")
                return None
            response.raise_for_status()
            
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' not in content_type:
                console.log(f"[yellow]Skipped {url}: Content-Type is '{content_type}', not HTML.[/yellow]")
                return None

            html = await response.text()
            soup = BeautifulSoup(html, 'html.parser')
            text_content = soup.get_text(separator=' ', strip=True)

            domain_info = urlparse(str(response.url))
            metadata = _extract_metadata(soup)
            contacts = _extract_contacts(text_content)
            links = _extract_links(soup, str(response.url))

            return {
                "source_url": url,
                "final_url": str(response.url),
                "domain_info": {
                    "scheme": domain_info.scheme,
                    "netloc": domain_info.netloc,
                    "path": domain_info.path,
                },
                "metadata": metadata,
                "contacts": contacts,
                "links": links,
                "link_counts": {k: len(v) for k, v in links.items()}
            }

    except asyncio.TimeoutError:
        console.log(f"[bold red]Timeout error scraping {url}[/bold red]")
        return None
    except aiohttp.ClientError as e:
        console.log(f"[bold red]Request error scraping {url}: {e}[/bold red]")
        return None
    except Exception as e:
        console.log(f"[bold red]An unexpected error occurred for {url}: {e}[/bold red]")
        return None

# --- Output & Presentation Modules ---

def display_results(results: List[Dict[str, Any]]):
    """
    Displays the scraped results in a rich TUI format.
    """
    if not results:
        console.print("\n[yellow]No data was successfully scraped.[/yellow]")
        return
        
    for result in results:
        if not result: continue
        console.print(Panel(
            f"[bold cyan]{result['source_url']}[/bold cyan]",
            title="[bold]Scrape Result[/bold]",
            expand=False
        ))

        meta_table = Table(show_header=False, box=None, padding=(0, 1))
        meta_table.add_row("[bold]Title[/bold]:", result['metadata']['title'])
        meta_table.add_row("[bold]Description[/bold]:", result['metadata']['description'] or "N/A")
        console.print(Panel(meta_table, title="[b green]Metadata[/b green]", border_style="green"))

        contact_table = Table(show_header=False, box=None, padding=(0, 1))
        if result['contacts']['emails']:
            contact_table.add_row("[bold]Emails[/bold]:", "\n".join(result['contacts']['emails']))
        if result['contacts']['phones']:
            contact_table.add_row("[bold]Phones[/bold]:", "\n".join(result['contacts']['phones']))
        if result['contacts']['emails'] or result['contacts']['phones']:
            console.print(Panel(contact_table, title="[b magenta]Contacts[/b magenta]", border_style="magenta"))

        link_table = Table(title="Link Details", box=None)
        link_table.add_column("Type", style="cyan")
        link_table.add_column("Count", style="magenta", justify="right")
        link_table.add_column("Examples", style="green")
        for link_type, urls in result['links'].items():
            examples = '\n'.join(urls[:3]) + ('\n...' if len(urls) > 3 else '')
            link_table.add_row(link_type.capitalize(), str(len(urls)), examples)
        console.print(Panel(link_table, title="[b blue]Links[/b blue]", border_style="blue"))
        console.print("-" * 80)


def save_to_file(data: List[Dict[str, Any]], filename: str, format_type: str):
    """Saves results to the specified file format."""
    if not data:
        console.print("[yellow]No data to save.[/yellow]")
        return

    output_dir = "reports/scraper_result"
    os.makedirs(output_dir, exist_ok=True)
    full_path = os.path.join(output_dir, filename)

    try:
        if format_type == 'json':
            with open(full_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False, sort_keys=True)
        elif format_type == 'csv':
            flat_data = []
            for item in data:
                if not item: continue
                flat_item = {
                    "source_url": item.get("source_url"), "final_url": item.get("final_url"),
                    "title": item.get("metadata", {}).get("title"), "description": item.get("metadata", {}).get("description"),
                    "keywords": item.get("metadata", {}).get("keywords"), "emails": ", ".join(item.get("contacts", {}).get("emails", [])),
                    "phones": ", ".join(item.get("contacts", {}).get("phones", [])),
                    "internal_links_count": item.get("link_counts", {}).get("internal", 0),
                    "external_links_count": item.get("link_counts", {}).get("external", 0),
                    "asset_links_count": item.get("link_counts", {}).get("assets", 0),
                }
                og_properties = item.get("metadata", {}).get("og_properties", {})
                for key, value in og_properties.items():
                    flat_item[f"og_{key}"] = value
                flat_data.append(flat_item)
            
            if flat_data:
                with open(full_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=flat_data[0].keys())
                    writer.writeheader()
                    writer.writerows(flat_data)

        console.print(f"\n[bold green]✔ Results successfully saved to {full_path}[/bold green]")

    except IOError as e:
        console.print(f"\n[bold red]Error: Could not write to file {full_path}. {e}[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red]Unexpected error writing file: {e}[/bold red]")


# --- TUI & Main Execution ---
async def process_batch(urls: List[str], header_factory: HeaderFactory):
    """Processes a batch of URLs asynchronously with a progress bar."""
    all_results = []
    async with aiohttp.ClientSession() as session:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[green]Scraping URLs...", total=len(urls))
            
            tasks = [scrape_url_async(url, session, header_factory) for url in urls]
            
            for f in asyncio.as_completed(tasks):
                result = await f
                if result:
                    all_results.append(result)
                progress.update(task, advance=1)
    
    return all_results


def get_output_choice():
    """Prompts user for how to handle the output."""
    console.print("\n[bold]How would you like to receive the results?[/bold]")
    console.print("1. Display in console")
    console.print("2. Save to JSON file")
    console.print("3. Save to CSV file")
    choice = IntPrompt.ask("Enter your choice", choices=["1", "2", "3"], default=1)
    
    filename = None
    if choice == 2:
        filename = Prompt.ask("Enter JSON filename", default="report.json")
    elif choice == 3:
        filename = Prompt.ask("Enter CSV filename", default="report.csv")
        
    return choice, filename


async def main_menu(header_factory: HeaderFactory):
    """Displays the main menu and handles user choices."""
    while True:
        clear_console()
        console.print(Panel.fit(
            '[bold magenta]🚀 Website Scraper Engine 🚀[/bold magenta]\n\n'
            'Select an option to begin:',
            padding=(1, 2),
            title="Main Menu"
        ))
        
        console.print("\n[bold]1.[/bold] Scrape a single URL")
        console.print("[bold]2.[/bold] Scrape URLs from a file (Batch Mode)")
        console.print("[bold]3.[/bold] Exit")
        
        choice = IntPrompt.ask("\nEnter your choice", choices=["1", "2", "3"], default=1)
        
        urls_to_scan = []
        if choice == 1:
            url = Prompt.ask("\n[cyan]Enter the URL to scrape[/cyan]")
            urls_to_scan.append(url)
        elif choice == 2:
            file_path = Prompt.ask("\n[cyan]Enter the path to the file containing URLs[/cyan]")
            try:
                with open(file_path, 'r') as f:
                    urls_to_scan = [line.strip() for line in f if line.strip()]
                if not urls_to_scan:
                    console.print("[yellow]File is empty or contains no valid URLs.[/yellow]")
                    continue
            except FileNotFoundError:
                console.print(f"[bold red]Error: File not found at '{file_path}'[/bold red]")
                Prompt.ask("\nPress Enter to continue...")
                continue
        elif choice == 3:
            console.print("\n[bold blue]Goodbye![/bold blue]")
            break

        if urls_to_scan:
            results = await process_batch(urls_to_scan, header_factory)
            
            if results:
                output_choice, filename = get_output_choice()
                if output_choice == 1:
                    display_results(results)
                elif output_choice == 2 and filename:
                    save_to_file(results, filename, 'json')
                elif output_choice == 3 and filename:
                    save_to_file(results, filename, 'csv')
            else:
                 console.print("\n[yellow]Could not retrieve any data from the provided URL(s).[/yellow]")

            Prompt.ask("\nPress Enter to return to the main menu...")


if __name__ == "__main__":
    try:
        asyncio.run(main_menu())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Program interrupted by user. Exiting.[/bold yellow]")
    except Exception as e:
        console.print(f"\n[bold red]A critical error occurred: {e}[/bold red]")
