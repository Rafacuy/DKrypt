# modules/dir_bruteforcer.py
import requests
import os
import sys
from urllib.parse import urljoin
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, MofNCompleteColumn
from rich.panel import Panel
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.utils import load_wordlist, clear_console, header_banner

# Initialize colorama 
init()

# Initialize rich console for beautiful output
console = Console()

def save_report(found: list, report_path: str):
    """Saves the list of found URLs to a report file."""
    try:
        with open(report_path, 'w', encoding='utf-8') as f:
            for url in found:
                f.write(url + '\n')
        console.print(f"\n[bold green]✓ Report saved to[/bold green] {report_path}")
    except Exception as e:
        console.print(f"[bold red]Failed to save report:[/bold red] {e}")

def scan_url(url: str, valid_codes: list, session: requests.Session):
    """
    Scans a single URL and checks if its status code is in the valid list.
    
    Args:
        url (str): The URL to scan.
        valid_codes (list): A list of integer status codes to consider valid.
        session (requests.Session): The session object to use for the request.

    Returns:
        tuple[str, int] or tuple[None, None]: The found URL and its status code, or None if not found.
    """
    try:
        # Use the session object to make the GET request
        with session.get(url, timeout=5) as resp:
            if resp.status_code in valid_codes:
                return url, resp.status_code
    except requests.RequestException:
        # Ignore connection errors, timeouts, etc.
        pass
    return None, None

def run_concurrent_scan(base_url: str, wordlist: list, extensions: list, valid_codes: list, max_workers: int) -> list:
    """
    Scans for directories and files concurrently using a thread pool.
    
    Args:
        base_url (str): The base URL of the target.
        wordlist (list): The list of words to test.
        extensions (list): The list of extensions to append.
        valid_codes (list): A list of integer status codes to consider valid.
        max_workers (int): The number of concurrent threads to use.

    Returns:
        list: A list of found URLs.
    """
    found = []
    # Create all possible URL combinations
    urls_to_scan = [urljoin(base_url.rstrip('/') + '/', f"{word}{ext}") for word in wordlist for ext in extensions]
    
    if not urls_to_scan:
        console.print("[yellow]No URLs to scan based on the provided wordlist and extensions.[/yellow]")
        return []

    # Define the progress bar style
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    )

    with progress:
        task = progress.add_task("[cyan]Scanning...", total=len(urls_to_scan))
        # Use a ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Use a requests.Session object for connection pooling and performance
            with requests.Session() as session:
                # Submit all scan tasks to the executor
                futures = {executor.submit(scan_url, url, valid_codes, session) for url in urls_to_scan}

                # Process results as they are completed
                for future in as_completed(futures):
                    url, status_code = future.result()
                    if url:
                        # Print found URLs with their status codes
                        console.print(f"{Fore.GREEN}[FOUND {status_code}]{Style.RESET_ALL} {url}")
                        found.append(url)
                    # Update the progress bar for each completed task
                    progress.update(task, advance=1)
    return found

def main(args=None):
    """Main function to run the directory bruteforcer tool."""
    clear_console()
    init(autoreset=True) # Initialize colorama
    
    header_banner(tool_name="Dir Bruteforcer")

    if args:
        base_url = args.url
        wordlist_path = args.wordlist
        extensions = [ext.strip() for ext in args.extensions.split(",")]
        valid_codes = [int(code.strip()) for code in args.valid_codes.split(",")]
        max_workers = args.max_workers
        report_path = args.report
    else:
        # --- Get Target URL ---
        base_url = console.input("[bold yellow]Enter the target URL (e.g., https://example.com):[/bold yellow] ").strip()
        if not base_url.startswith(('http://', 'https://')):
            console.print("[bold red]Invalid URL. Please include http:// or https://[/bold red]")
            sys.exit(1)

        # --- Check Server Availability ---
        try:
            console.print(f"\n[cyan]Pinging server at {base_url}...[/cyan]")
            r = requests.head(base_url, timeout=20, allow_redirects=True)
            if not r.ok:
                console.print(f"[bold red]Target server returned a non-OK status: {r.status_code}[/bold red]")
                sys.exit(1)
            console.print(f"[green]✓ Server is online (Status: {r.status_code}).[/green]")
        except requests.RequestException as e:
            console.print(f"[bold red]Failed to connect to the target server:[/bold red] {e}")
            sys.exit(1)

        # --- Configure Status Codes ---
        default_codes = [200, 301, 302, 403, 401, 500]
        console.print(f"\n[cyan]Default detection codes: {default_codes}[/cyan]")
        add_custom = console.input("[bold yellow]Want to detect other status codes? (y/N):[/bold yellow] ").strip().lower()
        if add_custom == 'y':
            custom_codes_str = console.input("[bold yellow]Enter custom codes (comma-separated, e.g., 404,418):[/bold yellow] ").strip()
            try:
                custom_codes = [int(code.strip()) for code in custom_codes_str.split(',')]
                default_codes.extend(custom_codes)
                # Remove duplicates
                valid_codes = sorted(list(set(default_codes)))
                console.print(f"[green]✓ Now detecting: {valid_codes}[/green]")
            except ValueError:
                console.print("[bold red]Invalid input. Using default codes only.[/bold red]")
                valid_codes = default_codes
        else:
            valid_codes = default_codes

        # --- Tool Configuration ---
        wordlist_path = os.path.join('wordlists', 'directory-brute.txt')
        report_path = 'dir_reports.txt'
        extensions = ['/', '.php', '.html', '.htm', '.asp', '.aspx', '.js', '.json', '.txt', '.bak', '.old', '.zip', '.tar.gz']
        max_workers = 20 # Number of threads for concurrency

    # --- Run Scan ---
    words = load_wordlist(wordlist_path)
    console.print(f"\n[cyan]Starting scan with {max_workers} threads...[/cyan]")
    found_urls = run_concurrent_scan(base_url, words, extensions, valid_codes, max_workers)

    # --- Report Results ---
    if found_urls:
        console.print(f"\n[bold green]Scan complete. Found {len(found_urls)} items.[/bold green]")
        save_report(found_urls, report_path)
    else:
        console.print("\n[bold yellow]Scan complete. No directories or files found.[/bold yellow]")
