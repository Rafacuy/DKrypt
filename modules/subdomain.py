# modules/subdomain.py
import dns.resolver
import random
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from time import time, sleep
from rich.console import Console, Group
from rich.panel import Panel
from rich.live import Live
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.text import Text
from rich.box import ROUNDED
from rich.layout import Layout

import socks
import itertools
from threading import Semaphore
from core.utils import clear_console, load_wordlist

# --- Initialize Rich Console ---
console = Console()

def chunked(iterable, size):
    """
    Splits an iterable into chunks of a given size using a generator.
    This is memory-efficient as it doesn't load all chunks into memory.
    """
    it = iter(iterable)
    while True:
        chunk = tuple(itertools.islice(it, size))
        if not chunk:
            break
        yield chunk

class DNSScanner:
    """
    A class to perform DNS scanning with support for proxies, rate limiting,
    and efficient, multi-threaded subdomain enumeration.
    """
    def __init__(self, rate_limit=50):
        """
        Initializes the scanner.
        Args:
            rate_limit (int): Maximum number of concurrent DNS queries.
        """
        self.resolvers = [
            '8.8.8.8',        # Google
            '1.1.1.1',        # Cloudflare
            '9.9.9.9',        # Quad9
            '208.67.222.222'  # OpenDNS
        ]
        self.default_ports = {
            'socks4': 1080,
            'socks5': 1080,
            'http': 8080
        }
        # --- FIX: Configurable rate limiting ---
        # Use a Semaphore to limit concurrent requests, preventing DNS server overload.
        self.rate_limiter = Semaphore(rate_limit)

    def configure_proxy(self, proxy_type, proxy_host, proxy_port=None):
        """
        Configures a network proxy for all subsequent socket operations and
        redirects DNS resolution through the proxy.
        """
        try:
            proxy_port = int(proxy_port) if proxy_port else self.default_ports.get(proxy_type, 1080)
            proxy_map = {
                'socks4': socks.SOCKS4,
                'socks5': socks.SOCKS5,
                'http': socks.HTTP
            }
            socks.set_default_proxy(
                proxy_map[proxy_type],
                proxy_host,
                proxy_port
            )
            socket.socket = socks.socksocket
            
            # --- Proxy Support for DNS ---
            # The dns.resolver module does not automatically use the patched socket.
            # We must explicitly configure the default resolver to use the proxy as its nameserver.
            # This assumes the proxy server can handle DNS queries.
            dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
            dns.resolver.default_resolver.nameservers = [proxy_host]
            
            console.print(f"[green]✓ Proxy {proxy_type}://{proxy_host}:{proxy_port} configured[/green]")
            console.print(f"[yellow]  DNS queries will be routed through {proxy_host}[/yellow]")
            return True
        except Exception as e:
            console.print(f"[red]× Proxy configuration error: {str(e)}[/red]")
            return False

    def dns_query(self, domain, retries=2, timeout=2):
        """
        Performs DNS queries for multiple record types (A, AAAA, CNAME).

        Args:
            domain (str): The domain to resolve.
            retries (int): Number of times to retry on failure.
            timeout (int): Timeout for each DNS query in seconds.

        Returns:
            tuple: A tuple of (Record Type, Value) or None if resolution fails.
        """
        # Use the globally configured resolver (which may be using the proxy)
        resolver = dns.resolver.get_default_resolver()
        # If no proxy is set, pick a random public resolver for load distribution
        if not socks.get_default_proxy():
            resolver.nameservers = [random.choice(self.resolvers)]
        
        resolver.timeout = timeout
        resolver.lifetime = timeout + 1
        
        # Check for A, AAAA, and CNAME records for more comprehensive results.
        record_types = ['A', 'AAAA', 'CNAME']

        for _ in range(retries):
            for rtype in record_types:
                try:
                    answers = resolver.resolve(domain, rtype)
                    if answers:
                        if rtype == 'CNAME':
                            return (rtype, str(answers[0].target))
                        return (rtype, str(answers[0]))
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    # This domain doesn't exist for this record type, which is normal.
                    # We break here to avoid retrying for a known non-existent domain.
                    return None
                except dns.exception.Timeout:
                    # Timeout occurred, sleep and the outer loop will retry.
                    sleep(0.2)
                    break 
                except Exception:
                    # Another error occurred, sleep before retrying.
                    sleep(0.5)
                    break
            else: # If inner loop completed without break
                continue
            break # If inner loop was broken by timeout/error
        return None

    def scan_subdomain(self, target_domain, sub, table):
        """
        Scans a single subdomain and adds the result to the live table.
        
        Args:
            target_domain (str): The main domain (e.g., 'example.com').
            sub (str): A subdomain to test.
            table (rich.table.Table): The live table to add results to.

        Returns:
            tuple: (found_domain, record_type, value) or None.
        """
        # Acquire the semaphore; this will block if the rate limit is reached.
        with self.rate_limiter:
            full_domain = f"{sub}.{target_domain}"
            result = self.dns_query(full_domain)
            if result:
                record_type, value = result
                # Add to the live table for real-time display
                table.add_row(full_domain, record_type, value, style="bright_green")
                return (full_domain, record_type, value)
        return None

def run_subdomain_scanner():
    """Main function to run the subdomain scanner tool."""
    clear_console()
    console.print(Panel.fit("[bold]🚀 SUBDOMAIN SCANNER [/]", style="cyan", padding=(1, 2)))

    # --- Configuration ---
    rate_limit = int(console.input("[bold]Enter rate limit (concurrent requests, default: 50): [/]") or "50")
    scanner = DNSScanner(rate_limit=rate_limit)

    if console.input("[bold]Use proxy? (y/N): [/]").lower() == 'y':
        proxy_type = console.input("[bold]Proxy type (socks4/socks5/http): [/]").strip().lower()
        proxy_host = console.input("[bold]Proxy host: [/]").strip()
        proxy_port = console.input(f"[bold]Proxy port (default: {scanner.default_ports.get(proxy_type, 'N/A')}): [/]").strip()
        if not scanner.configure_proxy(proxy_type, proxy_host, proxy_port or None):
            return # Exit if proxy configuration fails

    wordlist = load_wordlist()
    if not wordlist:
        console.print("[red]× Wordlist could not be loaded. Exiting.[/red]")
        return
    
    wordlist_size = len(wordlist)

    targets_input = console.input("[bold]Enter target domains (comma-separated): [/]")
    targets = list({t.strip() for t in targets_input.split(',') if '.' in t})
    if not targets:
        console.print("[red]× No valid target domains entered. Exiting.[/red]")
        return

    # --- Configuration for Threading ---
    MAX_WORKERS = rate_limit + 10 # Set workers slightly higher than rate limit

    console.print(f"[cyan]Wordlist loaded: {wordlist_size} subdomains.[/cyan]")
    console.print(f"[cyan]Rate limit set to {rate_limit} concurrent requests.[/cyan]")

    # --- Setup Live UI ---
    results_table = Table(title="Discovered Subdomains", box=ROUNDED, expand=True)
    results_table.add_column("Subdomain", justify="left", style="cyan", no_wrap=True)
    results_table.add_column("Type", justify="center", style="yellow", width=8)
    results_table.add_column("Value", justify="left", style="magenta")

    total_tasks = wordlist_size * len(targets)
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed} of {task.total})"),
        console=console,
    )
    progress_task = progress.add_task("[green]Scanning...", total=total_tasks)
    
    # Group the progress bar and results table for a clean live view.
    live_group = Group(Panel(progress, title="Overall Progress", border_style="green"), results_table)

    all_found = defaultdict(list)
    start_time = time()

    with Live(live_group, refresh_per_second=10, console=console):
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for chunk in chunked(((target, sub) for target in targets for sub in wordlist), MAX_WORKERS):
                futures = [executor.submit(scanner.scan_subdomain, t, s, results_table) for t, s in chunk]
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            all_found[result[0].split('.')[-2] + '.' + result[0].split('.')[-1]].append(result)
                    except Exception as exc:
                        console.print(f'[red]× A task generated an exception: {exc}[/red]')
                    finally:
                        progress.advance(progress_task)

    # --- Final Summary and Save Results ---
    total_found_count = sum(len(v) for v in all_found.values())
    scan_duration = time() - start_time
    
    console.print("\n" + "="*60)
    console.print(f"[bold green]✓ Scan Complete![/bold green]")
    console.print(f"  [+] Duration: {scan_duration:.2f} seconds")
    console.print(f"  [+] Total Subdomains Found: {total_found_count}")
    console.print("="*60 + "\n")

    if total_found_count > 0:
        for target, subs in all_found.items():
            filename = f"found_subdomains_{target.replace('.','_')}.txt"
            console.print(f"[bold]Saving results for [cyan]{target}[/cyan] to [yellow]{filename}[/yellow]...")
            try:
                with open(filename, 'w') as f:
                    f.write(f"Subdomain scan results for {target}\n\n")
                    f.write("Subdomain".ljust(40) + "Type".ljust(10) + "Value\n")
                    f.write("-" * 70 + "\n")
                    for domain, rtype, value in sorted(subs):
                        f.write(f"{domain.ljust(40)}{rtype.ljust(10)}{value}\n")
                console.print(f"[green]  ✓ Successfully saved.[/green]")
            except IOError as e:
                console.print(f"[red]  × Error saving file: {e}[/red]")

if __name__ == '__main__':
    try:
        run_subdomain_scanner()
    except KeyboardInterrupt:
        console.print("\n[bold red]Operation cancelled by user.[/bold red]")

