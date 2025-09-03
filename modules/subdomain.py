# modules/subdomain.py
import dns.resolver
import random
import socket
import os
import itertools
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from time import time, sleep
from threading import Semaphore

# Rich library for beautiful TUIs
from rich.console import Console, Group
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from rich.live import Live
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.box import ROUNDED
from rich.text import Text
from rich.align import Align
from core.utils import clear_console, load_wordlist, header_banner

# Optional: SOCKS proxy support
try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False

# --- Initialize Rich Console ---
console = Console()


def chunked(iterable, size):
    """
    Splits an iterable into chunks of a given size.
    Memory-efficient as it doesn't load all chunks at once.
    """
    it = iter(iterable)
    while True:
        chunk = tuple(itertools.islice(it, size))
        if not chunk:
            break
        yield chunk

def create_results_dir(base_dir="reports/subdomain_results/"):
    """
    Creates the main directory for storing scan results.
    """
    Path(base_dir).mkdir(parents=True, exist_ok=True)
    return base_dir

# --- Core Scanner Class ---

class DNSScanner:
    """
    Performs DNS scanning with support for rate limiting and proxies.
    """
    def __init__(self, rate_limit=50):
        self.resolvers = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222']
        self.default_ports = {'socks4': 1080, 'socks5': 1080, 'http': 8080}
        self.rate_limiter = Semaphore(rate_limit)
        self.proxy_configured = False

    def configure_proxy(self, proxy_type, proxy_host, proxy_port=None):
        """Configures a SOCKS proxy for DNS resolution."""
        if not SOCKS_AVAILABLE:
            console.print("[red]Error:[/] PySocks library not installed. Cannot configure proxy.")
            console.print("Install it with: [bold]pip install PySocks[/bold]")
            return False
        try:
            proxy_port = int(proxy_port) if proxy_port else self.default_ports.get(proxy_type, 1080)
            proxy_map = {'socks4': socks.SOCKS4, 'socks5': socks.SOCKS5, 'http': socks.HTTP}
            socks.set_default_proxy(proxy_map[proxy_type], proxy_host, proxy_port)
            socket.socket = socks.socksocket
            dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
            dns.resolver.default_resolver.nameservers = [proxy_host]
            self.proxy_configured = True
            console.print(f"[green]✓ Proxy {proxy_type}://{proxy_host}:{proxy_port} configured.[/green]")
            return True
        except Exception as e:
            console.print(f"[red]× Proxy configuration error: {e}[/red]")
            return False

    def dns_query(self, domain, retries=2, timeout=2):
        """Performs DNS queries for A, AAAA, and CNAME records."""
        resolver = dns.resolver.Resolver(configure=False)
    
        resolver.nameservers = self.resolvers if not self.proxy_configured else [random.choice(self.resolvers)]
        
        resolver.timeout = timeout
        resolver.lifetime = timeout + 1
        record_types = ['A', 'AAAA', 'CNAME']

        for _ in range(retries):
            for rtype in record_types:
                try:
                    answers = resolver.resolve(domain, rtype)
                    if answers:
                        value = str(answers[0].target) if rtype == 'CNAME' else str(answers[0])
                        return (rtype, value)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    return None # Domain doesn't exist for this record type
                except dns.exception.Timeout:
                    sleep(0.2)
                    break
                except Exception:
                    sleep(0.5)
                    break
            else:
                continue
            break
        return None

    def scan_subdomain(self, target_domain, sub, table):
        """Scans a single subdomain and updates the live table."""
        with self.rate_limiter:
            full_domain = f"{sub}.{target_domain}"
            result = self.dns_query(full_domain)
            if result:
                record_type, value = result
                table.add_row(full_domain, record_type, value, style="bright_green")
                return (full_domain, record_type, value)
        return None

# --- TUI & Main Logic ---

def get_scan_config(scanner):
    """Prompts user for rate limit and proxy settings."""
    rate_limit = IntPrompt.ask("[bold]Enter rate limit (concurrent requests)[/]", default=50)
    scanner.rate_limiter = Semaphore(rate_limit)
    
    if SOCKS_AVAILABLE and Prompt.ask("[bold]Use proxy? (y/N)[/]", default='n').lower() == 'y':
        proxy_type = Prompt.ask("[bold]Proxy type[/]", choices=['socks4', 'socks5', 'http'], default='socks5')
        proxy_host = Prompt.ask("[bold]Proxy host[/]").strip()
        proxy_port = Prompt.ask(f"[bold]Proxy port (default: {scanner.default_ports.get(proxy_type, 'N/A')})[/]").strip()
        if not scanner.configure_proxy(proxy_type, proxy_host, proxy_port or None):
            return False # Proxy config failed
    return True

def perform_scan(targets, scanner, wordlist):
    """
    Manages the entire scanning process for a list of targets.
    """
    base_results_dir = create_results_dir()
    wordlist_size = len(wordlist)
    
    for target_domain in targets:
        console.rule(f"[bold cyan]Scanning: {target_domain}[/bold cyan]")
        
        # --- Setup Live UI ---
        results_table = Table(title=f"Discovered Subdomains for {target_domain}", box=ROUNDED, expand=True)
        results_table.add_column("Subdomain", style="cyan", no_wrap=True)
        results_table.add_column("Type", style="yellow", width=8)
        results_table.add_column("Value", style="magenta")

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        )
        progress_task = progress.add_task("[green]Scanning...", total=wordlist_size)
        live_group = Panel(Group(progress, results_table), title="Scan Progress", border_style="green")

        found_subs = []
        start_time = time()

        with Live(live_group, refresh_per_second=10, console=console):
            with ThreadPoolExecutor(max_workers=scanner.rate_limiter._value + 10) as executor:
                futures = [executor.submit(scanner.scan_subdomain, target_domain, sub, results_table) for sub in wordlist]
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            found_subs.append(result)
                    except Exception as exc:
                        console.log(f'[red]A task generated an exception: {exc}[/red]')
                    finally:
                        progress.advance(progress_task)
        
        scan_duration = time() - start_time
        save_results(target_domain, found_subs, base_results_dir, scan_duration)

def save_results(target, results, base_dir, duration):
    """Saves the scan results to a structured directory and file."""
    if not results:
        console.print(f"\n[yellow]No subdomains found for {target}.[/yellow]")
        return
        
    # Create a unique, timestamped directory for this target's scan
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_dir_name = f"{target.replace('.', '_')}_{timestamp}"
    target_path = Path(base_dir) / target_dir_name
    target_path.mkdir(exist_ok=True)
    
    filename = target_path / f"found_subdomains.txt"
    
    console.print("\n" + "="*60)
    console.print(f"[bold green]✓ Scan for [cyan]{target}[/cyan] Complete![/bold green]")
    console.print(f"  [+] Duration: {duration:.2f} seconds")
    console.print(f"  [+] Total Found: {len(results)}")
    console.print(f"  [+] Saving results to: [yellow]{filename}[/yellow]")
    console.print("="*60 + "\n")

    try:
        with open(filename, 'w') as f:
            f.write(f"# Subdomain scan results for {target}\n")
            f.write(f"# Scan completed on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"{'Subdomain':<40}{'Type':<10}{'Value'}\n")
            f.write(f"{'-'*40}{'-'*10}{'-'*30}\n")
            for domain, rtype, value in sorted(results):
                f.write(f"{domain:<40}{rtype:<10}{value}\n")
        console.print(f"[green]  ✓ Successfully saved.[/green]\n")
    except IOError as e:
        console.print(f"[red]  × Error saving file: {e}[/red]\n")


def main_menu():
    """Displays the main menu and handles user choices."""
    scanner = DNSScanner()
    wordlist = None

    while True:
        clear_console()
        header_banner(tool_name="Subdomain Scanner")
        
        menu_text = (
            "[1] Single URL Scan\n"
            "[2] Batch Scan from File\n"
            "[3] Exit"
        )
        panel = Panel(
            Align.center(menu_text, vertical="middle"),
            title="[bold]Scan Options[/bold]",
            border_style="cyan",
            padding=(1, 4)
        )
        console.print(panel)
        
        choice = Prompt.ask("[bold]Choose an option[/bold]", choices=['1', '2', '3'], default='1')

        if choice == '3':
            console.print("[bold magenta]Goodbye![/bold magenta]")
            break
        
        if not get_scan_config(scanner):
            sleep(2)
            continue # Return to menu if proxy config fails

        if wordlist is None:
            ask_for_custom = Prompt.ask("[bold]Want to use custom wordlist? (y/N): ", default="N")
            if ask_for_custom.lower() == 'y':
                wordlist_path = Prompt.ask("[bold]Enter path to wordlist[/]", default="wordlists/subdomain.txt")
                wordlist = load_wordlist(path=wordlist_path)
                if not wordlist:
                    console.print("[red]Wordlist could not be loaded. Returning to menu.[/red]")
                    sleep(2)
                    continue
            else:
                console.print("[green][!] Using default wordlist. [/green]")
                wordlist = load_wordlist(path="wordlists/subdomain.txt")    

        targets = []
        if choice == '1':
            target_url = Prompt.ask("[bold]Enter the target domain (e.g., example.com)[/]").strip()
            if '.' in target_url:
                targets.append(target_url)
            else:
                console.print("[red]Invalid domain format.[/red]")
                sleep(2)
                continue

        elif choice == '2':
            file_path = Prompt.ask("[bold]Enter the path to the file with URLs[/]").strip()
            try:
                with open(file_path, 'r') as f:
                    targets = [line.strip() for line in f if '.' in line.strip()]
                if not targets:
                    console.print("[red]No valid domains found in file.[/red]")
                    sleep(2)
                    continue
            except FileNotFoundError:
                console.print(f"[red]Error: File not found at '{file_path}'[/red]")
                sleep(2)
                continue
        
        perform_scan(targets, scanner, wordlist)
        Prompt.ask("\n[bold]Press Enter to return to the main menu...[/bold]")


if __name__ == '__main__':
    try:
        main_menu()
    except KeyboardInterrupt:
        console.print("\n\n[bold red]Operation cancelled by user.[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred: {e}[/bold red]")

