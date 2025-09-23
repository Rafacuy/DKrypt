# modules/subdomain.py
import dns.resolver
import dns.exception
import random
import socket
import os
import json
import csv
import asyncio
import aiohttp
import itertools
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from time import time, sleep
from threading import Semaphore
import urllib.parse
import ssl
import certifi

# Rich library for beautiful TUIs
from rich.console import Console, Group
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.live import Live
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
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

# --- Scan Mode Enums ---
class ScanMode:
    API_ONLY = "api_only"
    BRUTEFORCE_ONLY = "bruteforce_only"
    HYBRID = "hybrid"  # Both API and bruteforce
    
    @classmethod
    def all_modes(cls):
        return [cls.API_ONLY, cls.BRUTEFORCE_ONLY, cls.HYBRID]

# --- API Sources Configuration ---
API_SOURCES = {
    'crt.sh': {
        'url': 'https://crt.sh/?q=%25.{domain}&output=json',
        'timeout': 30,
        'enabled': True
    },
    'hackertarget': {
        'url': 'https://api.hackertarget.com/hostsearch/?q={domain}',
        'timeout': 15,
        'enabled': True
    },
    'threatcrowd': {
        'url': 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}',
        'timeout': 20,
        'enabled': True
    },
    'urlscan': {
        'url': 'https://urlscan.io/api/v1/search/?q=domain:{domain}',
        'timeout': 25,
        'enabled': True
    },
    'virustotal': {
        'url': 'https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={domain}',
        'timeout': 30,
        'enabled': False,  # Requires API key
        'requires_key': True
    }
}

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
    def __init__(self, rate_limit=100, scan_mode=ScanMode.HYBRID, api_keys=None, 
                 dns_timeout=2, max_retries=2, dns_threads=200):  
        self.resolvers = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222', '8.8.4.4', '1.0.0.1']
        self.default_ports = {'socks4': 1080, 'socks5': 1080, 'http': 8080}
        self.rate_limit = rate_limit
        self.scan_mode = scan_mode
        self.proxy_configured = False
        self.api_keys = api_keys or {}
        self.session = None
        self.found_subdomains = set()
        self.verified_subdomains = []
        
        # Performance 
        self.dns_timeout = dns_timeout
        self.max_retries = max_retries
        self.dns_threads = dns_threads
        self.dns_executor = ThreadPoolExecutor(max_workers=dns_threads)
        
        # Caching for DNS resolvers
        self.resolver_pool = self._create_resolver_pool()
        
    def _create_resolver_pool(self):
        """Create a pool of DNS resolvers for better performance"""
        resolvers = []
        for nameserver in self.resolvers:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [nameserver]
            resolver.timeout = self.dns_timeout
            resolver.lifetime = self.dns_timeout + 1
            resolvers.append(resolver)
        return resolvers
        
    @property
    def use_api(self):
        """Check if API enumeration should be used"""
        return self.scan_mode in [ScanMode.API_ONLY, ScanMode.HYBRID]
    
    @property
    def use_bruteforce(self):
        """Check if bruteforce enumeration should be used"""
        return self.scan_mode in [ScanMode.BRUTEFORCE_ONLY, ScanMode.HYBRID]
    
    def set_scan_mode(self, mode):
        """Set the scan mode with validation"""
        if mode not in ScanMode.all_modes():
            raise ValueError(f"Invalid scan mode. Must be one of: {ScanMode.all_modes()}")
        self.scan_mode = mode
        console.print(f"[green]Scan mode set to: {mode}[/green]")
        
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(
            ssl=ssl.create_default_context(cafile=certifi.where()),
            limit=200,  # Increased connection pool
            limit_per_host=50,  # Increased per-host limit
            ttl_dns_cache=300,  # DNS cache TTL
            use_dns_cache=True,
        )
        timeout = aiohttp.ClientTimeout(total=60, connect=30)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
        if self.dns_executor:
            self.dns_executor.shutdown(wait=True)

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

    def dns_query(self, domain):
        """DNS query with connection pooling and minimal retries"""
        # Use round-robin resolver selection for load balancing
        resolver = random.choice(self.resolver_pool)
        
        record_types = ['A', 'AAAA']  # Focus on essential records first for speed
        results = {}

        for attempt in range(self.max_retries):
            try:
                # Try A record first (most common)
                answers = resolver.resolve(domain, 'A')
                if answers:
                    results['A'] = [str(answer) for answer in answers]
                    # If A record exists, try other types in single attempt
                    for rtype in ['AAAA', 'CNAME', 'MX']:
                        try:
                            extra_answers = resolver.resolve(domain, rtype)
                            if extra_answers:
                                if rtype == 'CNAME':
                                    results[rtype] = [str(answer.target).rstrip('.') for answer in extra_answers]
                                elif rtype == 'MX':
                                    results[rtype] = [f"{answer.preference} {str(answer.exchange).rstrip('.')}" for answer in extra_answers]
                                else:
                                    results[rtype] = [str(answer) for answer in extra_answers]
                        except:
                            continue
                    break  # Success, no need to retry
                    
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                # Domain doesn't exist, no point retrying
                break
            except (dns.exception.Timeout, Exception):
                if attempt < self.max_retries - 1:
                    continue
                else:
                    break
                    
        return results if results else None

    async def fetch_api_subdomains(self, domain, progress_callback=None):
        """Fetch subdomains from various APIs asynchronously."""
        if not self.use_api:
            return []
            
        all_subdomains = set()
        
        # Run API calls concurrently
        tasks = []
        for source_name, config in API_SOURCES.items():
            if not config.get('enabled', True):
                continue
                
            if config.get('requires_key') and source_name not in self.api_keys:
                continue
                
            tasks.append(self._fetch_single_api(source_name, config, domain, progress_callback))
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, set):
                    all_subdomains.update(result)
                elif isinstance(result, Exception):
                    console.log(f"[yellow]API error: {str(result)[:50]}[/yellow]")
                    
        return list(all_subdomains)
    
    async def _fetch_single_api(self, source_name, config, domain, progress_callback):
        """Fetch from a single API source"""
        try:
            if progress_callback:
                progress_callback(f"Fetching from {source_name}...")
                
            url = config['url'].format(
                domain=domain,
                api_key=self.api_keys.get(source_name, '')
            )
            
            async with self.session.get(url, timeout=config['timeout']) as response:
                if response.status == 200:
                    data = await response.text()
                    subdomains = self._parse_api_response(source_name, data, domain)
                    
                    if progress_callback:
                        progress_callback(f"Found {len(subdomains)} from {source_name}")
                    
                    return subdomains
                    
        except asyncio.TimeoutError:
            if progress_callback:
                progress_callback(f"Timeout for {source_name}")
        except Exception as e:
            if progress_callback:
                progress_callback(f"Error with {source_name}: {str(e)[:50]}")
                
        return set()

    def _parse_api_response(self, source, data, domain):
        """Parse API responses based on the source."""
        subdomains = set()
        
        try:
            if source == 'crt.sh':
                entries = json.loads(data)
                for entry in entries:
                    name_value = entry.get('name_value', '')
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip().lower()
                        if subdomain.endswith(f'.{domain}') and '*' not in subdomain:
                            subdomains.add(subdomain)
                            
            elif source == 'hackertarget':
                for line in data.split('\n'):
                    line = line.strip()
                    if line and ',' in line:
                        subdomain = line.split(',')[0].strip().lower()
                        if subdomain.endswith(f'.{domain}'):
                            subdomains.add(subdomain)
                            
            elif source == 'threatcrowd':
                data_json = json.loads(data)
                for subdomain in data_json.get('subdomains', []):
                    subdomain = subdomain.strip().lower()
                    if subdomain.endswith(f'.{domain}'):
                        subdomains.add(f"{subdomain}.{domain}")
                        
            elif source == 'urlscan':
                data_json = json.loads(data)
                for result in data_json.get('results', []):
                    page_domain = result.get('page', {}).get('domain', '')
                    if page_domain and page_domain.endswith(f'.{domain}'):
                        subdomains.add(page_domain.lower())
                        
            elif source == 'virustotal':
                data_json = json.loads(data)
                for subdomain in data_json.get('subdomains', []):
                    subdomain = subdomain.strip().lower()
                    if subdomain.endswith(f'.{domain}'):
                        subdomains.add(subdomain)
                        
        except (json.JSONDecodeError, KeyError, AttributeError) as e:
            pass  
            
        return subdomains

    async def scan_subdomain_batch(self, target_domain, subdomains, progress_callback=None, batch_size=500):
        """Highly batch scanning with aggressive concurrency"""
        if not subdomains:
            return []
            
        # Use semaphore to control concurrency
        semaphore = asyncio.Semaphore(self.rate_limit)
        results = []
        
        async def scan_single(subdomain):
            async with semaphore:
                full_domain = f"{subdomain}.{target_domain}" if not subdomain.endswith(target_domain) else subdomain
                
                # Skip if already processed
                if full_domain in self.found_subdomains:
                    return None
                    
                self.found_subdomains.add(full_domain)
                
                # Use thread executor for DNS query
                loop = asyncio.get_event_loop()
                try:
                    result = await loop.run_in_executor(
                        self.dns_executor, 
                        self.dns_query, 
                        full_domain
                    )
                    
                    if result:
                        subdomain_data = {
                            'subdomain': full_domain,
                            'records': result,
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        if progress_callback:
                            await progress_callback(subdomain_data)
                        
                        return subdomain_data
                except Exception as e:
                    # Silent fail for performance
                    pass
                    
                return None
        
        # Process in batches
        for batch_start in range(0, len(subdomains), batch_size):
            batch = subdomains[batch_start:batch_start + batch_size]
            
            # Create tasks for this batch
            tasks = [scan_single(subdomain) for subdomain in batch]
            
            # Process batch concurrently
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Collect valid results
            for result in batch_results:
                if result and not isinstance(result, Exception):
                    results.append(result)
            
            # Small delay between batches to prevent overwhelming
            if batch_start + batch_size < len(subdomains):
                await asyncio.sleep(0.01)
        
        return results

def save_results(target, results, base_dir, duration, scan_mode, output_formats=['json', 'csv', 'txt']):
    """Save comprehensive results in multiple formats."""
    if not results:
        console.print(f"\n[yellow]No subdomains found for {target}.[/yellow]")
        return {}
        
    # Create timestamped directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_dir_name = f"{target.replace('.', '_')}_{timestamp}"
    target_path = Path(base_dir) / target_dir_name
    target_path.mkdir(exist_ok=True)
    
    # Prepare comprehensive data
    report_data = {
        'target': target,
        'scan_timestamp': datetime.now().isoformat(),
        'scan_mode': scan_mode,
        'duration_seconds': duration,
        'total_found': len(results),
        'scan_summary': {
            'total_subdomains': len(results),
            'unique_ips': len(set(ip for result in results for ips in result['records'].get('A', []) + result['records'].get('AAAA', []) for ip in [ips])),
            'record_types_found': list(set(record_type for result in results for record_type in result['records'].keys())),
        },
        'subdomains': results
    }
    
    saved_files = {}
    
    # Save JSON format
    if 'json' in output_formats:
        json_file = target_path / f"scan_results.json"
        try:
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            saved_files['json'] = str(json_file)
        except Exception as e:
            console.print(f"[red]Error saving JSON: {e}[/red]")
    
    # Save CSV format
    if 'csv' in output_formats:
        csv_file = target_path / f"scan_results.csv"
        try:
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Subdomain', 'IP_Addresses', 'CNAME', 'MX', 'Timestamp'])
                
                for result in results:
                    subdomain = result['subdomain']
                    records = result['records']
                    timestamp = result['timestamp']
                    
                    ip_addresses = '; '.join(records.get('A', []) + records.get('AAAA', []))
                    cname = '; '.join(records.get('CNAME', []))
                    mx = '; '.join(records.get('MX', []))
                    
                    writer.writerow([subdomain, ip_addresses, cname, mx, timestamp])
            saved_files['csv'] = str(csv_file)
        except Exception as e:
            console.print(f"[red]Error saving CSV: {e}[/red]")
    
    # Save TXT format 
    if 'txt' in output_formats:
        txt_file = target_path / f"scan_results.txt"
        try:
            with open(txt_file, 'w', encoding='utf-8') as f:
                f.write(f"# === Scanned by DKrypt ===\n")
                f.write(f"# Subdomain Scan Report for {target}\n")
                f.write(f"# Scan Mode: {scan_mode}\n")
                f.write(f"# Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Duration: {duration:.2f} seconds\n")
                f.write(f"# Total subdomains found: {len(results)}\n\n")
                
                f.write("="*80 + "\n")
                f.write("SCAN SUMMARY\n")
                f.write("="*80 + "\n")
                f.write(f"Target Domain: {target}\n")
                f.write(f"Scan Mode: {scan_mode}\n")
                f.write(f"Unique Subdomains: {report_data['scan_summary']['total_subdomains']}\n")
                f.write(f"Unique IP Addresses: {report_data['scan_summary']['unique_ips']}\n")
                f.write(f"Record Types Found: {', '.join(report_data['scan_summary']['record_types_found'])}\n\n")
                
                f.write("="*80 + "\n")
                f.write("SUBDOMAIN LIST\n")
                f.write("="*80 + "\n")
                
                for result in sorted(results, key=lambda x: x['subdomain']):
                    ip_addresses = ', '.join(result['records'].get('A', []))
                    f.write(f"{result['subdomain']:<40} {ip_addresses}\n")
            saved_files['txt'] = str(txt_file)
        except Exception as e:
            console.print(f"[red]Error saving TXT: {e}[/red]")
    
    # Display summary
    console.print("\n" + "="*80)
    console.print(f"[bold green]✓ Scan for [cyan]{target}[/cyan] Complete![/bold green]")
    console.print(f"  [+] Scan Mode: {scan_mode}")
    console.print(f"  [+] Duration: {duration:.2f} seconds")
    console.print(f"  [+] Total Found: {len(results)}")
    console.print(f"  [+] Unique IPs: {report_data['scan_summary']['unique_ips']}")
    console.print(f"  [+] Speed: {len(results)/duration:.1f} subdomains/second")
    
    for format_type, file_path in saved_files.items():
        console.print(f"  [+] Saved {format_type.upper()}: [yellow]{file_path}[/yellow]")
    console.print("="*80 + "\n")
    
    return saved_files

# --- TUI & Main Logic ---

async def get_scan_config(scanner):
    """configuration prompt with clear mode selection"""
    
    # Scan mode selection
    console.print("\n[bold cyan]🎯 Scan Mode Selection[/bold cyan]")
    mode_descriptions = {
        '1': f"[green]{ScanMode.HYBRID}[/] - Use both API sources and wordlist bruteforce (comprehensive)",
        '2': f"[blue]{ScanMode.API_ONLY}[/] - Use only API sources (fast, less noisy)",
        '3': f"[yellow]{ScanMode.BRUTEFORCE_ONLY}[/yellow] - Use only wordlist bruteforce (thorough)"
    }
    
    for key, desc in mode_descriptions.items():
        console.print(f"  [{key}] {desc}")
    
    mode_choice = Prompt.ask(
        "\n[bold]Select scan mode[/bold]", 
        choices=['1', '2', '3'], 
        default='1'
    )
    
    mode_map = {
        '1': ScanMode.HYBRID,
        '2': ScanMode.API_ONLY,
        '3': ScanMode.BRUTEFORCE_ONLY
    }
    
    scanner.set_scan_mode(mode_map[mode_choice])
    
    # Performance configuration
    console.print(f"\n[bold cyan]⚡ Performance Configuration[/bold cyan]")
    
    if scanner.use_bruteforce:
        rate_limit = IntPrompt.ask(
            "[bold]Concurrent DNS queries (recommended: 100-500 for 10k+ wordlists)[/]", 
            default=200
        )
        scanner.rate_limit = rate_limit
        
        dns_timeout = IntPrompt.ask(
            "[bold]DNS timeout in seconds (lower = faster, higher = more reliable)[/]",
            default=2
        )
        scanner.dns_timeout = dns_timeout
        
        dns_threads = IntPrompt.ask(
            "[bold]DNS thread pool size (recommended: 100-300)[/]",
            default=200
        )
        scanner.dns_threads = dns_threads
        scanner.dns_executor = ThreadPoolExecutor(max_workers=dns_threads)
    
    # API Configuration
    if scanner.use_api:
        console.print(f"\n[cyan]API Sources Available:[/cyan]")
        for source, config in API_SOURCES.items():
            status = "✓" if config['enabled'] else "✗"
            key_req = " (API key required)" if config.get('requires_key') else ""
            console.print(f"  {status} {source}{key_req}")
        
        # Ask for API keys if needed
        api_keys = {}
        if Confirm.ask("\n[bold]Do you have any API keys to configure?[/]", default=False):
            for source, config in API_SOURCES.items():
                if config.get('requires_key'):
                    key = Prompt.ask(f"Enter API key for {source} (optional)", default="").strip()
                    if key:
                        api_keys[source] = key
                        API_SOURCES[source]['enabled'] = True
        scanner.api_keys = api_keys
    
    # Proxy Configuration
    if SOCKS_AVAILABLE and Prompt.ask("\n[bold]Use proxy? (y/N)[/]", default='n').lower() == 'y':
        proxy_type = Prompt.ask("[bold]Proxy type[/]", choices=['socks4', 'socks5', 'http'], default='socks5')
        proxy_host = Prompt.ask("[bold]Proxy host[/]").strip()
        proxy_port = Prompt.ask(f"[bold]Proxy port (default: {scanner.default_ports.get(proxy_type, 'N/A')})[/]").strip()
        if not scanner.configure_proxy(proxy_type, proxy_host, proxy_port or None):
            return False
    
    return True

async def perform_scan(targets, scanner, wordlist, output_formats=['json', 'csv', 'txt']):
    base_results_dir = create_results_dir()
    
    for target_domain in targets:
        console.rule(f"[bold cyan]Scanning: {target_domain} ({scanner.scan_mode})[/bold cyan]")
        
        # Setup live UI
        results_table = Table(title=f"Discovered Subdomains for {target_domain}", box=ROUNDED, expand=True)
        results_table.add_column("Subdomain", style="cyan", no_wrap=True)
        results_table.add_column("A Records", style="green", width=15)
        results_table.add_column("CNAME", style="yellow", width=20)
        results_table.add_column("Status", style="magenta", width=10)

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        )
        
        # Create progress tasks based on scan mode
        tasks_info = {}
        if scanner.use_api:
            tasks_info['api'] = progress.add_task("[blue]API Enumeration...", total=1)
        
        if scanner.use_bruteforce:
            tasks_info['bruteforce'] = progress.add_task("[green]Wordlist Scan...", total=len(wordlist) if wordlist else 1)
        
        live_group = Panel(Group(progress, results_table), title="Scan Progress", border_style="green")
        
        all_results = []
        start_time = time()
        
        async with scanner: 
            with Live(live_group, refresh_per_second=10, console=console):
                
                # API Enumeration
                api_subdomains = []
                if scanner.use_api:
                    def api_progress_callback(message):
                        progress.update(tasks_info['api'], description=f"[blue]API: {message}")
                    
                    try:
                        api_subdomains = await scanner.fetch_api_subdomains(target_domain, api_progress_callback)
                        console.log(f"[green]Found {len(api_subdomains)} subdomains from APIs[/green]")
                    except Exception as e:
                        console.log(f"[red]API enumeration error: {e}[/red]")
                
                    progress.update(tasks_info['api'], completed=1)
                
                # Prepare subdomain list based on scan mode
                all_subdomains = set()
                
                if scanner.scan_mode == ScanMode.API_ONLY:
                    # Only use API results
                    for api_sub in api_subdomains:
                        if api_sub.endswith(f'.{target_domain}'):
                            sub_part = api_sub.replace(f'.{target_domain}', '')
                            all_subdomains.add(sub_part)
                        else:
                            all_subdomains.add(api_sub)
                    console.log(f"[cyan]API-only mode: scanning {len(all_subdomains)} subdomains[/cyan]")
                    
                elif scanner.scan_mode == ScanMode.BRUTEFORCE_ONLY:
                    # Only use wordlist
                    if wordlist:
                        all_subdomains.update(wordlist)
                        console.log(f"[yellow]Bruteforce-only mode: scanning {len(wordlist)} wordlist entries[/yellow]")
                    else:
                        console.log("[red]No wordlist provided for bruteforce-only mode[/red]")
                        continue
                        
                elif scanner.scan_mode == ScanMode.HYBRID:
                    # Combine both API and wordlist
                    for api_sub in api_subdomains:
                        if api_sub.endswith(f'.{target_domain}'):
                            sub_part = api_sub.replace(f'.{target_domain}', '')
                            all_subdomains.add(sub_part)
                    
                    if wordlist:
                        all_subdomains.update(wordlist)
                    
                    console.log(f"[magenta]Hybrid mode: scanning {len(all_subdomains)} total subdomains[/magenta]")
                
                all_subdomains = list(all_subdomains)
                
                # Update progress task total if needed
                if scanner.use_bruteforce and 'bruteforce' in tasks_info:
                    progress.update(tasks_info['bruteforce'], total=len(all_subdomains))
                
                # DNS Verification with callback
                processed_count = 0
                async def result_callback(subdomain_data):
                    nonlocal processed_count
                    processed_count += 1
                    
                    if subdomain_data:
                        all_results.append(subdomain_data)
                        
                        records = subdomain_data['records']
                        a_records = ', '.join(records.get('A', [])[:2])  
                        cname_records = ', '.join(records.get('CNAME', [])[:1])
                        status = "✓ Active"
                        
                        results_table.add_row(
                            subdomain_data['subdomain'], 
                            a_records or "-",
                            cname_records or "-", 
                            status,
                            style="bright_green"
                        )
                    
                    # Update progress for bruteforce task
                    if scanner.use_bruteforce and 'bruteforce' in tasks_info:
                        progress.update(tasks_info['bruteforce'], completed=processed_count)
                
                # Execute batch scanning
                if all_subdomains:
                    batch_results = await scanner.scan_subdomain_batch(
                        target_domain, 
                        all_subdomains, 
                        result_callback,
                        batch_size=1000  # Large batches for better performance
                    )
                    
                    # Final progress update
                    if scanner.use_bruteforce and 'bruteforce' in tasks_info:
                        progress.update(tasks_info['bruteforce'], completed=len(all_subdomains))
        
        scan_duration = time() - start_time
        
        # Save results with scan mode info
        saved_files = save_results(
            target_domain, 
            all_results, 
            base_results_dir, 
            scan_duration, 
            scanner.scan_mode,
            output_formats
        )

async def main_menu(args=None):
    scanner = DNSScanner()
    wordlist = None
    
    if args and args.command:
        scanner.rate_limit = getattr(args, 'rate_limit', 200)
        
        # Handle scan mode flags
        if hasattr(args, 'api_only') and args.api_only:
            scanner.set_scan_mode(ScanMode.API_ONLY)
        elif hasattr(args, 'bruteforce_only') and args.bruteforce_only:
            scanner.set_scan_mode(ScanMode.BRUTEFORCE_ONLY)
        else:
            scanner.set_scan_mode(ScanMode.HYBRID)  # Default
        
        # Performance settings
        if hasattr(args, 'dns_timeout'):
            scanner.dns_timeout = args.dns_timeout
        if hasattr(args, 'dns_threads'):
            scanner.dns_threads = args.dns_threads
            scanner.dns_executor = ThreadPoolExecutor(max_workers=args.dns_threads)
        
        # Configure API keys if provided
        if hasattr(args, 'api_keys') and args.api_keys:
            scanner.api_keys = args.api_keys
        
        # Configure proxy
        if hasattr(args, 'proxy_type') and hasattr(args, 'proxy_host') and args.proxy_type and args.proxy_host:
            if not scanner.configure_proxy(args.proxy_type, args.proxy_host, getattr(args, 'proxy_port', None)):
                return

        # Load wordlist only if needed
        if scanner.use_bruteforce:
            wordlist_path = getattr(args, 'wordlist', 'wordlists/subdomain.txt')
            wordlist = load_wordlist(path=wordlist_path)
            if not wordlist:
                console.print("[red]Wordlist could not be loaded.[/red]")
                return

        targets = []
        if args.command == 'single':
            if '.' in args.target:
                targets.append(args.target)
            else:
                console.print("[red]Invalid domain format.[/red]")
                return
        elif args.command == 'batch':
            try:
                with open(args.file, 'r') as f:
                    targets = [line.strip() for line in f if '.' in line.strip()]
                if not targets:
                    console.print("[red]No valid domains found in file.[/red]")
                    return
            except FileNotFoundError:
                console.print(f"[red]Error: File not found at '{args.file}'[/red]")
                return
        
        # Determine output formats
        output_formats = getattr(args, 'output_formats', ['json', 'csv', 'txt'])
        if isinstance(output_formats, str):
            output_formats = [output_formats]
        
        await perform_scan(targets, scanner, wordlist, output_formats)
        return

    # Interactive mode
    while True:
        clear_console()
        header_banner(tool_name="Subdomain Scanner")
        
        # menu with scan mode info
        menu_text = (
            "[1] Single URL Scan\n"
            "[2] Batch Scan from File\n"
            "[3] Performance Test Mode\n"
            "[4] Exit"
        )
        panel = Panel(
            Align.center(menu_text, vertical="middle"),
            title="[bold]Scan Options[/bold]",
            border_style="red",
            padding=(1, 4)
        )
        console.print(panel)
        
        choice = Prompt.ask("[bold]Choose an option[/bold]", choices=['1', '2', '3', '4'], default='1')

        if choice == '4':
            console.print("[bold magenta]Goodbye![/bold magenta]")
            break
        
        if choice == '3':
            # Performance test mode
            console.print("\n[bold yellow]🚀 Performance Test Mode[/bold yellow]")
            console.print("This mode will test scanning speed with a small wordlist")
            
            test_domain = Prompt.ask("[bold]Enter test domain[/bold]", default="example.com")
            test_wordlist = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'app', 'blog', 'shop', 'ssh', 'smtp'] * 100  # 1000 entries
            
            scanner.set_scan_mode(ScanMode.BRUTEFORCE_ONLY)
            scanner.rate_limit = 500
            scanner.dns_timeout = 1
            scanner.dns_threads = 300
            scanner.dns_executor = ThreadPoolExecutor(max_workers=300)
            
            console.print(f"[green]Testing with {len(test_wordlist)} subdomains at maximum speed...[/green]")
            await perform_scan([test_domain], scanner, test_wordlist, ['txt'])
            
            Prompt.ask("\n[bold]Press Enter to return to the main menu...[/bold]")
            continue
        
        if not await get_scan_config(scanner):
            sleep(2)
            continue

        # Load wordlist only if bruteforce is enabled
        if scanner.use_bruteforce and wordlist is None:
            ask_for_custom = Prompt.ask("[bold]Want to use custom wordlist? (y/N): ", default="N")
            if ask_for_custom.lower() == 'y':
                wordlist_path = Prompt.ask("[bold]Enter path to wordlist[/]", default="wordlists/subdomain.txt")
                wordlist = load_wordlist(path=wordlist_path)
                if not wordlist:
                    console.print("[red]Wordlist could not be loaded. Returning to menu.[/red]")
                    sleep(2)
                    continue
            else:
                console.print("[green][!] Using default wordlist.[/green]")
                wordlist = load_wordlist(path="wordlists/subdomain.txt")

        # Output format selection
        console.print("\n[cyan]Select output formats:[/cyan]")
        output_formats = []
        if Confirm.ask("Generate JSON report?", default=True):
            output_formats.append('json')
        if Confirm.ask("Generate CSV report?", default=True):
            output_formats.append('csv') 
        if Confirm.ask("Generate TXT report?", default=True):
            output_formats.append('txt')
        
        if not output_formats:
            output_formats = ['txt']  # Default fallback

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
        
        await perform_scan(targets, scanner, wordlist, output_formats)
        Prompt.ask("\n[bold]Press Enter to return to the main menu...[/bold]")

# Backward compatibility
def main_menu_sync(args=None):
    """Synchronous wrapper for backward compatibility."""
    asyncio.run(main_menu(args))


if __name__ == "__main__":
    asyncio.run(main_menu())