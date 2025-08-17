# modules/port_scanner.py
"""
Port scanner module for DKrypt. This includes asynchronous tasks, 
stealth scanning procedures, an organized file save system, and batch scanning capabilities.
"""

import asyncio
import socket
import json
import csv
import time
import re
import os
import random
from collections import namedtuple
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from rich.text import Text

# Suppress ResourceWarning for unclosed sockets in async operations
import warnings
warnings.filterwarnings("ignore", category=ResourceWarning, message="unclosed.*")

try:
    from scapy.layers.inet import IP, TCP, sr1
    from scapy.config import conf
    # Suppress Scapy's verbosity
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# --- Constants and Configuration ---
CONSOLE = Console()
DEFAULT_TIMEOUT = 1.0 # Default timeout
MAX_WORKERS = 200 # Maximum concurrent workers
CACHE_TTL = 3600  # 1 hour
REPORTS_DIR = "reports/port_scanner/" # Reports file saved in the `reports/port_scanner` directory.

# --- Data Structures ---
PortStatus = namedtuple('PortStatus', ['port', 'status', 'service', 'error'])
ScanResult = namedtuple('ScanResult', ['target', 'open_ports', 'closed_ports', 'filtered_ports'])

class PortScanner:
    """
    A modern, silent port scanner with asynchronous capabilities, multiple scan techniques,
    and enhanced performance features for single and batch scanning.
    """

    def __init__(self, max_workers=MAX_WORKERS, verbosity=1):
        """
        Initializes the PortScanner.

        Args:
            max_workers (int): The maximum number of concurrent tasks.
            verbosity (int): The level of output verbosity (0=quiet, 1=normal, 2=debug).
        """
        self.service_cache = {}
        self.timeout_profile = {
            'stealth': 0.5,
            'connect': 1.0
        }
        self.max_workers = min(max_workers, os.cpu_count() * 10 if os.cpu_count() else 100)
        self.verbosity = verbosity
        self._lock = asyncio.Lock()
        self._start_time = 0

    async def _get_service_name(self, port: int) -> str:
        """
        Asynchronously retrieves the service name for a port, with caching.
        """
        async with self._lock:
            current_time = time.time()
            if port in self.service_cache:
                name, timestamp = self.service_cache[port]
                if current_time - timestamp < CACHE_TTL:
                    return name

        try:
            loop = asyncio.get_running_loop()
            service_name = await loop.run_in_executor(
                None, lambda: socket.getservbyport(port, 'tcp')
            )
            async with self._lock:
                self.service_cache[port] = (service_name, time.time())
            return service_name
        except (OSError, asyncio.CancelledError):
            return "unknown"

    async def resolve_target(self, hostname: str) -> str | None:
        """
        Asynchronously resolves a hostname to an IP address.
        """
        try:
            # Check if it's already an IP
            socket.inet_aton(hostname)
            return hostname
        except socket.error:
            if self.verbosity > 0:
                CONSOLE.log(f"[cyan]Resolving {hostname}...[/cyan]")
            try:
                loop = asyncio.get_running_loop()
                addr_info = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
                ip_address = addr_info[0][4][0]
                if self.verbosity > 0:
                    CONSOLE.log(f"[green]Resolved {hostname} to {ip_address}[/green]")
                return ip_address
            except socket.gaierror as e:
                CONSOLE.log(f"[bold red]Error: Could not resolve host '{hostname}': {e}[/bold red]")
                return None
            except asyncio.CancelledError:
                CONSOLE.log(f"[bold yellow]DNS resolution cancelled for {hostname}[/bold yellow]")
                return None


    def parse_ports(self, port_spec: str) -> list[int]:
        """
        Parses a port specification string into a list of unique integers.
        """
        if not re.match(r'^(\d+(-\d+)?)(,\s*\d+(-\d+)?)*$', port_spec):
            raise ValueError("Invalid port format. Use formats like '80', '1-1024', or '22,80,443'.")

        ports = set()
        parts = [p.strip() for p in port_spec.split(',')]
        for part in parts:
            if '-' in part:
                start, end = map(int, part.split('-'))
                if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                    raise ValueError(f"Invalid port range: {part}. Ports must be 1-65535 and start <= end.")
                ports.update(range(start, end + 1))
            else:
                port = int(part)
                if not (1 <= port <= 65535):
                     raise ValueError(f"Invalid port number: {port}. Port must be between 1 and 65535.")
                ports.add(port)
        return sorted(list(ports))

    async def _scan_port_syn_async(self, target_ip: str, port: int, semaphore: asyncio.Semaphore) -> PortStatus:
        """
        Asynchronously scans a single port using a TCP SYN (stealth) scan.
        """
        async with semaphore:
            await asyncio.sleep(random.uniform(0.01, 0.05))
            try:
                ip_packet = IP(dst=target_ip)
                tcp_packet = TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
                packet = ip_packet / tcp_packet

                loop = asyncio.get_running_loop()
                response = await loop.run_in_executor(
                    None, lambda: sr1(packet, timeout=self.timeout_profile['stealth'], verbose=0)
                )

                if response is None:
                    return PortStatus(port, 'FILTERED', 'unknown', 'No response')
                elif response.haslayer(TCP):
                    if response.getlayer(TCP).flags == 0x12: # SYN-ACK
                        rst_packet = IP(dst=target_ip) / TCP(sport=tcp_packet.sport, dport=port, flags="R")
                        await loop.run_in_executor(None, lambda: sr1(rst_packet, timeout=1, verbose=0))
                        service = await self._get_service_name(port)
                        return PortStatus(port, 'OPEN', service, None)
                    elif response.getlayer(TCP).flags == 0x14: # RST-ACK
                        return PortStatus(port, 'CLOSED', 'unknown', None)
                return PortStatus(port, 'FILTERED', 'unknown', 'Unexpected response')
            except Exception as e:
                if self.verbosity > 1:
                    CONSOLE.log(f"[yellow]Error during SYN scan on port {port}: {e}[/yellow]")
                return PortStatus(port, 'ERROR', 'unknown', str(e))

    async def _scan_port_connect_async(self, target_ip: str, port: int, semaphore: asyncio.Semaphore) -> PortStatus:
        """
        Asynchronously scans a single port using a standard TCP connect.
        """
        async with semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target_ip, port), timeout=self.timeout_profile['connect']
                )
                writer.close()
                await writer.wait_closed()
                service = await self._get_service_name(port)
                return PortStatus(port, 'OPEN', service, None)
            except asyncio.TimeoutError:
                return PortStatus(port, 'FILTERED', 'unknown', 'Timeout')
            except ConnectionRefusedError:
                return PortStatus(port, 'CLOSED', 'unknown', None)
            except OSError as e:
                if self.verbosity > 1:
                    CONSOLE.log(f"[yellow]OS Error on port {port}: {e}[/yellow]")
                return PortStatus(port, 'ERROR', 'unknown', str(e))

    async def run_scan_async(self, target: str, ports: list[int], scan_type: str = 'SYN', progress=None, task_id=None) -> ScanResult:
        """
        Asynchronously runs the port scan for a single target.
        """
        target_ip = await self.resolve_target(target)
        if not target_ip:
            return ScanResult(target, [], [], [])

        scan_method = self._scan_port_syn_async if scan_type.upper() == 'SYN' else self._scan_port_connect_async
        
        num_ports = len(ports)
        semaphore = asyncio.Semaphore(self.max_workers)
        
        tasks = [scan_method(target_ip, port, semaphore) for port in ports]
        results = []
        
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)
            if progress and task_id is not None:
                progress.update(task_id, advance=1)

        open_ports = sorted([r for r in results if r.status == 'OPEN'], key=lambda p: p.port)
        closed_ports = sorted([r for r in results if r.status == 'CLOSED'], key=lambda p: p.port)
        filtered_ports = sorted([r for r in results if r.status in ('FILTERED', 'ERROR')], key=lambda p: p.port)

        return ScanResult(target, open_ports, closed_ports, filtered_ports)

    def display_results(self, result: ScanResult, duration: float):
        """Displays scan results for a single target in a formatted table."""
        if not result.open_ports:
            CONSOLE.print(f"\n[bold yellow]No open ports found for {result.target}.[/bold yellow]")
        else:
            table = Table(title=f"[bold green]Open Ports for {result.target}[/bold green]", show_header=True, header_style="bold magenta")
            table.add_column("PORT", style="dim", width=12)
            table.add_column("STATE", justify="center")
            table.add_column("SERVICE")
            for res in result.open_ports:
                table.add_row(f"[bold]{res.port}[/bold]", "[green]OPEN[/green]", res.service)
            CONSOLE.print(table)

        if self.verbosity > 0 and result.filtered_ports:
             CONSOLE.print(f"[yellow]Filtered/Errored Ports:[/] {len(result.filtered_ports)} ports")

        CONSOLE.print(f"\n[dim]Scan for {result.target} completed in {duration:.2f} seconds.[/dim]")

    def save_results(self, filename: str, results: list[ScanResult], file_format: str = 'json'):
        """
        Saves the open ports from one or more scans to a file.
        """
        if not any(r.open_ports for r in results):
            CONSOLE.print("[yellow]No open ports found to save.[/yellow]")
            return
        
        os.makedirs(REPORTS_DIR, exist_ok=True)
        filepath = os.path.join(REPORTS_DIR, filename)
        
        output_data = []
        for result in results:
            for r in result.open_ports:
                output_data.append({'target': result.target, 'port': r.port, 'status': r.status, 'service': r.service})

        try:
            if file_format.lower() == 'json':
                full_path = f"{filepath}.json"
                with open(full_path, 'w') as f:
                    json.dump(output_data, f, indent=4)
            elif file_format.lower() == 'csv':
                full_path = f"{filepath}.csv"
                with open(full_path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=['target', 'port', 'status', 'service'])
                    writer.writeheader()
                    writer.writerows(output_data)
            else:
                CONSOLE.print(f"[red]Error: Unsupported format '{file_format}'[/red]")
                return
            
            CONSOLE.print(f"\n[bold green]✔ Results saved to {full_path}[/bold green]")
        except IOError as e:
            CONSOLE.print(f"[red]Error saving file: {e}[/red]")

def clear_console():
    """Clears the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def get_scan_parameters(is_batch=False):
    """Prompts user for common scan parameters."""
    ports_str = Prompt.ask("[bold green]Enter ports (e.g., 1-1024 or 22,80,443)[/bold green]", default="1-1024")
    
    scan_choices = ["SYN", "CON"] if SCAPY_AVAILABLE else ["CON"]
    default_scan = "SYN" if SCAPY_AVAILABLE else "CON"
    if not SCAPY_AVAILABLE:
        CONSOLE.print("[yellow]Scapy not found. SYN scan is disabled. Falling back to CON scan.[/yellow]")
    scan_type = Prompt.ask("[bold green]Choose scan type[/bold green]", choices=scan_choices, default=default_scan)
    
    verbosity = int(Prompt.ask("[bold green]Enter verbosity level (0-2)[/bold green]", choices=["0", "1", "2"], default="1"))
    
    save_prompt = "[bold green]Save results? (json, csv, or no)[/bold green]"
    output_format = Prompt.ask(save_prompt, choices=["json", "csv", "no"], default="json" if is_batch else "no")
    
    return ports_str, scan_type, verbosity, output_format

async def run_single_scan():
    """Handles the logic for scanning a single target."""
    CONSOLE.print(Panel("Single Target Scan", style="cyan", expand=False))
    try:
        target = Prompt.ask("[bold green]Enter target host (e.g., scanme.nmap.org)[/bold green]")
        ports_str, scan_type, verbosity, output_format = get_scan_parameters()

        scanner = PortScanner(verbosity=verbosity)
        ports = scanner.parse_ports(ports_str)

        start_time = time.time()
        
        progress_columns = (
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn()
        )
        with Progress(*progress_columns, console=CONSOLE) as progress:
            task_id = progress.add_task(f"[green]Scanning {target}...", total=len(ports))
            result = await scanner.run_scan_async(target, ports, scan_type, progress, task_id)
        
        duration = time.time() - start_time
        scanner.display_results(result, duration)

        if output_format != 'no':
            filename = f"scan_{target.replace('.', '_')}_{int(time.time())}"
            scanner.save_results(filename, [result], file_format=output_format)

    except (ValueError, KeyboardInterrupt) as e:
        CONSOLE.print(f"\n[bold red]Error: {e}[/bold red]")
    except Exception as e:
        CONSOLE.print(f"\n[bold red]An unexpected error occurred: {e}[/bold red]")

async def run_batch_scan():
    """Handles the logic for scanning multiple targets from a file."""
    CONSOLE.print(Panel("Batch URL Scan", style="cyan", expand=False))
    try:
        file_path = Prompt.ask("[bold green]Enter the path to the file with URLs (one per line)[/bold green]")
        
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]

        if not targets:
            CONSOLE.print("[bold red]File is empty or contains no valid URLs.[/bold red]")
            return

        ports_str, scan_type, verbosity, output_format = get_scan_parameters(is_batch=True)
        
        scanner = PortScanner(verbosity=verbosity)
        ports = scanner.parse_ports(ports_str)

        start_time = time.time()
        all_results = []
        
        progress_columns = (
            TextColumn("[progress.description]{task.description}"), BarColumn(),
            TextColumn("{task.completed}/{task.total} Targets"), TimeRemainingColumn()
        )
        
        with Progress(*progress_columns, console=CONSOLE) as progress:
            batch_task = progress.add_task("[green]Scanning all targets...", total=len(targets))
            
            tasks = [scanner.run_scan_async(target, ports, scan_type) for target in targets]
            
            for future in asyncio.as_completed(tasks):
                result = await future
                all_results.append(result)
                progress.update(batch_task, advance=1, description=f"[green]Scanning... Last completed: {result.target}")

        total_duration = time.time() - start_time
        CONSOLE.print(f"\n[bold]Batch scan complete in {total_duration:.2f} seconds.[/bold]")

        # Display summary
        for result in all_results:
            if result.open_ports:
                CONSOLE.print(f"  [cyan]• {result.target}:[/cyan] [green]{len(result.open_ports)} open ports[/green]")
            else:
                CONSOLE.print(f"  [cyan]• {result.target}:[/cyan] [yellow]No open ports found[/yellow]")

        if output_format != 'no':
            filename = f"batch_scan_{int(time.time())}"
            scanner.save_results(filename, all_results, file_format=output_format)

    except FileNotFoundError:
        CONSOLE.print(f"\n[bold red]Error: File not found at '{file_path}'[/bold red]")
    except (ValueError, KeyboardInterrupt) as e:
        CONSOLE.print(f"\n[bold red]Error: {e}[/bold red]")
    except Exception as e:
        CONSOLE.print(f"\n[bold red]An unexpected error occurred: {e}[/bold red]")


async def main_menu():
    """Displays the main interactive menu."""
    while True:
        clear_console()
        header = Panel.fit(
            '[bold magenta]Port Scanner[/bold magenta]\n',
            padding=(1, 2)
        )

        CONSOLE.print(header)

        menu_table = Table.grid(padding=(1, 2))
        menu_table.add_column(style="bold cyan")
        menu_table.add_column()
        menu_table.add_row("[1]", "Single URL Scan")
        menu_table.add_row("[2]", "Batch URL Scan")
        menu_table.add_row("[3]", "Quit")
        
        CONSOLE.print(Panel(menu_table, title="[bold]Menu[/bold]", expand=False))

        choice = Prompt.ask("[bold green]Choose an option[/bold green]", choices=["1", "2", "3"], default="1")

        if choice == '1':
            await run_single_scan()
        elif choice == '2':
            await run_batch_scan()
        elif choice == '3':
            CONSOLE.print("[bold cyan]Goodbye![/bold cyan]")
            break
        
        Prompt.ask("\n[dim]Press Enter to return to the menu...[/dim]")


if __name__ == "__main__":
    try:
        asyncio.run(main_menu())
    except KeyboardInterrupt:
        CONSOLE.print("\n[bold yellow]Program interrupted by user. Exiting.[/bold yellow]")

