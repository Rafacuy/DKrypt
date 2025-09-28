# modules/port_scanner.py
import asyncio
import socket
import json
import csv
import time
import re
import os
import random
import subprocess
import platform
from collections import namedtuple
from typing import List, Dict, Optional, Tuple, Any
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.text import Text
from rich.columns import Columns

from core.utils import header_banner, clear_console

# Suppress ResourceWarning for unclosed sockets in async operations
import warnings
warnings.filterwarnings("ignore", category=ResourceWarning, message="unclosed.*")

# Try to import python-nmap
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# Fallback to legacy scanning if needed
try:
    from scapy.layers.inet import IP, TCP, sr1
    from scapy.config import conf
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# --- Constants and Configuration ---
CONSOLE = Console()
DEFAULT_TIMEOUT = 1.0
MAX_WORKERS = 200
CACHE_TTL = 3600  # 1 hour
REPORTS_DIR = "reports/port_scanner/"

# NMAP timing profiles
TIMING_PROFILES = {
    'paranoid': '-T0',    # Very slow, for IDS evasion
    'sneaky': '-T1',      # Slow, for IDS evasion
    'polite': '-T2',      # Slow, less bandwidth and target machine resources
    'normal': '-T3',      # Default timing
    'aggressive': '-T4',  # Fast, assumes reliable network
    'insane': '-T5'       # Very fast, assumes extraordinary fast network
}

# Common NMAP scan types
SCAN_TYPES = {
    'SYN': '-sS',         # SYN stealth scan (default)
    'CON': '-sT',         # TCP connect scan
    'UDP': '-sU',         # UDP scan
    'ACK': '-sA',         # ACK scan
    'WIN': '-sW',         # Window scan
    'FIN': '-sF',         # FIN scan
    'NULL': '-sN',       # Null scan
    'XMAS': '-sX',        # Xmas scan
    'PING': '-sn'         # Ping scan (no port scan)
}

# --- Data Structures ---
PortStatus = namedtuple('PortStatus', [
    'port', 'status', 'service', 'version', 'product', 
    'extrainfo', 'confidence', 'cpe', 'script_results', 'error'
])

ScanResult = namedtuple('ScanResult', [
    'target', 'open_ports', 'closed_ports', 'filtered_ports', 
    'os_info', 'host_info', 'scan_stats'
])

class NMAPPortScanner:
    """
    NMAP-integrated port scanner with multiple scan techniques, service detection, OS fingerprinting, and script scanning
    """

    def __init__(self, max_workers=MAX_WORKERS, verbosity=1):
        """
        Initializes the NMAPPortScanner.

        Args:
            max_workers (int): maximum number of concurrent tasks.
            verbosity (int): level of output verbosity (0=quiet, 1=normal, 2=debug).
        """
        self.service_cache = {}
        self.max_workers = min(max_workers, os.cpu_count() * 10 if os.cpu_count() else 100)
        self.verbosity = verbosity
        self._lock = asyncio.Lock()
        self._start_time = 0
        
        # Initialize NMAP scanner if available
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
            self._check_nmap_installation()
        else:
            self.nm = None
            if verbosity > 0:
                CONSOLE.print("[yellow]Warning: python-nmap not found. Some features will be limited.[/yellow]")

    # Check if nmap already installed
    def _check_nmap_installation(self) -> bool:
        try:
            # Test NMAP installation
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                if self.verbosity > 1:
                    version_line = result.stdout.split('\n')[0]
                    CONSOLE.log(f"[green]NMAP detected: {version_line}[/green]")
                return True
            else:
                if self.verbosity > 0:
                    CONSOLE.print("[yellow]Warning: NMAP not found in PATH. Some features may not work.[/yellow]")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            if self.verbosity > 0:
                CONSOLE.print("[yellow]Warning: NMAP installation check failed.[/yellow]")
            return False

    def _check_privileges(self) -> Tuple[bool, str]:
        """Check if the current user has sufficient privileges for raw socket operations."""
        system = platform.system().lower()
        
        if system == "windows":
            # Windows requires admin privileges for raw sockets
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                return is_admin, "Administrator privileges required for SYN scans on Windows"
            except:
                return False, "Unable to check administrator privileges"
        
        elif system in ["linux", "darwin"]:  # Linux/macOS
            # Check if running as root or with capabilities
            if os.geteuid() == 0:
                return True, "Running as root"
            else:
                return False, "Root privileges required for SYN scans on Unix systems"
        
        return False, "Unknown system privileges"

    async def resolve_target(self, hostname: str) -> Optional[str]:
        """resolves a hostname to an IP address"""
        try:
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

    def parse_ports(self, port_spec: str) -> List[int]:
        """Parses a port specification string into a list of unique integers"""
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

    def _build_nmap_command(self, target: str, ports: List[int], scan_type: str, 
                           timing: str, service_detection: bool, os_detection: bool,
                           script_scan: str, custom_args: str) -> str:
        """Builds NMAP command arguments based on scan parameters."""
        args = []
        
        # Basic scan type
        if scan_type in SCAN_TYPES:
            args.append(SCAN_TYPES[scan_type])
        else:
            args.append('-sS')  # Default to SYN scan
            
        # Port specification
        if ports:
            port_str = ','.join(map(str, ports))
            args.extend(['-p', port_str])
        
        # Timing template
        if timing in TIMING_PROFILES:
            args.append(TIMING_PROFILES[timing])
        
        # Service/version detection
        if service_detection:
            args.append('-sV')
        
        # OS detection
        if os_detection:
            args.append('-O')
        
        # Script scanning
        if script_scan and script_scan.lower() != 'none':
            args.extend(['--script', script_scan])
        
        # Custom arguments
        if custom_args:
            # Parse custom arguments safely
            custom_parts = custom_args.split()
            args.extend(custom_parts)
        
        # Always get XML output for parsing
        args.extend(['-oX', '-'])
        
        return ' '.join(args)

    def _parse_nmap_results(self, target: str, nm_result: Dict[str, Any]) -> ScanResult:
        """Parses NMAP scan results into our standard format."""
        if target not in nm_result.all_hosts():
            return ScanResult(target, [], [], [], {}, {}, {})
        
        host_info = {
            'hostname': nm_result[target].hostname(),
            'state': nm_result[target].state(),
            'all_protocols': nm_result[target].all_protocols()
        }
        
        # OS information
        os_info = {}
        if 'osmatch' in nm_result[target]:
            os_matches = nm_result[target]['osmatch']
            if os_matches:
                os_info = {
                    'name': os_matches[0].get('name', 'Unknown'),
                    'accuracy': os_matches[0].get('accuracy', '0'),
                    'line': os_matches[0].get('line', ''),
                    'osclass': os_matches[0].get('osclass', [])
                }
        
        # Scan statistics
        scan_stats = nm_result.scanstats()
        
        # Port information
        open_ports = []
        closed_ports = []
        filtered_ports = []
        
        for protocol in nm_result[target].all_protocols():
            ports = nm_result[target][protocol].keys()
            
            for port in ports:
                port_info = nm_result[target][protocol][port]
                state = port_info['state']
                
                # Extract script results if available
                script_results = {}
                if 'script' in port_info:
                    script_results = port_info['script']
                
                port_status = PortStatus(
                    port=int(port),
                    status=state.upper(),
                    service=port_info.get('name', 'unknown'),
                    version=port_info.get('version', ''),
                    product=port_info.get('product', ''),
                    extrainfo=port_info.get('extrainfo', ''),
                    confidence=port_info.get('conf', ''),
                    cpe=port_info.get('cpe', ''),
                    script_results=script_results,
                    error=None
                )
                
                if state == 'open':
                    open_ports.append(port_status)
                elif state == 'closed':
                    closed_ports.append(port_status)
                else:  # filtered, open|filtered, etc.
                    filtered_ports.append(port_status)
        
        return ScanResult(target, open_ports, closed_ports, filtered_ports, 
                         os_info, host_info, scan_stats)

    async def _run_nmap_scan_async(self, target: str, ports: List[int], scan_type: str = 'SYN',
                                  timing: str = 'normal', service_detection: bool = True,
                                  os_detection: bool = False, script_scan: str = 'none',
                                  custom_args: str = '') -> ScanResult:
        """runs NMAP scan for a single target."""
        if not NMAP_AVAILABLE:
            return await self._fallback_scan_async(target, ports, scan_type)
        
        try:
            target_ip = await self.resolve_target(target)
            if not target_ip:
                return ScanResult(target, [], [], [], {}, {}, {})
            
            # Check privileges for certain scan types
            if scan_type == 'SYN':
                has_privs, priv_msg = self._check_privileges()
                if not has_privs and self.verbosity > 0:
                    CONSOLE.log(f"[yellow]Warning: {priv_msg}. Falling back to connect scan.[/yellow]")
                    scan_type = 'CON'
            
            # Build NMAP arguments
            nmap_args = self._build_nmap_command(target_ip, ports, scan_type, timing,
                                               service_detection, os_detection, 
                                               script_scan, custom_args)
            
            if self.verbosity > 1:
                CONSOLE.log(f"[dim]NMAP command: nmap {nmap_args} {target_ip}[/dim]")
            
            # Run NMAP scan in executor to avoid blocking
            loop = asyncio.get_running_loop()
            nm_result = await loop.run_in_executor(
                None, lambda: self.nm.scan(target_ip, arguments=nmap_args)
            )
            
            return self._parse_nmap_results(target_ip, nm_result)
            
        except Exception as e:
            if self.verbosity > 1:
                CONSOLE.log(f"[yellow]NMAP scan error for {target}: {e}[/yellow]")
            # Fallback to legacy scanning
            return await self._fallback_scan_async(target, ports, scan_type)

    async def _fallback_scan_async(self, target: str, ports: List[int], scan_type: str) -> ScanResult:
        """Fallback to legacy scanning methods when NMAP is not available"""
        if self.verbosity > 0:
            CONSOLE.log(f"[yellow]Using fallback scanning for {target}[/yellow]")
        
        target_ip = await self.resolve_target(target)
        if not target_ip:
            return ScanResult(target, [], [], [], {}, {}, {})
        
        # Use legacy methods (simplified version of original scanner)
        semaphore = asyncio.Semaphore(self.max_workers)
        tasks = [self._scan_port_connect_async(target_ip, port, semaphore) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        open_ports = []
        closed_ports = []
        filtered_ports = []
        
        for result in results:
            if isinstance(result, Exception):
                continue
            if result.status == 'OPEN':
                # Convert to new format
                enhanced_result = PortStatus(
                    port=result.port,
                    status=result.status,
                    service=result.service,
                    version='', product='', extrainfo='', confidence='', cpe='',
                    script_results={}, error=result.error
                )
                open_ports.append(enhanced_result)
            elif result.status == 'CLOSED':
                enhanced_result = PortStatus(
                    port=result.port,
                    status=result.status,
                    service='unknown',
                    version='', product='', extrainfo='', confidence='', cpe='',
                    script_results={}, error=result.error
                )
                closed_ports.append(enhanced_result)
            else:
                enhanced_result = PortStatus(
                    port=result.port,
                    status=result.status,
                    service='unknown',
                    version='', product='', extrainfo='', confidence='', cpe='',
                    script_results={}, error=result.error
                )
                filtered_ports.append(enhanced_result)
        
        return ScanResult(target, open_ports, closed_ports, filtered_ports, {}, {}, {})

    async def _scan_port_connect_async(self, target_ip: str, port: int, semaphore: asyncio.Semaphore):
        """Legacy fallback TCP connect scan"""
        async with semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target_ip, port), timeout=1.0
                )
                writer.close()
                await writer.wait_closed()
                
                # Try to get service name
                try:
                    service_name = socket.getservbyport(port, 'tcp')
                except OSError:
                    service_name = 'unknown'
                
                # Return in old format for compatibility
                from collections import namedtuple
                OldPortStatus = namedtuple('PortStatus', ['port', 'status', 'service', 'error'])
                return OldPortStatus(port, 'OPEN', service_name, None)
            except asyncio.TimeoutError:
                OldPortStatus = namedtuple('PortStatus', ['port', 'status', 'service', 'error'])
                return OldPortStatus(port, 'FILTERED', 'unknown', 'Timeout')
            except ConnectionRefusedError:
                OldPortStatus = namedtuple('PortStatus', ['port', 'status', 'service', 'error'])
                return OldPortStatus(port, 'CLOSED', 'unknown', None)
            except OSError as e:
                OldPortStatus = namedtuple('PortStatus', ['port', 'status', 'service', 'error'])
                return OldPortStatus(port, 'ERROR', 'unknown', str(e))

    async def run_scan_async(self, target: str, ports: List[int], scan_type: str = 'SYN',
                           timing: str = 'normal', service_detection: bool = True,
                           os_detection: bool = False, script_scan: str = 'none',
                           custom_args: str = '', progress=None, task_id=None) -> ScanResult:
        """Main scan method"""
        result = await self._run_nmap_scan_async(
            target, ports, scan_type, timing, service_detection, 
            os_detection, script_scan, custom_args
        )
        
        if progress and task_id is not None:
            progress.update(task_id, advance=len(ports))
        
        return result

    def display_results(self, result: ScanResult, duration: float):
        """Enhanced display of scan results with NMAP data."""
        if not result.open_ports:
            CONSOLE.print(f"\n[bold yellow]No open ports found for {result.target}.[/bold yellow]")
        else:
            # Main results table
            table = Table(title=f"[bold green]Open Ports for {result.target}[/bold green]", 
                         show_header=True, header_style="bold magenta")
            table.add_column("PORT", style="dim", width=8)
            table.add_column("STATE", justify="center", width=8)
            table.add_column("SERVICE", width=12)
            table.add_column("VERSION", width=20)
            table.add_column("PRODUCT", width=15)
            
            for port_info in result.open_ports:
                version_info = f"{port_info.product} {port_info.version}".strip()
                if not version_info:
                    version_info = port_info.extrainfo or ""
                
                table.add_row(
                    f"[bold]{port_info.port}[/bold]",
                    "[green]OPEN[/green]",
                    port_info.service,
                    version_info[:20] + ("..." if len(version_info) > 20 else ""),
                    port_info.product[:15] + ("..." if len(port_info.product) > 15 else "")
                )
            
            CONSOLE.print(table)
            
            # Display script results if available
            script_results = [p for p in result.open_ports if p.script_results]
            if script_results and self.verbosity > 0:
                CONSOLE.print("\n[bold cyan]Script Results:[/bold cyan]")
                for port_info in script_results:
                    for script_name, script_output in port_info.script_results.items():
                        CONSOLE.print(f"[yellow]Port {port_info.port} - {script_name}:[/yellow]")
                        # Truncate long script outputs
                        output = script_output[:300] + ("..." if len(script_output) > 300 else "")
                        CONSOLE.print(f"[dim]{output}[/dim]")

        # Display OS information if available
        if result.os_info and self.verbosity > 0:
            CONSOLE.print(f"\n[bold cyan]OS Detection:[/bold cyan]")
            CONSOLE.print(f"  [green]OS:[/green] {result.os_info.get('name', 'Unknown')}")
            if result.os_info.get('accuracy'):
                CONSOLE.print(f"  [green]Accuracy:[/green] {result.os_info['accuracy']}%")

        # Display host information
        if result.host_info and self.verbosity > 1:
            CONSOLE.print(f"\n[bold cyan]Host Information:[/bold cyan]")
            if result.host_info.get('hostname'):
                CONSOLE.print(f"  [green]Hostname:[/green] {result.host_info['hostname']}")
            CONSOLE.print(f"  [green]State:[/green] {result.host_info.get('state', 'Unknown')}")

        # Display scan statistics
        if result.scan_stats and self.verbosity > 1:
            stats = result.scan_stats
            CONSOLE.print(f"\n[dim]Scan Statistics: {stats.get('uphosts', '0')} hosts up, "
                         f"{stats.get('downhosts', '0')} hosts down[/dim]")

        if self.verbosity > 0 and result.filtered_ports:
            CONSOLE.print(f"[yellow]Filtered/Errored Ports:[/] {len(result.filtered_ports)} ports")

        CONSOLE.print(f"\n[dim]Scan for {result.target} completed in {duration:.2f} seconds.[/dim]")

    def save_results(self, filename: str, results: List[ScanResult], file_format: str = 'json'):
        """save functionality with nmap data"""
        if not any(r.open_ports for r in results):
            CONSOLE.print("[yellow]No open ports found to save.[/yellow]")
            return
        
        os.makedirs(REPORTS_DIR, exist_ok=True)
        filepath = os.path.join(REPORTS_DIR, filename)
        
        output_data = []
        for result in results:
            for port_info in result.open_ports:
                port_data = {
                    'target': result.target,
                    'port': port_info.port,
                    'status': port_info.status,
                    'service': port_info.service,
                    'version': port_info.version,
                    'product': port_info.product,
                    'extrainfo': port_info.extrainfo,
                    'confidence': port_info.confidence,
                    'cpe': port_info.cpe,
                    'script_results': port_info.script_results
                }
                
                # Add OS and host info for first port of each target
                if port_info == result.open_ports[0]:
                    port_data.update({
                        'os_info': result.os_info,
                        'host_info': result.host_info,
                        'scan_stats': result.scan_stats
                    })
                
                output_data.append(port_data)

        try:
            if file_format.lower() == 'json':
                full_path = f"{filepath}.json"
                with open(full_path, 'w') as f:
                    json.dump(output_data, f, indent=4)
            elif file_format.lower() == 'csv':
                full_path = f"{filepath}.csv"
                with open(full_path, 'w', newline='') as f:
                    if output_data:
                        fieldnames = ['target', 'port', 'status', 'service', 'version', 
                                    'product', 'extrainfo', 'confidence']
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        for row in output_data:
                            # Flatten complex fields for CSV
                            csv_row = {k: v for k, v in row.items() if k in fieldnames}
                            writer.writerow(csv_row)
            else:
                CONSOLE.print(f"[red]Error: Unsupported format '{file_format}'[/red]")
                return
            
            CONSOLE.print(f"\n[bold green]✓ Results saved to {full_path}[/bold green]")
        except IOError as e:
            CONSOLE.print(f"[red]Error saving file: {e}[/red]")

def get_scan_parameters(is_batch=False):
    """Enhanced parameter collection with NMAP options."""
    ports_str = Prompt.ask("[bold green]Enter ports (e.g., 1-1024 or 22,80,443)[/bold green]", default="1-1024")
    
    # Scan type selection
    scan_choices = list(SCAN_TYPES.keys()) if NMAP_AVAILABLE else ["CON"]
    default_scan = "SYN" if NMAP_AVAILABLE else "CON"
    
    if not NMAP_AVAILABLE:
        CONSOLE.print("[yellow]NMAP not available. Limited to basic TCP connect scans.[/yellow]")
    
    scan_type = Prompt.ask("[bold green]Choose scan type[/bold green]", 
                          choices=scan_choices, default=default_scan)
    
    # Advanced NMAP options (only if NMAP is available)
    timing = 'normal'
    service_detection = True
    os_detection = False
    script_scan = 'none'
    custom_args = ''
    
    if NMAP_AVAILABLE:
        # Timing profile
        timing_choices = list(TIMING_PROFILES.keys())
        timing = Prompt.ask("[bold green]Choose timing profile[/bold green]", 
                           choices=timing_choices, default="normal")
        
        # Service detection
        service_detection = Confirm.ask("[bold green]Enable service/version detection (-sV)?[/bold green]", 
                                      default=True)
        
        # OS detection
        os_detection = Confirm.ask("[bold green]Enable OS detection (-O)?[/bold green]", 
                                 default=False)
        
        # Script scanning
        script_options = ['none', 'default', 'safe', 'vuln', 'auth', 'discovery']
        script_scan = Prompt.ask("[bold green]Choose script scan[/bold green]", 
                               choices=script_options, default="none")
        
        # Custom NMAP arguments
        use_custom = Confirm.ask("[bold green]Add custom NMAP arguments?[/bold green]", default=False)
        if use_custom:
            custom_args = Prompt.ask("[bold green]Enter custom NMAP arguments[/bold green]", default="")
    
    # Common options
    verbosity = int(Prompt.ask("[bold green]Enter verbosity level (0-2)[/bold green]", 
                              choices=["0", "1", "2"], default="1"))
    
    output_format = Prompt.ask("[bold green]Save results? (json, csv, or no)[/bold green]", 
                              choices=["json", "csv", "no"], 
                              default="json" if is_batch else "no")
    
    return (ports_str, scan_type, timing, service_detection, os_detection, 
            script_scan, custom_args, verbosity, output_format)

async def run_single_scan(target, ports_str, scan_type, timing, service_detection, os_detection, script_scan, custom_args, verbosity, output_format):
    """single target scanning with NMAP features."""
    CONSOLE.print(Panel("Single Target Scan", style="cyan", expand=False))
    try:
        scanner = NMAPPortScanner(verbosity=verbosity)
        ports = scanner.parse_ports(ports_str)

        start_time = time.time()
        
        progress_columns = (
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"), 
            BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), 
            TimeRemainingColumn()
        )
        
        with Progress(*progress_columns, console=CONSOLE) as progress:
            task_id = progress.add_task(f"[green]Scanning {target}...", total=len(ports))
            result = await scanner.run_scan_async(
                target, ports, scan_type, timing, service_detection, 
                os_detection, script_scan, custom_args, progress, task_id
            )
        
        duration = time.time() - start_time
        scanner.display_results(result, duration)

        if output_format != 'no':
            filename = f"scan_{target.replace('.', '_')}_{int(time.time())}"
            scanner.save_results(filename, [result], file_format=output_format)

    except (ValueError, KeyboardInterrupt) as e:
        CONSOLE.print(f"\n[bold red]Error: {e}[/bold red]")
    except Exception as e:
        CONSOLE.print(f"\n[bold red]An unexpected error occurred: {e}[/bold red]")

async def run_batch_scan(file_path, ports_str, scan_type, timing, service_detection, os_detection, script_scan, custom_args, verbosity, output_format):
    """batch scanning with NMAP features."""
    CONSOLE.print(Panel("Batch URL Scan", style="cyan", expand=False))
    try:
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]

        if not targets:
            CONSOLE.print("[bold red]File is empty or contains no valid URLs.[/bold red]")
            return

        scanner = NMAPPortScanner(verbosity=verbosity)
        ports = scanner.parse_ports(ports_str)

        start_time = time.time()
        all_results = []
        
        progress_columns = (
            TextColumn("[progress.description]{task.description}"), BarColumn(),
            TextColumn("{task.completed}/{task.total} Targets"), TimeRemainingColumn()
        )
        
        with Progress(*progress_columns, console=CONSOLE) as progress:
            batch_task = progress.add_task("[green]Scanning all targets...", total=len(targets))
            
            # Create tasks for all targets
            tasks = []
            for target in targets:
                task = scanner.run_scan_async(
                    target, ports, scan_type, timing, service_detection,
                    os_detection, script_scan, custom_args
                )
                tasks.append(task)
            
            # Process results as they complete
            for future in asyncio.as_completed(tasks):
                result = await future
                all_results.append(result)
                progress.update(batch_task, advance=1, 
                              description=f"[green]Scanning... Last completed: {result.target}")

        total_duration = time.time() - start_time
        CONSOLE.print(f"\n[bold]Batch scan complete in {total_duration:.2f} seconds.[/bold]")

        # Display enhanced summary
        summary_table = Table(title="[bold green]Batch Scan Summary[/bold green]", 
                            show_header=True, header_style="bold magenta")
        summary_table.add_column("TARGET", style="cyan")
        summary_table.add_column("OPEN PORTS", justify="center")
        summary_table.add_column("SERVICES", width=30)
        summary_table.add_column("OS INFO", width=20)
        
        for result in all_results:
            if result.open_ports:
                services = ", ".join([f"{p.port}({p.service})" for p in result.open_ports[:3]])
                if len(result.open_ports) > 3:
                    services += f" +{len(result.open_ports)-3} more"
                
                os_info = result.os_info.get('name', 'Unknown')[:18] if result.os_info else 'Unknown'
                
                summary_table.add_row(
                    result.target,
                    f"[green]{len(result.open_ports)}[/green]",
                    services,
                    os_info
                )
            else:
                summary_table.add_row(
                    result.target,
                    "[yellow]0[/yellow]",
                    "No open ports",
                    "Unknown"
                )
        
        CONSOLE.print(summary_table)

        if output_format != 'no':
            filename = f"batch_scan_{int(time.time())}"
            scanner.save_results(filename, all_results, file_format=output_format)

    except FileNotFoundError:
        CONSOLE.print(f"\n[bold red]Error: File not found at '{file_path}'[/bold red]")
    except (ValueError, KeyboardInterrupt) as e:
        CONSOLE.print(f"\n[bold red]Error: {e}[/bold red]")
    except Exception as e:
        CONSOLE.print(f"\n[bold red]An unexpected error occurred: {e}[/bold red]")

def display_nmap_info():
    info_panel = Panel.fit(
        """[bold cyan]NMAP Integration Features:[/bold cyan]

[green]✓[/green] Advanced scan types: SYN, TCP Connect, UDP, ACK, etc.
[green]✓[/green] Service/version detection (-sV)
[green]✓[/green] OS fingerprinting (-O) 
[green]✓[/green] NSE script scanning (vuln, auth, discovery, etc.)
[green]✓[/green] Timing profiles (paranoid to insane)
[green]✓[/green] Custom NMAP arguments support
[green]✓[/green] execution for batch scans
[green]✓[/green] reporting with detailed service info

[yellow]Note:[/yellow] Some features require root/administrator privileges.
[yellow]Fallback:[/yellow] Legacy scanning available if NMAP unavailable.
        """,
        title="[bold]About NMAP Integration[/bold]",
        style="dim"
    )
    CONSOLE.print(info_panel)
    Prompt.ask("\n[dim]Press Enter to continue...[/dim]")

def display_scan_examples():
    """Display examples of advanced scan configurations."""
    examples = Table(title="[bold green]Scan Configuration Examples[/bold green]", 
                    show_header=True, header_style="bold magenta")
    examples.add_column("SCENARIO", style="cyan", width=20)
    examples.add_column("SCAN TYPE", width=10)
    examples.add_column("TIMING", width=10)
    examples.add_column("OPTIONS", width=30)
    examples.add_column("CUSTOM ARGS", width=25)
    
    example_configs = [
        ("Stealth Recon", "SYN", "sneaky", "Service: Yes, OS: No, Script: safe", "-f --source-port 53"),
        ("Fast Discovery", "SYN", "aggressive", "Service: Yes, OS: Yes, Script: discovery", "--min-rate 1000"),
        ("Vuln Assessment", "SYN", "normal", "Service: Yes, OS: No, Script: vuln", "--script-args=unsafe=1"),
        ("Firewall Evasion", "FIN", "polite", "Service: No, OS: No, Script: none", "-f -D RND:10"),
        ("Service Enum", "CON", "normal", "Service: Yes, OS: No, Script: default", "--version-intensity 9")
    ]
    
    for scenario, scan_type, timing, options, custom in example_configs:
        examples.add_row(scenario, scan_type, timing, options, custom)
    
    CONSOLE.print(examples)
    Prompt.ask("\n[dim]Press Enter to continue...[/dim]")

async def main_menu(args=None):
    if args and args.command:
        if args.command == 'single':
            await run_single_scan(args.target, args.ports, args.scan_type, args.timing, args.service_detection, args.os_detection, args.script_scan, args.custom_args, args.verbosity, args.output)
        elif args.command == 'batch':
            await run_batch_scan(args.file, args.ports, args.scan_type, args.timing, args.service_detection, args.os_detection, args.script_scan, args.custom_args, args.verbosity, args.output)
        return

    """Enhanced main menu with NMAP integration options."""
    while True:
        clear_console()
        header_banner(tool_name="NMAP Port Scanner")
        
        # Display NMAP status
        nmap_status = "[green]Available[/green]" if NMAP_AVAILABLE else "[red]Not Available[/red]"
        CONSOLE.print(f"[dim]NMAP Integration: {nmap_status}[/dim]")

        menu_table = Table.grid(padding=(1, 2))
        menu_table.add_column(style="bold cyan")
        menu_table.add_column()
        menu_table.add_row("[1]", "Single Target Scan")
        menu_table.add_row("[2]", "Batch Target Scan")
        menu_table.add_row("[3]", "About NMAP Integration")
        menu_table.add_row("[4]", "Scan Examples")
        menu_table.add_row("[5]", "Quit")
        
        CONSOLE.print(Panel(menu_table, title="[bold]Main Menu[/bold]", expand=False))

        choice = Prompt.ask("[bold green]Choose an option[/bold green]", 
                           choices=["1", "2", "3", "4", "5"], default="1")

        if choice == '1':
            target = Prompt.ask("Enter target URL or IP address")
            ports_str, scan_type, timing, service_detection, os_detection, script_scan, custom_args, verbosity, output_format = get_scan_parameters()
            await run_single_scan(target, ports_str, scan_type, timing, service_detection, os_detection, script_scan, custom_args, verbosity, output_format)
        elif choice == '2':
            file_path = Prompt.ask("Enter path to file with targets")
            ports_str, scan_type, timing, service_detection, os_detection, script_scan, custom_args, verbosity, output_format = get_scan_parameters(is_batch=True)
            await run_batch_scan(file_path, ports_str, scan_type, timing, service_detection, os_detection, script_scan, custom_args, verbosity, output_format)
        elif choice == '3':
            display_nmap_info()
            continue
        elif choice == '4':
            display_scan_examples()
            continue
        elif choice == '5':
            CONSOLE.print("[bold cyan]Goodbye![/bold cyan]")
            break
        
        if choice in ['1', '2']:
            Prompt.ask("\n[dim]Press Enter to return to the menu...[/dim]")