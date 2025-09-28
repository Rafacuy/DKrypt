# modules/tracepulse.py

import os
import sys
import json
import csv
import time
import socket
import statistics
import re
import ipaddress
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from core.utils import clear_console, header_banner

try:
    from scapy.all import IP, ICMP, TCP, UDP, sr1, conf
    from rich.console import Console
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.live import Live
    from rich.panel import Panel
    from rich.text import Text
    from rich import print as rprint
    import requests
    from requests.exceptions import ConnectTimeout, ReadTimeout, ConnectionError, RequestException
except ImportError as e:
    print(f"Missing required dependencies: {e}")
    print("Please install: pip install scapy rich requests")
    sys.exit(1)

# Disable Scapy verbose output
conf.verb = 0

console = Console()

#  Configure logging for error tracking
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('tracepulse_errors.log'),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)

class TracerouteResult:
    """Data class to store traceroute hop information"""
    def __init__(self, hop: int, ip: str, hostname: str = "", 
                 rtt: float = 0.0, jitter: float = 0.0, 
                 loss: float = 0.0, asn: str = "", location: str = ""):
        self.hop = hop
        self.ip = ip
        self.hostname = hostname
        self.rtt = rtt
        self.jitter = jitter
        self.loss = loss
        self.asn = asn
        self.location = location

class SecurityValidator:
    """Security validation utilities"""
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """  Validate domain name format"""
        # Basic domain validation regex
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(domain_pattern, domain):
            return False
        if len(domain) > 253:
            return False
        return True
    
    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """  Check if IP is private/reserved"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return (
                ip.is_private or 
                ip.is_loopback or 
                ip.is_multicast or 
                ip.is_reserved or
                ip.is_link_local
            )
        except ValueError:
            return False
    
    @staticmethod
    def validate_destination(destination: str, allow_private: bool = False) -> Tuple[bool, str, str]:
        """
          Comprehensive destination validation
        Returns: (is_valid, validated_ip, error_message)
        """
        destination = destination.strip().lower()
        
        # Check for empty input
        if not destination:
            return False, "", "Destination cannot be empty"
        
        # Try to parse as IP address first
        try:
            ip = ipaddress.ip_address(destination)
            ip_str = str(ip)
            
            # Security check for private/reserved IPs
            if SecurityValidator.is_private_ip(ip_str) and not allow_private:
                return False, "", "Private, loopback, and multicast addresses are not allowed. Use --allow-private to override."
            
            return True, ip_str, ""
        except ValueError:
            pass
        
        # Validate as domain name
        if not SecurityValidator.is_valid_domain(destination):
            return False, "", "Invalid domain name format"
        
        # Resolve domain to IP
        try:
            resolved_ip = socket.gethostbyname(destination)
            
            # Security check for resolved IP
            if SecurityValidator.is_private_ip(resolved_ip) and not allow_private:
                return False, "", f"Domain resolves to private IP ({resolved_ip}). Use --allow-private to override."
            
            return True, resolved_ip, ""
        except socket.gaierror as e:
            return False, "", f"Cannot resolve domain: {str(e)}"
    
    @staticmethod
    def sanitize_filename(filename: str) -> Tuple[bool, str, str]:
        """  Sanitize filename to prevent path traversal"""
        if not filename:
            return False, "", "Filename cannot be empty"
        
        # Remove any path components and keep only the filename
        filename = os.path.basename(filename)
        
        # Allow only safe characters: alphanumeric, hyphens, underscores, dots
        safe_pattern = r'^[a-zA-Z0-9\-_.]+$'
        if not re.match(safe_pattern, filename):
            return False, "", "Filename contains invalid characters. Only alphanumeric, hyphens, underscores, and dots are allowed."
        
        # Prevent hidden files and files starting with dots
        if filename.startswith('.'):
            return False, "", "Filename cannot start with a dot"
        
        # Prevent overly long filenames
        if len(filename) > 255:
            return False, "", "Filename is too long (max 255 characters)"
        
        return True, filename, ""

class TracePulse:
    """Advanced Traceroute Tool with Rich TUI - Security Hardened"""
    
    def __init__(self, allow_private: bool = False):
        self.console = Console()
        self.results: List[TracerouteResult] = []
        self.config = {}
        self.allow_private = allow_private
        
        # Rate limiting configuration
        self.default_probe_delay = 0.1  # seconds between probes
    
    def get_user_config(self) -> Dict[str, Any]:
        """Interactive configuration collection using rich.prompt"""
        self.console.print("\n[bold blue]🔧 Configuration Setup[/bold blue]")
        
        config = {}
        
        #   Enhanced destination validation
        while True:
            destination = Prompt.ask("Enter destination (domain or IP)")
            is_valid, validated_ip, error_msg = SecurityValidator.validate_destination(
                destination, self.allow_private
            )
            
            if is_valid:
                config['destination'] = destination.strip()
                config['resolved_ip'] = validated_ip
                break
            else:
                self.console.print(f"[red]Error: {error_msg}[/red]")
                if "private" in error_msg.lower():
                    self.console.print("[yellow]Tip: Run with --allow-private flag to override this restriction[/yellow]")
        
        # Get protocol
        config['protocol'] = Prompt.ask(
            "Select protocol", 
            choices=['icmp', 'tcp', 'udp'], 
            default='icmp'
        )
        
        # Get port (only for TCP/UDP)
        if config['protocol'] in ['tcp', 'udp']:
            while True:
                try:
                    port = int(Prompt.ask("Enter destination port", default="80"))
                    if 1 <= port <= 65535:
                        config['port'] = port
                        break
                    else:
                        self.console.print("[red]Port must be between 1 and 65535![/red]")
                except ValueError:
                    self.console.print("[red]Please enter a valid port number![/red]")
        else:
            config['port'] = None
        
        # Get maximum hops
        while True:
            try:
                max_hops = int(Prompt.ask("Enter maximum number of hops", default="30"))
                if 1 <= max_hops <= 255:
                    config['max_hops'] = max_hops
                    break
                else:
                    self.console.print("[red]Max hops must be between 1 and 255![/red]")
            except ValueError:
                self.console.print("[red]Please enter a valid number![/red]")
        
        # Get timeout
        while True:
            try:
                timeout = float(Prompt.ask("Timeout per probe in seconds", default="2"))
                if 0.1 <= timeout <= 30:
                    config['timeout'] = timeout
                    break
                else:
                    self.console.print("[red]Timeout must be between 0.1 and 30 seconds![/red]")
            except ValueError:
                self.console.print("[red]Please enter a valid timeout value![/red]")
        
        #   Rate limiting configuration
        while True:
            try:
                probe_delay = float(Prompt.ask("Delay between probes in seconds", default=str(self.default_probe_delay)))
                if 0.01 <= probe_delay <= 5:
                    config['probe_delay'] = probe_delay
                    break
                else:
                    self.console.print("[red]Probe delay must be between 0.01 and 5 seconds![/red]")
            except ValueError:
                self.console.print("[red]Please enter a valid delay value![/red]")
        
        # Ask about saving results
        config['save_results'] = Confirm.ask("Do you want to save the results?")
        
        #   Enhanced filename validation
        if config['save_results']:
            while True:
                filename = Prompt.ask("Enter output filename (e.g., results.json, data.csv, file.txt)")
                is_valid, safe_filename, error_msg = SecurityValidator.sanitize_filename(filename)
                
                if is_valid:
                    config['filename'] = safe_filename
                    break
                else:
                    self.console.print(f"[red]Error: {error_msg}[/red]")
        
        self.config = config
        return config
    
    def resolve_hostname(self, ip: str) -> str:
        """Perform reverse DNS lookup with timeout"""
        try:
            #   Add timeout to prevent hanging
            socket.setdefaulttimeout(2)
            hostname = socket.gethostbyaddr(ip)[0]
            socket.setdefaulttimeout(None)
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout):
            socket.setdefaulttimeout(None)
            return ip
    
    def get_geo_info(self, ip: str) -> Tuple[str, str]:
        """  Hardened GeoIP lookup with proper error handling"""
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,city,as",
                timeout=3, 
                allow_redirects=False  # Prevent redirect attacks
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    country = data.get('country', 'Unknown')
                    city = data.get('city', 'Unknown')
                    asn = data.get('as', 'Unknown')
                    
                    # Sanitize data to prevent injection
                    country = str(country)[:50] if country else 'Unknown'
                    city = str(city)[:50] if city else 'Unknown'
                    asn = str(asn)[:100] if asn else 'Unknown'
                    
                    location = f"{city}, {country}" if city != 'Unknown' else country
                    return asn, location
            
        except (ConnectTimeout, ReadTimeout, ConnectionError) as e:
            #Log specific network errors but don't expose to user
            logger.warning(f"Network error in GeoIP lookup for {ip}: {type(e).__name__}")
        except RequestException as e:
            # Handle other request exceptions
            logger.warning(f"Request error in GeoIP lookup for {ip}: {type(e).__name__}")
        except (ValueError, KeyError) as e:
            # Handle JSON parsing errors
            logger.warning(f"Data parsing error in GeoIP lookup for {ip}: {type(e).__name__}")
        except Exception as e:
            # Catch any other unexpected errors
            logger.error(f"Unexpected error in GeoIP lookup for {ip}: {type(e).__name__}")
        
        # Always return safe defaults on any error
        return "Unknown", "Unknown"
    
    def create_packet(self, destination: str, ttl: int) -> Any:
        """Create packet based on protocol configuration"""
        protocol = self.config['protocol']
        port = self.config.get('port')
        
        if protocol == 'icmp':
            packet = IP(dst=destination, ttl=ttl) / ICMP()
        elif protocol == 'tcp':
            packet = IP(dst=destination, ttl=ttl) / TCP(dport=port, flags="S")
        elif protocol == 'udp':
            packet = IP(dst=destination, ttl=ttl) / UDP(dport=port)
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")
        
        return packet
    
    def probe_hop(self, destination: str, ttl: int, num_probes: int = 3) -> TracerouteResult:
        """  Rate-limited hop probing with enhanced error handling"""
        rtts = []
        responses = 0
        ip = ""
        
        for i in range(num_probes):
            try:
                packet = self.create_packet(destination, ttl)
                start_time = time.time()
                
                reply = sr1(packet, timeout=self.config['timeout'], verbose=0)
                
                if reply:
                    end_time = time.time()
                    rtt = (end_time - start_time) * 1000  # Convert to milliseconds
                    rtts.append(rtt)
                    responses += 1
                    ip = reply.src
                    
            except Exception as e:
                #   Log errors without exposing to user
                logger.debug(f"Probe error for hop {ttl}, probe {i+1}: {type(e).__name__}")
                continue
            finally:
                #   Rate limiting - delay between probes
                if i < num_probes - 1:  # Don't delay after the last probe
                    time.sleep(self.config.get('probe_delay', self.default_probe_delay))
        
        # Calculate metrics
        if rtts:
            avg_rtt = statistics.mean(rtts)
            jitter = statistics.stdev(rtts) if len(rtts) > 1 else 0.0
        else:
            avg_rtt = 0.0
            jitter = 0.0
        
        loss_percent = ((num_probes - responses) / num_probes) * 100
        
        # Get hostname and geo info
        hostname = ""
        asn = ""
        location = ""
        
        if ip:
            hostname = self.resolve_hostname(ip)
            asn, location = self.get_geo_info(ip)
        
        return TracerouteResult(
            hop=ttl,
            ip=ip or "*",
            hostname=hostname,
            rtt=avg_rtt,
            jitter=jitter,
            loss=loss_percent,
            asn=asn,
            location=location
        )
    
    def get_rtt_color(self, rtt: float) -> str:
        """Get color based on RTT value"""
        if rtt == 0:
            return "red"
        elif rtt < 50:
            return "green"
        elif rtt < 150:
            return "yellow"
        else:
            return "red"
    
    def create_results_table(self) -> Table:
        """Create and populate the results table"""
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Hop", style="dim", width=4)
        table.add_column("IP Address/Hostname", min_width=20)
        table.add_column("RTT (ms)", justify="right", min_width=10)
        table.add_column("Jitter (ms)", justify="right", min_width=12)
        table.add_column("Loss (%)", justify="right", min_width=9)
        table.add_column("ASN", min_width=15)
        table.add_column("Location", min_width=20)
        
        for result in self.results:
            # Format display values
            display_ip = result.hostname if result.hostname != result.ip else result.ip
            rtt_text = f"{result.rtt:.2f}" if result.rtt > 0 else "*"
            jitter_text = f"{result.jitter:.2f}" if result.jitter > 0 else "*"
            loss_text = f"{result.loss:.0f}" if result.ip != "*" else "*"
            
            # Apply RTT coloring
            rtt_color = self.get_rtt_color(result.rtt)
            
            table.add_row(
                str(result.hop),
                display_ip,
                Text(rtt_text, style=rtt_color),
                jitter_text,
                loss_text,
                result.asn,
                result.location
            )
        
        return table
    
    def run_traceroute(self) -> List[TracerouteResult]:
        """Execute the traceroute with real-time display"""
        destination = self.config['resolved_ip']  # Use validated IP
        max_hops = self.config['max_hops']
        
        self.console.print(f"\n[bold green]🚀 Starting traceroute to {self.config['destination']} ({destination})[/bold green]")
        self.console.print(f"Protocol: {self.config['protocol'].upper()}")
        if self.config.get('port'):
            self.console.print(f"Port: {self.config['port']}")
        self.console.print(f"Max hops: {max_hops}, Timeout: {self.config['timeout']}s")
        self.console.print(f"Probe delay: {self.config.get('probe_delay', self.default_probe_delay)}s\n")
        
        # Create live table
        table = self.create_results_table()
        
        with Live(table, refresh_per_second=2) as live:
            for ttl in range(1, max_hops + 1):
                # Update status
                live.console.print(f"[dim]Probing hop {ttl}...[/dim]")
                
                # Probe the hop
                result = self.probe_hop(destination, ttl)
                self.results.append(result)
                
                # Update table
                table = self.create_results_table()
                live.update(table)
                
                # Check if we've reached the destination
                if result.ip != "*" and result.ip == destination:
                    self.console.print(f"\n[bold green]✅ Reached destination {self.config['destination']}![/bold green]")
                    break
                
                # Small delay between hops
                time.sleep(0.1)
        
        return self.results
    
    def save_results_to_file(self, results: List[TracerouteResult], filename: str):
        """  Secure file saving within reports directory"""
        # Create reports directory if it doesn't exist
        reports_dir = Path("reports/tracepulse")
        reports_dir.mkdir(exist_ok=True)
        
        # Ensure file is saved only in reports directory
        safe_filepath = reports_dir / filename
        
        # Resolve path and ensure it's still within reports directory
        try:
            resolved_path = safe_filepath.resolve()
            reports_resolved = reports_dir.resolve()
            
            if not str(resolved_path).startswith(str(reports_resolved)):
                raise ValueError("Path traversal attempt detected")
            
        except (OSError, ValueError) as e:
            self.console.print(f"[red]❌ Security error: Invalid file path[/red]")
            logger.error(f"File path security violation: {e}")
            return
        
        extension = safe_filepath.suffix.lower()
        
        try:
            if extension == '.json':
                self.save_to_json(results, safe_filepath)
            elif extension == '.csv':
                self.save_to_csv(results, safe_filepath)
            else:
                # Default to txt format
                safe_filepath = safe_filepath.with_suffix('.txt')
                self.save_to_txt(results, safe_filepath)
            
            self.console.print(f"[green]✅ Results saved to: {safe_filepath}[/green]")
            
        except PermissionError:
            self.console.print(f"[red]❌ Permission denied: Cannot write to {safe_filepath}[/red]")
        except OSError as e:
            self.console.print(f"[red]❌ File system error: Cannot save file[/red]")
            logger.error(f"File save error: {e}")
        except Exception as e:
            self.console.print(f"[red]❌ Error saving file[/red]")
            logger.error(f"Unexpected file save error: {e}")
    
    def save_to_json(self, results: List[TracerouteResult], filepath: Path):
        """Save results to JSON format"""
        data = {
            "timestamp": datetime.now().isoformat(),
            "destination": self.config['destination'],
            "resolved_ip": self.config['resolved_ip'],
            "protocol": self.config['protocol'],
            "port": self.config.get('port'),
            "max_hops": self.config['max_hops'],
            "timeout": self.config['timeout'],
            "probe_delay": self.config.get('probe_delay'),
            "hops": []
        }
        
        for result in results:
            hop_data = {
                "hop": result.hop,
                "ip": result.ip,
                "hostname": result.hostname,
                "rtt_ms": result.rtt,
                "jitter_ms": result.jitter,
                "loss_percent": result.loss,
                "asn": result.asn,
                "location": result.location
            }
            data["hops"].append(hop_data)
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def save_to_csv(self, results: List[TracerouteResult], filepath: Path):
        """Save results to CSV format"""
        with open(filepath, 'w', newline='') as csvfile:
            fieldnames = ['hop', 'ip', 'hostname', 'rtt_ms', 'jitter_ms', 
                         'loss_percent', 'asn', 'location']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in results:
                writer.writerow({
                    'hop': result.hop,
                    'ip': result.ip,
                    'hostname': result.hostname,
                    'rtt_ms': result.rtt,
                    'jitter_ms': result.jitter,
                    'loss_percent': result.loss,
                    'asn': result.asn,
                    'location': result.location
                })
    
    def save_to_txt(self, results: List[TracerouteResult], filepath: Path):
        """Save results to plain text format"""
        with open(filepath, 'w') as f:
            f.write(f"TracePulse Results\n")
            f.write(f"==================\n")
            f.write(f"Destination: {self.config['destination']} ({self.config['resolved_ip']})\n")
            f.write(f"Protocol: {self.config['protocol'].upper()}\n")
            if self.config.get('port'):
                f.write(f"Port: {self.config['port']}\n")
            f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write(f"{'Hop':<4} {'IP/Hostname':<25} {'RTT (ms)':<10} {'Jitter':<10} {'Loss %':<8} {'ASN':<15} {'Location'}\n")
            f.write("-" * 100 + "\n")
            
            for result in results:
                display_ip = result.hostname if result.hostname != result.ip else result.ip
                rtt_text = f"{result.rtt:.2f}" if result.rtt > 0 else "*"
                jitter_text = f"{result.jitter:.2f}" if result.jitter > 0 else "*"
                loss_text = f"{result.loss:.0f}" if result.ip != "*" else "*"
                
                f.write(f"{result.hop:<4} {display_ip:<25} {rtt_text:<10} {jitter_text:<10} "
                       f"{loss_text:<8} {result.asn:<15} {result.location}\n")
    
    def display_summary(self, results: List[TracerouteResult]):
        """Display summary statistics"""
        if not results:
            return
        
        # Filter out failed hops
        successful_hops = [r for r in results if r.ip != "*"]
        
        if successful_hops:
            avg_rtt = statistics.mean([r.rtt for r in successful_hops if r.rtt > 0])
            total_loss = statistics.mean([r.loss for r in successful_hops])
            
            summary = Panel(
                f"[bold]Summary Statistics[/bold]\n"
                f"Total hops: {len(results)}\n"
                f"Successful hops: {len(successful_hops)}\n"
                f"Average RTT: {avg_rtt:.2f} ms\n"
                f"Overall packet loss: {total_loss:.1f}%",
                title="📊 Traceroute Complete",
                title_align="left"
            )
            self.console.print(summary)
    
    def check_privileges(self):
        """  Enhanced privilege checking and warning"""
        if os.name != 'nt':  # Unix-like systems
            if os.geteuid() != 0:
                self.console.print("[red]⚠️  Warning: Root privileges may be required for raw socket operations[/red]")
                self.console.print("[yellow]If you encounter permission errors, try running with sudo[/yellow]")
            else:
                self.console.print("[yellow]⚠️  Running with root privileges. Consider using a dedicated user account.[/yellow]")
    
    def run(self):
        """  Hardened main execution flow"""
        try:
            #   Check privileges
            self.check_privileges()
            
            # Display banner
            clear_console()
            header_banner("TRACEPULSE")
            
            # Get configuration from user
            config = self.get_user_config()
            
            # Run traceroute
            results = self.run_traceroute()
            
            # Display summary
            self.display_summary(results)
            
            # Save results if requested
            if config['save_results']:
                self.save_results_to_file(results, config['filename'])
            
            self.console.print("\n[bold green]🎉 TracePulse completed successfully![/bold green]")
            
        except KeyboardInterrupt:
            self.console.print("\n[yellow]⏸️ Traceroute interrupted by user[/yellow]")
        except Exception as e:
            logger.error(f"Traceroute execution error: {type(e).__name__}: {str(e)}", exc_info=True)
            self.console.print("\n[red]❌ An internal error occurred. Please check the logs for details.[/red]")
            sys.exit(1)

def main(cli_args=None):
    """Entry point with command line argument support"""
    if cli_args:
        allow_private = cli_args.allow_private
        config = {
            'destination': cli_args.destination,
            'protocol': cli_args.protocol,
            'port': cli_args.port,
            'max_hops': cli_args.max_hops,
            'timeout': cli_args.timeout,
            'probe_delay': cli_args.probe_delay,
            'save_results': cli_args.save,
            'filename': cli_args.output
        }
        is_valid, validated_ip, error_msg = SecurityValidator.validate_destination(
            config['destination'], allow_private
        )
        if not is_valid:
            console.print(f"[red]Error: {error_msg}[/red]")
            return
        config['resolved_ip'] = validated_ip

        tracer = TracePulse(allow_private=allow_private)
        tracer.config = config
        results = tracer.run_traceroute()
        tracer.display_summary(results)
        if config['save_results']:
            tracer.save_results_to_file(results, config['filename'])

    else:
        tracer = TracePulse(allow_private=False)
        tracer.run()