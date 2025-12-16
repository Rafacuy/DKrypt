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
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Coroutine

from pydantic import BaseModel, Field
from pydantic.functional_validators import field_validator

# Dependency management
try:
    from scapy.all import IP, ICMP, TCP, UDP, sr1, conf, Raw
    from scapy.layers.inet import traceroute
    import aiodns
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
    import folium
except ImportError as e:
    print(f"Missing required dependencies: {e}")
    print("Please install: pip install scapy rich requests pydantic aiodns folium")
    sys.exit(1)

# Initial configuration
conf.verb = 0  # Disable Scapy verbose output
console = Console()

# --- Logging Configuration ---
try:
    from core.logger import logger as dkrypt_logger
    logger = dkrypt_logger.get_logger('tracepulse')
except ImportError:
    # Fallback to basic logging if core logger is not available
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)


# Pydantic models for configuration and results
class TracerouteSettings(BaseModel):
    """Strongly-typed configuration for a traceroute session."""
    destination: str
    resolved_ip: str = ""
    protocol: str = Field('icmp', pattern=r'^(icmp|tcp|udp)$')
    port: Optional[int] = 80
    max_hops: int = Field(30, ge=1, le=255)
    timeout: float = Field(2.0, ge=0.1, le=30)
    probes_per_hop: int = Field(3, ge=1, le=10)
    probe_delay: float = Field(0.1, ge=0.01, le=5)
    allow_private: bool = False
    save_results: bool = False
    filename: Optional[str] = "tracepulse_results"

    @field_validator('port')
    def port_must_be_valid(cls, v):
        if v is not None and not (1 <= v <= 65535):
            raise ValueError("Port must be between 1 and 65535")
        return v


class HopResult(BaseModel):
    """Data class for storing information about a single hop."""
    hop: int
    ip: str
    hostname: str = ""
    rtts: List[float] = []
    avg_rtt: float = 0.0
    jitter: float = 0.0
    loss: float = 0.0
    asn: str = ""
    location: str = ""
    mpls_labels: List[str] = []


# Security and validation utilities
class SecurityValidator:
    """Security validation utilities."""

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Validate domain name format."""
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, domain)) and len(domain) <= 253

    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """Check if IP is private/reserved."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved or ip.is_link_local
        except ValueError:
            return False

    @staticmethod
    async def validate_destination(destination: str, allow_private: bool = False) -> Tuple[Optional[str], Optional[str]]:
        """Comprehensive async destination validation."""
        destination = destination.strip().lower()
        if not destination:
            return None, "Destination cannot be empty"

        try:
            ip = ipaddress.ip_address(destination)
            ip_str = str(ip)
            if SecurityValidator.is_private_ip(ip_str) and not allow_private:
                return None, "Private/reserved addresses are not allowed. Use --allow-private to override."
            return ip_str, None
        except ValueError:
            pass

        if not SecurityValidator.is_valid_domain(destination):
            return None, "Invalid domain name format"

        try:
            resolver = aiodns.DNSResolver()
            result = await resolver.gethostbyname(destination, socket.AF_INET)
            # The standard way to access the result for aiodns
            # In some versions it's 'hosts', others might have 'address' or 'addresses'
            if hasattr(result, 'hosts'):
                resolved_ip_list = result.hosts
            elif hasattr(result, 'addresses'):
                resolved_ip_list = result.addresses
            elif hasattr(result, 'address'):
                resolved_ip_list = [result.address]
            else:
                # Last resort - fallback to synchronous resolution
                import socket
                resolved_ip = socket.gethostbyname(destination)
                if SecurityValidator.is_private_ip(resolved_ip) and not allow_private:
                    return None, f"Domain resolves to private IP ({resolved_ip}). Use --allow-private to override."
                return resolved_ip, None

            if resolved_ip_list and len(resolved_ip_list) > 0:
                resolved_ip = resolved_ip_list[0]
                if SecurityValidator.is_private_ip(resolved_ip) and not allow_private:
                    return None, f"Domain resolves to private IP ({resolved_ip}). Use --allow-private to override."
                return resolved_ip, None
            else:
                return None, f"No IP addresses found for domain: {destination}"
        except aiodns.error.DNSError as e:
            return None, f"Cannot resolve domain: {e}"
        except Exception as e:
            # If aiodns fails for any reason, fallback to synchronous resolution
            try:
                import socket
                resolved_ip = socket.gethostbyname(destination)
                if SecurityValidator.is_private_ip(resolved_ip) and not allow_private:
                    return None, f"Domain resolves to private IP ({resolved_ip}). Use --allow-private to override."
                return resolved_ip, None
            except Exception as sync_error:
                return None, f"Cannot resolve domain: {str(sync_error)}"

    @staticmethod
    def sanitize_filename(filename: str) -> Tuple[bool, str, str]:
        """Sanitize filename to prevent path traversal."""
        if not filename:
            return False, "", "Filename cannot be empty"
        
        filename = os.path.basename(filename)
        safe_pattern = r'^[a-zA-Z0-9\-_.]+$'
        if not re.match(safe_pattern, filename) or filename.startswith('.'):
            return False, "", "Invalid filename. Use alphanumeric, hyphens, underscores, dots. Cannot start with a dot."
        
        if len(filename) > 255:
            return False, "", "Filename is too long."
        
        return True, filename, ""


# Data enrichment utilities
class IPInfoProvider:
    """Centralized provider for GeoIP and ASN information with caching."""
    _cache: Dict[str, Dict[str, Any]] = {}

    @classmethod
    async def get_info(cls, ip: str) -> Dict[str, Any]:
        """Get GeoIP and ASN info for an IP, using cache if available."""
        if ip in cls._cache:
            return cls._cache[ip]
        if SecurityValidator.is_private_ip(ip) or ip == "*":
            return {"asn": "Private", "location": "N/A", "org": "Private Network"}

        loop = asyncio.get_running_loop()
        try:
            future = loop.run_in_executor(
                None,
                lambda: requests.get(
                    f"http://ip-api.com/json/{ip}?fields=status,country,city,as,org",
                    timeout=3,
                    allow_redirects=False
                )
            )
            response = await asyncio.wait_for(future, timeout=4)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    info = {
                        "asn": str(data.get('as', 'Unknown')),
                        "location": f"{data.get('city', '')}, {data.get('country', '')}".strip(', '),
                        "org": str(data.get('org', 'Unknown'))
                    }
                    cls._cache[ip] = info
                    return info
        except (asyncio.TimeoutError, RequestException) as e:
            logger.warning(f"IP info lookup failed for {ip}: {type(e).__name__}")
        
        return {"asn": "Unknown", "location": "Unknown", "org": "Unknown"}

    @classmethod
    async def resolve_hostname(cls, ip: str) -> str:
        """Async reverse DNS lookup."""
        if ip == "*":
            return ""
        try:
            resolver = aiodns.DNSResolver()
            return await resolver.gethostbyaddr(ip)
        except (aiodns.error.DNSError, KeyError):
            return ""


# Core network tracer logic
class TracePulse:
    """Network path tracer for route analysis."""

    def __init__(self, settings: TracerouteSettings):
        self.settings = settings
        self.results: List[HopResult] = []
        self.console = console

    def _create_packet(self, ttl: int, probe_num: int) -> Any:
        """Create packet with Paris-mode variations."""
        dst = self.settings.destination
        proto = self.settings.protocol
        port = self.settings.port

        # Paris traceroute: vary properties to keep flow consistent
        if proto == 'icmp':
            # Vary ICMP checksum by changing the payload
            return IP(dst=dst, ttl=ttl) / ICMP() / Raw(load=f"probe{probe_num}")
        elif proto == 'tcp':
            # Vary source port
            return IP(dst=dst, ttl=ttl) / TCP(sport=24000 + ttl * 3 + probe_num, dport=port, flags="S")
        elif proto == 'udp':
            # Vary source port
            return IP(dst=dst, ttl=ttl) / UDP(sport=33434 + ttl * 3 + probe_num, dport=port)
        raise ValueError(f"Unsupported protocol: {proto}")

    def _process_reply(self, reply: Any) -> Tuple[Optional[str], Optional[List[str]]]:
        """Extract IP and MPLS labels from a reply packet."""
        if not reply:
            return None, None
        
        ip = reply.src
        mpls_labels = []
        
        # Check for MPLS labels in ICMP time-exceeded payloads
        if ICMP in reply and reply[ICMP].type == 11 and reply[ICMP].code == 0:
            inner_ip = reply[ICMP].payload.getlayer(IP)
            if inner_ip:
                # Scapy doesn't have a dedicated MPLS layer, so we check raw bytes
                # This is a heuristic and might need adjustment
                payload = bytes(inner_ip)
                # MPLS label is 4 bytes, common label values are > 15
                # This is a simplified check
                for i in range(len(payload) - 4):
                    # Check for a potential MPLS stack
                    if payload[i+2] & 0x01: # Bottom of stack bit
                         # Heuristic: Check if looks like a label
                        if (payload[i] << 12 | payload[i+1] << 4 | payload[i+2] >> 4) > 15:
                            label = f"L={payload[i] << 12 | payload[i+1] << 4 | payload[i+2] >> 4}, TC={payload[i+2] >> 1 & 0x07}, S={payload[i+2] & 0x01}, TTL={payload[i+3]}"
                            mpls_labels.append(label)
        
        return ip, mpls_labels

    async def _probe_hop(self, ttl: int) -> HopResult:
        """Asynchronously probe a single hop."""
        hop_result = HopResult(hop=ttl, ip="*")
        ips_at_hop = set()
        
        tasks = []
        for i in range(self.settings.probes_per_hop):
            packet = self._create_packet(ttl, i)
            task = asyncio.create_task(self._send_probe(packet))
            tasks.append(task)
            await asyncio.sleep(self.settings.probe_delay)

        probe_results = await asyncio.gather(*tasks)

        for rtt, reply in probe_results:
            if rtt is not None and reply is not None:
                hop_result.rtts.append(rtt)
                ip, mpls = self._process_reply(reply)
                if ip:
                    ips_at_hop.add(ip)
                if mpls:
                    hop_result.mpls_labels.extend(mpls)

        # In case of multiple IPs, pick the most common one
        if ips_at_hop:
            hop_result.ip = max(ips_at_hop, key=list(ips_at_hop).count)
        
        # Calculate stats
        if hop_result.rtts:
            hop_result.avg_rtt = statistics.mean(hop_result.rtts)
            hop_result.jitter = statistics.stdev(hop_result.rtts) if len(hop_result.rtts) > 1 else 0.0
        
        hop_result.loss = (1 - (len(hop_result.rtts) / self.settings.probes_per_hop)) * 100

        # Enrich data
        if hop_result.ip != "*":
            hostname_task = IPInfoProvider.resolve_hostname(hop_result.ip)
            info_task = IPInfoProvider.get_info(hop_result.ip)
            hostname, info = await asyncio.gather(hostname_task, info_task)
            
            hop_result.hostname = hostname[0] if isinstance(hostname, list) and hostname else (hostname if isinstance(hostname, str) else "")
            hop_result.asn = info.get('asn', '')
            hop_result.location = info.get('location', '')

        return hop_result

    async def _send_probe(self, packet: Any) -> Tuple[Optional[float], Optional[Any]]:
        """Send a single probe and return RTT and reply."""
        loop = asyncio.get_running_loop()
        try:
            start_time = time.time()
            future = loop.run_in_executor(
                None,
                lambda: sr1(packet, timeout=self.settings.timeout, verbose=0)
            )
            reply = await asyncio.wait_for(future, timeout=self.settings.timeout + 0.1)
            end_time = time.time()
            
            if reply:
                return (end_time - start_time) * 1000, reply
        except (asyncio.TimeoutError, Exception) as e:
            logger.debug(f"Probe timeout/error for TTL {packet.ttl}: {e}")
        
        return None, None

    def _get_rtt_color(self, rtt: float) -> str:
        """Get color based on RTT value."""
        if rtt == 0: return "red"
        if rtt < 50: return "green"
        if rtt < 150: return "yellow"
        return "red"

    def _create_results_table(self) -> Table:
        """Create and populate the results table."""
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Hop", style="dim", width=4)
        table.add_column("IP/Hostname", min_width=25)
        table.add_column("RTT (ms)", justify="right", min_width=10)
        table.add_column("Jitter", justify="right", min_width=10)
        table.add_column("Loss %", justify="right", min_width=8)
        table.add_column("ASN/Org", min_width=20)
        table.add_column("Location", min_width=20)
        table.add_column("MPLS", min_width=15)

        for res in self.results:
            display_ip = res.hostname if res.hostname and res.hostname != res.ip else res.ip
            rtt_text = f"{res.avg_rtt:.2f}" if res.avg_rtt > 0 else "*"
            jitter_text = f"{res.jitter:.2f}" if res.jitter > 0 else "*"
            loss_text = f"{res.loss:.0f}%"
            mpls_text = "\n".join(res.mpls_labels)
            
            table.add_row(
                str(res.hop),
                display_ip,
                Text(rtt_text, style=self._get_rtt_color(res.avg_rtt)),
                jitter_text,
                loss_text,
                res.asn,
                res.location,
                mpls_text
            )
        return table

    async def run(self):
        """Execute the full traceroute process."""
        self.console.print(f"\n[bold green]Starting network trace to {self.settings.destination} ({self.settings.resolved_ip})[/bold green]")
        self.console.print(f"Protocol: {self.settings.protocol.upper()}, Port: {self.settings.port}, Max hops: {self.settings.max_hops}, Timeout: {self.settings.timeout}s\n")
        
        table = self._create_results_table()
        with Live(table, refresh_per_second=4, console=self.console) as live:
            for ttl in range(1, self.settings.max_hops + 1):
                live.console.print(f"[dim]Probing hop {ttl}...[/dim]")
                try:
                    result = await self._probe_hop(ttl)
                    self.results.append(result)
                    
                    live.update(self._create_results_table())

                    if result.ip == self.settings.resolved_ip:
                        self.console.print(f"\n[bold green]Destination {self.settings.destination} reached![/bold green]")
                        break
                except Exception as e:
                    logger.error(f"Error at hop {ttl}: {e}", exc_info=True)
                    break
        
        self.display_summary()
        if self.settings.save_results:
            self.save_results()

    def display_summary(self):
        """Display a summary panel of the traceroute results."""
        if not self.results: return

        successful_hops = [r for r in self.results if r.ip != "*"]
        if not successful_hops:
            self.console.print(Panel("[bold red]No successful hops recorded.[/bold red]", title="Summary"))
            return

        avg_rtt = statistics.mean([r.avg_rtt for r in successful_hops if r.avg_rtt > 0])
        total_loss = statistics.mean([r.loss for r in self.results])
        path_asns = {r.asn for r in successful_hops if r.asn and "Private" not in r.asn}
        
        summary_text = (
            f"[bold]Path Summary[/bold]\n"
            f"Total hops: {len(self.results)}\n"
            f"Responsive hops: {len(successful_hops)}\n"
            f"Average RTT (end-to-end): {avg_rtt:.2f} ms\n"
            f"Average packet loss: {total_loss:.1f}%\n"
            f"Unique ASNs encountered: {len(path_asns)}\n"
        )
        self.console.print(Panel(summary_text, title="Traceroute Complete", title_align="left"))

    def save_results(self):
        """Save results to file based on extension."""
        if not self.settings.filename: return
        
        is_valid, safe_filename, error_msg = SecurityValidator.sanitize_filename(self.settings.filename)
        if not is_valid:
            self.console.print(f"[red]Error saving file: {error_msg}[/red]")
            return

        reports_dir = Path("reports/tracepulse")
        reports_dir.mkdir(parents=True, exist_ok=True)
        filepath = reports_dir / safe_filename
        
        ext = filepath.suffix.lower()
        savers = {
            '.json': self._save_to_json,
            '.csv': self._save_to_csv,
            '.html': self._save_to_html_map,
            '.txt': self._save_to_txt
        }
        
        # If no valid extension, default to .txt
        saver = savers.get(ext)
        if not saver:
            filepath = filepath.with_suffix('.txt')
            saver = self._save_to_txt
        
        try:
            saver(filepath)
            self.console.print(f"[green]Results saved to: {filepath}[/green]")
        except Exception as e:
            self.console.print(f"[red]Error saving file: {e}[/red]")
            logger.error(f"File save error to {filepath}: {e}", exc_info=True)

    def _save_to_json(self, filepath: Path):
        data = self.settings.dict()
        data["results"] = [r.dict() for r in self.results]
        data["timestamp"] = datetime.now().isoformat()
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def _save_to_csv(self, filepath: Path):
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            headers = HopResult.__fields__.keys()
            writer.writerow(headers)
            for res in self.results:
                writer.writerow([getattr(res, h) for h in headers])

    def _save_to_txt(self, filepath: Path):
         with open(filepath, 'w') as f:
            f.write(f"Network Tracer Results for {self.settings.destination}\n")
            f.write("="*40 + "\n")
            # Use a captured console to write the table to the file
            capture_console = Console(file=f, record=True)
            capture_console.print(self._create_results_table())

    def _save_to_html_map(self, filepath: Path):
        """Generate and save an interactive HTML map of the traceroute path."""
        # Find a central point for the map
        locations = []
        for res in self.results:
            if res.ip != "*" and not SecurityValidator.is_private_ip(res.ip):
                try:
                    # This is a blocking call, but acceptable for file saving
                    geo_data = requests.get(f"http://ip-api.com/json/{res.ip}?fields=lat,lon").json()
                    if 'lat' in geo_data and 'lon' in geo_data:
                        locations.append(((geo_data['lat'], geo_data['lon']), res))
                except RequestException:
                    continue

        if not locations:
            self.console.print("[yellow]No geolocations found to generate a map.[/yellow]")
            return

        avg_lat = statistics.mean([loc[0][0] for loc in locations])
        avg_lon = statistics.mean([loc[0][1] for loc in locations])
        
        m = folium.Map(location=[avg_lat, avg_lon], zoom_start=4)

        # Add points and lines
        for i, (coords, res) in enumerate(locations):
            popup_html = f"""
            <b>Hop {res.hop}</b>: {res.ip}<br>
            <b>Hostname</b>: {res.hostname}<br>
            <b>RTT</b>: {res.avg_rtt:.2f} ms<br>
            <b>ASN</b>: {res.asn}<br>
            <b>Location</b>: {res.location}
            """
            folium.Marker(
                location=coords,
                popup=folium.Popup(popup_html, max_width=300),
                tooltip=f"Hop {res.hop}: {res.ip}",
                icon=folium.Icon(color='blue' if i > 0 else 'green')
            ).add_to(m)

            if i > 0:
                folium.PolyLine([locations[i-1][0], coords], color="blue", weight=2.5, opacity=1).add_to(m)

        m.save(str(filepath))

# User interaction functions
async def get_user_config() -> Optional[TracerouteSettings]:
    """Interactive configuration collection."""
    console.print("\n[bold blue]Network Tracer Configuration[/bold blue]")
    
    dest = Prompt.ask("Enter destination (domain or IP)")
    resolved_ip, error = await SecurityValidator.validate_destination(dest, allow_private=False)
    if error:
        console.print(f"[red]Error: {error}[/red]")
        return None

    settings_dict = {
        "destination": dest,
        "resolved_ip": resolved_ip,
        "protocol": Prompt.ask("Select protocol", choices=['icmp', 'tcp', 'udp'], default='icmp'),
    }

    if settings_dict['protocol'] in ['tcp', 'udp']:
        settings_dict['port'] = int(Prompt.ask("Enter destination port", default="80"))
    
    settings_dict['max_hops'] = int(Prompt.ask("Max hops", default="30"))
    settings_dict['timeout'] = float(Prompt.ask("Timeout (s)", default="2.0"))
    
    if Confirm.ask("Save results?", default=False):
        settings_dict['save_results'] = True
        settings_dict['filename'] = Prompt.ask("Output filename (e.g., results.json, map.html)", default="tracepulse_results.json")

    return TracerouteSettings(**settings_dict)


def check_privileges():
    """Warn if not running with sufficient privileges."""
    if os.name != 'nt' and os.geteuid() != 0:
        console.print("[yellow]Warning: Running without root privileges. ICMP/TCP may fail. Try 'sudo'.[/yellow]")


# Main execution functions
async def amain(cli_args: Optional[Any] = None):
    """Asynchronous main entry point."""
    try:
        from core.utils import clear_console, header_banner
        clear_console()
        header_banner("Network Tracer")
    except (ModuleNotFoundError, ImportError):
        print("Network Tracer - Path Analysis Tool")
        print("="*40)


    check_privileges()

    settings = None
    if cli_args and cli_args.destination:
        # Non-interactive mode
        resolved_ip, error = await SecurityValidator.validate_destination(cli_args.destination, cli_args.allow_private)
        if error:
            console.print(f"[red]Error: {error}[/red]")
            return
        
        settings = TracerouteSettings(
            destination=cli_args.destination,
            resolved_ip=resolved_ip,
            protocol=cli_args.protocol,
            port=cli_args.port,
            max_hops=cli_args.max_hops,
            timeout=cli_args.timeout,
            probe_delay=cli_args.probe_delay,
            save_results=cli_args.save,
            filename=cli_args.output,
            allow_private=cli_args.allow_private
        )
    else:
        # Interactive mode
        settings = await get_user_config()

    if settings:
        tracer = TracePulse(settings)
        await tracer.run()
        console.print("\n[bold green]Network trace completed.[/bold green]")


def main(cli_args=None):
    try:
        # Check if we're already in an event loop
        import asyncio
        try:
            loop = asyncio.get_running_loop()
            # If there's already a running event loop, run the async function using create_task
            # But we need to ensure it runs to completion, so schedule it and wait
            coro = amain(cli_args)
            # If we're in an event loop, we can't use asyncio.run, so we use create_task
            # and expect the caller to handle awaiting it properly
            task = loop.create_task(coro)
            # Since we're in a sync context, we need to use a different approach
            # The ideal fix is to make this function async too, but for compatibility
            # we'll use a synchronous executor
            import concurrent.futures
            import threading

            def run_async_in_thread():
                # Create a new event loop in a new thread
                new_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(new_loop)
                try:
                    return new_loop.run_until_complete(amain(cli_args))
                finally:
                    new_loop.close()

            # Run in a separate thread with its own event loop
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(run_async_in_thread)
                return future.result()
        except RuntimeError:
            # No event loop running, safe to use asyncio.run()
            asyncio.run(amain(cli_args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Traceroute interrupted by user.[/yellow]")
    except Exception as e:
        logger.error(f"A critical error occurred: {e}", exc_info=True)
        console.print(f"\n[bold red]❌ An unexpected error occurred: {e}. Check logs for details.[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    # This allows the script to be run standalone for testing
    # A simplified arg parser for standalone mode
    import argparse
    parser = argparse.ArgumentParser(description="Network Tracer - Path Analysis Tool")
    parser.add_argument("destination", nargs='?', default=None, help="The destination domain or IP address.")
    parser.add_argument("--protocol", choices=['icmp', 'tcp', 'udp'], default='icmp')
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--max-hops", type=int, default=30)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--probe-delay", type=float, default=0.1)
    parser.add_argument("--save", action='store_true', help="Save results to a file.")
    parser.add_argument("--output", default="tracepulse_results.json", help="Output filename.")
    parser.add_argument("--allow-private", action='store_true', help="Allow tracing to private IP ranges.")
    
    args = parser.parse_args()

    # If no destination is provided, run interactively
    if not args.destination:
        main()
    else:
        main(args)
