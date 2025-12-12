# modules/http_desync/engine/smuggler.py
import httpx
import os
import threading
import time
import sys
import ssl
import socket
import urllib.parse
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.text import Text

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from .baseline_comparator import BaselineComparator
from .payload_generator import (ModernPayloadGenerator, TargetValidator, 
                                RANDOMIZER_AVAILABLE, ConfidenceLevel, VulnStatus, 
                                ProtocolVersion, TestResult, BaselineResponse)

from exports.result_saver import ResultSaver

console = Console()

# Import the randomizer module for stealth headers
try:
    from core.randomizer import HeaderFactory
    RANDOMIZER_AVAILABLE = True
except ImportError:
    RANDOMIZER_AVAILABLE = False
    print("Warning: randomizer.py not found. Using basic headers.")

try:
    from core.utils import clear_console, header_banner
except ImportError:
    def clear_console():
        import os
        os.system('cls' if os.name == 'nt' else 'clear')

# ============================================================================
# MAIN REQUEST SMUGGLER CLASS
# ============================================================================

class RequestSmuggler:
    """
    HTTP Request Smuggling tester with modern payloads,
    HTTP/2 support, stealth capabilities, and improved detection.
    """

    def __init__(self, url: str, port: int, custom_headers: str = ""):
        self.target_url = url
        self.port = port
        self.custom_headers = self._parse_headers(custom_headers)
        self.results: List[TestResult] = []
        self.lock = threading.Lock()
        self.scan_completed = False

        # Initialize components
        self.validator = TargetValidator(console)
        self.comparator = BaselineComparator()
        self.payload_generator = None
        self.headers_factory = None

        # Initialize header factory if randomizer is available
        if RANDOMIZER_AVAILABLE:
            try:
                self.headers_factory = HeaderFactory(pool_size=100)
                console.print("[green]✅ Stealth header factory initialized[/green]")
            except Exception as e:
                console.print(f"[yellow]⚠️ Header factory failed: {e}[/yellow]")

        # Target information
        self.target_info: Dict[str, Any] = {}

    def _parse_headers(self, headers_str: str) -> Dict[str, str]:
        """Parse custom headers string into dictionary"""
        headers = {}
        if headers_str:
            try:
                for header in headers_str.split(','):
                    if ':' in header:
                        key, value = header.split(':', 1)
                        headers[key.strip()] = value.strip()
            except ValueError:
                console.print("[bold red]Invalid header format. Using default headers.[/bold red]")
        return headers
    
    def validate_target(self) -> bool:
        """Validate target before testing"""
        console.print("\n[bold cyan]Step 1: Target Validation[/bold cyan]")

        is_valid, error_msg, target_info = self.validator.validate_target(self.target_url, self.port)

        if not is_valid:
            console.print(f"[bold red]❌ Target validation failed: {error_msg}[/bold red]")
            return False

        self.target_info = target_info

        # Display target information
        info_table = Table(title="Target Information", show_header=True)
        info_table.add_column("Property", style="cyan")
        info_table.add_column("Value", style="white")

        info_table.add_row("Host", target_info["host"])
        info_table.add_row("Port", str(target_info["port"]))
        info_table.add_row("Scheme", target_info["scheme"])

        # HTTP versions
        versions = [v for v, supported in target_info["http_versions"].items() if supported]
        info_table.add_row("HTTP Versions", ", ".join(versions) or "None detected")

        # Server info
        server_info = target_info.get("server_info", {})
        if "server" in server_info:
            info_table.add_row("Server", server_info["server"])
        if "powered_by" in server_info:
            info_table.add_row("X-Powered-By", server_info["powered_by"])

        console.print(info_table)

        # Initialize payload generator with target info
        parsed_url = urllib.parse.urlparse(self.target_url)
        self.payload_generator = ModernPayloadGenerator(
            target_host=parsed_url.hostname,
            target_port=self.port
        )

        return True

    def establish_baselines(self) -> bool:
        """Establish baseline responses"""
        console.print("\n[bold cyan]Step 2: Baseline Establishment[/bold cyan]")

        return self.comparator.establish_baselines(
            url=self.target_url,
            port=self.port,
            console=console,  # Add this
            headers_factory=self.headers_factory,
            count=5
        )

    def generate_test_payloads(self) -> List[Dict[str, Any]]:
        """Generate comprehensive test payloads"""
        console.print("\n[bold cyan]Step 3: Payload Generation[/bold cyan]")

        if not self.payload_generator:
            console.print("[red]❌ Payload generator not initialized[/red]")
            return []

        payloads = []

        # Add classic payloads
        classic_payloads = self.payload_generator.generate_classic_payloads()
        payloads.extend(classic_payloads)
        console.print(f"[green]✅ Generated {len(classic_payloads)} classic payloads[/green]")

        # Add modern payloads
        modern_payloads = self.payload_generator.generate_modern_payloads()
        payloads.extend(modern_payloads)
        console.print(f"[green]✅ Generated {len(modern_payloads)} modern payloads[/green]")

        console.print(f"[bold green]Total payloads: {len(payloads)}[/bold green]")
        return payloads

    def test_payload(self, payload_data: Dict[str, Any], progress: Progress, task_id: Any):
        """
        Test a single payload with error handling and analysis.

        Args:
            payload_data: Dictionary containing payload information
            progress: Rich progress instance
            task_id: Progress task identifier
        """
        payload_type = payload_data["type"]
        protocol = payload_data.get("protocol", "HTTP/1.1")

        result = TestResult(
            payload_type=payload_type,
            status="Error",
            confidence="Low",
            details="",
            response_time=0.0,
            protocol=protocol
        )

        try:
            # Get stealth headers if available
            headers = {}
            if self.headers_factory and RANDOMIZER_AVAILABLE:
                headers = self.headers_factory.get_headers()
            else:
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                }

            # Add custom headers
            headers.update(self.custom_headers)

            start_time = time.time()

            if protocol == "HTTP/2":
                response_data = self._send_http2_request(payload_data, headers)
            else:
                response_data = self._send_http1_request(payload_data, headers)

            elapsed = time.time() - start_time
            result.response_time = elapsed

            # Analyze response using enhanced comparator
            confidence, details = self.comparator.compare_response(response_data)

            # Update result based on analysis
            if confidence == ConfidenceLevel.HIGH:
                result.status = f"[bold red]{VulnStatus.VULNERABLE.value} Vulnerable[/bold red]"
                result.confidence = "[red]High[/red]"
            elif confidence == ConfidenceLevel.MEDIUM:
                result.status = f"[bold yellow]{VulnStatus.POTENTIAL.value} Potentially Vulnerable[/bold yellow]"
                result.confidence = "[yellow]Medium[/yellow]"
            # OPTIMIZATION: Handle new INFO confidence level for WAF/blocking/safe rejections
            elif confidence == ConfidenceLevel.INFO:
                result.status = f"[blue]{VulnStatus.BLOCKED.value} Informational[/blue]"
                result.confidence = "[blue]Info[/blue]"
            else:
                result.status = f"[green]{VulnStatus.SAFE.value} Likely Safe[/green]"
                result.confidence = "[green]Low[/green]"

            result.details = details

        except httpx.ReadTimeout:
            result.status = f"[bold yellow]{VulnStatus.TIMEOUT.value} Timeout[/bold yellow]"
            result.confidence = "[yellow]Medium[/yellow]"
            result.details = "Request timed out - possible desync or server overload"

        except httpx.ConnectTimeout:
            result.status = f"[red]{VulnStatus.ERROR.value} Connection Timeout[/red]"
            result.details = "Could not establish connection within timeout period"

        except httpx.ConnectError as e:
            result.status = f"[red]{VulnStatus.ERROR.value} Connection Error[/red]"
            result.details = f"Connection failed: {str(e)}"

        except Exception as e:
            result.details = f"Unexpected error: {str(e)}"

        with self.lock:
            self.results.append(result)

        progress.update(task_id, advance=1)

    def _send_http1_request(self, payload_data: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        """Send HTTP/1.1 request with raw payload"""
        raw_payload = payload_data["payload"]

        # For raw payloads, we need to send them directly
        parsed_url = urllib.parse.urlparse(self.target_url)

        if isinstance(raw_payload, bytes):
            # Send raw bytes directly via socket
            return self._send_raw_payload(raw_payload, parsed_url.hostname, self.port)
        else:
            # Use httpx for structured requests
            with httpx.Client(http2=False, verify=False, timeout=20) as client:
                response = client.post(
                    f"{self.target_url}:{self.port}",
                    headers=headers,
                    content=raw_payload
                )

                return {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'body': response.text,
                    'elapsed': response.elapsed.total_seconds()
                }

    def _send_raw_payload(self, payload: bytes, host: str, port: int) -> Dict[str, Any]:
        """Send raw payload via direct socket connection"""
        try:
            start_time = time.time()

            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(20)

            # Handle SSL/TLS if needed
            if self.target_url.startswith('https'):
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))
            sock.send(payload)

            # Read response
            response_data = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                except socket.timeout:
                    break

            sock.close()
            elapsed = time.time() - start_time

            # Parse HTTP response
            response_text = response_data.decode('utf-8', errors='ignore')

            # Extract status code
            status_code = 0
            if response_text:
                first_line = response_text.split('\n')[0]
                if 'HTTP/' in first_line:
                    parts = first_line.split()
                    if len(parts) >= 2:
                        try:
                            status_code = int(parts[1])
                        except ValueError:
                            status_code = 0

            # Extract headers
            headers = {}
            if '\r\n\r\n' in response_text:
                header_section = response_text.split('\r\n\r\n')[0]
                for line in header_section.split('\r\n')[1:]:  # Skip status line
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()

            # Extract body
            body = ""
            if '\r\n\r\n' in response_text:
                body = response_text.split('\r\n\r\n', 1)[1]

            return {
                'status_code': status_code,
                'headers': headers,
                'body': body,
                'elapsed': elapsed
            }

        except Exception as e:
            return {
                'status_code': 0,
                'headers': {},
                'body': f"Error: {str(e)}",
                'elapsed': 0
            }

    def _send_http2_request(self, payload_data: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        """Send HTTP/2 request using h2 library"""
        try:
            # HTTP/2 requests use httpx with http2=True
            with httpx.Client(http2=True, verify=False, timeout=20) as client:
                h2_payload = payload_data["payload"]

                # For HTTP/2, payload should be a dict with method, path, headers, body
                if isinstance(h2_payload, dict):
                    method = h2_payload.get("method", "GET")
                    path = h2_payload.get("path", "/")
                    h2_headers = h2_payload.get("headers", {})
                    body = h2_payload.get("body", "")

                    # Merge with stealth headers
                    final_headers = {**headers, **h2_headers}

                    if method.upper() == "POST":
                        response = client.post(
                            f"{self.target_url}:{self.port}{path}",
                            headers=final_headers,
                            content=body
                        )
                    else:
                        response = client.get(
                            f"{self.target_url}:{self.port}{path}",
                            headers=final_headers
                        )

                    return {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'body': response.text,
                        'elapsed': response.elapsed.total_seconds()
                    }
                else:
                    # Fallback for malformed HTTP/2 payload
                    return {
                        'status_code': 0,
                        'headers': {},
                        'body': "Invalid HTTP/2 payload format",
                        'elapsed': 0
                    }

        except Exception as e:
            return {
                'status_code': 0,
                'headers': {},
                'body': f"HTTP/2 Error: {str(e)}",
                'elapsed': 0
            }

    def run_concurrent_tests(self, payloads: List[Dict[str, Any]], max_threads: int = 5):
        """
        Execute all payload tests with controlled concurrency.

        Args:
            payloads: List of payload dictionaries to test
            max_threads: Maximum number of concurrent threads
        """
        console.print(f"\n[bold cyan]Step 4: Executing {len(payloads)} tests[/bold cyan] 🚀")
        console.print(f"[dim]Using max {max_threads} concurrent threads for controlled testing[/dim]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Testing Payloads...", total=len(payloads))

            # Use ThreadPoolExecutor for better thread management
            from concurrent.futures import ThreadPoolExecutor, as_completed

            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                # Submit all tasks
                futures = []
                for payload in payloads:
                    future = executor.submit(self.test_payload, payload, progress, task)
                    futures.append(future)

                    # Small delay to avoid overwhelming the target
                    time.sleep(0.2)

                # Wait for completion
                for future in as_completed(futures):
                    try:
                        future.result()  # This will raise any exceptions that occurred
                    except Exception as e:
                        console.print(f"[red]Thread error: {e}[/red]")

        self.scan_completed = True

    def display_results(self):
        """Display comprehensive results with enhanced formatting"""
        console.print("\n[bold green]✨ Scan Complete! Analysis Results:[/bold green]")

        if not self.results:
            console.print("[yellow]No results to display[/yellow]")
            return
        
        # Create results table
        table = Table(
            title="HTTP Desync Test Results",
            show_lines=True,
            header_style="bold magenta",
            title_style="bold white"
        )

        table.add_column("Payload Type", style="cyan", no_wrap=False, min_width=20)
        table.add_column("Protocol", style="blue", justify="center", min_width=8)
        table.add_column("Status", justify="center", min_width=18)
        table.add_column("Confidence", justify="center", min_width=10)
        table.add_column("Response Time", justify="right", min_width=12)
        table.add_column("Details", style="dim", min_width=30)

        # Sort results: High confidence first, then Medium, then Low
        def sort_key(result):
            if "[red]High[/red]" in result.confidence:
                return (0, result.payload_type)
            elif "[yellow]Medium[/yellow]" in result.confidence:
                return (1, result.payload_type)
            elif "[blue]Info[/blue]" in result.confidence:
                return (2, result.payload_type)
            else:
                return (3, result.payload_type)

        sorted_results = sorted(self.results, key=sort_key)

        # Add rows to table
        for result in sorted_results:
            table.add_row(
                result.payload_type,
                result.protocol,
                result.status,
                result.confidence,
                f"{result.response_time:.2f}s",
                result.details[:80] + "..." if len(result.details) > 80 else result.details
            )

        console.print(table)

        # Summary statistics
        self._display_summary_stats()

        # Recommendations
        self._display_recommendations()

    def _display_summary_stats(self):
        """Display summary statistics"""
        if not self.results:
            return

        total = len(self.results)
        high_confidence = sum(1 for r in self.results if "[red]High[/red]" in r.confidence)
        medium_confidence = sum(1 for r in self.results if "[yellow]Medium[/yellow]" in r.confidence)
        low_confidence = sum(1 for r in self.results if "[green]Low[/green]" in r.confidence)
        info_findings = sum(1 for r in self.results if "[blue]Info[/blue]" in r.confidence)


        avg_response_time = sum(r.response_time for r in self.results) / total

        stats_table = Table(title="Summary Statistics", show_header=False)
        stats_table.add_column("Metric", style="bold cyan")
        stats_table.add_column("Value", style="white")

        stats_table.add_row("Total Tests", str(total))
        stats_table.add_row("High Confidence", f"[red]{high_confidence}[/red]")
        stats_table.add_row("Medium Confidence", f"[yellow]{medium_confidence}[/yellow]")
        stats_table.add_row("Low Confidence", f"[green]{low_confidence}[/green]")
        stats_table.add_row("Informational", f"[blue]{info_findings}[/blue]")
        stats_table.add_row("Average Response Time", f"{avg_response_time:.2f}s")

        console.print("\n", stats_table)

    def _display_recommendations(self):
        """Display actionable recommendations based on results"""
        high_confidence_results = [r for r in self.results if "[red]High[/red]" in r.confidence]
        medium_confidence_results = [r for r in self.results if "[yellow]Medium[/yellow]" in r.confidence]

        recommendations = []

        if high_confidence_results:
            recommendations.extend([
                "🚨 [bold red]HIGH PRIORITY[/bold red]: Potential HTTP Request Smuggling vulnerabilities detected!",
                "   • Immediately investigate the high-confidence findings",
                "   • Check server/proxy configurations for HTTP parsing inconsistencies",
                "   • Review load balancer and reverse proxy settings",
                "   • Consider implementing strict HTTP parsing rules"
            ])

        if medium_confidence_results:
            recommendations.extend([
                "⚠️ [bold yellow]MEDIUM PRIORITY[/bold yellow]: Suspicious behavior detected:",
                "   • Manually verify medium-confidence findings",
                "   • Monitor for unusual response patterns",
                "   • Check for timeout-based detection evasion"
            ])

        if not high_confidence_results and not medium_confidence_results:
            recommendations.extend([
                "✅ [green]No obvious vulnerabilities detected[/green]",
                "   • Target appears to handle HTTP parsing consistently",
                "   • Consider testing with additional payloads or different conditions",
                "   • Verify that security controls are not interfering with tests"
            ])

        # General recommendations
        recommendations.extend([
            "",
            "📋 [bold]General Security Recommendations:[/bold]",
            "   • Ensure consistent HTTP parsing across all infrastructure components",
            "   • Implement proper HTTP validation and sanitization",
            "   • Use HTTP/2 where possible (more resistant to smuggling)",
            "   • Monitor for unusual HTTP traffic patterns",
            "   • Regular security testing of web infrastructure"
        ])

        console.print("\n[bold]🎯 Recommendations:[/bold]")
        for rec in recommendations:
            console.print(rec)

    def run_full_scan(self):
        """
        Execute the complete scanning workflow with all enhanced features.
        """
        clear_console()
        header_banner(tool_name="Request Smuggler")

        try:
            # Step 1: Validate target
            if not self.validate_target():
                console.print("[red]❌ Target validation failed. Exiting.[/red]")
                sys.exit(1)

            # Step 2: Establish baselines
            if not self.establish_baselines():
                console.print("[red]❌ Baseline establishment failed. Exiting.[/red]")
                sys.exit(1)

            # Step 3: Generate payloads
            payloads = self.generate_test_payloads()
            if not payloads:
                console.print("[red]❌ No payloads generated. Exiting.[/red]")
                sys.exit(1)

            # Step 4: Execute tests with default thread count for CLI mode
            max_threads = 3  # Default for CLI mode, can be configured via args
            console.print(f"[cyan]Using {max_threads} concurrent threads for testing[/cyan]")

            self.run_concurrent_tests(payloads, max_threads)

            # Step 5: Display results
            self.display_results()

            # Automatically save results in CLI mode
            console.print("\n[bold]Saving results to file...[/bold]")
            ResultSaver.save_results_to_file(
                self.results,
                self.target_url,
                self.port,
                self.target_info
            )

        except KeyboardInterrupt:
            console.print("\n[yellow]⚠️ Scan interrupted by user[/yellow]")
            if self.results:
                console.print("Displaying partial results...")
                self.display_results()
        except Exception as e:
            console.print(f"\n[red]❌ Unexpected error during scan: {e}[/red]")
            if self.results:
                console.print("Displaying partial results...")
                self.display_results()
