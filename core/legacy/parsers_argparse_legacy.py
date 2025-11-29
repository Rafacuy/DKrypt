#!/usr/bin/env python3
"""
Typer-based command parsers for all DKrypt modules (Migrated from Argparse)
Provides modern, type-safe CLI interface for all penetration testing tools.
"""

import typer
import asyncio
import json
from typing import Optional
from rich.console import Console

from modules import (
    subdomain, ssl_inspector,
    dir_bruteforcer, header_audit, port_scanner,
    cors_scan, sqli_scan, tracepulse,
    jscrawler, py_obfuscator, graphql_introspect
)
from modules.crawler_engine import crawler_utils
from modules.waf_bypass import tui
from modules.http_desync import main_runner
from modules.xss import scanner

console = Console()


def create_parser():
    """
    Deprecated: Create an argparse parser (for backward compatibility only).
    Use register_commands() with Typer instead.
    """
    console.print("[yellow]⚠️  create_parser() is deprecated. Use Typer directly.[/yellow]")
    
    import argparse
    parser = argparse.ArgumentParser(
        prog="dkrypt",
        description="DKrypt - Advanced Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', help='Available modules', metavar='MODULE')

    # SQLI Module
    sqli_parser = subparsers.add_parser('sqli', help='SQL Injection Scanner: Detects SQL injection vulnerabilities in web applications.')
    sqli_parser.add_argument('--url', required=True, help='Target URL to scan for SQL injection (e.g., https://example.com/vulnerable?id=1)')
    sqli_parser.add_argument('--test-forms', action='store_true', help='Enable testing of POST forms for SQL injection. The scanner will attempt to find and inject into forms.')
    sqli_parser.add_argument('--test-headers', action='store_true', help='Enable testing of HTTP headers for SQL injection. Useful for blind SQLi in headers.')
    sqli_parser.add_argument('--test-apis', action='store_true', help='Enable testing of API endpoints for SQL injection. Requires the URL to point to an API endpoint.')
    sqli_parser.add_argument('--export', default='html', choices=['html', 'csv', 'none'], help='Specify the format for exporting scan results. Options: \'html\', \'csv\', or \'none\'. Default is \'html\'.')

    # XSS Module
    xss_parser = subparsers.add_parser('xss', help='XSS Scanner: Detects Cross-Site Scripting vulnerabilities in web applications.')
    xss_parser.add_argument('--url', required=True, help='Target URL to scan for XSS (e.g., https://example.com/search?query=test)')
    xss_parser.add_argument('--threads', type=int, default=20, help='Number of concurrent threads to use for scanning. Higher values can speed up the scan but may be detected by WAFs. Default: 20.')
    xss_parser.add_argument('--rate-limit', type=int, default=5, help='Maximum number of requests per second to send. Helps in avoiding rate limiting by the target server. Default: 5.')
    xss_parser.add_argument('--max-payloads', type=int, default=15, help='Maximum number of XSS payloads to test per context (e.g., per input field). Default: 15.')
    xss_parser.add_argument('--batch-size', type=int, default=100, help='Number of payloads to send in a single batch. Default: 100.')
    xss_parser.add_argument('--smart-mode', action='store_true', help='Enable smart mode for more intelligent payload generation and detection, reducing false positives.')
    xss_parser.add_argument('--stealth-mode', action='store_true', help='Enable stealth mode to make the scan scan less detectable by WAFs and intrusion detection systems.')
    xss_parser.add_argument('--test-headers', action='store_true', help='Test HTTP headers for XSS vulnerabilities. Useful for reflected XSS in headers.')
    xss_parser.add_argument('--verbose', action='store_true', help='Enable verbose output to display detailed information during the scan.')

    # GRAPHQL Module
    graphql_parser = subparsers.add_parser('graphql', help='GraphQL endpoint analysis and vulnerability detection')
    graphql_parser.add_argument('--url', required=True, help='GraphQL endpoint URL to introspect (e.g., https://example.com/graphql)')
    graphql_parser.add_argument('--headers', default='{}', help='Custom headers as JSON string (e.g., \'{"Authorization": "Bearer token", "X-API-Key": "key123"}\')')
    graphql_parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds. Higher values recommended for slow endpoints. Default: 30.')
    graphql_parser.add_argument('--export', default='json,csv,txt', help='Export formats (comma-separated): json,csv,txt. Default exports all formats for comprehensive analysis.')
    graphql_parser.add_argument('--output', help='Output filename prefix for exported results. If not specified, auto-generates based on target and timestamp.')
    graphql_parser.add_argument('--verbose', action='store_true', help='Display detailed results in console including all queries, mutations, and analysis details.')
    graphql_parser.add_argument('--export-raw', action='store_true', help='Export raw GraphQL response even on failure for manual analysis and debugging.')
    graphql_parser.add_argument('--no-header-factory', action='store_true', help='Disable HeaderFactory and use basic static headers instead of realistic rotating headers.')
    graphql_parser.add_argument('--header-pool-size', type=int, help='Size of HeaderFactory pool for generating realistic browser headers. Larger pools provide more variety but use more memory. Default: uses config settings.')
    graphql_parser.add_argument('--rotate-headers', action='store_true', help='Enable header rotation during requests to mimic different browser sessions and avoid detection.')

    # PORTSCANNER Module
    portscanner_parser = subparsers.add_parser('portscanner', help='Port Scanner: Scans target hosts for open ports and services using NMAP.')
    portscanner_parser.add_argument('command', help='Subcommand: single or batch')
    portscanner_parser.add_argument('--target', help='Target host to scan (e.g., example.com or 192.168.1.1)')
    portscanner_parser.add_argument('--ports', default='1-1024', help='Ports to scan (e.g., \'1-1024\', \'80,443,8080\', or \'all\'). Default: 1-1024.')
    portscanner_parser.add_argument('--scan-type', default='SYN', choices=['SYN', 'CON', 'UDP'], help='Type of NMAP scan to perform. Options: \'SYN\' (stealthy), \'CON\' (connect), \'UDP\'. Default: SYN.')
    portscanner_parser.add_argument('--timing', default='normal', choices=['paranoid', 'sneaky', 'polite', 'normal', 'aggressive', 'insane'], help='Timing profile for the scan. Options: \'paranoid\', \'sneaky\', \'polite\', \'normal\', \'aggressive\', \'insane\'. Default: normal.')
    portscanner_parser.add_argument('--service-detection', action='store_true', help='Enable service and version detection on open ports.')
    portscanner_parser.add_argument('--os-detection', action='store_true', help='Enable operating system detection.')
    portscanner_parser.add_argument('--script-scan', default='none', choices=['default', 'vuln', 'none'], help='Perform an NMAP Scripting Engine (NSE) scan. Options: \'default\' (safe scripts), \'vuln\' (vulnerability scripts), or \'none\'. Default: none.')
    portscanner_parser.add_argument('--custom-args', default='', help='Additional custom NMAP arguments to pass directly to NMAP (e.g., \'-sV -O\').')
    portscanner_parser.add_argument('--verbosity', type=int, default=1, choices=range(0, 3), help='Verbosity level of NMAP output (0=silent, 1=normal, 2=detailed). Default: 1.')
    portscanner_parser.add_argument('--output', default='no', choices=['json', 'csv', 'no'], help='Output format for scan results. Options: \'json\', \'csv\', or \'no\' (no file output). Default: no.')
    portscanner_parser.add_argument('--file', help='Path to a file containing target hosts, one per line. (Used for batch mode)')

    # WAFTESTER Module
    waftester_parser = subparsers.add_parser('waftester', help='WAF Bypass Tester: Tests Web Application Firewalls for bypass vulnerabilities.')
    waftester_parser.add_argument('--url', required=True, help='Target URL to test against the WAF (e.g., https://example.com/login)')
    waftester_parser.add_argument('--method', default='GET', help='HTTP method to use for requests (GET, POST, PUT, etc.). Default: GET.')
    waftester_parser.add_argument('--packs', help='Comma-separated list of header packs to use for WAF bypass testing (e.g., \'identity_spoof,tool_evasion\').')
    waftester_parser.add_argument('--custom-headers', help='JSON string of custom headers to include in requests (e.g., \'{"X-Custom-Header": "value"}\').')
    waftester_parser.add_argument('--concurrency', type=int, default=10, help='Number of concurrent requests to send. Default: 10.')
    waftester_parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds. Default: 10.')
    waftester_parser.add_argument('--jitter', type=float, default=0.1, help='Random delay between requests in seconds to avoid detection. Default: 0.1.')
    waftester_parser.add_argument('--verify-tls', action='store_true', help='Verify TLS certificates for HTTPS connections.')
    waftester_parser.add_argument('--profile', help='Name of the profile to load.')
    waftester_parser.add_argument('--export', default='both', choices=['json', 'csv', 'both'], help='Export format for test results. Options: \'json\', \'csv\', or \'both\'. Default: both.')

    # SUBDOMAIN Module
    subdomain_parser = subparsers.add_parser('subdomain', help='Subdomain Enumeration: Advanced subdomain discovery with multiple scan modes and performance optimization.')
    subdomain_parser.add_argument('command', help='Subcommand: single or batch')
    subdomain_parser.add_argument('--target', help='Target domain to enumerate subdomains for (e.g., example.com)')
    subdomain_parser.add_argument('--api-only', action='store_true', help='Use only API sources for enumeration (fast, stealthy, less noisy)')
    subdomain_parser.add_argument('--bruteforce-only', action='store_true', help='Use only wordlist bruteforce for enumeration (thorough, comprehensive)')
    subdomain_parser.add_argument('--rate-limit', type=int, default=200, help='Number of concurrent DNS queries (recommended: 100-500 for large wordlists). Default: 200.')
    subdomain_parser.add_argument('--dns-timeout', type=int, default=2, help='DNS timeout in seconds (lower = faster, higher = more reliable). Default: 2.')
    subdomain_parser.add_argument('--dns-threads', type=int, default=200, help='DNS thread pool size for concurrent processing. Default: 200.')
    subdomain_parser.add_argument('--api-keys', help='JSON string of API keys for premium sources (e.g., \'{"virustotal": "your_api_key"}\'). Enables additional API sources.')
    subdomain_parser.add_argument('--proxy-type', help='Type of proxy to use for DNS resolution. Requires PySocks library.')
    subdomain_parser.add_argument('--proxy-host', help='Proxy host address (e.g., 127.0.0.1, proxy.example.com). Required if --proxy-type is specified.')
    subdomain_parser.add_argument('--proxy-port', type=int, help='Proxy port number. If not specified, uses default ports (1080 for SOCKS, 8080 for HTTP).')
    subdomain_parser.add_argument('--wordlist', default='wordlists/subdomain.txt', help='Path to custom wordlist file for subdomain brute-forcing. Default: wordlists/subdomain.txt')
    subdomain_parser.add_argument('--output-formats', default='json,csv,txt', help='Comma-separated list of output formats to generate. Options: json,csv,txt. Default: json,csv,txt.')
    subdomain_parser.add_argument('--file', help='Path to file containing target domains, one per line. (Used for batch mode)')

    # CRAWLER Module
    crawler_parser = subparsers.add_parser('crawler', help='Web Crawler: Crawls websites to discover pages, links, and resources.')
    crawler_parser.add_argument('command', help='Subcommand: single or batch')
    crawler_parser.add_argument('--url', help='URL to start crawling from (e.g., https://example.com)')
    crawler_parser.add_argument('--depth', type=int, default=3, help='Maximum depth to crawl from the starting URL. Default: 3.')
    crawler_parser.add_argument('--concurrency', type=int, default=10, help='Number of concurrent requests to make during crawling. Default: 10.')
    crawler_parser.add_argument('--max-urls', type=int, default=100, help='Maximum number of unique URLs to crawl. Default: 100.')
    crawler_parser.add_argument('--js-render', action='store_true', help='Enable JavaScript rendering for pages to discover dynamically loaded content.')
    crawler_parser.add_argument('--no-robots', action='store_true', help='Ignore robots.txt directives during crawling.')
    crawler_parser.add_argument('--output', help='Output format for crawl results. Options: \'json\' or \'csv\'.')
    crawler_parser.add_argument('--file', help='Path to a file containing URLs to crawl, one per line. (Used for batch mode)')
    crawler_parser.add_argument('--output-file', help='File path to save the crawl results to. (Used for batch mode)')

    # HEADERS Module
    headers_parser = subparsers.add_parser('headers', help='Header Audit: Audits HTTP security headers of web applications.')
    headers_parser.add_argument('command', help='Subcommand: single or batch')
    headers_parser.add_argument('--url', help='URL to audit (e.g., https://example.com)')
    headers_parser.add_argument('--verbose', action='store_true', help='Enable verbose mode to display detailed header information.')
    headers_parser.add_argument('--allow-private', action='store_true', help='Allow auditing of private IP addresses (e.g., localhost, internal networks).')
    headers_parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds. Default: 15.')
    headers_parser.add_argument('--file', help='Path to a file containing URLs to audit, one per line. (Used for batch mode)')

    # DIRBRUTE Module
    dirbrute_parser = subparsers.add_parser('dirbrute', help='Dirbrute: Directory and file brute-forcer for web applications.')
    dirbrute_parser.add_argument('--url', required=True, help='Base URL to brute force (e.g., https://example.com)')
    dirbrute_parser.add_argument('--wordlist', default='wordlists/directory-brute.txt', help='Path to wordlist file. Default: wordlists/directory-brute.txt')
    dirbrute_parser.add_argument('--threads', type=int, default=10, help='Number of concurrent threads. Default: 10.')
    dirbrute_parser.add_argument('--extensions', default='.php,.html,.js,.css,.txt,.zip,.bak,.sql', help='Comma-separated list of extensions to try. Default: .php,.html,.js,.css,.txt,.zip,.bak,.sql')
    dirbrute_parser.add_argument('--status-codes', default='200,204,301,302,403', help='Comma-separated list of status codes to consider as valid. Default: 200,204,301,302,403')
    dirbrute_parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds. Default: 10.')
    dirbrute_parser.add_argument('--delay', type=float, default=0.0, help='Delay between requests in seconds. Default: 0.0')
    dirbrute_parser.add_argument('--output', help='Output file to save results to.')
    dirbrute_parser.add_argument('--verbose', action='store_true', help='Enable verbose output.')

    # SSLINSPECT Module
    sslinspect_parser = subparsers.add_parser('sslinspect', help='SSLInspect: SSL/TLS Certificate Inspector')
    sslinspect_parser.add_argument('--target', required=True, help='Target host and port to inspect (e.g., example.com:443)')
    sslinspect_parser.add_argument('--export', default='json', choices=['json', 'txt'], help='Export format: json or txt. Default: json')
    sslinspect_parser.add_argument('--verbose', action='store_true', help='Enable verbose output.')

    # CORSTEST Module
    corstest_parser = subparsers.add_parser('corstest', help='CORS Test: Cross-Origin Resource Sharing (CORS) Misconfiguration Auditor')
    corstest_parser.add_argument('--url', required=True, help='Target URL to test CORS configuration')
    corstest_parser.add_argument('--export', default='json', choices=['json', 'txt'], help='Export format: json or txt. Default: json')
    corstest_parser.add_argument('--verbose', action='store_true', help='Enable verbose output.')
    corstest_parser.add_argument('--custom-origin', help='Custom origin header to test')

    # SMUGGLER Module
    smuggler_parser = subparsers.add_parser('smuggler', help='HTTP Request Smuggling Tester')
    smuggler_parser.add_argument('--url', required=True, help='Target URL to test for HTTP smuggling')
    smuggler_parser.add_argument('--port', type=int, default=80, help='Target port. Default: 80')
    smuggler_parser.add_argument('--method', default='GET', choices=['GET', 'POST'], help='HTTP method to use. Default: GET')
    smuggler_parser.add_argument('--verbose', action='store_true', help='Enable verbose output.')

    # TRACEPULSE Module
    tracepulse_parser = subparsers.add_parser('tracepulse', help='Tracepulse: Network Traceroute Utility')
    tracepulse_parser.add_argument('--destination', required=True, help='Target host or IP address to trace')
    tracepulse_parser.add_argument('--protocol', default='icmp', choices=['icmp', 'tcp', 'udp'], help='Protocol to use for tracing: icmp, tcp, or udp. Default: icmp')
    tracepulse_parser.add_argument('--max-hops', type=int, default=30, help='Maximum number of hops. Default: 30')
    tracepulse_parser.add_argument('--port', type=int, default=33434, help='Target port for TCP/UDP tracing. Default: 33434')

    # JS-CRAWLER Module
    jscrawler_parser = subparsers.add_parser('js-crawler', help='JS Crawler: JavaScript File Crawler and Endpoint Extractor')
    jscrawler_parser.add_argument('--url', required=True, help='Target URL to crawl for JavaScript files')
    jscrawler_parser.add_argument('--output', help='Output file to save results to')
    jscrawler_parser.add_argument('--depth', type=int, default=3, help='Maximum depth to crawl. Default: 3')
    jscrawler_parser.add_argument('--selenium', action='store_true', help='Use Selenium for dynamic content extraction')
    jscrawler_parser.add_argument('--extensions', default='.js', help='File extensions to look for. Default: .js')

    # PY-OBFUSCATOR Module
    pyobfuscator_parser = subparsers.add_parser('py-obfuscator', help='Python Code Obfuscator')
    pyobfuscator_parser.add_argument('--input', required=True, help='Input Python file to obfuscate')
    pyobfuscator_parser.add_argument('--output', help='Output file path for obfuscated code')
    pyobfuscator_parser.add_argument('--level', type=int, default=2, choices=range(1, 4), help='Obfuscation level (1-3). Higher is more obfuscated. Default: 2')
    pyobfuscator_parser.add_argument('--rename-vars', action='store_true', default=True, help='Rename variables. Default: True')
    pyobfuscator_parser.add_argument('--rename-funcs', action='store_true', default=True, help='Rename functions. Default: True')
    pyobfuscator_parser.add_argument('--flow-obfuscation', action='store_true', default=True, help='Apply flow obfuscation. Default: True')

    return parser

def register_commands(app: typer.Typer):
    """Register all module commands with the main Typer app"""
    
    # SQLI Module
    @app.command("sqli", help="SQL Injection Scanner: Detects SQL injection vulnerabilities in web applications.")
    def sqli_cmd(
        url: str = typer.Option(..., "--url", help="Target URL to scan for SQL injection (e.g., https://example.com/vulnerable?id=1)"),
        test_forms: bool = typer.Option(False, "--test-forms", help="Enable testing of POST forms for SQL injection. The scanner will attempt to find and inject into forms."),
        test_headers: bool = typer.Option(False, "--test-headers", help="Enable testing of HTTP headers for SQL injection. Useful for blind SQLi in headers."),
        test_apis: bool = typer.Option(False, "--test-apis", help="Enable testing of API endpoints for SQL injection. Requires the URL to point to an API endpoint."),
        export: str = typer.Option("html", "--export", help="Specify the format for exporting scan results. Options: 'html', 'csv', or 'none'. Default is 'html'.")
    ):
        """Run SQLI scanner"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="SQLi scanner")
        logger.info(f"Running SQLi scanner on {url}")
        sqli_scan.run_sqli_scan(url, test_forms, test_headers, test_apis, export)


    # XSS Module
    @app.command("xss", help="XSS Scanner: Detects Cross-Site Scripting vulnerabilities in web applications.")
    def xss_cmd(
        url: str = typer.Option(..., "--url", help="Target URL to scan for XSS (e.g., https://example.com/search?query=test)"),
        threads: int = typer.Option(20, "--threads", help="Number of concurrent threads to use for scanning. Higher values can speed up the scan but may be detected by WAFs. Default: 20."),
        rate_limit: int = typer.Option(5, "--rate-limit", help="Maximum number of requests per second to send. Helps in avoiding rate limiting by the target server. Default: 5."),
        max_payloads: int = typer.Option(15, "--max-payloads", help="Maximum number of XSS payloads to test per context (e.g., per input field). Default: 15."),
        batch_size: int = typer.Option(100, "--batch-size", help="Number of payloads to send in a single batch. Default: 100."),
        smart_mode: bool = typer.Option(False, "--smart-mode", help="Enable smart mode for more intelligent payload generation and detection, reducing false positives."),
        stealth_mode: bool = typer.Option(False, "--stealth-mode", help="Enable stealth mode to make the scan scan less detectable by WAFs and intrusion detection systems."),
        test_headers: bool = typer.Option(False, "--test-headers", help="Test HTTP headers for XSS vulnerabilities. Useful for reflected XSS in headers."),
        verbose: bool = typer.Option(False, "--verbose", help="Enable verbose output to display detailed information during the scan.")
    ):
        """Run XSS scanner"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="XSS scanner")
        logger.info(f"Running XSS scanner on {url}")
        asyncio.run(scanner.run_xss_scan(
            url, threads, rate_limit, max_payloads,
            batch_size, smart_mode, stealth_mode,
            test_headers, verbose
        ))


    # GRAPHQL Module
    @app.command("graphql", help="GraphQL endpoint analysis and vulnerability detection")
    def graphql_cmd(
        url: str = typer.Option(..., "--url", help="GraphQL endpoint URL to introspect (e.g., https://example.com/graphql)"),
        headers: str = typer.Option("{}", "--headers", help="Custom headers as JSON string (e.g., '{\"Authorization\": \"Bearer token\", \"X-API-Key\": \"key123\"}')"),
        timeout: int = typer.Option(30, "--timeout", help="Request timeout in seconds. Higher values recommended for slow endpoints. Default: 30."),
        export: str = typer.Option("json,csv,txt", "--export", help="Export formats (comma-separated): json,csv,txt. Default exports all formats for comprehensive analysis."),
        output: Optional[str] = typer.Option(None, "--output", help="Output filename prefix for exported results. If not specified, auto-generates based on target and timestamp."),
        verbose: bool = typer.Option(False, "--verbose", help="Display detailed results in console including all queries, mutations, and analysis details."),
        export_raw: bool = typer.Option(False, "--export-raw", help="Export raw GraphQL response even on failure for manual analysis and debugging."),
        no_header_factory: bool = typer.Option(False, "--no-header-factory", help="Disable HeaderFactory and use basic static headers instead of realistic rotating headers."),
        header_pool_size: Optional[int] = typer.Option(None, "--header-pool-size", help="Size of HeaderFactory pool for generating realistic browser headers. Larger pools provide more variety but use more memory. Default: uses config settings."),
        rotate_headers: bool = typer.Option(False, "--rotate-headers", help="Enable header rotation during requests to mimic different browser sessions and avoid detection.")
    ):
        """Run GraphQL introspection"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="GraphQL Introspection")
        logger.info(f"Running GraphQL introspection on {url}")
        # Create an args-like object for compatibility with existing function
        class Args:
            def __init__(self):
                self.url = url
                self.headers = headers
                self.timeout = timeout
                self.export = export
                self.output = output
                self.verbose = verbose
                self.export_raw = export_raw
                self.no_header_factory = no_header_factory
                self.header_pool_size = header_pool_size
                self.rotate_headers = rotate_headers
        args = Args()
        graphql_introspect.run_cli(args)


    # PORTSCANNER Module
    @app.command("portscanner", help="Port Scanner: Scans target hosts for open ports and services using NMAP.")
    def portscanner_cmd(
        command: str = typer.Argument(..., help="Subcommand: single or batch"),
        target: Optional[str] = typer.Option(None, "--target", help="Target host to scan (e.g., example.com or 192.168.1.1)"),
        ports: str = typer.Option("1-1024", "--ports", help="Ports to scan (e.g., '1-1024', '80,443,8080', or 'all'). Default: 1-1024."),
        scan_type: str = typer.Option("SYN", "--scan-type", help="Type of NMAP scan to perform. Options: 'SYN' (stealthy), 'CON' (connect), 'UDP'. Default: SYN."),
        timing: str = typer.Option("normal", "--timing", help="Timing profile for the scan. Options: 'paranoid', 'sneaky', 'polite', 'normal', 'aggressive', 'insane'. Default: normal."),
        service_detection: bool = typer.Option(False, "--service-detection", help="Enable service and version detection on open ports."),
        os_detection: bool = typer.Option(False, "--os-detection", help="Enable operating system detection."),
        script_scan: str = typer.Option("none", "--script-scan", help="Perform an NMAP Scripting Engine (NSE) scan. Options: 'default' (safe scripts), 'vuln' (vulnerability scripts), or 'none'. Default: none."),
        custom_args: str = typer.Option("", "--custom-args", help="Additional custom NMAP arguments to pass directly to NMAP (e.g., '-sV -O')."),
        verbosity: int = typer.Option(1, "--verbosity", help="Verbosity level of NMAP output (0=silent, 1=normal, 2=detailed). Default: 1."),
        output: str = typer.Option("no", "--output", help="Output format for scan results. Options: 'json', 'csv', or 'no' (no file output). Default: no."),
        file: Optional[str] = typer.Option(None, "--file", help="Path to a file containing target hosts, one per line. (Used for batch mode)")
    ):
        """Run port scanner"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="Port Scanner")
        logger.info(f"Running port scanner")
        
        # Create args object for compatibility
        class Args:
            def __init__(self):
                self.command = command
                self.target = target
                self.ports = ports
                self.scan_type = scan_type
                self.timing = timing
                self.service_detection = service_detection
                self.os_detection = os_detection
                self.script_scan = script_scan
                self.custom_args = custom_args
                self.verbosity = verbosity
                self.output = output
                self.file = file
        
        args = Args()
        asyncio.run(port_scanner.main_menu(args))


    # WAFTESTER Module
    @app.command("waftester", help="WAF Bypass Tester: Tests Web Application Firewalls for bypass vulnerabilities.")
    def waftester_cmd(
        url: str = typer.Option(..., "--url", help="Target URL to test against the WAF (e.g., https://example.com/login)"),
        method: str = typer.Option("GET", "--method", help="HTTP method to use for requests (GET, POST, PUT, etc.). Default: GET."),
        packs: Optional[str] = typer.Option(None, "--packs", help="Comma-separated list of header packs to use for WAF bypass testing (e.g., 'identity_spoof,tool_evasion')."),
        custom_headers: Optional[str] = typer.Option(None, "--custom-headers", help="JSON string of custom headers to include in requests (e.g., '{\"X-Custom-Header\": \"value\"}')."),
        concurrency: int = typer.Option(10, "--concurrency", help="Number of concurrent requests to send. Default: 10."),
        timeout: int = typer.Option(10, "--timeout", help="Request timeout in seconds. Default: 10."),
        jitter: float = typer.Option(0.1, "--jitter", help="Random delay between requests in seconds to avoid detection. Default: 0.1."),
        verify_tls: bool = typer.Option(False, "--verify-tls", help="Verify TLS certificates for HTTPS connections."),
        profile: Optional[str] = typer.Option(None, "--profile", help="Name of the profile to load."),
        export: str = typer.Option("both", "--export", help="Export format for test results. Options: 'json', 'csv', or 'both'. Default: both.")
    ):
        """Run WAF tester"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="WAF Tester")
        logger.info(f"Running WAF tester on {url}")
        app_waf = tui.WAFTUI()
        
        # Create args object for compatibility
        class Args:
            def __init__(self):
                self.url = url
                self.method = method
                self.packs = packs
                self.custom_headers = custom_headers
                self.concurrency = concurrency
                self.timeout = timeout
                self.jitter = jitter
                self.verify_tls = verify_tls
                self.profile = profile
                self.export = export
        
        args = Args()
        app_waf.run(args)


    # SUBDOMAIN Module
    @app.command("subdomain", help="Subdomain Enumeration: Advanced subdomain discovery with multiple scan modes and performance optimization.")
    def subdomain_cmd(
        command: str = typer.Argument(..., help="Subcommand: single or batch"),
        target: Optional[str] = typer.Option(None, "--target", help="Target domain to enumerate subdomains for (e.g., example.com)"),
        api_only: bool = typer.Option(False, "--api-only", help="Use only API sources for enumeration (fast, stealthy, less noisy)"),
        bruteforce_only: bool = typer.Option(False, "--bruteforce-only", help="Use only wordlist bruteforce for enumeration (thorough, comprehensive)"),
        rate_limit: int = typer.Option(200, "--rate-limit", help="Number of concurrent DNS queries (recommended: 100-500 for large wordlists). Default: 200."),
        dns_timeout: int = typer.Option(2, "--dns-timeout", help="DNS timeout in seconds (lower = faster, higher = more reliable). Default: 2."),
        dns_threads: int = typer.Option(200, "--dns-threads", help="DNS thread pool size for concurrent processing. Default: 200."),
        api_keys: Optional[str] = typer.Option(None, "--api-keys", help="JSON string of API keys for premium sources (e.g., '{\"virustotal\": \"your_api_key\"}'). Enables additional API sources."),
        proxy_type: Optional[str] = typer.Option(None, "--proxy-type", help="Type of proxy to use for DNS resolution. Requires PySocks library."),
        proxy_host: Optional[str] = typer.Option(None, "--proxy-host", help="Proxy host address (e.g., 127.0.0.1, proxy.example.com). Required if --proxy-type is specified."),
        proxy_port: Optional[int] = typer.Option(None, "--proxy-port", help="Proxy port number. If not specified, uses default ports (1080 for SOCKS, 8080 for HTTP)."),
        wordlist: str = typer.Option("wordlists/subdomain.txt", "--wordlist", help="Path to custom wordlist file for subdomain brute-forcing. Default: wordlists/subdomain.txt"),
        output_formats: str = typer.Option("json,csv,txt", "--output-formats", help="Comma-separated list of output formats to generate. Options: json,csv,txt. Default: json,csv,txt."),
        file: Optional[str] = typer.Option(None, "--file", help="Path to file containing target domains, one per line. (Used for batch mode)")
    ):
        """Run subdomain scanner"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="Subdomain Scanner")
        logger.info(f"Running subdomain scanner on {target or 'multiple targets'}")
        
        # Set performance parameters
        scan_mode = 'api_only' if api_only else 'bruteforce_only' if bruteforce_only else 'hybrid'
        
        # Create args object for compatibility
        import json
        class Args:
            def __init__(self):
                self.command = command
                self.target = target
                self.scan_mode = scan_mode
                self.rate_limit = rate_limit
                self.dns_timeout = dns_timeout
                self.dns_threads = dns_threads
                self.api_keys = json.loads(api_keys) if api_keys else {}
                self.proxy_type = proxy_type
                self.proxy_host = proxy_host
                self.proxy_port = proxy_port
                self.wordlist = wordlist
                self.output_formats = output_formats
                self.file = file
        
        args = Args()
        asyncio.run(subdomain.main_menu(args))


    # CRAWLER Module
    @app.command("crawler", help="Web Crawler: Crawls websites to discover pages, links, and resources.")
    def crawler_cmd(
        command: str = typer.Argument(..., help="Subcommand: single or batch"),
        url: Optional[str] = typer.Option(None, "--url", help="URL to start crawling from (e.g., https://example.com)"),
        depth: int = typer.Option(3, "--depth", help="Maximum depth to crawl from the starting URL. Default: 3."),
        concurrency: int = typer.Option(10, "--concurrency", help="Number of concurrent requests to make during crawling. Default: 10."),
        max_urls: int = typer.Option(100, "--max-urls", help="Maximum number of unique URLs to crawl. Default: 100."),
        js_render: bool = typer.Option(False, "--js-render", help="Enable JavaScript rendering for pages to discover dynamically loaded content."),
        no_robots: bool = typer.Option(False, "--no-robots", help="Ignore robots.txt directives during crawling."),
        output: Optional[str] = typer.Option(None, "--output", help="Output format for crawl results. Options: 'json' or 'csv'."),
        file: Optional[str] = typer.Option(None, "--file", help="Path to a file containing URLs to crawl, one per line. (Used for batch mode)"),
        output_file: Optional[str] = typer.Option(None, "--output-file", help="File path to save the crawl results to. (Used for batch mode)")
    ):
        """Run website crawler"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="Website Crawler")
        logger.info(f"Running crawler")
        
        # Create args object for compatibility
        class Args:
            def __init__(self):
                self.command = command
                self.url = url
                self.depth = depth
                self.concurrency = concurrency
                self.max_urls = max_urls
                self.js_render = js_render
                self.no_robots = no_robots
                self.output = output
                self.file = file
                self.output_file = output_file
        
        args = Args()
        asyncio.run(crawler_utils.main(args))


    # HEADERS Module
    @app.command("headers", help="Header Audit: Audits HTTP security headers of web applications.")
    def headers_cmd(
        command: str = typer.Argument(..., help="Subcommand: single or batch"),
        url: Optional[str] = typer.Option(None, "--url", help="URL to audit (e.g., https://example.com)"),
        verbose: bool = typer.Option(False, "--verbose", help="Enable verbose mode to display detailed header information."),
        allow_private: bool = typer.Option(False, "--allow-private", help="Allow auditing of private IP addresses (e.g., localhost, internal networks)."),
        timeout: int = typer.Option(15, "--timeout", help="Request timeout in seconds. Default: 15."),
        file: Optional[str] = typer.Option(None, "--file", help="Path to a file containing URLs to audit, one per line. (Used for batch mode)")
    ):
        """Run header audit"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="Headers Audit")
        logger.info(f"Running headers audit on {url or 'multiple targets'}")
        
        # Create args object for compatibility
        class Args:
            def __init__(self):
                self.command = command
                self.url = url
                self.verbose = verbose
                self.allow_private = allow_private
                self.timeout = timeout
                self.file = file
        
        args = Args()
        header_audit.HeaderAuditor().run(args)


    # DIRBRUTE Module
    @app.command("dirbrute", help="Dirbrute: Directory and file brute-forcer for web applications.")
    def dirbrute_cmd(
        url: str = typer.Option(..., "--url", help="Base URL to brute force (e.g., https://example.com)"),
        wordlist: str = typer.Option("wordlists/directory-brute.txt", "--wordlist", help="Path to wordlist file. Default: wordlists/directory-brute.txt"),
        threads: int = typer.Option(10, "--threads", help="Number of concurrent threads. Default: 10."),
        extensions: str = typer.Option(".php,.html,.js,.css,.txt,.zip,.bak,.sql", "--extensions", help="Comma-separated list of extensions to try. Default: .php,.html,.js,.css,.txt,.zip,.bak,.sql"),
        status_codes: str = typer.Option("200,204,301,302,403", "--status-codes", help="Comma-separated list of status codes to consider as valid. Default: 200,204,301,302,403"),
        timeout: int = typer.Option(10, "--timeout", help="Request timeout in seconds. Default: 10."),
        delay: float = typer.Option(0.0, "--delay", help="Delay between requests in seconds. Default: 0.0"),
        output: Optional[str] = typer.Option(None, "--output", help="Output file to save results to."),
        verbose: bool = typer.Option(False, "--verbose", help="Enable verbose output.")
    ):
        """Run directory brute-forcer"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="Dirbruteforcer")
        logger.info(f"Running directory brute forcer on {url}")
        
        # Create args object for compatibility
        class Args:
            def __init__(self):
                self.url = url
                self.wordlist = wordlist
                self.threads = threads
                self.extensions = extensions
                self.status_codes = status_codes
                self.timeout = timeout
                self.delay = delay
                self.output = output
                self.verbose = verbose
        
        args = Args()
        dir_bruteforcer.main(args)


    # SSLINSPECT Module
    @app.command("sslinspect", help="SSLInspect: SSL/TLS Certificate Inspector")
    def sslinspect_cmd(
        target: str = typer.Option(..., "--target", help="Target host and port to inspect (e.g., example.com:443)"),
        export: str = typer.Option("json", "--export", help="Export format: json or txt. Default: json"),
        verbose: bool = typer.Option(False, "--verbose", help="Enable verbose output.")
    ):
        """Run SSL/TLS inspector"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="SSL/TLS Inspector")
        logger.info(f"Running SSL/TLS inspection on {target}")
        ssl_inspector.run_ssl_inspector(target, export, verbose)


    # CORSTEST Module
    @app.command("corstest", help="CORS Test: Cross-Origin Resource Sharing (CORS) Misconfiguration Auditor")
    def corstest_cmd(
        url: str = typer.Option(..., "--url", help="Target URL to test CORS configuration"),
        export: str = typer.Option("json", "--export", help="Export format: json or txt. Default: json"),
        verbose: bool = typer.Option(False, "--verbose", help="Enable verbose output."),
        custom_origin: Optional[str] = typer.Option(None, "--custom-origin", help="Custom origin header to test")
    ):
        """Run CORS test"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="CORS Tester")
        logger.info(f"Running CORS test on {url}")
        cors_scan.main(url, export, verbose, custom_origin)


    # SMUGGLER Module
    @app.command("smuggler", help="HTTP Request Smuggling Tester")
    def smuggler_cmd(
        url: str = typer.Option(..., "--url", help="Target URL to test for HTTP smuggling"),
        port: int = typer.Option(80, "--port", help="Target port. Default: 80"),
        method: str = typer.Option("GET", "--method", help="HTTP method to use. Default: GET"),
        verbose: bool = typer.Option(False, "--verbose", help="Enable verbose output.")
    ):
        """Run HTTP smuggling test"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="HTTP Desync Attack Tester")
        logger.info(f"Running HTTP desync test on {url}")
        main_runner.run(url, port, method, verbose)


    # TRACEPULSE Module
    @app.command("tracepulse", help="Tracepulse: Network Traceroute Utility")
    def tracepulse_cmd(
        destination: str = typer.Option(..., "--destination", help="Target host or IP address to trace"),
        protocol: str = typer.Option("icmp", "--protocol", help="Protocol to use for tracing: icmp, tcp, or udp. Default: icmp"),
        max_hops: int = typer.Option(30, "--max-hops", help="Maximum number of hops. Default: 30"),
        port: int = typer.Option(33434, "--port", help="Target port for TCP/UDP tracing. Default: 33434")
    ):
        """Run network traceroute"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="Tracepulse")
        logger.info(f"Running tracepulse on {destination}")
        tracepulse.main(destination, protocol, max_hops, port)


    # JS-CRAWLER Module
    @app.command("js-crawler", help="JS Crawler: JavaScript File Crawler and Endpoint Extractor")
    def jscrawler_cmd(
        url: str = typer.Option(..., "--url", help="Target URL to crawl for JavaScript files"),
        output: Optional[str] = typer.Option(None, "--output", help="Output file to save results to"),
        depth: int = typer.Option(3, "--depth", help="Maximum depth to crawl. Default: 3"),
        selenium: bool = typer.Option(False, "--selenium", help="Use Selenium for dynamic content extraction"),
        extensions: str = typer.Option(".js", "--extensions", help="File extensions to look for. Default: .js")
    ):
        """Run JS crawler"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner("JS Crawler")
        logger.info(f"Running JS crawler on {url}")
        jscrawler.main(url, output, depth, selenium, extensions)


    # PY-OBFUSCATOR Module
    @app.command("py-obfuscator", help="Python Code Obfuscator")
    def pyobfuscator_cmd(
        input: str = typer.Option(..., "--input", help="Input Python file to obfuscate"),
        output: Optional[str] = typer.Option(None, "--output", help="Output file path for obfuscated code"),
        level: int = typer.Option(2, "--level", help="Obfuscation level (1-3). Higher is more obfuscated. Default: 2"),
        rename_vars: bool = typer.Option(True, "--rename-vars", help="Rename variables. Default: True"),
        rename_funcs: bool = typer.Option(True, "--rename-funcs", help="Rename functions. Default: True"),
        flow_obfuscation: bool = typer.Option(True, "--flow-obfuscation", help="Apply flow obfuscation. Default: True")
    ):
        """Run Python obfuscator"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner("Py Obfuscator")
        logger.info(f"Running Python obfuscator on {input}")
        py_obfuscator.main(input, output, level, rename_vars, rename_funcs, flow_obfuscation)