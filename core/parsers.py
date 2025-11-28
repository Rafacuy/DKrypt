#!/usr/bin/env python3

import typer
import asyncio
import json
import argparse
from typing import Optional
from rich.console import Console
from urllib.parse import urlparse

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


class ArgumentValidator:
    @staticmethod
    def validate_url(url: str) -> bool:
        try:
            result = urlparse(url)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except:
            return False
    
    @staticmethod
    def validate_port(port: int) -> bool:
        return 1 <= port <= 65535
    
    @staticmethod
    def validate_positive_int(value: int) -> bool:
        return value > 0
    
    @staticmethod
    def validate_choice(value: str, choices: list) -> bool:
        return value in choices


def create_parser():
    """
    Create a minimal argparse parser for backward compatibility with interactive CLI.
    Note: This function is deprecated. Use Typer directly instead.
    """
    parser = argparse.ArgumentParser(
        prog="dkrypt",
        description="DKrypt - Advanced Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', help='Available modules', metavar='MODULE')
    
    # SQLI Module
    sqli_parser = subparsers.add_parser('sqli', help='SQL Injection Scanner')
    sqli_parser.add_argument('--url', required=True, help='Target URL')
    sqli_parser.add_argument('--test-forms', action='store_true', help='Test POST forms')
    sqli_parser.add_argument('--test-headers', action='store_true', help='Test HTTP headers')
    sqli_parser.add_argument('--test-apis', action='store_true', help='Test API endpoints')
    sqli_parser.add_argument('--export', default='html', choices=['html', 'csv', 'none'], help='Export format')
    
    # XSS Module
    xss_parser = subparsers.add_parser('xss', help='XSS Scanner')
    xss_parser.add_argument('--url', required=True, help='Target URL')
    xss_parser.add_argument('--threads', type=int, default=20, help='Concurrent threads')
    xss_parser.add_argument('--rate-limit', type=int, default=5, help='Requests per second')
    xss_parser.add_argument('--max-payloads', type=int, default=15, help='Max payloads')
    xss_parser.add_argument('--batch-size', type=int, default=100, help='Batch size')
    xss_parser.add_argument('--smart-mode', action='store_true', help='Smart mode')
    xss_parser.add_argument('--stealth-mode', action='store_true', help='Stealth mode')
    xss_parser.add_argument('--test-headers', action='store_true', help='Test headers')
    xss_parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    # GRAPHQL Module
    graphql_parser = subparsers.add_parser('graphql', help='GraphQL Introspector')
    graphql_parser.add_argument('--url', required=True, help='GraphQL endpoint URL')
    graphql_parser.add_argument('--headers', default='{}', help='Custom headers as JSON')
    graphql_parser.add_argument('--timeout', type=int, default=30, help='Request timeout')
    graphql_parser.add_argument('--export', default='json,csv,txt', help='Export formats')
    graphql_parser.add_argument('--output', help='Output filename prefix')
    graphql_parser.add_argument('--verbose', action='store_true', help='Verbose output')
    graphql_parser.add_argument('--export-raw', action='store_true', help='Export raw response')
    graphql_parser.add_argument('--no-header-factory', action='store_true', help='Disable HeaderFactory')
    graphql_parser.add_argument('--header-pool-size', type=int, help='HeaderFactory pool size')
    graphql_parser.add_argument('--rotate-headers', action='store_true', help='Rotate headers')
    
    # PORTSCANNER Module
    portscanner_parser = subparsers.add_parser('portscanner', help='Port Scanner')
    portscanner_parser.add_argument('command', help='Subcommand: single or batch')
    portscanner_parser.add_argument('--target', help='Target host')
    portscanner_parser.add_argument('--ports', default='1-1024', help='Ports to scan')
    portscanner_parser.add_argument('--scan-type', default='SYN', choices=['SYN', 'CON', 'UDP'], help='Scan type')
    portscanner_parser.add_argument('--timing', default='normal', help='Timing profile')
    portscanner_parser.add_argument('--service-detection', action='store_true', help='Service detection')
    portscanner_parser.add_argument('--os-detection', action='store_true', help='OS detection')
    portscanner_parser.add_argument('--script-scan', default='none', help='NSE scan')
    portscanner_parser.add_argument('--custom-args', default='', help='Custom NMAP args')
    portscanner_parser.add_argument('--verbosity', type=int, default=1, help='Verbosity level')
    portscanner_parser.add_argument('--output', default='no', help='Output format')
    portscanner_parser.add_argument('--file', help='File with targets')
    
    # WAFTESTER Module
    waftester_parser = subparsers.add_parser('waftester', help='WAF Bypass Tester')
    waftester_parser.add_argument('--url', required=True, help='Target URL')
    waftester_parser.add_argument('--method', default='GET', help='HTTP method')
    waftester_parser.add_argument('--packs', help='Header packs')
    waftester_parser.add_argument('--custom-headers', help='Custom headers as JSON')
    waftester_parser.add_argument('--concurrency', type=int, default=10, help='Concurrent requests')
    waftester_parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    waftester_parser.add_argument('--jitter', type=float, default=0.1, help='Delay')
    waftester_parser.add_argument('--verify-tls', action='store_true', help='Verify TLS')
    waftester_parser.add_argument('--profile', help='Profile name')
    waftester_parser.add_argument('--export', default='both', help='Export format')
    
    # SUBDOMAIN Module
    subdomain_parser = subparsers.add_parser('subdomain', help='Subdomain Scanner')
    subdomain_parser.add_argument('command', help='Subcommand: single or batch')
    subdomain_parser.add_argument('--target', help='Target domain')
    subdomain_parser.add_argument('--api-only', action='store_true', help='Use only API')
    subdomain_parser.add_argument('--bruteforce-only', action='store_true', help='Use only bruteforce')
    subdomain_parser.add_argument('--rate-limit', type=int, default=200, help='DNS queries rate')
    subdomain_parser.add_argument('--dns-timeout', type=int, default=2, help='DNS timeout')
    subdomain_parser.add_argument('--dns-threads', type=int, default=200, help='DNS threads')
    subdomain_parser.add_argument('--api-keys', help='API keys as JSON')
    subdomain_parser.add_argument('--proxy-type', help='Proxy type')
    subdomain_parser.add_argument('--proxy-host', help='Proxy host')
    subdomain_parser.add_argument('--proxy-port', type=int, help='Proxy port')
    subdomain_parser.add_argument('--wordlist', default='wordlists/subdomain.txt', help='Wordlist')
    subdomain_parser.add_argument('--output-formats', default='json,csv,txt', help='Output formats')
    subdomain_parser.add_argument('--file', help='File with targets')
    
    # CRAWLER Module
    crawler_parser = subparsers.add_parser('crawler', help='Website Crawler')
    crawler_parser.add_argument('command', help='Subcommand: single or batch')
    crawler_parser.add_argument('--url', help='Starting URL')
    crawler_parser.add_argument('--depth', type=int, default=3, help='Crawl depth')
    crawler_parser.add_argument('--concurrency', type=int, default=10, help='Concurrent requests')
    crawler_parser.add_argument('--max-urls', type=int, default=100, help='Max URLs')
    crawler_parser.add_argument('--js-render', action='store_true', help='JS rendering')
    crawler_parser.add_argument('--no-robots', action='store_true', help='Ignore robots.txt')
    crawler_parser.add_argument('--output', help='Output format')
    crawler_parser.add_argument('--file', help='File with URLs')
    crawler_parser.add_argument('--output-file', help='Output file path')
    
    # HEADERS Module
    headers_parser = subparsers.add_parser('headers', help='Security Header Audit')
    headers_parser.add_argument('command', help='Subcommand: single or batch')
    headers_parser.add_argument('--url', help='Target URL')
    headers_parser.add_argument('--verbose', action='store_true', help='Verbose output')
    headers_parser.add_argument('--allow-private', action='store_true', help='Allow private IPs')
    headers_parser.add_argument('--timeout', type=int, default=15, help='Request timeout')
    headers_parser.add_argument('--file', help='File with URLs')
    
    # DIRBRUTE Module
    dirbrute_parser = subparsers.add_parser('dirbrute', help='Directory Bruteforcer')
    dirbrute_parser.add_argument('--url', required=True, help='Base URL')
    dirbrute_parser.add_argument('--wordlist', default='wordlists/directory-brute.txt', help='Wordlist')
    dirbrute_parser.add_argument('--threads', type=int, default=10, help='Threads')
    dirbrute_parser.add_argument('--extensions', default='.php,.html,.js,.css,.txt,.zip,.bak,.sql', help='Extensions')
    dirbrute_parser.add_argument('--status-codes', default='200,204,301,302,403', help='Status codes')
    dirbrute_parser.add_argument('--timeout', type=int, default=10, help='Timeout')
    dirbrute_parser.add_argument('--delay', type=float, default=0.0, help='Delay')
    dirbrute_parser.add_argument('--export', help='Export report to file')
    dirbrute_parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    # SSLINSPECT Module
    sslinspect_parser = subparsers.add_parser('sslinspect', help='SSL/TLS Inspector')
    sslinspect_parser.add_argument('--target', required=True, help='Target host:port')
    sslinspect_parser.add_argument('--export', default='json', choices=['json', 'txt'], help='Export format')
    sslinspect_parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    # CORSTEST Module
    corstest_parser = subparsers.add_parser('corstest', help='CORS Misconfiguration Auditor')
    corstest_parser.add_argument('--url', required=True, help='Target URL')
    corstest_parser.add_argument('--export', default='json', choices=['json', 'txt'], help='Export format')
    corstest_parser.add_argument('--verbose', action='store_true', help='Verbose output')
    corstest_parser.add_argument('--custom-origin', help='Custom origin header')
    
    # SMUGGLER Module
    smuggler_parser = subparsers.add_parser('smuggler', help='HTTP Request Smuggling Tester')
    smuggler_parser.add_argument('--url', required=True, help='Target URL')
    smuggler_parser.add_argument('--port', type=int, default=80, help='Target port')
    smuggler_parser.add_argument('--method', default='GET', choices=['GET', 'POST'], help='HTTP method')
    smuggler_parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    # TRACEPULSE Module
    tracepulse_parser = subparsers.add_parser('tracepulse', help='Network Traceroute Utility')
    tracepulse_parser.add_argument('--destination', required=True, help='Target host/IP')
    tracepulse_parser.add_argument('--protocol', default='icmp', choices=['icmp', 'tcp', 'udp'], help='Protocol')
    tracepulse_parser.add_argument('--max-hops', type=int, default=30, help='Max hops')
    tracepulse_parser.add_argument('--port', type=int, default=33434, help='Target port')
    
    # JS-CRAWLER Module
    jscrawler_parser = subparsers.add_parser('js-crawler', help='JS Crawler')
    jscrawler_parser.add_argument('--url', required=True, help='Target URL')
    jscrawler_parser.add_argument('--output', help='Output file')
    jscrawler_parser.add_argument('--depth', type=int, default=3, help='Crawl depth')
    jscrawler_parser.add_argument('--selenium', action='store_true', help='Use Selenium')
    jscrawler_parser.add_argument('--extensions', default='.js', help='File extensions')
    
    # PY-OBFUSCATOR Module
    pyobfuscator_parser = subparsers.add_parser('py-obfuscator', help='Python Code Obfuscator')
    pyobfuscator_parser.add_argument('--input', required=True, help='Input Python file')
    pyobfuscator_parser.add_argument('--output', help='Output file')
    pyobfuscator_parser.add_argument('--level', type=int, default=2, choices=range(1, 4), help='Obfuscation level')
    pyobfuscator_parser.add_argument('--rename-vars', action='store_true', default=True, help='Rename variables')
    pyobfuscator_parser.add_argument('--rename-funcs', action='store_true', default=True, help='Rename functions')
    pyobfuscator_parser.add_argument('--flow-obfuscation', action='store_true', default=True, help='Flow obfuscation')
    
    return parser


def register_commands(app: typer.Typer):
    """Register all module commands with the main Typer app"""
    
    # SQLI Module
    @app.command("sqli", help="SQL Injection Scanner: Detects SQL injection vulnerabilities in web applications.")
    def sqli_cmd(
        url: str = typer.Option(..., "--url", help="Target URL to scan for SQL injection (e.g., https://example.com/vulnerable?id=1)"),
        test_forms: bool = typer.Option(False, "--test-forms", help="Enable testing of POST forms for SQL injection"),
        test_headers: bool = typer.Option(False, "--test-headers", help="Enable testing of HTTP headers for SQL injection"),
        test_apis: bool = typer.Option(False, "--test-apis", help="Enable testing of API endpoints for SQL injection"),
        export: str = typer.Option("html", "--export", help="Export format: html, csv, or none")
    ):
        from core.utils import header_banner
        from core.logger import logger
        
        if not ArgumentValidator.validate_url(url):
            console.print("[red]✗ Invalid URL format. Use http:// or https://[/red]")
            raise typer.Exit(code=1)
        
        if export not in ['html', 'csv', 'none']:
            console.print("[red]✗ Export format must be html, csv, or none[/red]")
            raise typer.Exit(code=1)
        
        header_banner(tool_name="SQLi scanner")
        logger.info(f"Running SQLi scanner on {url}")
        sqli_scan.run_sqli_scan(url, test_forms, test_headers, test_apis, export)


    # XSS Module
    @app.command("xss", help="XSS Scanner: Detects Cross-Site Scripting vulnerabilities in web applications.")
    def xss_cmd(
        url: str = typer.Option(..., "--url", help="Target URL to scan for XSS"),
        threads: int = typer.Option(20, "--threads", help="Number of concurrent threads"),
        rate_limit: int = typer.Option(5, "--rate-limit", help="Requests per second"),
        max_payloads: int = typer.Option(15, "--max-payloads", help="Maximum XSS payloads per context"),
        batch_size: int = typer.Option(100, "--batch-size", help="Payloads per batch"),
        smart_mode: bool = typer.Option(False, "--smart-mode", help="Enable smart mode"),
        stealth_mode: bool = typer.Option(False, "--stealth-mode", help="Enable stealth mode"),
        test_headers: bool = typer.Option(False, "--test-headers", help="Test HTTP headers"),
        verbose: bool = typer.Option(False, "--verbose", help="Verbose output")
    ):
        from core.utils import header_banner
        from core.logger import logger
        
        if not ArgumentValidator.validate_url(url):
            console.print("[red]✗ Invalid URL format. Use http:// or https://[/red]")
            raise typer.Exit(code=1)
        
        if not ArgumentValidator.validate_positive_int(threads):
            console.print("[red]✗ Threads must be a positive integer[/red]")
            raise typer.Exit(code=1)
        
        if not ArgumentValidator.validate_positive_int(rate_limit):
            console.print("[red]✗ Rate limit must be a positive integer[/red]")
            raise typer.Exit(code=1)
        
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
        url: str = typer.Option(..., "--url", help="GraphQL endpoint URL"),
        headers: str = typer.Option("{}", "--headers", help="Custom headers as JSON"),
        timeout: int = typer.Option(30, "--timeout", help="Request timeout in seconds"),
        export: str = typer.Option("json,csv,txt", "--export", help="Export formats (comma-separated)"),
        output: Optional[str] = typer.Option(None, "--output", help="Output filename prefix"),
        verbose: bool = typer.Option(False, "--verbose", help="Verbose output"),
        export_raw: bool = typer.Option(False, "--export-raw", help="Export raw response on failure"),
        no_header_factory: bool = typer.Option(False, "--no-header-factory", help="Disable HeaderFactory"),
        header_pool_size: Optional[int] = typer.Option(None, "--header-pool-size", help="HeaderFactory pool size"),
        rotate_headers: bool = typer.Option(False, "--rotate-headers", help="Enable header rotation")
    ):
        from core.utils import header_banner
        from core.logger import logger
        
        if not ArgumentValidator.validate_url(url):
            console.print("[red]✗ Invalid URL format. Use http:// or https://[/red]")
            raise typer.Exit(code=1)
        
        if timeout <= 0:
            console.print("[red]✗ Timeout must be positive[/red]")
            raise typer.Exit(code=1)
        
        try:
            json.loads(headers)
        except json.JSONDecodeError:
            console.print("[red]✗ Headers must be valid JSON[/red]")
            raise typer.Exit(code=1)
        
        header_banner(tool_name="GraphQL Introspection")
        logger.info(f"Running GraphQL introspection on {url}")
        
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
        target: Optional[str] = typer.Option(None, "--target", help="Target host to scan"),
        ports: str = typer.Option("1-1024", "--ports", help="Ports to scan"),
        scan_type: str = typer.Option("SYN", "--scan-type", help="Scan type: SYN, CON, or UDP"),
        timing: str = typer.Option("normal", "--timing", help="Timing profile"),
        service_detection: bool = typer.Option(False, "--service-detection", help="Enable service detection"),
        os_detection: bool = typer.Option(False, "--os-detection", help="Enable OS detection"),
        script_scan: str = typer.Option("none", "--script-scan", help="NSE scan: default, vuln, or none"),
        custom_args: str = typer.Option("", "--custom-args", help="Custom NMAP arguments"),
        verbosity: int = typer.Option(1, "--verbosity", help="Verbosity level (0-2)"),
        output: str = typer.Option("no", "--output", help="Output format: json, csv, or no"),
        file: Optional[str] = typer.Option(None, "--file", help="File with target hosts")
    ):
        """Run port scanner"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="Port Scanner")
        logger.info("Running port scanner")
        
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
        url: str = typer.Option(..., "--url", help="Target URL"),
        method: str = typer.Option("GET", "--method", help="HTTP method"),
        packs: Optional[str] = typer.Option(None, "--packs", help="Header packs to use"),
        custom_headers: Optional[str] = typer.Option(None, "--custom-headers", help="Custom headers as JSON"),
        concurrency: int = typer.Option(10, "--concurrency", help="Concurrent requests"),
        timeout: int = typer.Option(10, "--timeout", help="Request timeout"),
        jitter: float = typer.Option(0.1, "--jitter", help="Delay between requests"),
        verify_tls: bool = typer.Option(False, "--verify-tls", help="Verify TLS certificates"),
        profile: Optional[str] = typer.Option(None, "--profile", help="Profile name"),
        export: str = typer.Option("both", "--export", help="Export format")
    ):
        """Run WAF tester"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="WAF Tester")
        logger.info(f"Running WAF tester on {url}")
        
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
        app_waf = tui.WAFTUI()
        app_waf.run(args)


    # SUBDOMAIN Module
    @app.command("subdomain", help="Subdomain Enumeration: Advanced subdomain discovery with multiple scan modes.")
    def subdomain_cmd(
        command: str = typer.Argument(..., help="Subcommand: single or batch"),
        target: Optional[str] = typer.Option(None, "--target", help="Target domain"),
        api_only: bool = typer.Option(False, "--api-only", help="Use only API sources"),
        bruteforce_only: bool = typer.Option(False, "--bruteforce-only", help="Use only wordlist bruteforce"),
        rate_limit: int = typer.Option(200, "--rate-limit", help="Concurrent DNS queries"),
        dns_timeout: int = typer.Option(2, "--dns-timeout", help="DNS timeout in seconds"),
        dns_threads: int = typer.Option(200, "--dns-threads", help="DNS thread pool size"),
        api_keys: Optional[str] = typer.Option(None, "--api-keys", help="API keys as JSON"),
        proxy_type: Optional[str] = typer.Option(None, "--proxy-type", help="Proxy type"),
        proxy_host: Optional[str] = typer.Option(None, "--proxy-host", help="Proxy host"),
        proxy_port: Optional[int] = typer.Option(None, "--proxy-port", help="Proxy port"),
        wordlist: str = typer.Option("wordlists/subdomain.txt", "--wordlist", help="Wordlist file"),
        output_formats: str = typer.Option("json,csv,txt", "--output-formats", help="Output formats"),
        file: Optional[str] = typer.Option(None, "--file", help="File with target domains")
    ):
        """Run subdomain scanner"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="Subdomain Scanner")
        logger.info(f"Running subdomain scanner on {target or 'multiple targets'}")
        
        scan_mode = 'api_only' if api_only else 'bruteforce_only' if bruteforce_only else 'hybrid'
        
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
        url: Optional[str] = typer.Option(None, "--url", help="Starting URL"),
        depth: int = typer.Option(3, "--depth", help="Crawl depth"),
        concurrency: int = typer.Option(10, "--concurrency", help="Concurrent requests"),
        max_urls: int = typer.Option(100, "--max-urls", help="Maximum URLs to crawl"),
        js_render: bool = typer.Option(False, "--js-render", help="Enable JavaScript rendering"),
        no_robots: bool = typer.Option(False, "--no-robots", help="Ignore robots.txt"),
        output: Optional[str] = typer.Option(None, "--output", help="Output format"),
        file: Optional[str] = typer.Option(None, "--file", help="File with URLs"),
        output_file: Optional[str] = typer.Option(None, "--output-file", help="Output file path")
    ):
        """Run website crawler"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="Website Crawler")
        logger.info("Running crawler")
        
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
        url: Optional[str] = typer.Option(None, "--url", help="Target URL"),
        verbose: bool = typer.Option(False, "--verbose", help="Verbose output"),
        allow_private: bool = typer.Option(False, "--allow-private", help="Allow private IPs"),
        timeout: int = typer.Option(15, "--timeout", help="Request timeout"),
        file: Optional[str] = typer.Option(None, "--file", help="File with URLs")
    ):
        """Run header audit"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="Headers Audit")
        logger.info(f"Running headers audit on {url or 'multiple targets'}")
        
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
        url: str = typer.Option(..., "--url", help="Base URL"),
        wordlist: str = typer.Option("wordlists/directory-brute.txt", "--wordlist", help="Wordlist file"),
        threads: int = typer.Option(10, "--threads", help="Concurrent threads"),
        extensions: str = typer.Option(".php,.html,.js,.css,.txt,.zip,.bak,.sql", "--extensions", help="File extensions"),
        status_codes: str = typer.Option("200,204,301,302,403", "--status-codes", help="Valid status codes"),
        timeout: int = typer.Option(10, "--timeout", help="Request timeout"),
        delay: float = typer.Option(0.0, "--delay", help="Delay between requests"),
        output: Optional[str] = typer.Option(None, "--output", help="Output file"),
        verbose: bool = typer.Option(False, "--verbose", help="Verbose output")
    ):
        """Run directory brute-forcer"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="Dirbruteforcer")
        logger.info(f"Running directory brute forcer on {url}")
        
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
        target: str = typer.Option(..., "--target", help="Target host:port"),
        export: str = typer.Option("json", "--export", help="Export format: json or txt"),
        verbose: bool = typer.Option(False, "--verbose", help="Verbose output")
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
        url: str = typer.Option(..., "--url", help="Target URL"),
        export: str = typer.Option("json", "--export", help="Export format"),
        verbose: bool = typer.Option(False, "--verbose", help="Verbose output"),
        custom_origin: Optional[str] = typer.Option(None, "--custom-origin", help="Custom origin header")
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
        url: str = typer.Option(..., "--url", help="Target URL"),
        port: int = typer.Option(80, "--port", help="Target port"),
        method: str = typer.Option("GET", "--method", help="HTTP method"),
        verbose: bool = typer.Option(False, "--verbose", help="Verbose output")
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
        destination: str = typer.Option(..., "--destination", help="Target host/IP"),
        protocol: str = typer.Option("icmp", "--protocol", help="Protocol: icmp, tcp, or udp"),
        max_hops: int = typer.Option(30, "--max-hops", help="Maximum hops"),
        port: int = typer.Option(33434, "--port", help="Target port")
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
        url: str = typer.Option(..., "--url", help="Target URL"),
        output: Optional[str] = typer.Option(None, "--output", help="Output file"),
        depth: int = typer.Option(3, "--depth", help="Crawl depth"),
        selenium: bool = typer.Option(False, "--selenium", help="Use Selenium"),
        extensions: str = typer.Option(".js", "--extensions", help="File extensions"),
        user_agent: str = typer.Option("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36", "--user-agent", help="User agent string for requests")
    ):
        """Run JS crawler"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="JS Crawler")
        logger.info(f"Running JS crawler on {url}")
        jscrawler.main(url=url, output=output, depth=depth, selenium=selenium, extensions=extensions, user_agent=user_agent)


    # PY-OBFUSCATOR Module
    @app.command("py-obfuscator", help="Python Code Obfuscator")
    def pyobfuscator_cmd(
        input: str = typer.Option(..., "--input", help="Input Python file"),
        output: Optional[str] = typer.Option(None, "--output", help="Output file"),
        level: int = typer.Option(2, "--level", help="Obfuscation level (1-3)"),
        rename_vars: bool = typer.Option(True, "--rename-vars", help="Rename variables"),
        rename_funcs: bool = typer.Option(True, "--rename-funcs", help="Rename functions"),
        flow_obfuscation: bool = typer.Option(True, "--flow-obfuscation", help="Apply flow obfuscation")
    ):
        """Run Python obfuscator"""
        from core.utils import header_banner
        from core.logger import logger
        header_banner(tool_name="Py Obfuscator")
        logger.info(f"Running Python obfuscator on {input}")
        py_obfuscator.main(input, output, level, rename_vars, rename_funcs, flow_obfuscation)
