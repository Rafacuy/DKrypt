# core/cli.py
import argparse
import sys
import asyncio
import json
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
from .utils import header_banner
from .banner import display_header

console = Console()

def create_parser():
    parser = argparse.ArgumentParser(
        description="""DKrypt - A penetration testing framework.
        Automate reconnaissance and vulnerability scanning with ease.
        
        Usage: python dkrypt.py <module> [options]
        
        Example:
            python dkrypt.py sqli --url https://example.com --test-forms
            python dkrypt.py subdomain single --target example.com
        """,
        formatter_class=argparse.RawTextHelpFormatter 
    )
    subparsers = parser.add_subparsers(
        dest="module",
        help="""Select a module to run. Use 'python dkrypt.py <module> --help' for module-specific options.
        
        Available modules:
        sqli          - SQL Injection Scanner
        xss           - Cross-Site Scripting Scanner
        portscanner   - Advanced Port Scanner (based on NMAP)
        waftester     - Web Application Firewall (WAF) Bypass Tester
        subdomain     - Subdomain Enumeration Tool
        crawler       - Comprehensive Web Crawler
        headers       - Security Header Auditor
        dirbrute      - Directory and File Bruteforcer
        sslinspect    - SSL/TLS Certificate Inspector
        corstest      - Cross-Origin Resource Sharing (CORS) Misconfiguration Auditor
        smuggler      - HTTP Request Smuggling Tester
        tracepulse    - Network Traceroute Utility
        js-crawler    - JavaScript File Crawler and Endpoint Extractor
        py-obfuscator - Python Code Obfuscator
        graphql       - GraphQL Introspection and Vulnerability Scanner
        """
    )

    # Add subparsers for each module
    add_sqli_parser(subparsers)
    add_xss_parser(subparsers)
    add_graphql_parser(subparsers)
    add_portscanner_parser(subparsers)
    add_waftester_parser(subparsers)
    add_subdomain_parser(subparsers)
    add_crawler_parser(subparsers)
    add_headers_parser(subparsers)
    add_dirbrute_parser(subparsers)
    add_sslinspect_parser(subparsers)
    add_corstest_parser(subparsers)
    add_smuggler_parser(subparsers)
    add_tracepulse_parser(subparsers)
    add_jscrawler_parser(subparsers)
    add_pyobfuscator_parser(subparsers)

    return parser

def run_cli():
    display_header()
    parser = create_parser()
    args = parser.parse_args()

    if args.module is None:
        parser.print_help()
        sys.exit(0)

    if args.module == "sqli":
        header_banner(tool_name="SQLi scanner")
        sqli_scan.run_sqli_scan(args.url, args.test_forms, args.test_headers, args.test_apis, args.export)
    elif args.module == "xss":
        header_banner(tool_name="XSS scanner")
        asyncio.run(scanner.run_xss_scan(args.url, args.threads, args.rate_limit, args.max_payloads, args.batch_size, args.smart_mode, args.stealth_mode, args.test_headers, args.verbose))
    elif args.module == "portscanner":
        header_banner(tool_name="Port Scanner")
        asyncio.run(port_scanner.main_menu(args))
    elif args.module == "waftester":
        header_banner(tool_name="WAF Tester")
        app = tui.WAFTUI()
        app.run(args)
    elif args.module == "subdomain":
        header_banner(tool_name="Subdomain Scanner")
        
        # Handle scan mode flags
        if hasattr(args, 'api_only') and args.api_only:
            args.scan_mode = 'api_only'
        elif hasattr(args, 'bruteforce_only') and args.bruteforce_only:
            args.scan_mode = 'bruteforce_only'  
        else:
            args.scan_mode = 'hybrid'  # Default hybrid mode
        
        # Set performance parameters
        if not hasattr(args, 'rate_limit'):
            args.rate_limit = 200
        if not hasattr(args, 'dns_timeout'):
            args.dns_timeout = 2
        if not hasattr(args, 'dns_threads'):
            args.dns_threads = 200
            
        # Parse API keys if provided
        api_keys = {}
        if hasattr(args, 'api_keys') and args.api_keys:
            try:
                api_keys = json.loads(args.api_keys)
            except json.JSONDecodeError:
                console.print("[red]Error: Invalid JSON format for API keys[/red]")
                return
        args.api_keys = api_keys
        
        # Parse output formats
        if hasattr(args, 'output_formats') and args.output_formats:
            output_formats = [fmt.strip().lower() for fmt in args.output_formats.split(',')]
            valid_formats = ['json', 'csv', 'txt']
            output_formats = [fmt for fmt in output_formats if fmt in valid_formats]
            if not output_formats:
                output_formats = ['json', 'csv', 'txt'] 
        else:
            output_formats = ['json', 'csv', 'txt']
        args.output_formats = output_formats
        
        # Validate proxy configuration
        if hasattr(args, 'proxy_type') and args.proxy_type and not hasattr(args, 'proxy_host'):
            console.print("[red]Error: --proxy-host is required when --proxy-type is specified[/red]")
            return
        
        asyncio.run(subdomain.main_menu(args))
    elif args.module == "crawler":
        header_banner(tool_name="Website Crawler")
        asyncio.run(crawler_utils.main(args))
    elif args.module == "headers":
        header_banner(tool_name="Headers Audit")
        header_audit.HeaderAuditor().run(args)
    elif args.module == "graphql":
        header_banner(tool_name="GraphQL Introspection")
        graphql_introspect.run_cli(args)    
    elif args.module == "dirbrute":
        header_banner(tool_name="Dirbruteforcer")
        dir_bruteforcer.main(args)
    elif args.module == "sslinspect":
        header_banner(tool_name="SSL/TLS Inspector")
        ssl_inspector.run_ssl_inspector(args)
    elif args.module == "corstest":
        header_banner(tool_name="CORS Tester")
        cors_scan.main(args)
    elif args.module == "smuggler":
        header_banner(tool_name="HTTP Desync Attack Tester")
        main_runner.run(args)
    elif args.module == "tracepulse":
        header_banner(tool_name="Tracepulse")
        tracepulse.main(args)
    elif args.module == "js-crawler":
        header_banner("JS Crawler")
        jscrawler.main(args)
    elif args.module == "py-obfuscator":
        header_banner("Py Obfuscator")
        py_obfuscator.main(args)   
    else:
        console.print(f"[red]Unknown module: {args.module}[/red]")

def add_sqli_parser(subparsers):
    parser = subparsers.add_parser(
        "sqli", 
        help="SQL Injection Scanner: Detects SQL injection vulnerabilities in web applications."
    )
    parser.add_argument(
        "--url", 
        help="Target URL to scan for SQL injection (e.g., https://example.com/vulnerable?id=1)", 
        required=True
    )
    parser.add_argument(
        "--test-forms", 
        help="Enable testing of POST forms for SQL injection. The scanner will attempt to find and inject into forms.", 
        action="store_true"
    )
    parser.add_argument(
        "--test-headers", 
        help="Enable testing of HTTP headers for SQL injection. Useful for blind SQLi in headers.", 
        action="store_true"
    )
    parser.add_argument(
        "--test-apis", 
        help="Enable testing of API endpoints for SQL injection. Requires the URL to point to an API endpoint.", 
        action="store_true"
    )
    parser.add_argument(
        "--export", 
        help="Specify the format for exporting scan results. Options: 'html', 'csv', or 'none'. Default is 'html'.", 
        default="html", 
        choices=["html", "csv", "none"]
    )

def add_xss_parser(subparsers):
    parser = subparsers.add_parser(
        "xss", 
        help="XSS Scanner: Detects Cross-Site Scripting vulnerabilities in web applications."
    )
    parser.add_argument(
        "--url", 
        help="Target URL to scan for XSS (e.g., https://example.com/search?query=test)", 
        required=True
    )
    parser.add_argument(
        "--threads", 
        help="Number of concurrent threads to use for scanning. Higher values can speed up the scan but may be detected by WAFs. Default: 20.", 
        type=int, 
        default=20
    )
    parser.add_argument(
        "--rate-limit", 
        help="Maximum number of requests per second to send. Helps in avoiding rate limiting by the target server. Default: 5.", 
        type=int, 
        default=5
    )
    parser.add_argument(
        "--max-payloads", 
        help="Maximum number of XSS payloads to test per context (e.g., per input field). Default: 15.", 
        type=int, 
        default=15
    )
    parser.add_argument(
        "--batch-size", 
        help="Number of payloads to send in a single batch. Default: 100.", 
        type=int, 
        default=100
    )
    parser.add_argument(
        "--smart-mode", 
        help="Enable smart mode for more intelligent payload generation and detection, reducing false positives.", 
        action="store_true"
    )
    parser.add_argument(
        "--stealth-mode", 
        help="Enable stealth mode to make the scan less detectable by WAFs and intrusion detection systems.", 
        action="store_true"
    )
    parser.add_argument(
        "--test-headers", 
        help="Test HTTP headers for XSS vulnerabilities. Useful for reflected XSS in headers.", 
        action="store_true"
    )
    parser.add_argument(
        "--verbose", 
        help="Enable verbose output to display detailed information during the scan.", 
        action="store_true"
    )
    
def add_graphql_parser(subparsers):
    parser = subparsers.add_parser(
        "graphql", 
        help="GraphQL endpoint analysis and vulnerability detection"
    )
    parser.add_argument(
        "--url", 
        help="GraphQL endpoint URL to introspect (e.g., https://example.com/graphql)", 
        required=True
    )
    parser.add_argument(
        "--headers", 
        help="Custom headers as JSON string (e.g., '{\"Authorization\": \"Bearer token\", \"X-API-Key\": \"key123\"}')", 
        default="{}"
    )
    parser.add_argument(
        "--timeout", 
        help="Request timeout in seconds. Higher values recommended for slow endpoints. Default: 30.", 
        type=int, 
        default=30
    )
    parser.add_argument(
        "--export", 
        help="Export formats (comma-separated): json,csv,txt. Default exports all formats for comprehensive analysis.", 
        default="json,csv,txt"
    )
    parser.add_argument(
        "--output", 
        help="Output filename prefix for exported results. If not specified, auto-generates based on target and timestamp."
    )
    parser.add_argument(
        "--verbose", 
        help="Display detailed results in console including all queries, mutations, and analysis details.", 
        action="store_true"
    )
    parser.add_argument(
        "--export-raw", 
        help="Export raw GraphQL response even on failure for manual analysis and debugging.", 
        action="store_true"
    )
    
    # HeaderFactory integration arguments
    parser.add_argument(
        "--no-header-factory", 
        help="Disable HeaderFactory and use basic static headers instead of realistic rotating headers.", 
        action="store_true"
    )
    parser.add_argument(
        "--header-pool-size", 
        help="Size of HeaderFactory pool for generating realistic browser headers. Larger pools provide more variety but use more memory. Default: uses config settings.", 
        type=int
    )
    parser.add_argument(
        "--rotate-headers", 
        help="Enable header rotation during requests to mimic different browser sessions and avoid detection.", 
        action="store_true"
    )

def add_portscanner_parser(subparsers):
    parser = subparsers.add_parser(
        "portscanner", 
        help="Port Scanner: Scans target hosts for open ports and services using NMAP."
    )
    port_subparsers = parser.add_subparsers(
        dest="command", 
        help="Port scanning commands. Use 'portscanner <command> --help' for more details."
    )

    # Single scan parser
    single_parser = port_subparsers.add_parser(
        "single", 
        help="Scan a single target host for open ports."
    )
    single_parser.add_argument(
        "--target", 
        help="Target host to scan (e.g., example.com or 192.168.1.1)", 
        required=True
    )
    single_parser.add_argument(
        "--ports", 
        help="Ports to scan (e.g., '1-1024', '80,443,8080', or 'all'). Default: 1-1024.", 
        default="1-1024"
    )
    single_parser.add_argument(
        "--scan-type", 
        help="Type of NMAP scan to perform. Options: 'SYN' (stealthy), 'CON' (connect), 'UDP'. Default: SYN.", 
        default="SYN", 
        choices=["SYN", "CON", "UDP"]
    )
    single_parser.add_argument(
        "--timing", 
        help="Timing profile for the scan. Options: 'paranoid', 'sneaky', 'polite', 'normal', 'aggressive', 'insane'. Default: normal.", 
        default="normal", 
        choices=["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"]
    )
    single_parser.add_argument(
        "--service-detection", 
        help="Enable service and version detection on open ports.", 
        action="store_true"
    )
    single_parser.add_argument(
        "--os-detection", 
        help="Enable operating system detection.", 
        action="store_true"
    )
    single_parser.add_argument(
        "--script-scan", 
        help="Perform an NMAP Scripting Engine (NSE) scan. Options: 'default' (safe scripts), 'vuln' (vulnerability scripts), or 'none'. Default: none.", 
        default="none", 
        choices=["default", "vuln", "none"]
    )
    single_parser.add_argument(
        "--custom-args", 
        help="Additional custom NMAP arguments to pass directly to NMAP (e.g., '-sV -O').", 
        default=""
    )
    single_parser.add_argument(
        "--verbosity", 
        help="Verbosity level of NMAP output (0=silent, 1=normal, 2=detailed). Default: 1.", 
        type=int, 
        default=1,
        choices=[0, 1, 2]
    )
    single_parser.add_argument(
        "--output", 
        help="Output format for scan results. Options: 'json', 'csv', or 'no' (no file output). Default: no.", 
        default="no", 
        choices=["json", "csv", "no"]
    )

    # Batch scan parser
    batch_parser = port_subparsers.add_parser(
        "batch", 
        help="Scan multiple targets listed in a file."
    )
    batch_parser.add_argument(
        "--file", 
        help="Path to a file containing target hosts, one per line.", 
        required=True
    )
    batch_parser.add_argument(
        "--ports", 
        help="Ports to scan (e.g., '1-1024', '80,443,8080', or 'all'). Default: 1-1024.", 
        default="1-1024"
    )
    batch_parser.add_argument(
        "--scan-type", 
        help="Type of NMAP scan to perform. Options: 'SYN' (stealthy), 'CON' (connect), 'UDP'. Default: SYN.", 
        default="SYN", 
        choices=["SYN", "CON", "UDP"]
    )
    batch_parser.add_argument(
        "--timing", 
        help="Timing profile for the scan. Options: 'paranoid', 'sneaky', 'polite', 'normal', 'aggressive', 'insane'. Default: normal.", 
        default="normal", 
        choices=["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"]
    )
    batch_parser.add_argument(
        "--service-detection", 
        help="Enable service and version detection on open ports.", 
        action="store_true"
    )
    batch_parser.add_argument(
        "--os-detection", 
        help="Enable operating system detection.", 
        action="store_true"
    )
    batch_parser.add_argument(
        "--script-scan", 
        help="Perform an NMAP Scripting Engine (NSE) scan. Options: 'default' (safe scripts), 'vuln' (vulnerability scripts), or 'none'. Default: none.", 
        default="none", 
        choices=["default", "vuln", "none"]
    )
    batch_parser.add_argument(
        "--custom-args", 
        help="Additional custom NMAP arguments to pass directly to NMAP (e.g., '-sV -O').", 
        default=""
    )
    batch_parser.add_argument(
        "--verbosity", 
        help="Verbosity level of NMAP output (0=silent, 1=normal, 2=detailed). Default: 1.", 
        type=int, 
        default=1,
        choices=[0, 1, 2]
    )
    batch_parser.add_argument(
        "--output", 
        help="Output format for scan results. Options: 'json', 'csv', or 'no' (no file output). Default: json.", 
        default="json", 
        choices=["json", "csv", "no"]
    )

def add_waftester_parser(subparsers):
    parser = subparsers.add_parser(
        "waftester", 
        help="WAF Bypass Tester: Tests Web Application Firewalls for bypass vulnerabilities."
    )
    parser.add_argument(
        "--url", 
        help="Target URL to test against the WAF (e.g., https://example.com/login)", 
        required=True
    )
    parser.add_argument(
        "--method", 
        help="HTTP method to use for requests (GET, POST, PUT, etc.). Default: GET.", 
        default="GET", 
        choices=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
    )
    parser.add_argument(
        "--packs", 
        help="Comma-separated list of header packs to use for WAF bypass testing (e.g., 'identity_spoof,tool_evasion')."
    )
    parser.add_argument(
        "--custom-headers", 
        help="JSON string of custom headers to include in requests (e.g., '{\"X-Custom-Header\": \"value\"}')."
    )
    parser.add_argument(
        "--concurrency", 
        help="Number of concurrent requests to send. Default: 10.", 
        type=int, 
        default=10
    )
    parser.add_argument(
        "--timeout", 
        help="Request timeout in seconds. Default: 10.", 
        type=int, 
        default=10
    )
    parser.add_argument(
        "--jitter", 
        help="Random delay between requests in seconds to avoid detection. Default: 0.1.", 
        type=float, 
        default=0.1
    )
    parser.add_argument(
        "--verify-tls", 
        help="Verify TLS certificates for HTTPS connections.", 
        action="store_true"
    )
    parser.add_argument(
        "--profile", 
        help="Name of the profile to load."
    )
    parser.add_argument(
        "--export", 
        help="Export format for test results. Options: 'json', 'csv', or 'both'. Default: both.", 
        default="both", 
        choices=["json", "csv", "both"]
    )

def add_subdomain_parser(subparsers):
    parser = subparsers.add_parser(
        "subdomain", 
        help="Subdomain Enumeration: Advanced subdomain discovery with multiple scan modes and performance optimization."
    )
    subdomain_subparsers = parser.add_subparsers(
        dest="command", 
        help="Subdomain enumeration commands. Use 'subdomain <command> --help' for more details."
    )

    # Single scan parser
    single_parser = subdomain_subparsers.add_parser(
        "single", 
        help="Enumerate subdomains for a single target domain using various scan modes."
    )
    single_parser.add_argument(
        "--target", 
        help="Target domain to enumerate subdomains for (e.g., example.com)", 
        required=True
    )
    
    # Scan mode flags (mutually exclusive)
    mode_group = single_parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--api-only", 
        help="Use only API sources for enumeration (fast, stealthy, less noisy)", 
        action="store_true"
    )
    mode_group.add_argument(
        "--bruteforce-only", 
        help="Use only wordlist bruteforce for enumeration (thorough, comprehensive)", 
        action="store_true"
    )
    
    # Performance settings
    single_parser.add_argument(
        "--rate-limit", 
        help="Number of concurrent DNS queries (recommended: 100-500 for large wordlists). Default: 200.", 
        type=int, 
        default=200
    )
    single_parser.add_argument(
        "--dns-timeout", 
        help="DNS timeout in seconds (lower = faster, higher = more reliable). Default: 2.", 
        type=int, 
        default=2
    )
    single_parser.add_argument(
        "--dns-threads", 
        help="DNS thread pool size for concurrent processing. Default: 200.", 
        type=int, 
        default=200
    )
    
    # API configuration
    single_parser.add_argument(
        "--api-keys", 
        help="JSON string of API keys for premium sources (e.g., '{\"virustotal\": \"your_api_key\"}'). Enables additional API sources.", 
        type=str
    )
    
    # Proxy configuration
    single_parser.add_argument(
        "--proxy-type", 
        help="Type of proxy to use for DNS resolution. Requires PySocks library.", 
        choices=["socks4", "socks5", "http"]
    )
    single_parser.add_argument(
        "--proxy-host", 
        help="Proxy host address (e.g., 127.0.0.1, proxy.example.com). Required if --proxy-type is specified."
    )
    single_parser.add_argument(
        "--proxy-port", 
        help="Proxy port number. If not specified, uses default ports (1080 for SOCKS, 8080 for HTTP).", 
        type=int
    )
    
    single_parser.add_argument(
        "--wordlist", 
        help="Path to custom wordlist file for subdomain brute-forcing. Default: wordlists/subdomain.txt.", 
        default="wordlists/subdomain.txt"
    )
    
    # Output configuration
    single_parser.add_argument(
        "--output-formats", 
        help="Comma-separated list of output formats to generate. Options: json,csv,txt. Default: json,csv,txt.", 
        default="json,csv,txt"
    )

    # Batch scan parser
    batch_parser = subdomain_subparsers.add_parser(
        "batch", 
        help="Enumerate subdomains for multiple targets listed in a file using various scan modes."
    )
    batch_parser.add_argument(
        "--file", 
        help="Path to file containing target domains, one per line.", 
        required=True
    )
    
    batch_mode_group = batch_parser.add_mutually_exclusive_group()
    batch_mode_group.add_argument(
        "--api-only", 
        help="Use only API sources for enumeration (fast, stealthy, less noisy)", 
        action="store_true"
    )
    batch_mode_group.add_argument(
        "--bruteforce-only", 
        help="Use only wordlist bruteforce for enumeration (thorough, comprehensive)", 
        action="store_true"
    )
    
    # Performance settings
    batch_parser.add_argument(
        "--rate-limit", 
        help="Number of concurrent DNS queries (recommended: 100-500 for large wordlists). Default: 200.", 
        type=int, 
        default=200
    )
    batch_parser.add_argument(
        "--dns-timeout", 
        help="DNS timeout in seconds (lower = faster, higher = more reliable). Default: 2.", 
        type=int, 
        default=2
    )
    batch_parser.add_argument(
        "--dns-threads", 
        help="DNS thread pool size for concurrent processing. Default: 200.", 
        type=int, 
        default=200
    )
    
    # API configuration
    batch_parser.add_argument(
        "--api-keys", 
        help="JSON string of API keys for premium sources (e.g., '{\"virustotal\": \"your_api_key\"}'). Enables additional API sources.", 
        type=str
    )
    
    # Proxy configuration
    batch_parser.add_argument(
        "--proxy-type", 
        help="Type of proxy to use for DNS resolution. Requires PySocks library.", 
        choices=["socks4", "socks5", "http"]
    )
    batch_parser.add_argument(
        "--proxy-host", 
        help="Proxy host address (e.g., 127.0.0.1, proxy.example.com). Required if --proxy-type is specified."
    )
    batch_parser.add_argument(
        "--proxy-port", 
        help="Proxy port number. If not specified, uses default ports (1080 for SOCKS, 8080 for HTTP).", 
        type=int
    )
    
    # Wordlist configuration 
    batch_parser.add_argument(
        "--wordlist", 
        help="Path to custom wordlist file for subdomain brute-forcing. Default: wordlists/subdomain.txt.", 
        default="wordlists/subdomain.txt"
    )
    
    batch_parser.add_argument(
        "--output-formats", 
        help="Comma-separated list of output formats to generate. Options: json,csv,txt. Default: json,csv,txt.", 
        default="json,csv,txt"
    )

def add_crawler_parser(subparsers):
    parser = subparsers.add_parser(
        "crawler", 
        help="Web Crawler: Crawls websites to discover pages, links, and resources."
    )
    crawler_subparsers = parser.add_subparsers(
        dest="command", 
        help="Web crawler commands. Use 'crawler <command> --help' for more details."
    )

    # Single scan parser
    single_parser = crawler_subparsers.add_parser(
        "single", 
        help="Crawl a single URL."
    )
    single_parser.add_argument(
        "--url", 
        help="URL to start crawling from (e.g., https://example.com)", 
        required=True
    )
    single_parser.add_argument(
        "--depth", 
        help="Maximum depth to crawl from the starting URL. Default: 3.", 
        type=int, 
        default=3
    )
    single_parser.add_argument(
        "--concurrency", 
        help="Number of concurrent requests to make during crawling. Default: 10.", 
        type=int, 
        default=10
    )
    single_parser.add_argument(
        "--max-urls", 
        help="Maximum number of unique URLs to crawl. Default: 100.", 
        type=int, 
        default=100
    )
    single_parser.add_argument(
        "--js-render", 
        help="Enable JavaScript rendering for pages to discover dynamically loaded content.", 
        action="store_true"
    )
    single_parser.add_argument(
        "--no-robots", 
        help="Ignore robots.txt directives during crawling.", 
        action="store_true"
    )
    single_parser.add_argument(
        "--output", 
        help="Output format for crawl results. Options: 'json' or 'csv'."
    )
    single_parser.add_argument(
        "--file", 
        help="File path to save the crawl results to."
    )

    # Batch scan parser
    batch_parser = crawler_subparsers.add_parser(
        "batch", 
        help="Crawl multiple URLs listed in a file."
    )
    batch_parser.add_argument(
        "--file", 
        help="Path to a file containing URLs to crawl, one per line.", 
        required=True
    )
    batch_parser.add_argument(
        "--depth", 
        help="Maximum depth to crawl from each starting URL. Default: 3.", 
        type=int, 
        default=3
    )
    batch_parser.add_argument(
        "--concurrency", 
        help="Number of concurrent requests to make during crawling. Default: 10.", 
        type=int, 
        default=10
    )
    batch_parser.add_argument(
        "--max-urls", 
        help="Maximum number of unique URLs to crawl per target. Default: 100.", 
        type=int, 
        default=100
    )
    batch_parser.add_argument(
        "--js-render", 
        help="Enable JavaScript rendering for pages to discover dynamically loaded content.", 
        action="store_true"
    )
    batch_parser.add_argument(
        "--no-robots", 
        help="Ignore robots.txt directives during crawling.", 
        action="store_true"
    )
    batch_parser.add_argument(
        "--output", 
        help="Output format for crawl results. Options: 'json' or 'csv'."
    )
    batch_parser.add_argument(
        "--output-file", 
        help="File path to save the crawl results to."
    )

def add_headers_parser(subparsers):
    parser = subparsers.add_parser(
        "headers", 
        help="Header Audit: Audits HTTP security headers of web applications."
    )
    headers_subparsers = parser.add_subparsers(
        dest="command", 
        help="Header audit commands. Use 'headers <command> --help' for more details."
    )

    # Single scan parser
    single_parser = headers_subparsers.add_parser(
        "single", 
        help="Audit security headers for a single URL."
    )
    single_parser.add_argument(
        "--url", 
        help="URL to audit (e.g., https://example.com)", 
        required=True
    )
    single_parser.add_argument(
        "--verbose", 
        help="Enable verbose mode to display detailed header information.", 
        action="store_true"
    )
    single_parser.add_argument(
        "--allow-private", 
        help="Allow auditing of private IP addresses (e.g., localhost, internal networks).", 
        action="store_true"
    )
    single_parser.add_argument(
        "--timeout", 
        help="Request timeout in seconds. Default: 15.", 
        type=int, 
        default=15
    )

    # Batch scan parser
    batch_parser = headers_subparsers.add_parser(
        "batch", 
        help="Audit security headers for multiple URLs listed in a file."
    )
    batch_parser.add_argument(
        "--file", 
        help="Path to a file containing URLs to audit, one per line.", 
        required=True
    )
    batch_parser.add_argument(
        "--verbose", 
        help="Enable verbose mode to display detailed header information.", 
        action="store_true"
    )
    batch_parser.add_argument(
        "--allow-private", 
        help="Allow auditing of private IP addresses (e.g., localhost, internal networks).", 
        action="store_true"
    )
    batch_parser.add_argument(
        "--timeout", 
        help="Request timeout in seconds. Default: 15.", 
        type=int, 
        default=15
    )
    batch_parser.add_argument(
        "--output", 
        help="Output format for audit results. Options: 'json' or 'csv'."
    )
    batch_parser.add_argument(
        "--output-file", 
        help="File path to save the audit results to."
    )

def add_dirbrute_parser(subparsers):
    parser = subparsers.add_parser(
        "dirbrute", 
        help="Directory Bruteforcer: Discovers hidden directories and files on a web server."
    )
    parser.add_argument(
        "--url", 
        help="Target URL to bruteforce (e.g., https://example.com/)", 
        required=True
    )
    parser.add_argument(
        "--wordlist", 
        help="Path to a custom wordlist file for directory brute-forcing. Default: wordlists/directory-brute.txt.", 
        default="wordlists/directory-brute.txt"
    )
    parser.add_argument(
        "--extensions", 
        help="Comma-separated list of file extensions to test (e.g., '.php,.html,.bak'). Default includes common extensions.", 
        default="/,.php,.html,.htm,.asp,.aspx,.js,.json,.txt,.bak,.old,.zip,.tar.gz"
    )
    parser.add_argument(
        "--valid-codes", 
        help="Comma-separated list of HTTP status codes to consider as valid (e.g., '200,301,403'). Default includes common success and redirection codes.", 
        default="200,301,302,403,401,500"
    )
    parser.add_argument(
        "--max-workers", 
        help="Number of concurrent threads to use for brute-forcing. Default: 20.", 
        type=int, 
        default=20
    )
    parser.add_argument(
        "--report", 
        help="File path to save the brute-forcing report to. Default: dir_reports.txt.", 
        default="dir_reports.txt"
    )

def add_sslinspect_parser(subparsers):
    parser = subparsers.add_parser(
        "sslinspect", 
        help="SSL Inspector: Analyzes SSL/TLS certificates and configurations of a target host."
    )
    parser.add_argument(
        "--target", 
        help="Target host and port to inspect (e.g., google.com:443, 192.168.1.1:8443)", 
        required=True
    )
    parser.add_argument(
        "--export", 
        help="Export format for SSL inspection results. Options: 'json' or 'txt'.", 
        choices=["json", "txt"]
    )

def add_corstest_parser(subparsers):
    parser = subparsers.add_parser(
        "corstest", 
        help="CORS Scanner: Audits Cross-Origin Resource Sharing (CORS) configurations for misconfigurations."
    )
    parser.add_argument(
        "--url", 
        help="Target URL to scan for CORS misconfigurations (e.g., https://example.com)", 
        required=True
    )
    parser.add_argument(
        "--export", 
        help="Export format for CORS scan results. Options: 'json', 'csv', 'txt', or 'all'.", 
        choices=["json", "csv", "txt", "all"]
    )
    parser.add_argument(
        "--output", 
        help="File path to save the CORS scan report to."
    )

def add_smuggler_parser(subparsers):
    parser = subparsers.add_parser(
        "smuggler", 
        help="HTTP Desync Attack Tester: Tests for HTTP Request Smuggling vulnerabilities."
    )
    parser.add_argument(
        "--url", 
        help="Target URL for HTTP Desync testing (e.g., https://example.com)", 
        required=True
    )
    parser.add_argument(
        "--port", 
        help="Target port for the HTTP Desync test. If not specified, defaults to 80 for HTTP and 443 for HTTPS.", 
        type=int
    )
    parser.add_argument(
        "--headers", 
        help="Custom headers to include in the requests, in key:val,key2:val2 format (e.g., 'X-Custom:1,User-Agent:Test')."
    )

def add_tracepulse_parser(subparsers):
    parser = subparsers.add_parser(
        "tracepulse", 
        help="Tracepulse: A network traceroute utility to map network paths."
    )
    parser.add_argument(
        "--destination", 
        help="Destination domain or IP address to trace (e.g., google.com, 8.8.8.8)", 
        required=True
    )
    parser.add_argument(
        "--protocol", 
        help="Protocol to use for traceroute. Options: 'icmp', 'tcp', or 'udp'. Default: icmp.", 
        default="icmp", 
        choices=["icmp", "tcp", "udp"]
    )
    parser.add_argument(
        "--port", 
        help="Destination port for TCP and UDP probes. Required for tcp/udp protocols.", 
        type=int
    )
    parser.add_argument(
        "--max-hops", 
        help="Maximum number of hops to trace. Default: 30.", 
        type=int, 
        default=30
    )
    parser.add_argument(
        "--timeout", 
        help="Timeout per probe in seconds. Default: 2.", 
        type=float, 
        default=2
    )
    parser.add_argument(
        "--probe-delay", 
        help="Delay between probes in seconds. Default: 0.1.", 
        type=float, 
        default=0.1
    )
    parser.add_argument(
        "--allow-private", 
        help="Allow traceroute to private, loopback, and multicast addresses.", 
        action="store_true"
    )
    parser.add_argument(
        "--save", 
        help="Save the traceroute results to a file.", 
        action="store_true"
    )
    parser.add_argument(
        "--output", 
        help="File path to save the traceroute results to. Used with --save."
    )

def add_jscrawler_parser(subparsers):
    parser = subparsers.add_parser(
        "js-crawler", 
        help="JS Crawler & Endpoint Extractor: Crawls JavaScript files to extract hidden endpoints and sensitive information."
    )
    parser.add_argument(
        "--url", 
        help="Target URL to start crawling JavaScript files from (e.g., https://example.com)", 
        required=True
    )
    parser.add_argument(
        "--selenium", 
        help="Enable JavaScript rendering using Selenium for dynamic content analysis.", 
        action="store_true"
    )
    parser.add_argument(
        "--output", 
        help="File path to save the extracted endpoints and information to."
    )
    parser.add_argument(
        "--format", 
        help="Output format for the extracted data. Options: 'json', 'csv', or 'text'. Default: text.", 
        default="text", 
        choices=["json", "csv", "text"]
    )
    parser.add_argument(
        "--no-robots", 
        help="Disable robots.txt compliance when crawling JavaScript files.", 
        action="store_true"
    )

def add_pyobfuscator_parser(subparsers):
    parser = subparsers.add_parser(
        "py-obfuscator", 
        help="Python Obfuscator: Obfuscates Python code to protect against reverse-engineering."
    )
    parser.add_argument(
        "--input", 
        help="Path to the Python file to obfuscate (e.g., my_script.py)", 
        required=True
    )
    parser.add_argument(
        "--output", 
        help="Path to save the obfuscated Python file. If not specified, a default name will be used."
    )
    parser.add_argument(
        "--key", 
        help="Custom encryption passphrase to use for obfuscation. Enhances protection."
    )
    parser.add_argument(
        "--level", 
        help="Protection level for obfuscation. Higher levels provide stronger protection but may increase file size. Options: 1, 2, or 3. Default: 2.", 
        type=int, 
        default=2, 
        choices=[1, 2, 3]
    )
    