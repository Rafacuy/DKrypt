# modules/cors_scan.py

"""
CORS Misconfiguration Auditor Module
"""

import requests
import urllib.parse
import json
import csv
import datetime
import sys
import os
from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
import time

from core.randomizer import HeaderFactory
from core.utils import clear_console, header_banner

console = Console()

class CORSAuditor:
    """
    CORS Auditor class withtesting and export capabilities.
    
    This class provides methods to systematically test various CORS attack vectors
    and provides detailed reporting with multiple export formats.
    """
    
    def __init__(self):
        """Initialize the CORS Auditor with default configuration and silent header factory."""
        self.session = requests.Session()
        
        # Initialize header factory silently by redirecting stdout
        import sys
        from io import StringIO
        
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        
        try:
            self.header_factory = HeaderFactory(pool_size=1000)  # Smaller pool for faster init
        except Exception as e:
            console.print(f"[bold red]Warning: Header factory initialization failed: {e}[/bold red]")
            self.header_factory = None
        finally:
            sys.stdout = old_stdout
        
        self.timeout = 15
        self.findings = []
        self.scan_metadata = {}
        
    def get_randomized_headers(self) -> Dict[str, str]:
        """Get randomized headers from the factory or fallback to basic headers."""
        if self.header_factory:
            return self.header_factory.get_headers()
        else:
            # Fallback headers if factory fails
            return {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }
        
    def validate_url(self, url: str) -> tuple:
        """
        Validate if the provided URL is properly formatted.
        
        Args:
            url (str): The URL to validate
            
        Returns:
            tuple: (is_valid, normalized_url) where is_valid is bool and 
                   normalized_url is the properly formatted URL
        """
        try:
            # Add https:// if no scheme is provided
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Parse and validate the URL structure
            parsed = urllib.parse.urlparse(url)
            
            # Check if the URL has a valid scheme and netloc
            if parsed.scheme in ['http', 'https'] and parsed.netloc:
                return True, url
            else:
                return False, None
                
        except Exception as e:
            return False, None
    
    def make_request(self, url: str, method: str = 'GET', custom_headers: Dict = None, timeout: int = None) -> Optional[requests.Response]:
        """
        Make an HTTP request with randomized headers and error handling.
        
        Args:
            url (str): Target URL
            method (str): HTTP method (GET, POST, OPTIONS)
            custom_headers (dict): Additional headers to send (will override randomized ones)
            timeout (int): Request timeout in seconds
            
        Returns:
            requests.Response or None: Response object or None if request failed
        """
        try:
            # Start with randomized headers
            request_headers = self.get_randomized_headers()
            
            # Override with custom headers if provided
            if custom_headers:
                request_headers.update(custom_headers)
            
            timeout = timeout or self.timeout
            
            if method.upper() == 'GET':
                response = self.session.get(url, headers=request_headers, timeout=timeout, verify=False)
            elif method.upper() == 'OPTIONS':
                response = self.session.options(url, headers=request_headers, timeout=timeout, verify=False)
            elif method.upper() == 'POST':
                response = self.session.post(url, headers=request_headers, timeout=timeout, verify=False)
            else:
                return None
                
            return response
            
        except requests.exceptions.RequestException as e:
            console.print(f"[bold red]Request failed: {str(e)}[/bold red]")
            return None
    
    def test_baseline_request(self, url: str) -> Optional[Dict]:
        """
        Perform baseline request without custom Origin header.
        
        Args:
            url (str): Target URL
            
        Returns:
            dict: Baseline response information
        """
        console.print("[dim]• Testing baseline request...[/dim]")
        
        response = self.make_request(url)
        if not response:
            return None
            
        return {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'cors_headers': {k: v for k, v in response.headers.items() 
                           if k.lower().startswith('access-control')}
        }
    
    def test_reflective_origin(self, url: str) -> Dict:
        """
        Test for reflective Origin header vulnerability.
        
        This test checks if the server reflects arbitrary Origin headers
        in the Access-Control-Allow-Origin response header.
        
        Args:
            url (str): Target URL
            
        Returns:
            dict: Test results with vulnerability information
        """
        console.print("[dim]• Testing reflective origin...[/dim]")
        
        test_origins = [
            "https://evil.com",
            "https://DKRYPT-MODULE.com", 
            "https://s412wsfm--2412--2312.com"
        ]
        
        for test_origin in test_origins:
            headers = {'Origin': test_origin}
            response = self.make_request(url, custom_headers=headers)
            
            if not response:
                continue
                
            acao_header = response.headers.get('Access-Control-Allow-Origin', '')
            acac_header = response.headers.get('Access-Control-Allow-Credentials', '').lower()
            
            if acao_header == test_origin:
                return {
                    'vulnerable': True,
                    'severity': 'HIGH',
                    'issue': 'Reflective Origin',
                    'description': f'Server reflects arbitrary origin: {test_origin}',
                    'test_origin': test_origin,
                    'response_headers': {
                        'Access-Control-Allow-Origin': acao_header,
                        'Access-Control-Allow-Credentials': acac_header
                    }
                }
        
        return {'vulnerable': False}
    
    def test_wildcard_with_credentials(self, url: str) -> Dict:
        """
        Test for wildcard origin with credentials vulnerability.
        
        This is a critical vulnerability where Access-Control-Allow-Origin: *
        is combined with Access-Control-Allow-Credentials: true.
        
        Args:
            url (str): Target URL
            
        Returns:
            dict: Test results with vulnerability information
        """
        console.print("[dim]• Testing wildcard with credentials...[/dim]")
        
        headers = {'Origin': 'https://evil.com'}
        response = self.make_request(url, custom_headers=headers)
        
        if not response:
            return {'vulnerable': False}
            
        acao_header = response.headers.get('Access-Control-Allow-Origin', '')
        acac_header = response.headers.get('Access-Control-Allow-Credentials', '').lower()
        
        if acao_header == '*' and acac_header == 'true':
            return {
                'vulnerable': True,
                'severity': 'CRITICAL',
                'issue': 'Wildcard with Credentials',
                'description': 'Wildcard origin combined with credentials=true allows credential theft',
                'response_headers': {
                    'Access-Control-Allow-Origin': acao_header,
                    'Access-Control-Allow-Credentials': acac_header
                }
            }
        elif acao_header == '*':
            return {
                'vulnerable': True,
                'severity': 'MEDIUM',
                'issue': 'Wildcard Origin',
                'description': 'Wildcard origin detected (without credentials)',
                'response_headers': {
                    'Access-Control-Allow-Origin': acao_header
                }
            }
            
        return {'vulnerable': False}
    
    def test_null_origin(self, url: str) -> Dict:
        """
        Test for null origin bypass vulnerability.
        
        Some applications incorrectly allow 'null' as a valid origin,
        which can be exploited through data URIs or sandboxed iframes.
        
        Args:
            url (str): Target URL
            
        Returns:
            dict: Test results with vulnerability information
        """
        console.print("[dim]• Testing null origin bypass...[/dim]")
        
        headers = {'Origin': 'null'}
        response = self.make_request(url, custom_headers=headers)
        
        if not response:
            return {'vulnerable': False}
            
        acao_header = response.headers.get('Access-Control-Allow-Origin', '')
        acac_header = response.headers.get('Access-Control-Allow-Credentials', '').lower()
        
        if acao_header == 'null':
            severity = 'HIGH' if acac_header == 'true' else 'MEDIUM'
            return {
                'vulnerable': True,
                'severity': severity,
                'issue': 'Null Origin Bypass',
                'description': 'Server allows null origin - exploitable via data URIs or sandboxed iframes',
                'response_headers': {
                    'Access-Control-Allow-Origin': acao_header,
                    'Access-Control-Allow-Credentials': acac_header
                }
            }
            
        return {'vulnerable': False}
    
    def test_subdomain_regex_misconfig(self, url: str) -> Dict:
        """
        Test for subdomain/regex misconfiguration vulnerability.
        
        This test checks if the server incorrectly validates origins using
        weak regex patterns that can be bypassed with crafted domain names.
        
        Args:
            url (str): Target URL
            
        Returns:
            dict: Test results with vulnerability information
        """
        console.print("[dim]• Testing subdomain/regex misconfiguration...[/dim]")
        
        # Parse the original URL to create realistic attack payloads
        parsed_url = urllib.parse.urlparse(url)
        base_domain = parsed_url.netloc
        
        # Test various bypass techniques
        test_origins = [
            f"https://evil{base_domain}",
            f"https://{base_domain}.evil.com",
            f"https://evil-{base_domain}",
            f"https://{base_domain}evil.com",
            f"https://sub.{base_domain}.attacker.com"
        ]
        
        for test_origin in test_origins:
            headers = {'Origin': test_origin}
            response = self.make_request(url, custom_headers=headers)
            
            if not response:
                continue
                
            acao_header = response.headers.get('Access-Control-Allow-Origin', '')
            acac_header = response.headers.get('Access-Control-Allow-Credentials', '').lower()
            
            if acao_header == test_origin:
                severity = 'HIGH' if acac_header == 'true' else 'MEDIUM'
                return {
                    'vulnerable': True,
                    'severity': severity,
                    'issue': 'Subdomain/Regex Misconfiguration',
                    'description': f'Server accepts crafted origin: {test_origin}',
                    'test_origin': test_origin,
                    'response_headers': {
                        'Access-Control-Allow-Origin': acao_header,
                        'Access-Control-Allow-Credentials': acac_header
                    }
                }
        
        return {'vulnerable': False}
    
    def test_preflight_headers(self, url: str) -> Dict:
        """
        Test preflight request for overly permissive headers.
        
        This test checks if the server responds to OPTIONS requests with
        overly permissive CORS headers that could enable broader attacks.
        
        Args:
            url (str): Target URL
            
        Returns:
            dict: Test results with vulnerability information
        """
        console.print("[dim]• Testing preflight headers...[/dim]")
        
        headers = {
            'Origin': 'https://evil.com',
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'Content-Type, Authorization, X-Custom-Header'
        }
        
        response = self.make_request(url, method='OPTIONS', custom_headers=headers)
        
        if not response:
            return {'vulnerable': False}
            
        # Extract relevant CORS headers from OPTIONS response
        acam_header = response.headers.get('Access-Control-Allow-Methods', '')
        acah_header = response.headers.get('Access-Control-Allow-Headers', '')
        acao_header = response.headers.get('Access-Control-Allow-Origin', '')
        acac_header = response.headers.get('Access-Control-Allow-Credentials', '').lower()
        
        issues = []
        severity = 'LOW'
        
        # Check for wildcard methods
        if '*' in acam_header:
            issues.append("Wildcard methods allowed")
            severity = 'MEDIUM'
        elif 'DELETE' in acam_header.upper() or 'PUT' in acam_header.upper():
            issues.append("Dangerous methods (DELETE/PUT) allowed")
            severity = 'MEDIUM'
            
        # Check for wildcard headers
        if '*' in acah_header:
            issues.append("Wildcard headers allowed")
            severity = 'MEDIUM'
        elif 'authorization' in acah_header.lower():
            issues.append("Authorization header allowed")
            
        if issues:
            return {
                'vulnerable': True,
                'severity': severity,
                'issue': 'Overly Permissive Preflight',
                'description': '; '.join(issues),
                'response_headers': {
                    'Access-Control-Allow-Methods': acam_header,
                    'Access-Control-Allow-Headers': acah_header,
                    'Access-Control-Allow-Origin': acao_header,
                    'Access-Control-Allow-Credentials': acac_header
                }
            }
            
        return {'vulnerable': False}
    
    def test_insecure_protocols(self, url: str) -> Dict:
        """
        Test for insecure protocol handling in CORS.
        
        Args:
            url (str): Target URL
            
        Returns:
            dict: Test results with vulnerability information
        """
        console.print("[dim]• Testing insecure protocol handling...[/dim]")
        
        # Test various insecure origins
        test_origins = [
            "http://evil.com",  # HTTP instead of HTTPS
            "file://evil.com",
            "ftp://evil.com"
        ]
        
        for test_origin in test_origins:
            headers = {'Origin': test_origin}
            response = self.make_request(url, custom_headers=headers)
            
            if not response:
                continue
                
            acao_header = response.headers.get('Access-Control-Allow-Origin', '')
            
            if acao_header == test_origin:
                return {
                    'vulnerable': True,
                    'severity': 'MEDIUM',
                    'issue': 'Insecure Protocol Allowed',
                    'description': f'Server accepts insecure protocol origin: {test_origin}',
                    'test_origin': test_origin,
                    'response_headers': {
                        'Access-Control-Allow-Origin': acao_header
                    }
                }
        
        return {'vulnerable': False}
    
    def run_all_tests(self, url: str) -> List[Dict]:
        """
        Execute all CORS tests against the target URL.
        
        Args:
            url (str): Target URL to test
            
        Returns:
            list: List of all findings from the tests
        """
        console.print(f"\n[bold green][+] Starting comprehensive CORS scan for {url}...[/bold green]\n")
        
        # Initialize scan metadata
        self.scan_metadata = {
            'target_url': url,
            'scan_time': datetime.datetime.now().isoformat(),
            'total_tests': 6,
            'completed_tests': 0
        }
        
        # Initialize findings list
        self.findings = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # Test baseline
            task = progress.add_task("Running baseline test...", total=1)
            baseline = self.test_baseline_request(url)
            progress.advance(task)
            progress.remove_task(task)
            
            if not baseline:
                console.print("[bold red]Failed to establish baseline connection![/bold red]")
                return []
            
            self.scan_metadata['baseline_status'] = baseline['status_code']
            
            # Run all vulnerability tests
            tests = [
                ("Reflective origin test", self.test_reflective_origin),
                ("Wildcard credentials test", self.test_wildcard_with_credentials),
                ("Null origin test", self.test_null_origin),
                ("Subdomain/regex test", self.test_subdomain_regex_misconfig),
                ("Preflight headers test", self.test_preflight_headers),
                ("Insecure protocols test", self.test_insecure_protocols)
            ]
            
            for test_name, test_func in tests:
                task = progress.add_task(f"Running {test_name}...", total=1)
                result = test_func(url)
                
                if result and result.get('vulnerable'):
                    self.findings.append(result)
                    
                self.scan_metadata['completed_tests'] += 1
                progress.advance(task)
                progress.remove_task(task)
        
        self.scan_metadata['total_vulnerabilities'] = len(self.findings)
        return self.findings
    
    def export_to_json(self, filename: str = None) -> str:
        """Export scan results to JSON format."""
        export_dir = "../reports/cors_scan"
        os.makedirs(export_dir, exist_ok=True)
        
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cors_scan_{timestamp}.json"
        
        full_path = os.path.join(export_dir, filename)
        
        export_data = {
            'scan_metadata': self.scan_metadata,
            'findings': self.findings
        }
        
        with open(full_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        return full_path
        
    def export_to_csv(self, filename: str = None) -> str:
        """Export scan results to CSV format."""
        export_dir = "../reports/cors_scan"
        os.makedirs(export_dir, exist_ok=True)
        
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cors_scan_{timestamp}.csv"
        
        full_path = os.path.join(export_dir, filename)
        
        with open(full_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Severity', 'Issue', 'Description', 'Test_Origin', 'ACAO_Header', 'ACAC_Header']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for finding in self.findings:
                row = {
                    'Severity': finding.get('severity', ''),
                    'Issue': finding.get('issue', ''),
                    'Description': finding.get('description', ''),
                    'Test_Origin': finding.get('test_origin', ''),
                    'ACAO_Header': finding.get('response_headers', {}).get('Access-Control-Allow-Origin', ''),
                    'ACAC_Header': finding.get('response_headers', {}).get('Access-Control-Allow-Credentials', '')
                }
                writer.writerow(row)
        
    
    def export_to_txt(self, filename: str = None) -> str:
        """Export scan results to readable text format."""
        export_dir = "../reports/cors_scan"
        os.makedirs(export_dir, exist_ok=True)
        
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cors_scan_{timestamp}.txt"
        
        full_path = os.path.join(export_dir, filename)
        
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write("CORS MISCONFIGURATION AUDIT REPORT\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Target URL: {self.scan_metadata.get('target_url', 'N/A')}\n")
            f.write(f"Scan Time: {self.scan_metadata.get('scan_time', 'N/A')}\n")
            f.write(f"Total Vulnerabilities Found: {len(self.findings)}\n\n")
            
            if not self.findings:
                f.write("No CORS misconfigurations detected.\n")
                f.write("The target appears to have proper CORS configuration.\n")
            else:
                # Sort findings by severity
                severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
                sorted_findings = sorted(self.findings, key=lambda x: severity_order.get(x['severity'], 4))
                
                for i, finding in enumerate(sorted_findings, 1):
                    f.write(f"{i}. [{finding['severity']}] {finding['issue']}\n")
                    f.write(f"   Description: {finding['description']}\n")
                    
                    if 'test_origin' in finding:
                        f.write(f"   Test Origin: {finding['test_origin']}\n")
                    
                    f.write("   Response Headers:\n")
                    for header, value in finding.get('response_headers', {}).items():
                        if value:
                            f.write(f"     {header}: {value}\n")
                    f.write("\n")
        
        return full_path
    
    def display_results(self, url: str, findings: List[Dict]):
        """
        Display the audit results in a formatted TUI style.
        
        Args:
            url (str): Target URL that was tested
            findings (list): List of vulnerability findings
        """
        console.print(f"\n[bold cyan]╔══ CORS Audit Results ══╗[/bold cyan]")
        console.print(f"[bold white]Target: {url}[/bold white]\n")
        
        if not findings:
            # No vulnerabilities found
            console.print("[green]└─ ✓ No CORS misconfiguration detected.[/green]")
            console.print("\n[dim]The target appears to have proper CORS configuration.[/dim]")
            return
        
        # Sort findings by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x['severity'], 4))
        
        # Display each finding
        for i, finding in enumerate(sorted_findings):
            severity = finding['severity']
            issue = finding['issue']
            description = finding['description']
            headers = finding.get('response_headers', {})
            
            # Color code by severity
            severity_colors = {
                'CRITICAL': 'bold red',
                'HIGH': 'bold yellow', 
                'MEDIUM': 'bold blue',
                'LOW': 'dim white'
            }
            
            color = severity_colors.get(severity, 'white')
            
            # Display finding with tree structure
            if i == len(sorted_findings) - 1:
                console.print(f"[{color}]└─ [{severity}] {issue}[/{color}]")
            else:
                console.print(f"[{color}]├─ [{severity}] {issue}[/{color}]")
            
            # Display description
            if i == len(sorted_findings) - 1:
                console.print(f"[dim]   └─ {description}[/dim]")
            else:
                console.print(f"[dim]│  └─ {description}[/dim]")
        
        # Display summary
        critical_count = sum(1 for f in findings if f['severity'] == 'CRITICAL')
        high_count = sum(1 for f in findings if f['severity'] == 'HIGH')
        
        console.print(f"\n[bold white]Summary:[/bold white]")
        if critical_count > 0:
            console.print(f"[bold red]⚠️  CRITICAL issues found: {critical_count}[/bold red]")
        if high_count > 0:
            console.print(f"[bold yellow]⚠️  HIGH severity issues found: {high_count}[/bold yellow]")
        
        console.print(f"[dim]Total issues: {len(findings)}[/dim]")


def get_target_url():
    """
    Prompt user for target URL with validation.
    
    Returns:
        str or None: Valid URL or None if user wants to exit
    """
    while True:
        try:
            console.print("\n[bold cyan]╔══ CORS Misconfiguration Auditor ══╗[/bold cyan]")
            console.print("[dim]Enter target URL (or 'q' to quit):[/dim]")
            
            url = console.input("[bold white]Target URL: [/bold white]").strip()
            
            if url.lower() in ['q', 'quit', 'exit']:
                return None
            
            if not url:
                console.print("[bold red]Please enter a valid URL.[/bold red]")
                continue
            
            auditor = CORSAuditor()
            is_valid, normalized_url = auditor.validate_url(url)
            
            if is_valid:
                return normalized_url
            else:
                console.print("[bold red]Invalid URL format. Please enter a valid URL (e.g., https://example.com)[/bold red]")
                
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Operation cancelled by user.[/bold yellow]")
            return None
        except Exception as e:
            console.print(f"[bold red]Error: {str(e)}[/bold red]")
            continue


def handle_export_options(auditor: CORSAuditor):
    """Handle export options after scan completion."""
    if not auditor.findings:
        return
    
    console.print(f"\n[bold cyan]Export Options:[/bold cyan]")
    
    export_choice = Prompt.ask(
        "Export results? (Choose format)",
        choices=["json", "csv", "txt", "all", "no"],
        default="no"
    )
    
    if export_choice == "no":
        return
    
    try:
        if export_choice == "json":
            filename = auditor.export_to_json()
            console.print(f"[green]✓ Results exported to: {filename}[/green]")
        
        elif export_choice == "csv":
            filename = auditor.export_to_csv()
            console.print(f"[green]✓ Results exported to: {filename}[/green]")
        
        elif export_choice == "txt":
            filename = auditor.export_to_txt()
            console.print(f"[green]✓ Results exported to: {filename}[/green]")
        
        elif export_choice == "all":
            json_file = auditor.export_to_json()
            csv_file = auditor.export_to_csv()
            txt_file = auditor.export_to_txt()
            console.print(f"[green]✓ Results exported to:[/green]")
            console.print(f"[green]  - JSON: {json_file}[/green]")
            console.print(f"[green]  - CSV: {csv_file}[/green]")
            console.print(f"[green]  - TXT: {txt_file}[/green]")
    
    except Exception as e:
        console.print(f"[bold red]Export failed: {str(e)}[/bold red]")


def main(args=None):
    """
    Main function that orchestrates the enhanced CORS auditing process.
    """
    try:
        # Disable urllib3 warnings for unverified HTTPS requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        clear_console()
        
        header_banner(tool_name="CORS Misconfig Scanner")

        if args:
            target_url = args.url
            export_format = args.export
            output_file = args.output
        else:
            # Get target URL from user
            target_url = get_target_url()
            if not target_url:
                console.print("[bold red]Exiting...[/bold red]")
                return
        
        # Initialize auditor and run tests
        auditor = CORSAuditor()
        findings = auditor.run_all_tests(target_url)
        
        # Display results
        auditor.display_results(target_url, findings)
        
        if args:
            if export_format:
                if export_format == 'json':
                    auditor.export_to_json(output_file)
                elif export_format == 'csv':
                    auditor.export_to_csv(output_file)
                elif export_format == 'txt':
                    auditor.export_to_txt(output_file)
        else:
            # Handle export options
            handle_export_options(auditor)
        
        console.print(f"\n[bold green]✓ Scan completed successfully![/bold green]")
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Program interrupted by user. Exiting.[/bold yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Unexpected error: {str(e)}[/bold red]")
        sys.exit(1)