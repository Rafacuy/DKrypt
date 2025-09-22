# modules/header_audit.py

from __future__ import annotations

import json
import re
import csv
import time
from datetime import datetime
import socket
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Callable, Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
import os

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from core.utils import clear_console, sanitize_filename, header_banner

# ---- Core Components ----
console = Console()

# ---- Data Structures ----
@dataclass
class HeaderSpec:
    """Specification for a security header, including validation logic."""
    name: str
    display: str
    description: str
    recommendation: str
    severity: str
    weight: int
    validate: Callable[..., Tuple[bool, str]]

@dataclass
class AuditResult:
    """Stores the result of a single header check."""
    header: str
    severity: str
    status: str
    value_recommendation: str
    raw_status: str
    raw_value: str

@dataclass
class RedirectStep:
    """Represents one step in a redirect chain."""
    url: str
    headers: Dict[str, str]
    results: List[AuditResult] = field(default_factory=list)
    score: int = 0
    total_weight: int = 0

# ---- Header Validators ----

def validate_hsts(value: str, is_https: bool) -> Tuple[bool, str]:
    """
    Validates Strict-Transport-Security header.
    Checks for HTTPS, max-age, includeSubDomains, and preload.
    """
    if not is_https:
        return False, "HSTS header should only be sent over HTTPS."
    if not value:
        return False, "Header not present."

    directives = {part.split('=')[0].strip().lower(): (part.split('=')[1].strip() if '=' in part else True) for part in value.split(';')}
    
    max_age = int(directives.get('max-age', 0))
    min_max_age = 31536000  # 1 year

    if max_age < min_max_age:
        return False, f"max-age is {max_age} but should be at least {min_max_age} seconds (1 year)."
    if 'includesubdomains' not in directives:
        return False, "'includeSubDomains' directive is missing."
    if 'preload' not in directives:
        return False, "'preload' directive is missing. Consider adding it for maximum security."
        
    return True, "Secure configuration with sufficient max-age, includeSubDomains, and preload."

def _parse_csp_directives(value: str) -> Dict[str, List[str]]:
    """Parses a CSP string into a dictionary of directives."""
    directives: Dict[str, List[str]] = {}
    if not value:
        return directives
    for part in [p.strip() for p in value.split(';') if p.strip()]:
        tokens = part.split()
        if not tokens:
            continue
        dir_name = tokens[0].lower()
        dir_values = tokens[1:]
        directives[dir_name] = dir_values
    return directives

def validate_csp(value: str) -> Tuple[bool, str]:
    """
    Validates Content-Security-Policy header.
    Checks for unsafe directives and missing frame-ancestors.
    """
    if not value:
        return False, "Header not present."
    directives = _parse_csp_directives(value)
    issues = []
    
    # Check for risky wildcards or unsafe directives
    for dir_name in ('default-src', 'script-src', 'style-src', 'object-src'):
        for v in directives.get(dir_name, []):
            if v.lower() in ("'*'", "http:", "https:") or "'unsafe-inline'" in v.lower() or "'unsafe-eval'" in v.lower():
                issues.append(f"Insecure value '{v}' in '{dir_name}'.")

    # Check for frame-ancestors to prevent clickjacking
    if 'frame-ancestors' not in directives:
        issues.append("'frame-ancestors' directive is missing, which is critical for preventing clickjacking.")
    
    if issues:
        return False, '; '.join(issues)
    return True, "Appears to be a reasonably strict policy."

def validate_x_frame_options(value: str) -> Tuple[bool, str]:
    """Validates X-Frame-Options header."""
    if not value:
        return False, "Header not present. Use CSP 'frame-ancestors' for modern protection."
    v = value.strip().upper()
    if v in ('DENY', 'SAMEORIGIN'):
        return True, f"Secure value '{v}'."
    return False, f"Insecure or invalid value: '{value}'."

def validate_x_content_type_options(value: str) -> Tuple[bool, str]:
    """Validates X-Content-Type-Options header."""
    if not value:
        return False, "Header not present."
    if value.strip().lower() == 'nosniff':
        return True, "Secure value 'nosniff'."
    return False, f"Invalid value: '{value}'."

def validate_cors(value: str, headers: Dict[str, str]) -> Tuple[bool, str]:
    """
    Validates Access-Control-Allow-Origin.
    Checks for wildcards and credential handling.
    """
    if not value:
        return False, "Header not present."
    if value.strip() == '*':
        allow_creds = headers.get('access-control-allow-credentials', 'false').lower()
        if allow_creds == 'true':
            return False, "Overly permissive wildcard '*' is used with 'Access-Control-Allow-Credentials' set to 'true'."
        return False, "Overly permissive wildcard '*' is used. Restrict to specific origins."
    return True, "Not using a wildcard origin."

def validate_referrer_policy(value: str) -> Tuple[bool, str]:
    """Validates Referrer-Policy against a list of secure values."""
    if not value:
        return False, "Header not present."
    secure_policies = [
        'no-referrer',
        'no-referrer-when-downgrade',
        'strict-origin',
        'strict-origin-when-cross-origin',
        'same-origin',
    ]
    if value.strip().lower() in secure_policies:
        return True, f"Secure policy '{value}' is used."
    return False, f"Insecure or less-secure policy '{value}' used. Consider one of: {', '.join(secure_policies)}."

def validate_presence(value: str) -> Tuple[bool, str]:
    """Generic validator to check if a header is present."""
    return (True, "Header is present.") if value else (False, "Header not present.")

# ---- Header Specifications ----
SECURITY_HEADERS: Dict[str, HeaderSpec] = {
    'content-security-policy': HeaderSpec('content-security-policy', 'Content-Security-Policy', 'Mitigates XSS and clickjacking.', "Use a strict policy, e.g., default-src 'self'; frame-ancestors 'self'", 'Critical', 20, validate_csp),
    'strict-transport-security': HeaderSpec('strict-transport-security', 'Strict-Transport-Security', 'Ensures browsers only connect over HTTPS.', 'Set for at least 1 year with includeSubDomains and preload.', 'High', 15, validate_hsts),
    'x-frame-options': HeaderSpec('x-frame-options', 'X-Frame-Options', 'Protects against clickjacking (legacy).', "Use DENY or SAMEORIGIN. Prefer CSP 'frame-ancestors'.", 'High', 10, validate_x_frame_options),
    'access-control-allow-origin': HeaderSpec('access-control-allow-origin', 'Access-Control-Allow-Origin', 'Controls which origins can access resources.', "Avoid using the wildcard '*'.", 'High', 15, validate_cors),
    'x-content-type-options': HeaderSpec('x-content-type-options', 'X-Content-Type-Options', "Prevents MIME-sniffing attacks.", "Set to 'nosniff'.", 'Medium', 10, validate_x_content_type_options),
    'referrer-policy': HeaderSpec('referrer-policy', 'Referrer-Policy', 'Controls how much referrer information is sent.', "Use 'strict-origin-when-cross-origin' or stricter.", 'Medium', 5, validate_referrer_policy),
    'permissions-policy': HeaderSpec('permissions-policy', 'Permissions-Policy', 'Controls which browser features can be used.', "Define a restrictive policy, e.g., geolocation=(), microphone=()", 'Medium', 8, validate_presence),
    'clear-site-data': HeaderSpec('clear-site-data', 'Clear-Site-Data', 'Clears browsing data for a site on logout.', 'Use `"cache", "cookies", "storage"` on logout pages.', 'Low', 3, validate_presence),
    'report-to': HeaderSpec('report-to', 'Report-To', 'Specifies an endpoint for browser reporting.', 'Configure to receive CSP and other violation reports.', 'Low', 2, validate_presence),
}

SEVERITY_STYLES = {'Critical': 'bold red', 'High': 'red', 'Medium': 'yellow', 'Low': 'cyan'}

# ---- Networking and URL Validation ----

def is_url_valid(url: str, allow_private: bool = False) -> Tuple[bool, Optional[str], Optional[str]]:
    """Validates URL format and resolves its IP, checking if it's private."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https') or not parsed.netloc:
            return False, 'Invalid URL format. Must include http/https and a hostname.', None
        hostname = parsed.hostname
        if not hostname:
            return False, 'Could not determine hostname.', None
        
        ip_str = socket.gethostbyname(hostname)
        ip = ip_address(ip_str)
        
        if ip.is_private and not allow_private:
            return False, f'Skipping private or local IP address: {ip}', ip_str
        
        return True, None, ip_str
    except socket.gaierror:
        return False, f'Could not resolve hostname: {urlparse(url).hostname}', None
    except Exception as e:
        return False, f'URL validation error: {e}', None

def fetch_headers_with_retries(url: str, timeout: int = 10, retries: int = 2, verbose: bool = False) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Fetches headers, follows redirects, and captures headers at each step.
    Implements a retry mechanism for failed connections.
    """
    history = []
    session = requests.Session()
    current_url = url
    
    for attempt in range(retries):
        try:
            response = session.get(current_url, timeout=timeout, allow_redirects=True)
            
            # Process redirect history
            for resp in response.history:
                history.append({
                    "url": resp.url,
                    "headers": {k.lower(): v for k, v in resp.headers.items()},
                    "status_code": resp.status_code
                })

            # Process the final response
            history.append({
                "url": response.url,
                "headers": {k.lower(): v for k, v in response.headers.items()},
                "status_code": response.status_code
            })
            
            # Check for HTTPS enforcement
            if url.startswith('http://') and response.url.startswith('https://'):
                if verbose: console.print("[green]✅ HTTP to HTTPS redirect enforced.[/green]")
            elif url.startswith('http://'):
                 if verbose: console.print("[yellow]⚠️ HTTP to HTTPS redirect was not enforced.[/yellow]")

            return history, None
        
        except requests.RequestException as e:
            error_msg = f"Request failed on attempt {attempt + 1}/{retries}: {e}"
            if verbose: console.print(f"[yellow]{error_msg}[/yellow]")
            time.sleep(1) # Wait before retrying
    
    return [], f"Failed to fetch headers for {url} after {retries} attempts."


# ---- Analysis and Reporting ----

def analyze_headers(headers: Dict[str, str], url: str) -> Tuple[List[AuditResult], int, int]:
    """Analyzes a dictionary of headers and returns results and scores."""
    results = []
    score = 0
    total_weight = sum(spec.weight for spec in SECURITY_HEADERS.values())
    is_https = url.startswith('https://')

    for key, spec in SECURITY_HEADERS.items():
        raw_value = headers.get(key)
        
        # Special handling for validators that need more context
        if spec.validate.__name__ == 'validate_hsts':
            is_secure, msg = spec.validate(raw_value, is_https)
        elif spec.validate.__name__ == 'validate_cors':
            is_secure, msg = spec.validate(raw_value, headers)
        else:
            is_secure, msg = spec.validate(raw_value)

        if raw_value is not None:
            if is_secure:
                status = '[green]Present (Secure)[/green]'
                score += spec.weight
                value_recommendation = f"Value: {raw_value}"
            else:
                status = '[bold yellow]Present (Insecure)[/bold yellow]'
                score += spec.weight // 3
                value_recommendation = f"Value: {raw_value}\n[yellow]Issue:[/yellow] {msg}"
        else:
            status = '[red]Missing[/red]'
            value_recommendation = f"[cyan]Recommendation:[/cyan] {spec.recommendation}"

        results.append(AuditResult(
            header=spec.display,
            severity=spec.severity,
            status=status,
            value_recommendation=value_recommendation,
            raw_status='Secure' if is_secure else ('Insecure' if raw_value else 'Missing'),
            raw_value=raw_value or ''
        ))

    return results, score, total_weight

def generate_report_table(results: List[AuditResult], url: str, status_code: int) -> Table:
    """Creates a Rich table for a single audit step."""
    t = Table(title=f"Audit for [bold]{url}[/bold] (Status: {status_code})", header_style='bold magenta', expand=True)
    t.add_column('Header', style='bold cyan', width=28)
    t.add_column('Severity', width=10)
    t.add_column('Status', width=20)
    t.add_column('Value / Recommendation', no_wrap=False)

    for r in results:
        sev_style = SEVERITY_STYLES.get(r.severity, 'white')
        t.add_row(r.header, f"[{sev_style}]{r.severity}[/]", r.status, r.value_recommendation)
    return t


def export_batch_report(all_steps: List[RedirectStep], output_format: str, filename: str):
    """Exports a consolidated report for a batch scan."""
    os.makedirs("reports/header_auditor", exist_ok=True)
    filepath = f"reports/header_auditor/{filename}"

    try:
        if output_format == 'json':
            export_data = []
            for step in all_steps:
                export_data.append({
                    'url': step.url,
                    'headers': step.headers,
                    'results': [r.__dict__ for r in step.results]
                })
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)

        elif output_format == 'csv':
            with open(filepath, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Header', 'Severity', 'Status', 'Value', 'Recommendation'])
                for step in all_steps:
                    for r in step.results:
                        writer.writerow([
                            step.url, r.header, r.severity, r.raw_status,
                            r.raw_value.replace('\n', ' '),
                            r.value_recommendation.replace('\n', ' ')
                        ])
        console.print(f"\n[green]Batch report exported to {filepath}[/green]")
    except IOError as e:
        console.print(f"[red]Error exporting batch report: {e}[/red]")


# ---- UI Application Class ----

class HeaderAuditor:
    def __init__(self):
        self.verbose = False
        self.allow_private = False
        self.timeout = 15

    def _get_main_menu_choice(self) -> str:
        console.print("\n[bold]Main Menu[/bold]")
        console.print("1. Single URL Scan")
        console.print("2. Batch URL Scan (from file)")
        console.print("3. Toggle Verbose Mode " + (f"([green]On[/green])" if self.verbose else "([red]Off[/red])"))
        console.print("4. Exit")
        return console.input("[bold cyan]Choose an option: [/bold cyan]").strip()

    def run(self, args=None):
        """Main application loop."""
        if args and args.command:
            self.verbose = args.verbose
            self.allow_private = args.allow_private
            self.timeout = args.timeout

            if args.command == 'single':
                self.run_single_scan(args.url)
            elif args.command == 'batch':
                self.run_batch_scan(args.file, args.output, args.output_file)
            return

        while True:
            clear_console()
            header_banner(tool_name="Header Auditor")
            choice = self._get_main_menu_choice()
            if choice == '1':
                self.run_single_scan()
            elif choice == '2':
                self.run_batch_scan()
            elif choice == '3':
                self.verbose = not self.verbose
            elif choice == '4':
                break
            else:
                console.print("[red]Invalid option. Please try again.[/red]")
                time.sleep(1)

    def run_single_scan(self, url_input=None):
        """Handles the logic for scanning a single URL."""
        if not url_input:
            console.print(Panel.fit("[bold]Single URL Scan[/bold]"))
            
            while True:
                url_input = console.input('\nEnter target URL (e.g., http://example.com): ').strip()
                if not urlparse(url_input).scheme:
                    url_input = 'http://' + url_input
                
                ok, reason, ip = is_url_valid(url_input, self.allow_private)
                if ok:
                    if self.verbose and ip:
                        console.print(f"[cyan]Resolved {urlparse(url_input).hostname} to {ip}[/cyan]")
                    break
                console.print(f"[red]Error:[/red] {reason}")

        console.print(f"\n[cyan]Auditing headers for {url_input}...[/cyan]")
        redirect_chain, err = fetch_headers_with_retries(url_input, timeout=self.timeout, verbose=self.verbose)
        
        if err:
            console.print(f"[red]Fatal Error:[/red] {err}")
            console.input("\nPress Enter to return to the menu...")
            return

        if not redirect_chain:
            console.print("[yellow]No headers were fetched. The server may be down or unreachable.[/yellow]")
            console.input("\nPress Enter to return to the menu...")
            return

        final_score, final_total_weight = 0, 0
        for step_data in redirect_chain:
            url, headers, status_code = step_data['url'], step_data['headers'], step_data['status_code']
            results, score, total_weight = analyze_headers(headers, url)
            
            # Display table for this step
            table = generate_report_table(results, url, status_code)
            console.print(table)
            
            # The final score is taken from the last step in the chain
            final_score, final_total_weight = score, total_weight

        # Display summary for the final destination
        self.display_summary(redirect_chain[-1]['url'], final_score, final_total_weight)
        console.input("\nPress Enter to return to the menu...")

    def run_batch_scan(self, filepath=None, output_format=None, output_file=None):
        """Handles the logic for scanning multiple URLs from a file."""
        if not filepath:
            clear_console()
            console.print(Panel.fit("[bold]Batch URL Scan[/bold]"))
            
            while True:
                filepath = console.input("Enter the path to the file containing URLs (one per line): ").strip()
                if os.path.exists(filepath):
                    break
                console.print(f"[red]File not found at '{filepath}'. Please try again.[/red]")

        with open(filepath, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]

        console.print(f"\nFound {len(urls)} URLs. Starting batch scan...")
        
        all_results: List[RedirectStep] = []
        for i, url in enumerate(urls):
            console.rule(f"Processing {i+1}/{len(urls)}: {url}")
            
            ok, reason, _ = is_url_valid(url, self.allow_private)
            if not ok:
                console.print(f"[yellow]Skipping invalid URL {url}: {reason}[/yellow]")
                continue

            redirect_chain, err = fetch_headers_with_retries(url, timeout=self.timeout, verbose=self.verbose)
            if err:
                console.print(f"[red]Failed to scan {url}: {err}[/red]")
                continue

            for step_data in redirect_chain:
                results, score, total_weight = analyze_headers(step_data['headers'], step_data['url'])
                step = RedirectStep(
                    url=step_data['url'],
                    headers=step_data['headers'],
                    results=results,
                    score=score,
                    total_weight=total_weight
                )
                all_results.append(step)

        if not all_results:
            console.print("[yellow]Batch scan completed, but no data was collected.[/yellow]")
            console.input("\nPress Enter to return to the menu...")
            return

        console.rule("Batch Scan Complete")
        if not output_format:
            output_format = console.input("Export consolidated report? ([bold]c[/bold]sv / [bold]j[/bold]son / [bold]n[/bold]o): ").lower()
        
        if output_format in ('c', 'csv', 'j', 'json'):
            fmt = 'csv' if output_format.startswith('c') else 'json'
            if not output_file:
                ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_file = sanitize_filename(f"batch_report_{ts}.{fmt}")
            export_batch_report(all_results, fmt, output_file)
        
        console.input("\nPress Enter to return to the menu...")

    def display_summary(self, url: str, score: int, total_weight: int):
        """Displays a summary panel for the final audit result."""
        percentage = (score / total_weight * 100) if total_weight > 0 else 0
        
        if percentage >= 80:
            grade, style = "A", "bold green"
        elif percentage >= 60:
            grade, style = "B", "green"
        elif percentage >= 40:
            grade, style = "C", "yellow"
        else:
            grade, style = "D", "bold red"
            
        summary = Text()
        summary.append(f"Final Destination: {url}\n")
        summary.append(f"Overall Score: {score} / {total_weight}\n")
        summary.append(f"Security Grade: ",)
        summary.append(f"{grade}", style=style)
        
        console.print(Panel(summary, title='[bold]Audit Summary[/bold]', expand=False, border_style="blue"))



