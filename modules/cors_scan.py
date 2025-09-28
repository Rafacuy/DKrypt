# modules/cors_scan.py

"""
CORS Misconfiguration Auditor Module
"""

import asyncio
import aiohttp
import urllib.parse
import json
import csv
import datetime
import sys
import os
from typing import Dict, Any, List, Optional, Tuple
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
import time
import ssl

from core.randomizer import HeaderFactory
from core.utils import clear_console, header_banner

console = Console()

class CORSAuditor():
    """
    Primary class and scanner logic for CORS including the tests
    """
    def __init__(self):
        """Initialize the CORS Auditor with default configuration."""
        self.timeout = 15
        self.findings = []
        self.scan_metadata = {}
        self.max_concurrent_requests = 10
        
        import sys
        from io import StringIO
        
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        
        try:
            self.header_factory = HeaderFactory(pool_size=1000)
        except Exception as e:
            console.print(f"[bold red]Warning: Header factory initialization failed: {e}[/bold red]")
            self.header_factory = None
        finally:
            sys.stdout = old_stdout
        
        # Dynamic test registry
        self.test_registry = [
            ("Baseline Request", self.test_baseline_request),
            ("Reflective Origin", self.test_reflective_origin),
            ("Wildcard with Credentials", self.test_wildcard_with_credentials),
            ("Null Origin Bypass", self.test_null_origin),
            ("Subdomain/Regex Misconfiguration", self.test_subdomain_regex_misconfig),
            ("Preflight Headers Analysis", self.test_preflight_headers),
            ("Insecure Protocols", self.test_insecure_protocols),
            ("Vary Origin Header Check", self.test_vary_origin),
            ("Advanced Credential Handling", self.test_advanced_credentials),
        ]
        
    def get_randomized_headers(self) -> Dict[str, str]:
        """Get randomized headers from the factory or fallback to basic headers."""
        if self.header_factory:
            return self.header_factory.get_headers()
        else:
            return {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }
        
    def validate_url(self, url: str) -> Tuple[bool, Optional[str]]:
        """Validate if the provided URL is properly formatted."""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed = urllib.parse.urlparse(url)
            
            if parsed.scheme in ['http', 'https'] and parsed.netloc:
                return True, url
            else:
                return False, None
                
        except Exception as e:
            return False, None
    
    async def make_async_request(self, session: aiohttp.ClientSession, url: str, 
                                method: str = 'GET', custom_headers: Dict = None) -> Optional[Dict]:
        try:
            request_headers = self.get_randomized_headers()
            
            if custom_headers:
                request_headers.update(custom_headers)
            
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            
            async with session.request(
                method=method.upper(),
                url=url,
                headers=request_headers,
                timeout=timeout,
                ssl=False
            ) as response:
                response_headers = dict(response.headers)
                return {
                    'status_code': response.status,
                    'headers': response_headers,
                    'cors_headers': {k: v for k, v in response_headers.items() 
                                   if k.lower().startswith('access-control')},
                    'vary_header': response_headers.get('Vary', ''),
                    'url': str(response.url)
                }
                
        except asyncio.TimeoutError:
            console.print(f"[bold red]Request timeout for {url}[/bold red]")
            return None
        except Exception as e:
            console.print(f"[bold red]Request failed for {url}: {str(e)}[/bold red]")
            return None
    
    async def test_baseline_request(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict]:
        """Perform baseline request without custom Origin header."""
        console.print("[dim]• Testing baseline request...[/dim]")
        
        response = await self.make_async_request(session, url)
        if not response:
            return None
            
        return response
    
    async def test_reflective_origin(self, session: aiohttp.ClientSession, url: str) -> Dict:
        """test for reflective Origin header vulnerability with comprehensive checks."""
        console.print("[dim]• Testing reflective origin...[/dim]")
        
        test_origins = [
            "https://evil.com",
            "https://DKRYPT-MODULE.com",
            "https://s412wsfm--2412--2312.com",
            "https://attacker-site.evil",
            "https://malicious.domain",
            "https://xss.payload.net"
        ]
        
        vulnerable_origins = []
        
        # Test multiple origins to confirm reflective behavior
        for test_origin in test_origins:
            headers = {'Origin': test_origin}
            response = await self.make_async_request(session, url, custom_headers=headers)
            
            if not response:
                continue
                
            acao_header = response['headers'].get('Access-Control-Allow-Origin', '')
            acac_header = response['headers'].get('Access-Control-Allow-Credentials', '').lower()
            vary_header = response.get('vary_header', '').lower()
            
            if acao_header == test_origin:
                vulnerable_origins.append({
                    'origin': test_origin,
                    'acao': acao_header,
                    'acac': acac_header,
                    'has_vary_origin': 'origin' in vary_header
                })
        
        if vulnerable_origins:
            # Determine severity based on credentials and vary header
            severity = 'HIGH'
            has_credentials = any(vo['acac'] == 'true' for vo in vulnerable_origins)
            has_vary = any(vo['has_vary_origin'] for vo in vulnerable_origins)
            
            if has_credentials and not has_vary:
                severity = 'CRITICAL'
            elif has_credentials:
                severity = 'HIGH'
            elif not has_vary:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
            
            return {
                'vulnerable': True,
                'severity': severity,
                'issue': 'Reflective Origin Vulnerability',
                'description': f'Server reflects {len(vulnerable_origins)} different origins. '
                              f'Credentials: {has_credentials}, Vary header: {has_vary}',
                'vulnerable_origins': vulnerable_origins,
                'response_headers': vulnerable_origins[0]  # First example
            }
        
        return {'vulnerable': False}
    
    async def test_wildcard_with_credentials(self, session: aiohttp.ClientSession, url: str) -> Dict:
        """test for wildcard origin with credentials vulnerability"""
        console.print("[dim]• Testing wildcard with credentials...[/dim]")
        
        # Test with and without origin header to detect different behaviors
        test_scenarios = [
            {'Origin': 'https://evil.com'},
            {},  # No origin header
            {'Origin': 'null'},
        ]
        
        for headers in test_scenarios:
            response = await self.make_async_request(session, url, custom_headers=headers)
            
            if not response:
                continue
                
            acao_header = response['headers'].get('Access-Control-Allow-Origin', '')
            acac_header = response['headers'].get('Access-Control-Allow-Credentials', '').lower()
            vary_header = response.get('vary_header', '').lower()
            
            if acao_header == '*':
                if acac_header == 'true':
                    return {
                        'vulnerable': True,
                        'severity': 'CRITICAL',
                        'issue': 'Wildcard with Credentials (Critical)',
                        'description': 'Wildcard origin (*) combined with credentials=true - allows credential theft from any origin',
                        'test_scenario': headers,
                        'response_headers': {
                            'Access-Control-Allow-Origin': acao_header,
                            'Access-Control-Allow-Credentials': acac_header,
                            'Vary': response.get('vary_header', '')
                        }
                    }
                else:
                    return {
                        'vulnerable': True,
                        'severity': 'MEDIUM',
                        'issue': 'Wildcard Origin (Medium Risk)',
                        'description': 'Wildcard origin (*) detected without credentials - allows cross-origin requests from any domain',
                        'test_scenario': headers,
                        'response_headers': {
                            'Access-Control-Allow-Origin': acao_header,
                            'Vary': response.get('vary_header', '')
                        }
                    }
            
        return {'vulnerable': False}
    
    async def test_null_origin(self, session: aiohttp.ClientSession, url: str) -> Dict:
        """test for null origin bypass vulnerability"""
        console.print("[dim]• Testing null origin bypass...[/dim]")
        
        headers = {'Origin': 'null'}
        response = await self.make_async_request(session, url, custom_headers=headers)
        
        if not response:
            return {'vulnerable': False}
            
        acao_header = response['headers'].get('Access-Control-Allow-Origin', '')
        acac_header = response['headers'].get('Access-Control-Allow-Credentials', '').lower()
        vary_header = response.get('vary_header', '').lower()
        
        if acao_header == 'null':
            severity = 'HIGH' if acac_header == 'true' else 'MEDIUM'
            has_vary = 'origin' in vary_header
            
            if not has_vary and acac_header == 'true':
                severity = 'CRITICAL'
            
            return {
                'vulnerable': True,
                'severity': severity,
                'issue': 'Null Origin Bypass',
                'description': f'Server allows null origin - exploitable via data URIs, sandboxed iframes, or file:// protocol. '
                              f'Vary header present: {has_vary}',
                'response_headers': {
                    'Access-Control-Allow-Origin': acao_header,
                    'Access-Control-Allow-Credentials': acac_header,
                    'Vary': response.get('vary_header', '')
                }
            }
            
        return {'vulnerable': False}
    
    async def test_subdomain_regex_misconfig(self, session: aiohttp.ClientSession, url: str) -> Dict:
        """test for subdomain/regex misconfiguration vulnerability."""
        console.print("[dim]• Testing subdomain/regex misconfiguration...[/dim]")
        
        parsed_url = urllib.parse.urlparse(url)
        base_domain = parsed_url.netloc
        
        # Expanded bypass techniques
        test_origins = [
            f"https://evil{base_domain}",
            f"https://{base_domain}.evil.com",
            f"https://evil-{base_domain}",
            f"https://{base_domain}evil.com",
            f"https://sub.{base_domain}.attacker.com",
            f"https://attacker.{base_domain}",
            f"https://{base_domain}-attacker.com",
            f"https://evil.{base_domain}",
        ]
        
        vulnerable_patterns = []
        
        for test_origin in test_origins:
            headers = {'Origin': test_origin}
            response = await self.make_async_request(session, url, custom_headers=headers)
            
            if not response:
                continue
                
            acao_header = response['headers'].get('Access-Control-Allow-Origin', '')
            acac_header = response['headers'].get('Access-Control-Allow-Credentials', '').lower()
            vary_header = response.get('vary_header', '').lower()
            
            if acao_header == test_origin:
                vulnerable_patterns.append({
                    'origin': test_origin,
                    'acao': acao_header,
                    'acac': acac_header,
                    'has_vary': 'origin' in vary_header
                })
        
        if vulnerable_patterns:
            has_credentials = any(vp['acac'] == 'true' for vp in vulnerable_patterns)
            has_vary = any(vp['has_vary'] for vp in vulnerable_patterns)
            
            severity = 'HIGH' if has_credentials else 'MEDIUM'
            if has_credentials and not has_vary:
                severity = 'CRITICAL'
            
            return {
                'vulnerable': True,
                'severity': severity,
                'issue': 'Subdomain/Regex Misconfiguration',
                'description': f'Server accepts {len(vulnerable_patterns)} crafted origins due to weak regex validation',
                'vulnerable_patterns': vulnerable_patterns,
                'response_headers': vulnerable_patterns[0]
            }
        
        return {'vulnerable': False}
    
    async def test_preflight_headers(self, session: aiohttp.ClientSession, url: str) -> Dict:
        """preflight request testing with comprehensive header analysi"""
        console.print("[dim]• Testing preflight headers...[/dim]")
        
        # Test multiple preflight scenarios
        test_scenarios = [
            {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'Content-Type, Authorization, X-Custom-Header'
            },
            {
                'Origin': 'https://attacker.com',
                'Access-Control-Request-Method': 'DELETE',
                'Access-Control-Request-Headers': 'Authorization, X-API-Key'
            },
            {
                'Origin': 'https://malicious.net',
                'Access-Control-Request-Method': 'PUT',
                'Access-Control-Request-Headers': '*'
            }
        ]
        
        findings = []
        
        for scenario in test_scenarios:
            response = await self.make_async_request(session, url, method='OPTIONS', custom_headers=scenario)
            
            if not response:
                continue
                
            acam_header = response['headers'].get('Access-Control-Allow-Methods', '')
            acah_header = response['headers'].get('Access-Control-Allow-Headers', '')
            acao_header = response['headers'].get('Access-Control-Allow-Origin', '')
            acac_header = response['headers'].get('Access-Control-Allow-Credentials', '').lower()
            vary_header = response.get('vary_header', '').lower()
            
            issues = []
            severity = 'LOW'
            
            # analysis
            if '*' in acam_header:
                issues.append("Wildcard methods (*) allowed in preflight")
                severity = 'HIGH'
            elif any(method.upper() in acam_header.upper() for method in ['DELETE', 'PUT', 'PATCH']):
                issues.append("Dangerous methods (DELETE/PUT/PATCH) allowed")
                severity = 'MEDIUM'
                
            if '*' in acah_header:
                issues.append("Wildcard headers (*) allowed - any header accepted")
                severity = 'HIGH'
            elif 'authorization' in acah_header.lower():
                issues.append("Authorization header explicitly allowed")
                severity = 'MEDIUM'
                
            # Check for origin reflection in preflight
            if acao_header == scenario['Origin']:
                issues.append("Origin reflected in preflight response")
                if acac_header == 'true':
                    severity = 'HIGH'
            
            # Check Vary header presence
            if 'origin' not in vary_header and acao_header not in ['*', '']:
                issues.append("Missing Vary: Origin header with dynamic CORS")
                
            if issues:
                findings.append({
                    'severity': severity,
                    'issues': issues,
                    'scenario': scenario,
                    'response_headers': {
                        'Access-Control-Allow-Methods': acam_header,
                        'Access-Control-Allow-Headers': acah_header,
                        'Access-Control-Allow-Origin': acao_header,
                        'Access-Control-Allow-Credentials': acac_header,
                        'Vary': response.get('vary_header', '')
                    }
                })
        
        if findings:
            # Return the most severe finding
            most_severe = max(findings, key=lambda x: {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(x['severity'], 0))
            
            return {
                'vulnerable': True,
                'severity': most_severe['severity'],
                'issue': 'Overly Permissive Preflight Configuration',
                'description': '; '.join(most_severe['issues']),
                'all_findings': findings,
                'response_headers': most_severe['response_headers']
            }
            
        return {'vulnerable': False}
    
    async def test_insecure_protocols(self, session: aiohttp.ClientSession, url: str) -> Dict:
        """Test for insecure protocol handling in CORS."""
        console.print("[dim]• Testing insecure protocol handling...[/dim]")
        
        test_origins = [
            "http://evil.com",
            "file://evil.com",
            "ftp://evil.com",
            "data:text/html,<script>alert('xss')</script>",
        ]
        
        vulnerable_protocols = []
        
        for test_origin in test_origins:
            headers = {'Origin': test_origin}
            response = await self.make_async_request(session, url, custom_headers=headers)
            
            if not response:
                continue
                
            acao_header = response['headers'].get('Access-Control-Allow-Origin', '')
            acac_header = response['headers'].get('Access-Control-Allow-Credentials', '').lower()
            
            if acao_header == test_origin:
                vulnerable_protocols.append({
                    'origin': test_origin,
                    'acao': acao_header,
                    'acac': acac_header
                })
        
        if vulnerable_protocols:
            has_credentials = any(vp['acac'] == 'true' for vp in vulnerable_protocols)
            severity = 'HIGH' if has_credentials else 'MEDIUM'
            
            return {
                'vulnerable': True,
                'severity': severity,
                'issue': 'Insecure Protocol Origins Allowed',
                'description': f'Server accepts {len(vulnerable_protocols)} insecure protocol origins',
                'vulnerable_protocols': vulnerable_protocols,
                'response_headers': vulnerable_protocols[0]
            }
        
        return {'vulnerable': False}
    
    async def test_vary_origin(self, session: aiohttp.ClientSession, url: str) -> Dict:
        """Test for proper Vary: Origin header implementation."""
        console.print("[dim]• Testing Vary: Origin header implementation...[/dim]")
        
        test_origins = [
            'https://example1.com',
            'https://example2.com',
            None  # No origin header
        ]
        
        responses = []
        
        for origin in test_origins:
            headers = {'Origin': origin} if origin else {}
            response = await self.make_async_request(session, url, custom_headers=headers)
            
            if response:
                responses.append({
                    'origin': origin,
                    'acao': response['headers'].get('Access-Control-Allow-Origin', ''),
                    'vary': response.get('vary_header', '').lower()
                })
        
        if len(responses) < 2:
            return {'vulnerable': False}
        
        # Check if responses vary but Vary: Origin is missing
        acao_values = [r['acao'] for r in responses if r['acao']]
        unique_acao = set(acao_values)
        has_vary_origin = any('origin' in r['vary'] for r in responses)
        
        if len(unique_acao) > 1 and not has_vary_origin:
            return {
                'vulnerable': True,
                'severity': 'LOW',
                'issue': 'Missing Vary: Origin Header',
                'description': 'Server returns different CORS headers for different origins but lacks Vary: Origin header - may cause caching issues',
                'response_analysis': responses
            }
        
        return {'vulnerable': False}
    
    async def test_advanced_credentials(self, session: aiohttp.ClientSession, url: str) -> Dict:
        """test for credential handling edge cases."""
        console.print("[dim]• Testing advanced credential handling...[/dim]")
        
        # Test various credential scenarios
        test_scenarios = [
            {'Origin': 'https://evil.com', 'Cookie': 'sessionid=test123'},
            {'Origin': 'https://attacker.net', 'Authorization': 'Bearer token123'},
            {'Origin': 'null', 'Cookie': 'auth=secret'},
        ]
        
        credential_issues = []
        
        for scenario in test_scenarios:
            response = await self.make_async_request(session, url, custom_headers=scenario)
            
            if not response:
                continue
                
            acao_header = response['headers'].get('Access-Control-Allow-Origin', '')
            acac_header = response['headers'].get('Access-Control-Allow-Credentials', '').lower()
            
            # Check for dangerous credential combinations
            if (acao_header == '*' and acac_header == 'true') or \
               (acao_header == scenario['Origin'] and acac_header == 'true'):
                credential_issues.append({
                    'scenario': scenario,
                    'acao': acao_header,
                    'acac': acac_header,
                    'risk': 'Credentials allowed with permissive origin'
                })
        
        if credential_issues:
            return {
                'vulnerable': True,
                'severity': 'HIGH',
                'issue': 'Advanced Credential Handling Issues',
                'description': f'Found {len(credential_issues)} credential handling vulnerabilities',
                'credential_issues': credential_issues
            }
        
        return {'vulnerable': False}
    
    async def run_all_tests_async(self, url: str) -> List[Dict]:
        """Execute all CORS tests asynchronously against the target URL."""
        console.print(f"\n\n\n[bold green][+] Starting  CORS scan for {url}...[/bold green]\n")
        
        # Initialize scan metadata with dynamic test count
        total_tests = len(self.test_registry)
        self.scan_metadata = {
            'target_url': url,
            'scan_time': datetime.datetime.now().isoformat(),
            'total_tests': total_tests,
            'completed_tests': 0,
            'async_enabled': True
        }
        
        self.findings = []
        
        # Create SSL context that doesn't verify certificates
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Create connector with SSL context
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent_requests,
            ssl=ssl_context
        )
        
        async with aiohttp.ClientSession(connector=connector) as session:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                
                # Run baseline test first
                baseline_task = progress.add_task("Running baseline test...", total=1)
                baseline = await self.test_baseline_request(session, url)
                progress.advance(baseline_task)
                progress.remove_task(baseline_task)
                
                if not baseline:
                    console.print("[bold red]Failed to establish baseline connection![/bold red]")
                    return []
                
                self.scan_metadata['baseline_status'] = baseline['status_code']
                
                # Create tasks for all vulnerability tests (excluding baseline)
                test_tasks = []
                progress_tasks = []
                
                for test_name, test_func in self.test_registry[1:]:  # Skip baseline test
                    if test_func != self.test_baseline_request:  # Double check
                        task_id = progress.add_task(f"Running {test_name.lower()}...", total=1)
                        progress_tasks.append(task_id)
                        test_tasks.append(test_func(session, url))
                
                # Execute all tests concurrently
                results = await asyncio.gather(*test_tasks, return_exceptions=True)
                
                # Process results and update progress
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        console.print(f"[bold red]Test failed: {str(result)}[/bold red]")
                    elif result and result.get('vulnerable'):
                        self.findings.append(result)
                    
                    if i < len(progress_tasks):
                        progress.advance(progress_tasks[i])
                        progress.remove_task(progress_tasks[i])
                    
                    self.scan_metadata['completed_tests'] += 1
        
        self.scan_metadata['total_vulnerabilities'] = len(self.findings)
        return self.findings
    
    def get_export_dir(self, base_export_dir: str = "reports/cors_scan") -> str:
        """Get export directory based on target domain and timestamp"""
        try:
            target_url = self.scan_metadata.get('target_url', 'unknown_target')
            parsed_url = urllib.parse.urlparse(target_url)
            domain = parsed_url.netloc.replace('.', '_')  
            
            scan_time = self.scan_metadata.get('scan_time', datetime.datetime.now())
            if isinstance(scan_time, str):
                scan_time = datetime.datetime.fromisoformat(scan_time)
            
            timestamp_str = scan_time.strftime("%Y%m%d_%H%M%S")
            
            folder_name = f"{domain}_{timestamp_str}"
            export_dir = os.path.join(base_export_dir, folder_name)
            
            return export_dir
            
        except Exception as e:
            console.print(f"[bold yellow]Warning: Could not create target-based folder: {e}[/bold yellow]")
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            return os.path.join(base_export_dir, f"scan_{timestamp}")
    
    def export_to_json(self, filename: str = None) -> str:
        """Export scan results to JSON format."""
        
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cors_scan_{timestamp}.json"
        
        export_dir = self.get_export_dir()
        os.makedirs(export_dir, exist_ok=True)
        full_path = os.path.join(export_dir, filename)
        
        export_data = {
            'scan_metadata': self.scan_metadata,
            'findings': self.findings,
            'enhancement_notes': {
                'dynamic_test_count': True,
                'async_scanning': True,
                'detection': True,
                'vary_header_checks': True,
                'preflight': True
            }
        }
        
        with open(full_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        return full_path
        
    def export_to_csv(self, filename: str = None) -> str:
        """Export scan results to CSV format."""
        
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cors_scan_{timestamp}.csv"
        
        export_dir = self.get_export_dir()
        os.makedirs(export_dir, exist_ok=True)
        full_path = os.path.join(export_dir, filename)
        
        with open(full_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Severity', 'Issue', 'Description', 'Test_Data', 'ACAO_Header', 'ACAC_Header', 'Vary_Header']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for finding in self.findings:
                row = {
                    'Severity': finding.get('severity', ''),
                    'Issue': finding.get('issue', ''),
                    'Description': finding.get('description', ''),
                    'Test_Data': str(finding.get('test_origin', finding.get('test_scenario', ''))),
                    'ACAO_Header': finding.get('response_headers', {}).get('Access-Control-Allow-Origin', ''),
                    'ACAC_Header': finding.get('response_headers', {}).get('Access-Control-Allow-Credentials', ''),
                    'Vary_Header': finding.get('response_headers', {}).get('Vary', '')
                }
                writer.writerow(row)
                
        return full_path        
    
    def export_to_txt(self, filename: str = None) -> str:
        """Export scan results to readable text format."""
        
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cors_scan_{timestamp}.txt"
        
        export_dir = self.get_export_dir()
        os.makedirs(export_dir, exist_ok=True)
        full_path = os.path.join(export_dir, filename)
        
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write("=== Scanned by DKrypt ===\n")
            f.write("CORS MISCONFIGURATION AUDIT REPORT\n")
            
            f.write(f"Target URL: {self.scan_metadata.get('target_url', 'N/A')}\n")
            f.write(f"Scan Time: {self.scan_metadata.get('scan_time', 'N/A')}\n")
            f.write(f"Total Tests Run: {self.scan_metadata.get('total_tests', 'N/A')}\n")
            f.write(f"Async Scanning: {self.scan_metadata.get('async_enabled', False)}\n")
            f.write(f"Total Vulnerabilities Found: {len(self.findings)}\n\n")
            
            if not self.findings:
                f.write("No CORS misconfigurations detected.\n")
                f.write("The target appears to have proper CORS configuration.\n")
            else:
                severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
                sorted_findings = sorted(self.findings, key=lambda x: severity_order.get(x['severity'], 4))
                
                for i, finding in enumerate(sorted_findings, 1):
                    f.write(f"{i}. [{finding['severity']}] {finding['issue']}\n")
                    f.write(f"   Description: {finding['description']}\n")
                    
                    # Handle different types of test data
                    if 'test_origin' in finding:
                        f.write(f"   Test Origin: {finding['test_origin']}\n")
                    elif 'test_scenario' in finding:
                        f.write(f"   Test Scenario: {finding['test_scenario']}\n")
                    elif 'vulnerable_origins' in finding:
                        f.write(f"   Vulnerable Origins: {len(finding['vulnerable_origins'])} found\n")
                    
                    f.write("   Response Headers:\n")
                    headers = finding.get('response_headers', {})
                    if isinstance(headers, dict):
                        for header, value in headers.items():
                            if value:
                                f.write(f"     {header}: {value}\n")
                    f.write("\n")
                
                # Summary statistics
                f.write("="*50 + "\n")
                f.write("SUMMARY STATISTICS\n")
                f.write("="*50 + "\n")
                critical_count = sum(1 for f in self.findings if f['severity'] == 'CRITICAL')
                high_count = sum(1 for f in self.findings if f['severity'] == 'HIGH')
                medium_count = sum(1 for f in self.findings if f['severity'] == 'MEDIUM')
                low_count = sum(1 for f in self.findings if f['severity'] == 'LOW')
                
                f.write(f"Critical Issues: {critical_count}\n")
                f.write(f"High Severity: {high_count}\n")
                f.write(f"Medium Severity: {medium_count}\n")
                f.write(f"Low Severity: {low_count}\n")
        
        return full_path
    
    def display_results(self, url: str, findings: List[Dict]):
        console.print(f"\n[bold cyan]╔═══ CORS Audit Results ═══╗[/bold cyan]")
        console.print(f"[bold white]Target: {url}[/bold white]")
        console.print(f"[dim]Tests Run: {self.scan_metadata.get('total_tests', 'N/A')} | Async: {self.scan_metadata.get('async_enabled', False)}[/dim]\n")
        
        if not findings:
            console.print("[green]└─ ✓ No CORS misconfiguration detected.[/green]")
            console.print("\n[dim]The target appears to have proper CORS configuration with all checks passed.[/dim]")
            return
        
        # Sort findings by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x['severity'], 4))
        
        for i, finding in enumerate(sorted_findings):
            severity = finding['severity']
            issue = finding['issue']
            description = finding['description']
            
            # color coding by severity
            severity_colors = {
                'CRITICAL': 'bold red on white',
                'HIGH': 'bold red', 
                'MEDIUM': 'bold yellow',
                'LOW': 'dim blue'
            }
            
            severity_icons = {
                'CRITICAL': '🔥',
                'HIGH': '⚠️ ',
                'MEDIUM': '⚡',
                'LOW': 'ℹ️ '
            }
            
            color = severity_colors.get(severity, 'white')
            icon = severity_icons.get(severity, '•')
            
            # Display finding with tree structure
            if i == len(sorted_findings) - 1:
                console.print(f"[{color}]└─ {icon} [{severity}] {issue}[/{color}]")
            else:
                console.print(f"[{color}]├─ {icon} [{severity}] {issue}[/{color}]")
            
            if i == len(sorted_findings) - 1:
                console.print(f"[dim]   └─ {description}[/dim]")
            else:
                console.print(f"[dim]│  └─ {description}[/dim]")
                
            if 'vulnerable_origins' in finding:
                count = len(finding['vulnerable_origins'])
                if i == len(sorted_findings) - 1:
                    console.print(f"[dim]      └─ Found {count} vulnerable origins[/dim]")
                else:
                    console.print(f"[dim]│     └─ Found {count} vulnerable origins[/dim]")
        
        #summary with statistics
        critical_count = sum(1 for f in findings if f['severity'] == 'CRITICAL')
        high_count = sum(1 for f in findings if f['severity'] == 'HIGH')
        medium_count = sum(1 for f in findings if f['severity'] == 'MEDIUM')
        low_count = sum(1 for f in findings if f['severity'] == 'LOW')
        
        console.print(f"\n[bold white]Scan Summary:[/bold white]")
        
        if critical_count > 0:
            console.print(f"[bold red on white]🔥 CRITICAL: {critical_count} - Immediate action required![/bold red on white]")
        if high_count > 0:
            console.print(f"[bold red]⚠️  HIGH: {high_count} - Security risk present[/bold red]")
        if medium_count > 0:
            console.print(f"[bold yellow]⚡ MEDIUM: {medium_count} - Potential vulnerabilities[/bold yellow]")
        if low_count > 0:
            console.print(f"[dim blue]ℹ️  LOW: {low_count} - Minor issues or recommendations[/dim blue]")
        
        console.print(f"[dim]Total issues found: {len(findings)}[/dim]")


def get_target_url():
    """Prompt user for target URL with validation."""
    while True:
        try:
            console.print("\n[bold cyan]╔═══ CORS Misconfiguration Auditor ═══╗[/bold cyan]")
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
            console.print(f"[green]✓ results exported to: {filename}[/green]")
        
        elif export_choice == "csv":
            filename = auditor.export_to_csv()
            console.print(f"[green]✓ results exported to: {filename}[/green]")
        
        elif export_choice == "txt":
            filename = auditor.export_to_txt()
            console.print(f"[green]✓ results exported to: {filename}[/green]")
        
        elif export_choice == "all":
            json_file = auditor.export_to_json()
            csv_file = auditor.export_to_csv()
            txt_file = auditor.export_to_txt()
            console.print(f"[green]✓ results exported to:[/green]")
            console.print(f"[green]  - JSON: {json_file}[/green]")
            console.print(f"[green]  - CSV: {csv_file}[/green]")
            console.print(f"[green]  - TXT: {txt_file}[/green]")
    
    except Exception as e:
        console.print(f"[bold red]Export failed: {str(e)}[/bold red]")


async def main_async(args=None):
    try:
        # Disable urllib3 warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        clear_console()
        header_banner(tool_name="CORS Scanner")

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
        
        auditor = CORSAuditor()
        
        start_time = time.time()
        findings = await auditor.run_all_tests_async(target_url)
        scan_duration = time.time() - start_time
        
        # Add performance metrics
        auditor.scan_metadata['scan_duration_seconds'] = round(scan_duration, 2)
        
        # Displayresults
        auditor.display_results(target_url, findings)
        
        console.print(f"\n[dim]Scan completed in {scan_duration:.2f} seconds with async processing[/dim]")
        
        if args:
            if export_format:
                if export_format == 'json':
                    filename = auditor.export_to_json(output_file)
                    console.print(f"[green]✓ results exported to: {filename}[/green]")
                elif export_format == 'csv':
                    filename = auditor.export_to_csv(output_file)
                    console.print(f"[green]✓ results exported to: {filename}[/green]")
                elif export_format == 'txt':
                    filename = auditor.export_to_txt(output_file)
                    console.print(f"[green]✓ results exported to: {filename}[/green]")
                    
                elif export_format == 'all':
                    json_file = auditor.export_to_json()
                    csv_file = auditor.export_to_csv()
                    txt_file = auditor.export_to_txt()
                    console.print(f"[green]✓ results exported to:[/green]")
                    console.print(f"[green]  - JSON: {json_file}[/green]")
                    console.print(f"[green]  - CSV: {csv_file}[/green]")
                    console.print(f"[green]  - TXT: {txt_file}[/green]")    
        else:
            # Handle export options
            handle_export_options(auditor)
        
        console.print(f"\n[bold green]✓ scan completed successfully![/bold green]")
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]scan interrupted by user. Exiting.[/bold yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Unexpected error in scanner: {str(e)}[/bold red]")
        sys.exit(1)


def main(args=None):
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user.[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")


if __name__ == "__main__":
    main()