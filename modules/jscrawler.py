#modules/jscrawler.py
from __future__ import annotations

import csv
import json
import re
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

#Networking
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib import robotparser

# Concurrency
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TimeRemainingColumn,
    SpinnerColumn,
)
from rich.table import Table
from rich.text import Text

# Selenium check will be handled dynamically
try:
    from selenium import webdriver  # type: ignore
    from selenium.webdriver.chrome.options import Options  # type: ignore
    from selenium.common.exceptions import WebDriverException  # type: ignore
    _SELENIUM_PKG_AVAILABLE = True
except Exception:
    _SELENIUM_PKG_AVAILABLE = False

from core.utils import clear_console, header_banner
from core.randomizer import HeaderFactory

console = Console()

# --- Configuration dataclass -------------------------------------------------

@dataclass
class JSCrawlerConfig:
    request_timeout: int = 15
    max_workers: int = 8
    retry_total: int = 3
    backoff_factor: float = 0.5
    respect_robots: bool = True
    rate_limit_delay: float = 0.5  # seconds between requests to same domain
    allow_selenium: bool = True
    output_format: str = "text"  # 'text', 'json', or 'csv'
    verify_ssl: bool = True
    max_js_size_bytes: int = 5 * 1024 * 1024  # 5 MB


# --- Patterns & helpers ------------------------------------------------------
PATTERNS: Dict[str, List[str]] = {
    "endpoints": [
        r"\bfetch\s*\(\s*[\'\"](?P<url>https?://[^\'\"]+)",
        r"\baxios\.(?:get|post|put|delete|patch)\s*\(\s*[\'\"](?P<url>https?://[^\'\"]+)",
        r"\bfetch\s*\(\s*[\'\"](?P<rel>/[^\'\"]+)",
        r"\baxios\.(?:get|post|put|delete|patch)\s*\(\s*[\'\"](?P<rel>/[^\'\"]+)",
        r"\b\$\.(?:get|post|ajax)\s*\(\s*[\'\"](?P<rel>/[^\'\"]+)",
        r"\bXMLHttpRequest\s*\(\)?.*?open\s*\(\s*[\'\"](?:GET|POST|PUT|DELETE|PATCH)[\'\"]\s*,\s*[\'\"](?P<rel>/[^\'\"]+)",
        # direct string endpoints
        r"[\'\"](?P<rel>/[a-zA-Z0-9_\-/.]{2,200})(?:[\'\"])",
        r"[\'\"](?P<url>https?://[a-zA-Z0-9_.-]+(?:\:[0-9]+)?/[\w\-\./?=&%~+#:,]{2,400})[\'\"]",
    ],
    "secrets": [
        # common secret formats
        r"(?P<stripe>sk_live_[0-9a-zA-Z]{24,})",
        r"(?P<stripe_test>sk_test_[0-9a-zA-Z]{24,})",
        r"(?P<google>AIza[0-9A-Za-z\-_]{35})",
        r"(?P<aws_id>AKIA[0-9A-Z]{16})",
        r"(?P<gh>gh[pousr]_[0-9A-Za-z]{36})",
        r"(?P<jwt>eyJ[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+)",
        r"(?P<bearer>Bearer\s+[0-9A-Za-z\-\._~\+\/]+=*)",
        r"(?P<generic_key>['\"]?(?:api|apikey|api_key|access_token|secret|secret_key)['\"]?\s*[:=]\s*['\"](?P<val>[^'\"]{8,200})['\"])",
    ],
}

# Static file extensions to ignore for endpoint-like matches
_STATIC_EXTS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".ico",
    ".css",
    ".map",
}


def is_probable_endpoint(url: str) -> bool:
    """Heuristics to filter out false positives for endpoints."""
    if not url:
        return False
    url = url.strip()
    if url.startswith("data:"):
        return False
    lower = url.lower()
    for ext in _STATIC_EXTS:
        if lower.endswith(ext):
            return False
    # Exclude very short tokens or single chars
    if len(url) < 3:
        return False
    # exclude template literals or JS expressions
    if "${" in url or "}" in url:
        return False
    return True


# --- Selenium availability check --------------------------------------------

def check_selenium_availability() -> Tuple[bool, Optional[str]]:
    """
    Check whether Selenium package is installed and whether a Chrome driver is usable.
    Returns: (available: bool, reason: Optional[str])
    """
    if not _SELENIUM_PKG_AVAILABLE:
        return False, "selenium package not installed"

    # Attempt to instantiate a headless Chrome WebDriver briefly.
    try:
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-dev-shm-usage")
        # Try to create a driver
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(5)
        driver.quit()
        return True, None
    except WebDriverException as e:
        return False, f"webdriver error: {e}"
    except Exception as e:  # pragma: no cover - defensive
        return False, f"unknown selenium error: {e}"


# --- Main crawler class -----------------------------------------------------

class JSCrawler:
    def __init__(self, config: Optional[JSCrawlerConfig] = None) -> None:
        self.config = config or JSCrawlerConfig()
        self.session = requests.Session()
        self.session.verify = self.config.verify_ssl

        self.header_factory = HeaderFactory(pool_size=1000)

        # Setup retry strategy for requests
        retries = Retry(
            total=self.config.retry_total,
            backoff_factor=self.config.backoff_factor,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "POST"),
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        # Results
        self.js_files: Set[str] = set()
        self._endpoints_set: Set[Tuple[str, str]] = set()  # (endpoint, source)
        self._secrets_set: Set[Tuple[str, str, str]] = set()  # (secret, type, source)

        # Rate limiting
        self._domain_last_request: Dict[str, float] = {}
        self._lock = threading.Lock()

    # ---- Utility methods -------------------------------------------------
    def normalize_url(self, link: str, base: str) -> str:
        return urljoin(base, link)

    def _enforce_rate_limit(self, url: str) -> None:
        domain = urlparse(url).netloc
        now = time.time()
        with self._lock:
            last = self._domain_last_request.get(domain)
            if last:
                delta = now - last
                if delta < self.config.rate_limit_delay:
                    wait = self.config.rate_limit_delay - delta
                    time.sleep(wait)
            self._domain_last_request[domain] = time.time()

    def _safe_get(self, url: str, stream: bool = False) -> Optional[requests.Response]:
        """Perform a GET with retries/backoff using session. Returns None on unrecoverable error."""
        try:
            self._enforce_rate_limit(url)
            headers = self.header_factory.get_headers()
            resp = self.session.get(
                url,
                headers=headers,
                timeout=self.config.request_timeout,
                stream=stream
            )
            resp.raise_for_status()
            return resp
        except requests.RequestException as e:
            # Already retried by adapter - we present a clear message.
            console.print(f"[yellow]Request failed for {url}: {e}")
            return None

    # ---- Discovery -------------------------------------------------------
    def discover_js_files_requests(self, url: str) -> Set[str]:
        """Discover JS files from HTML using requests (no JS execution)."""
        found: Set[str] = set()
        resp = self._safe_get(url)
        if not resp:
            return found

        text = resp.text
        # script tags with src
        for m in re.finditer(r"<script[^>]+src=[\'\"](?P<src>[^\'\"]+\.js(?:\?[^\'\"]*)?)[\'\"][^>]*>", text, re.IGNORECASE):
            src = m.group("src")
            full = self.normalize_url(src, url)
            found.add(full)

        # Find javascript file references in HTML (href/src attributes)
        for m in re.finditer(r"[\'\"](?P<file>https?://[^\'\"]+\.js(?:\?[^\'\"]*)?)[\'\"]", text, re.IGNORECASE):
            found.add(m.group("file"))

        return found

    def discover_js_files_selenium(self, url: str) -> Set[str]:
        """Discover JS files by loading with Selenium (if available).
        This function assumes Selenium availability has been checked by check_selenium_availability().
        """
        if not _SELENIUM_PKG_AVAILABLE:
            console.print("[yellow]Selenium package not available; skipping Selenium discovery.")
            return set()

        try:
            options = Options()
            options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument(f"--user-agent={self.config.user_agent}")
            driver = webdriver.Chrome(options=options)
        except Exception as e:
            console.print(f"[yellow]Selenium driver error: {e}")
            return set()

        found: Set[str] = set()
        try:
            driver.set_page_load_timeout(30)
            driver.get(url)
            scripts = driver.find_elements("tag name", "script")
            for s in scripts:
                src = s.get_attribute("src")
                if src and src.lower().endswith(".js"):
                    found.add(src)
        except Exception as e:  # pragma: no cover - best effort
            console.print(f"[yellow]Selenium discovery issue: {e}")
        finally:
            try:
                driver.quit()
            except Exception:
                pass

        return found

    # ---- Download & analyze ----------------------------------------------
    def download_js(self, js_url: str) -> str:
        """Download JS content with safety checks (size limit). Returns empty string if failed."""
        resp = self._safe_get(js_url, stream=True)
        if not resp:
            return ""

        # Respect size limit
        try:
            content_chunks = []
            total = 0
            for chunk in resp.iter_content(chunk_size=8192):
                if not chunk:
                    break
                total += len(chunk)
                if total > self.config.max_js_size_bytes:
                    console.print(f"[yellow]Skipping {js_url}: exceeds max size {self.config.max_js_size_bytes} bytes")
                    return ""
                content_chunks.append(chunk)
            return b"".join(content_chunks).decode(errors="replace")
        finally:
            try:
                resp.close()
            except Exception:
                pass

    def extract_from_content(self, content: str, source: str) -> None:
        """Extract endpoints & secrets and add to deduplicated sets."""
        # Endpoints
        for pattern in PATTERNS["endpoints"]:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                groupdict = m.groupdict()
                candidate = groupdict.get("url") or groupdict.get("rel") or next((v for v in groupdict.values() if v), None)
                if not candidate:
                    # fallback to first group
                    try:
                        candidate = m.group(1)
                    except Exception:
                        candidate = None
                if not candidate:
                    continue
                candidate = candidate.strip()
                # Normalize relative
                if candidate.startswith("/"):
                    endpoint = candidate
                else:
                    endpoint = candidate
                if not is_probable_endpoint(endpoint):
                    continue
                key = (endpoint, source)
                if key not in self._endpoints_set:
                    self._endpoints_set.add(key)

        # Secrets
        for pattern in PATTERNS["secrets"]:
            for m in re.finditer(pattern, content):
                # attempt to pick named group if present
                secret = None
                gd = m.groupdict()
                if gd:
                    # Prefer explicit val group
                    if "val" in gd and gd["val"]:
                        secret = gd["val"]
                    else:
                        for v in gd.values():
                            if v:
                                secret = v
                                break
                else:
                    try:
                        secret = m.group(0)
                    except Exception:
                        secret = None

                if not secret:
                    continue
                secret = secret.strip()
                if len(secret) < 8:
                    continue
                s_type = self.identify_secret_type(secret)
                tup = (secret, s_type, source)
                if tup not in self._secrets_set:
                    self._secrets_set.add(tup)

    def identify_secret_type(self, secret: str) -> str:
        s = secret
        if s.startswith("sk_"):
            return "Stripe Secret"
        if s.startswith("AIza"):
            return "Google API Key"
        if s.startswith("AKIA"):
            return "AWS Access Key ID"
        if s.startswith("gh"):
            return "GitHub Token"
        if s.startswith("eyJ"):
            return "JWT"
        if s.lower().startswith("bearer"):
            return "Bearer Token"
        # heuristics
        if "api" in s.lower() or "key" in s.lower() or "token" in s.lower():
            return "Potential API Key / Token"
        return "Unknown"

    # ---- Orchestration --------------------------------------------------
    def crawl(self, url: str, use_selenium: bool = False) -> Dict[str, Iterable]:
        console.print(f"\n[blue]Starting crawl of: {url}")

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # robots.txt
        if self.config.respect_robots:
            rp = robotparser.RobotFileParser()
            robots_url = urljoin(base, "/robots.txt")
            try:
                rp.set_url(robots_url)
                rp.read()
                if not rp.can_fetch(self.config.user_agent, url):
                    console.print(f"[red]Blocked by robots.txt: {url}")
                    return {"endpoints": [], "secrets": [], "js_files": []}
            except Exception:
                # If robots can't be fetched, default to proceeding but warn
                console.print(f"[yellow]Could not fetch robots.txt ({robots_url}) — proceeding")

        # Discover JS files
        discovered: Set[str] = set()
        discovered.update(self.discover_js_files_requests(url))
        if use_selenium and self.config.allow_selenium:
            discovered.update(self.discover_js_files_selenium(url))

        if not discovered:
            console.print("[red]No JavaScript files found!")
            return {"endpoints": [], "secrets": [], "js_files": []}

        self.js_files = discovered
        console.print(f"[green]Found {len(self.js_files)} JavaScript files")

        # Concurrent download & analyze with progress
        progress = Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeRemainingColumn(),
            console=console,
        )

        download_task = progress.add_task("Processing JS files", total=len(self.js_files))

        # ThreadPool to download & analyze
        with progress:
            with ThreadPoolExecutor(max_workers=self.config.max_workers) as ex:
                futures = {}
                for js in sorted(self.js_files):
                    futures[ex.submit(self._download_and_extract_worker, js)] = js

                for fut in as_completed(futures):
                    js = futures[fut]
                    try:
                        fut.result()
                    except Exception as e:  # pragma: no cover - catch worker exceptions
                        console.print(f"[yellow]Worker error for {js}: {e}")
                    finally:
                        progress.advance(download_task)

        # Prepare results lists from sets (preserve insertion-like order by sorting)
        endpoints = sorted(list(self._endpoints_set))
        secrets = sorted(list(self._secrets_set))

        return {"endpoints": endpoints, "secrets": secrets, "js_files": sorted(self.js_files)}

    def _download_and_extract_worker(self, js_url: str) -> None:
        content = self.download_js(js_url)
        if content:
            self.extract_from_content(content, js_url)

    # ---- Output saving --------------------------------------------------
    def save_results(self, results: Dict[str, Iterable], output_file: str, target_url: str) -> bool:
        fmt = self.config.output_format.lower()
        
        reports_dir = Path("reports/jscrawler")
        reports_dir.mkdir(parents=True, exist_ok=True)
    
        p = reports_dir / output_file
        try:
            if fmt == "json" or p.suffix.lower() == ".json":
                data = {
                    "target": target_url,
                    "js_files": list(results.get("js_files", [])),
                    "endpoints": [ {"endpoint": e, "source": s} for e, s in results.get("endpoints", []) ],
                    "secrets": [ {"secret": v, "type": t, "source": s} for v, t, s in results.get("secrets", []) ],
                }
                p.write_text(json.dumps(data, indent=2), encoding="utf-8")
                return True

            if fmt == "csv" or p.suffix.lower() == ".csv":
                # create two CSVs grouped into a folder if filename given is a folder-like or prefix
                base = str(p.with_suffix("") )
                # endpoints
                with open(f"{base}_endpoints.csv", "w", newline="", encoding="utf-8") as fh:
                    writer = csv.writer(fh)
                    writer.writerow(["endpoint", "source"])
                    for e, s in results.get("endpoints", []):
                        writer.writerow([e, s])
                # secrets
                with open(f"{base}_secrets.csv", "w", newline="", encoding="utf-8") as fh:
                    writer = csv.writer(fh)
                    writer.writerow(["secret", "type", "source"])
                    for v, t, s in results.get("secrets", []):
                        writer.writerow([v, t, s])
                # js files
                with open(f"{base}_jsfiles.csv", "w", newline="", encoding="utf-8") as fh:
                    writer = csv.writer(fh)
                    writer.writerow(["js_file"])
                    for j in results.get("js_files", []):
                        writer.writerow([j])
                return True

            # default: human readable text
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(f"JS Crawler Results for: {target_url}\n")
                fh.write("=" * 80 + "\n\n")
                fh.write(f"JS Files Analyzed ({len(results.get('js_files', []))}):\n")
                fh.write("-" * 30 + "\n")
                for js in results.get("js_files", []):
                    fh.write(f"• {js}\n")
                fh.write("\n")

                fh.write(f"Discovered Endpoints ({len(results.get('endpoints', []))}):\n")
                fh.write("-" * 30 + "\n")
                for e, s in results.get("endpoints", []):
                    fh.write(f"• {e}\n  Source: {s}\n\n")

                fh.write(f"Discovered Secrets ({len(results.get('secrets', []))}):\n")
                fh.write("-" * 30 + "\n")
                for v, t, s in results.get("secrets", []):
                    fh.write(f"• Type: {t}\n  Value: {v}\n  Source: {s}\n\n")
            return True
        except Exception as e:
            console.print(f"[red]Error saving results: {e}")
            return False


# --- UI / Display helpers --------------------------------------------------

def display_disclaimer() -> None:
    disclaimer_text = Text()
    disclaimer_text.append("⚠️  SECURITY DISCLAIMER ⚠️\n\n", style="bold red")
    disclaimer_text.append("This tool is intended ", style="white")
    disclaimer_text.append("ONLY", style="bold red")
    disclaimer_text.append(" for authorized security testing or bug bounty purposes.\n", style="white")
    disclaimer_text.append("Do not use it without explicit permission from the target website owner.\n\n", style="white")
    disclaimer_text.append("Unauthorized use may violate laws and terms of service.", style="yellow")
    panel = Panel(disclaimer_text, title="⚡ JS Crawler & Endpoint Extractor ⚡", border_style="red")
    console.print(panel)


def display_results(results: Dict[str, Iterable], output_file: str) -> None:
    console.print("\n" + "=" * 60)
    console.print("[bold green]CRAWLING RESULTS")
    console.print("=" * 60)

    endpoints = list(results.get("endpoints", []))
    secrets = list(results.get("secrets", []))

    if endpoints:
        t = Table(title="🔍 Discovered Endpoints", show_header=True, header_style="bold yellow")
        t.add_column("Endpoint", style="cyan")
        t.add_column("Source File", style="dim")
        for e, s in endpoints:
            t.add_row(e, s)
        console.print(t)
    else:
        console.print("[yellow]No endpoints found.")

    if secrets:
        t2 = Table(title="🔐 Discovered Secrets & Tokens", show_header=True, header_style="bold red")
        t2.add_column("Secret/Token", style="red")
        t2.add_column("Type", style="yellow")
        t2.add_column("Source File", style="dim")
        for v, ttype, s in secrets:
            display_val = v if len(v) <= 60 else v[:60] + "..."
            t2.add_row(display_val, ttype, s)
        console.print(t2)
    else:
        console.print("[green]No secrets or tokens found.")

    summary = (
        f"JS Files Analyzed: {len(results.get('js_files', []))}\n"
        f"Unique Endpoints: {len(endpoints)}\n"
        f"Secrets/Tokens: {len(secrets)}\n"
        f"Results saved to: {output_file}"
    )
    console.print(Panel(summary, title="📊 Summary", border_style="green"))


# --- CLI / main -----------------------------------------------------------

def main() -> None:
    clear_console()
    header_banner(tool_name="JS Crawler")
    display_disclaimer()

    target_url = Prompt.ask("🎯 Target URL")
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    # Selenium availability check
    selenium_available, selenium_reason = check_selenium_availability()
    use_selenium = False
    if selenium_available and JSCrawlerConfig().allow_selenium:
        use_selenium = Confirm.ask("🔄 Enable JS Rendering (Selenium)?", default=False)
    else:
        if JSCrawlerConfig().allow_selenium:
            console.print(f"[yellow]Selenium unavailable: {selenium_reason}; continuing without Selenium")

    # Output format prompt hint
    parsed = urlparse(target_url)
    domain_hint = parsed.netloc.replace(".", "_")
    default_filename = f"{domain_hint}_findings.txt"
    output_file = Prompt.ask("📁 Output file (use .json or .csv suffix for machine formats)", default=default_filename)

    # Determine format from suffix if user provided
    cfg = JSCrawlerConfig()
    if output_file.lower().endswith(".json"):
        cfg.output_format = "json"
    elif output_file.lower().endswith(".csv"):
        cfg.output_format = "csv"
    else:
        cfg.output_format = "text"

    # Allow user to tweak some settings interactively (quick toggle)
    if Confirm.ask("⚙️ Respect robots.txt?", default=cfg.respect_robots):
        cfg.respect_robots = True
    else:
        cfg.respect_robots = False

    # Build crawler
    crawler = JSCrawler(config=cfg)

    try:
        results = crawler.crawl(target_url, use_selenium=use_selenium)
        display_results(results, output_file)
        saved = crawler.save_results(results, output_file, target_url)
        if saved:
            console.print(f"[green]Results saved to {output_file}")
        else:
            console.print("[red]Failed to save results")
    except KeyboardInterrupt:
        console.print("\n[yellow]Crawling interrupted by user.")
    except Exception as e:  # pragma: no cover - guard
        console.print(f"[red]Unexpected error during crawl: {e}")


if __name__ == "__main__":
    main()
