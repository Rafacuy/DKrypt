# core_crawler.py
"""
This module contains the core web crawling and scraping logic.
"""
import asyncio
import os
import re
import tempfile
import socket
import urllib.robotparser
import weakref
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

import aiohttp
import phonenumbers
from aiodns import DNSResolver
from appium import webdriver as appium_webdriver
from appium.options.android import UiAutomator2Options
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from rich.progress import (BarColumn, Progress, SpinnerColumn, TextColumn,
                           TimeRemainingColumn)

from core.randomizer import HeaderFactory
from .config_ui import CrawlConfig, console


class RobotsTxtChecker:
    """Handles robots.txt compliance checking with async support."""

    def __init__(self, session: aiohttp.ClientSession):
        self.robots_cache: Dict[str, urllib.robotparser.RobotFileParser] = {}
        self.session = session
        self._cache_lock = asyncio.Lock()

    async def can_fetch(self, url: str, user_agent: str = "*") -> bool:
        """Check if URL can be fetched according to robots.txt."""
        try:
            parsed_url = urlparse(url)
            domain = f"{parsed_url.scheme}://{parsed_url.netloc}"

            async with self._cache_lock:
                if domain not in self.robots_cache:
                    robots_url = urljoin(domain, '/robots.txt')
                    rp = urllib.robotparser.RobotFileParser()
                    rp.set_url(robots_url)

                    try:
                        # Use async request for robots.txt
                        async with self.session.get(robots_url, timeout=10) as response:
                            if response.status == 200:
                                robots_content = await response.text()
                                # Create a temporary file for robots parser
                                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
                                    tmp.write(robots_content)
                                    tmp.flush()
                                    rp.set_url(f"file://{tmp.name}")
                                    rp.read()
                                # Clean up temp file
                                os.unlink(tmp.name)
                            else:
                                # If no robots.txt, allow everything
                                rp = None
                    except Exception:
                        # If can't fetch robots.txt, allow everything
                        rp = None

                    self.robots_cache[domain] = rp

            rp = self.robots_cache[domain]
            return rp.can_fetch(user_agent, url) if rp else True

        except Exception:
            return True

class BrowserManager:
    """Manages browser instances for JavaScript rendering with proper resource management."""

    def __init__(self, config: CrawlConfig):
        self.config = config
        self.driver = None
        self._driver_lock = asyncio.Lock()
        self._is_closed = False

        # Register cleanup on exit
        weakref.finalize(self, self._cleanup_driver, self.driver)

    async def __aenter__(self):
        """Async context manager entry."""
        await self._setup_driver()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def _setup_driver(self):
        """Setup the appropriate driver based on configuration."""
        if self._is_closed:
            raise RuntimeError("BrowserManager has been closed")

        async with self._driver_lock:
            if self.driver is not None:
                return

            try:
                if self.config.android_mode:
                    await self._setup_android_driver()
                else:
                    await self._setup_chrome_driver()
            except Exception as e:
                console.log(f"[bold red]Failed to setup browser driver: {e}[/bold red]")
                self.driver = None
                raise

    async def _setup_chrome_driver(self):
        """Setup Chrome/Chromium driver."""
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--window-size=1920,1080')
        options.add_argument('--disable-blink-features=AutomationControlled')
        options.add_argument('--disable-extensions')
        options.add_argument('--disable-plugins')
        options.add_argument('--disable-images')  # Faster loading
        options.add_argument('--disable-javascript-harmony-shipping')
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)

        try:
            # Run driver setup in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            self.driver = await loop.run_in_executor(None, self._create_chrome_driver, options)

            if self.driver:
                # Execute anti-detection script
                await loop.run_in_executor(
                    None,
                    self.driver.execute_script,
                    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
                )
        except Exception as e:
            console.log(f"[yellow]Chrome driver setup failed: {e}. Trying with default path...[/yellow]")
            try:
                loop = asyncio.get_event_loop()
                service = Service()
                self.driver = await loop.run_in_executor(
                    None,
                    lambda: webdriver.Chrome(service=service, options=options)
                )
            except Exception as e2:
                console.log(f"[red]Chrome driver completely failed: {e2}[/red]")
                raise e2

    def _create_chrome_driver(self, options):
        """Create Chrome driver in thread pool."""
        return webdriver.Chrome(options=options)

    async def _setup_android_driver(self):
        """Setup Android driver via Appium with configurable options."""
        options = UiAutomator2Options()
        android_config = self.config.android_config

        options.platform_name = android_config.platform_name
        options.browser_name = android_config.browser_name
        options.device_name = android_config.device_name
        options.platform_version = android_config.platform_version
        options.new_command_timeout = android_config.new_command_timeout

        try:
            loop = asyncio.get_event_loop()
            self.driver = await loop.run_in_executor(
                None,
                lambda: appium_webdriver.Remote(
                    command_executor=android_config.appium_server_url,
                    options=options
                )
            )

            # Set implicit wait
            if self.driver:
                await loop.run_in_executor(
                    None,
                    self.driver.implicitly_wait,
                    android_config.implicit_wait
                )

        except Exception as e:
            console.log(f"[red]Android driver setup failed: {e}[/red]")
            raise e

    async def render_page(self, url: str) -> Optional[str]:
        """Render a page with JavaScript and return HTML."""
        if self._is_closed or not self.driver:
            return None

        async with self._driver_lock:
            if self._is_closed or not self.driver:
                return None

            try:
                loop = asyncio.get_event_loop()

                # Navigate to page
                await loop.run_in_executor(None, self.driver.get, url)

                # Wait for page to load
                wait = WebDriverWait(self.driver, 10)
                await loop.run_in_executor(
                    None,
                    wait.until,
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )

                # Additional wait for dynamic content
                await asyncio.sleep(2)

                # Get page source
                page_source = await loop.run_in_executor(None, lambda: self.driver.page_source)
                return page_source

            except (TimeoutException, WebDriverException) as e:
                console.log(f"[yellow]Browser rendering failed for {url}: {e}[/yellow]")
                return None
            except Exception as e:
                console.log(f"[red]Unexpected error rendering {url}: {e}[/red]")
                return None

    @staticmethod
    def _cleanup_driver(driver):
        """Static method for cleanup during finalization."""
        if driver:
            try:
                driver.quit()
            except Exception:
                pass

    async def close(self):
        """Close the browser driver safely."""
        async with self._driver_lock:
            if not self._is_closed and self.driver:
                try:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, self.driver.quit)
                except Exception:
                    pass
                finally:
                    self.driver = None
                    self._is_closed = True


class WebCrawler:
    """web crawler with multi-layer crawling and JavaScript rendering."""

    def __init__(self, config: CrawlConfig, header_factory: HeaderFactory):
        self.config = config
        self.header_factory = header_factory
        self.visited_urls: Set[str] = set()
        self.url_lock = asyncio.Lock()  # Thread-safe access to visited_urls
        self.semaphore = asyncio.Semaphore(config.max_concurrent)
        self.session: Optional[aiohttp.ClientSession] = None
        self.robots_checker: Optional[RobotsTxtChecker] = None
        self.browser_manager: Optional[BrowserManager] = None
        self._closed = False

    async def __aenter__(self):
        """Async context manager entry."""
        # Setup session with proper timeout configuration
        timeout = aiohttp.ClientTimeout(
            total=self.config.request_timeout + 10,
            connect=10,
            sock_read=self.config.request_timeout
        )

        resolver = DNSResolver(nameservers=["1.1.1.1", "8.8.8.8"])
        connector = aiohttp.TCPConnector(
            limit=self.config.max_concurrent,
            limit_per_host=10,
            ttl_dns_cache=300,
            use_dns_cache=True,
            resolver=resolver,
        )

        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector
        )

        # Initialize robots checker with session
        if self.config.respect_robots:
            self.robots_checker = RobotsTxtChecker(self.session)

        # Initialize browser manager if needed
        if self.config.use_javascript:
            self.browser_manager = BrowserManager(self.config)
            await self.browser_manager._setup_driver()

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def close(self):
        """Clean up all resources."""
        if self._closed:
            return

        self._closed = True

        # Close browser manager
        if self.browser_manager:
            await self.browser_manager.close()
            self.browser_manager = None

        # Close HTTP session
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for consistent comparison."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        try:
            parsed = urlparse(url)
            # Remove fragment and normalize
            normalized = urlunparse((
                parsed.scheme,
                parsed.netloc.lower(),
                parsed.path.rstrip('/') or '/',
                parsed.params,
                parsed.query,
                ''  # Remove fragment
            ))
            return normalized
        except Exception:
            return url

    def _is_same_domain(self, url1: str, url2: str) -> bool:
        """Check if two URLs belong to the same domain."""
        try:
            domain1 = urlparse(url1).netloc.lower()
            domain2 = urlparse(url2).netloc.lower()
            return domain1 == domain2
        except Exception:
            return False

    async def _is_url_visited(self, url: str) -> bool:
        """Thread-safe check if URL has been visited."""
        normalized_url = self._normalize_url(url)
        async with self.url_lock:
            return normalized_url in self.visited_urls

    async def _mark_url_visited(self, url: str) -> bool:
        """Thread-safe marking of URL as visited. Returns True if newly added."""
        normalized_url = self._normalize_url(url)
        async with self.url_lock:
            if normalized_url in self.visited_urls:
                return False
            self.visited_urls.add(normalized_url)
            return True

    async def _acquire_semaphore_with_timeout(self) -> bool:
        """Acquire semaphore with timeout to prevent deadlocks."""
        try:
            await asyncio.wait_for(
                self.semaphore.acquire(),
                timeout=self.config.semaphore_timeout
            )
            return True
        except asyncio.TimeoutError:
            console.log("[red]Semaphore acquisition timeout - potential deadlock avoided[/red]")
            return False

    async def _fetch_with_retry(self, url: str) -> Optional[Tuple[str, str]]:
        """Fetch URL with retry mechanism and exponential backoff."""
        if not await self._acquire_semaphore_with_timeout():
            return None

        try:
            for attempt in range(self.config.max_retries + 1):
                try:
                    # Check if crawler is closed
                    if self._closed:
                        return None

                    # Check robots.txt
                    if self.robots_checker and not await self.robots_checker.can_fetch(url):
                        console.log(f"[yellow]Blocked by robots.txt: {url}[/yellow]")
                        return None

                    # Try JavaScript rendering first if enabled
                    if self.browser_manager and not self._closed:
                        try:
                            html = await self.browser_manager.render_page(url)
                            if html:
                                return html, url
                        except Exception as e:
                            console.log(f"[yellow]Browser rendering failed for {url}: {e}[/yellow]")
                        # Fallback to regular HTTP if browser fails

                    # Regular HTTP request
                    if self.session and not self.session.closed:
                        headers = self.header_factory.get_headers()

                        async with self.session.get(
                            url,
                            headers=headers,
                            timeout=self.config.request_timeout,
                            allow_redirects=True
                        ) as response:

                            # Handle specific error codes that warrant retry
                            if response.status in [429, 500, 502, 503, 504]:
                                if attempt < self.config.max_retries:
                                    delay = self.config.retry_delay * (2 ** attempt)
                                    console.log(f"[yellow]Status {response.status} for {url}, retrying in {delay:.1f}s (attempt {attempt + 1})[/yellow]")
                                    await asyncio.sleep(delay)
                                    continue

                            if response.status == 403:
                                console.log(f"[bold yellow]Access forbidden (403): {url}[/bold yellow]")
                                return None
                            if response.status == 404:
                                console.log(f"[yellow]Not found (404): {url}[/yellow]")
                                return None

                            response.raise_for_status()

                            content_type = response.headers.get('Content-Type', '')
                            if 'text/html' not in content_type:
                                console.log(f"[yellow]Skipped {url}: Content-Type '{content_type}' is not HTML[/yellow]")
                                return None

                            html = await response.text()
                            return html, str(response.url)
                    else:
                        console.log(f"[red]Session closed, cannot fetch {url}[/red]")
                        return None

                except asyncio.TimeoutError:
                    if attempt < self.config.max_retries:
                        delay = self.config.retry_delay * (2 ** attempt)
                        console.log(f"[yellow]Timeout for {url}, retrying in {delay:.1f}s (attempt {attempt + 1})[/yellow]")
                        await asyncio.sleep(delay)
                    else:
                        console.log(f"[bold red]Timeout error (final): {url}[/bold red]")

                except aiohttp.ClientError as e:
                    if attempt < self.config.max_retries:
                        delay = self.config.retry_delay * (2 ** attempt)
                        console.log(f"[yellow]Client error for {url}: {e}, retrying in {delay:.1f}s (attempt {attempt + 1})[/yellow]")
                        await asyncio.sleep(delay)
                    else:
                        console.log(f"[bold red]Client error (final) for {url}: {e}[/bold red]")

                except Exception as e:
                    console.log(f"[bold red]Unexpected error for {url}: {e}[/bold red]")
                    break

        finally:
            self.semaphore.release()

        return None

    def _extract_metadata(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Extract key metadata from a BeautifulSoup object."""
        try:
            title_tag = soup.find('title')
            title = title_tag.get_text().strip() if title_tag else "No Title Found"

            metadata = {
                'title': title,
                'description': '',
                'keywords': '',
                'og_properties': {},
                'other_meta': []
            }

            for tag in soup.find_all('meta'):
                try:
                    name = tag.get('name', '').lower()
                    prop = tag.get('property', '').lower()
                    content = tag.get('content', '')

                    if name == 'description':
                        metadata['description'] = content
                    elif name == 'keywords':
                        metadata['keywords'] = content
                    elif prop.startswith('og:'):
                        metadata['og_properties'][prop[3:]] = content
                    else:
                        if name or prop:
                            metadata['other_meta'].append({'name': name or prop, 'content': content})
                except Exception:
                    continue

            return metadata
        except Exception as e:
            console.log(f"[yellow]Error extracting metadata: {e}[/yellow]")
            return {'title': 'Error extracting metadata', 'description': '', 'keywords': '', 'og_properties': {}, 'other_meta': []}

    def _extract_contacts(self, soup: BeautifulSoup, text: str) -> Dict[str, List[str]]:
        """Extract email addresses and phone numbers from HTML and text content."""
        emails = set()
        phones = set()

        try:
            # Extract from mailto links
            for link in soup.find_all('a', href=True):
                try:
                    href = link['href']
                    if href.startswith('mailto:'):
                        email = href[7:].split('?')[0]  # Remove query parameters
                        if '@' in email and '.' in email.split('@')[1]:
                            emails.add(email)
                except Exception:
                    continue

            # Extract from tel links
            for link in soup.find_all('a', href=True):
                try:
                    href = link['href']
                    if href.startswith('tel:'):
                        phone = href[4:]
                        phones.add(phone)
                except Exception:
                    continue

            # Extract emails from text using regex
            try:
                email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                text_emails = set(re.findall(email_regex, text))
                emails.update(text_emails)
            except Exception:
                pass

            # Extract phone numbers from text using phonenumbers library
            try:
                for match in phonenumbers.PhoneNumberMatcher(text, "ZZ"):
                    formatted_number = phonenumbers.format_number(
                        match.number, phonenumbers.PhoneNumberFormat.INTERNATIONAL
                    )
                    phones.add(formatted_number)
            except Exception:
                pass

        except Exception as e:
            console.log(f"[yellow]Error extracting contacts: {e}[/yellow]")

        return {
            'emails': sorted(list(emails)),
            'phones': sorted(list(phones))
        }

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> Dict[str, List[str]]:
        """Extract and categorize all links from a page."""
        links: Dict[str, Set[str]] = {'internal': set(), 'external': set(), 'assets': set()}

        try:
            parsed_base = urlparse(base_url)

            for tag in soup.find_all(['a', 'link', 'img', 'script', 'source']):
                try:
                    url = tag.get('href') or tag.get('src')
                    if not url or url.startswith(('mailto:', 'tel:', 'javascript:', '#')):
                        continue

                    absolute_url = urljoin(base_url, url)
                    parsed_url = urlparse(absolute_url)

                    # Skip invalid URLs
                    if not parsed_url.netloc:
                        continue

                    if any(absolute_url.lower().endswith(ext) for ext in
                           ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp',
                            '.pdf', '.doc', '.docx', '.zip', '.mp3', '.mp4', '.avi')):
                        links['assets'].add(absolute_url)
                    elif parsed_url.netloc.lower() == parsed_base.netloc.lower():
                        links['internal'].add(absolute_url)
                    else:
                        links['external'].add(absolute_url)
                except Exception:
                    continue
        except Exception as e:
            console.log(f"[yellow]Error extracting links: {e}[/yellow]")

        return {key: sorted(list(value)) for key, value in links.items()}

    async def _scrape_single_url(self, url: str, depth: int) -> Optional[Dict[str, Any]]:
        """Scrape a single URL and return structured data."""
        if self._closed:
            return None

        # Check if already visited (thread-safe)
        if not await self._mark_url_visited(url):
            return None

        try:
            fetch_result = await self._fetch_with_retry(url)
            if not fetch_result:
                return None

            html, final_url = fetch_result
            soup = BeautifulSoup(html, 'html.parser')
            text_content = soup.get_text(separator=' ', strip=True)

            domain_info = urlparse(final_url)
            metadata = self._extract_metadata(soup)
            contacts = self._extract_contacts(soup, text_content)
            links = self._extract_links(soup, final_url)

            return {
                "source_url": url,
                "final_url": final_url,
                "domain_info": {
                    "scheme": domain_info.scheme,
                    "netloc": domain_info.netloc,
                    "path": domain_info.path,
                },
                "metadata": metadata,
                "contacts": contacts,
                "links": links,
                "link_counts": {k: len(v) for k, v in links.items()},
                "crawl_depth": depth
            }
        except Exception as e:
            console.log(f"[red]Error scraping {url}: {e}[/red]")
            return None

    async def crawl_urls(self, seed_urls: List[str]) -> List[Dict[str, Any]]:
        """Crawl URLs with specified depth using BFS approach."""
        if self._closed:
            return []

        all_results = []
        urls_processed = 0

        # Initialize crawl queue with seed URLs at depth 0
        crawl_queue = deque()
        for url in seed_urls:
            crawl_queue.append((url, 0))

        # Track URLs by domain for internal link filtering
        seed_domains = set()
        for url in seed_urls:
            try:
                parsed = urlparse(self._normalize_url(url))
                seed_domains.add(parsed.netloc.lower())
            except Exception:
                continue

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console,
        ) as progress:

            # Estimate total URLs (this will be updated as we discover more)
            total_estimate = len(seed_urls)
            task = progress.add_task("[green]Crawling URLs...", total=total_estimate)

            while crawl_queue and urls_processed < self.config.max_urls_per_crawl and not self._closed:
                # Process current batch
                current_batch = []
                batch_size = min(self.config.max_concurrent, len(crawl_queue))

                for _ in range(batch_size):
                    if crawl_queue and urls_processed < self.config.max_urls_per_crawl:
                        current_batch.append(crawl_queue.popleft())

                if not current_batch:
                    break

                # Create tasks for current batch (only for unvisited URLs)
                tasks = []
                for url, depth in current_batch:
                    if not await self._is_url_visited(url) and not self._closed:
                        task_coro = self._scrape_single_url(url, depth)
                        tasks.append((task_coro, url, depth))

                # Execute batch with proper error handling
                if tasks:
                    try:
                        task_results = await asyncio.gather(
                            *[task[0] for task in tasks],
                            return_exceptions=True
                        )

                        # Process results and queue next level URLs
                        for i, result in enumerate(task_results):
                            if self._closed:
                                break

                            urls_processed += 1

                            if isinstance(result, Exception):
                                console.log(f"[red]Task exception: {result}[/red]")
                                continue

                            if result:
                                all_results.append(result)

                                # Queue internal links for next depth level
                                _, original_url, depth = tasks[i]
                                if (depth < self.config.max_depth and
                                        urls_processed < self.config.max_urls_per_crawl and
                                        not self._closed):

                                    try:
                                        domain = urlparse(result['final_url']).netloc.lower()
                                        if domain in seed_domains:
                                            # Limit internal links to prevent memory overflow
                                            internal_links = result['links']['internal'][:50]  # Limit to 50 per page
                                            for internal_url in internal_links:
                                                if not await self._is_url_visited(internal_url):
                                                    crawl_queue.append((internal_url, depth + 1))

                                                    # Break if we've queued too many URLs
                                                    if len(crawl_queue) > 500:  # Limit queue size
                                                        break
                                    except Exception as e:
                                        console.log(f"[yellow]Error processing links from {result['final_url']}: {e}[/yellow]")

                            # Update progress
                            queue_size = len(crawl_queue)
                            if queue_size > total_estimate - urls_processed:
                                total_estimate = urls_processed + min(queue_size, self.config.max_urls_per_crawl - urls_processed)
                                progress.update(task, total=total_estimate)

                            progress.update(task, advance=1)

                    except Exception as e:
                        console.log(f"[red]Batch processing error: {e}[/red]")
                        # Continue with next batch even if current batch fails
                        continue

        return all_results
