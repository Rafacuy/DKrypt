#!/usr/bin/env python3
"""
Advanced WAF bypass tester module
DKrypt - Advanced WAF Header Bypass Testing Module

"""

import asyncio
import httpx
import csv
import json
import os
import time
import hashlib
import re
import random
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.spinner import Spinner
from rich.progress import Progress, TaskID

from core.utils import clear_console

console = Console()

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.abspath(os.path.join(BASE_DIR, "../reports"))

PROFILES_DIR = os.path.join(REPORTS_DIR, "waf_profiles")
RESULTS_DIR = os.path.join(REPORTS_DIR, "waf_results")
os.makedirs(PROFILES_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# Network settings
DEFAULT_TIMEOUT = 10
DEFAULT_RETRIES = 2
DEFAULT_DELAY = 1
DEFAULT_MAX_CONCURRENCY = 10
DEFAULT_JITTER = 0.5

# WAF Detection Patterns
WAF_FINGERPRINTS = {
    'cloudflare': [
        r'cloudflare', r'cf-ray', r'__cfduid', r'cf-cache-status'
    ],
    'incapsula': [
        r'incap_ses', r'visid_incap', r'incapsula'
    ],
    'akamai': [
        r'akamai', r'ak-bmsc', r'_abck'
    ],
    'f5-bigip': [
        r'f5-bigip', r'bigipserver', r'f5\s*big-?ip'
    ],
    'mod_security': [
        r'mod_security', r'modsecurity', r'mod.security'
    ],
    'aws-waf': [
        r'awswaf', r'aws.*waf', r'x-amzn-requestid'
    ],
    'sucuri': [
        r'sucuri', r'x-sucuri'
    ],
    'barracuda': [
        r'barracuda', r'barra'
    ]
}

WAF_ERROR_PATTERNS = [
    r'web application firewall',
    r'blocked by.*firewall',
    r'access denied.*security',
    r'forbidden.*waf',
    r'request blocked',
    r'security policy violation'
]

# --- Data Structures ---

@dataclass
class BaselineCapture:
    """Single baseline request/response data"""
    method: str
    status_code: int
    headers: Dict[str, str]
    content_length: int
    response_time: float
    body_hash: str
    body_snippet: str
    title: Optional[str]
    redirect_chain: List[str]
    waf_indicators: List[str]

@dataclass
class WAFFingerprint:
    """WAF detection results"""
    detected: bool
    vendor: Optional[str]
    confidence: float
    indicators: List[str]
    blocking_behavior: Optional[str]

@dataclass
class TestResult:
    """Individual test result with scoring"""
    test_id: str
    name: str
    headers: Dict[str, str]
    status_code: int
    content_length: int
    response_time: float
    body_hash: str
    body_snippet: str
    title: Optional[str]
    redirect_chain: List[str]
    bypass_score: float
    bypass_confirmed: bool
    contributing_signals: List[str]
    replay_count: int = 0

@dataclass
class ScanResults:
    """Complete scan results structure"""
    target_url: str
    method: str
    timestamp: float
    baseline: List[BaselineCapture]
    waf_fingerprint: WAFFingerprint
    tests: List[TestResult]
    config: Dict[str, Any]

# --- Header Preset Packs ---

HEADER_PACKS = {
    'identity_spoof': [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-For": "8.8.8.8"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"CF-Connecting-IP": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
    ],
    'routing_path': [
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Forwarded-Path": "/admin"},
        {"X-Forwarded-Host": "localhost"},
        {"Host": "localhost"},
        {"X-Host": "internal.domain.com"},
    ],
    'parser_tricks': [
        {"Content-Type": "application/json; charset=utf-8"},
        {"Content-Type": "text/plain"},
        {"Accept": "application/json, */*"},
        {"Accept-Encoding": "identity"},
        {"Transfer-Encoding": "chunked"},
        {"Content-Encoding": "gzip"},
    ],
    'tool_evasion': [
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        {"User-Agent": "GoogleBot/2.1"},
        {"User-Agent": "curl/7.68.0"},
        {"X-Requested-With": "XMLHttpRequest"},
        {"Cache-Control": "no-cache"},
        {"Pragma": "no-cache"},
    ]
}

# --- Pipeline Classes ---

class BaselineStage:
    """Stage 1: Capture multiple baseline requests"""
    
    def __init__(self, url: str, method: str = "GET", verify_tls: bool = False):
        self.url = url
        self.method = method.upper()
        self.verify_tls = verify_tls
        
    async def capture(self) -> List[BaselineCapture]:
        """Capture 2-3 baseline requests with variations"""
        baselines = []
        
        # Standard request
        baseline = await self._single_baseline({})
        if baseline:
            baselines.append(baseline)
        
        # Request with common headers
        baseline = await self._single_baseline({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5"
        })
        if baseline:
            baselines.append(baseline)
        
        # POST-specific baseline if method is POST
        if self.method == "POST":
            baseline = await self._single_baseline({
                "Content-Type": "application/x-www-form-urlencoded"
            })
            if baseline:
                baselines.append(baseline)
        
        return baselines
    
    async def _single_baseline(self, extra_headers: Dict[str, str]) -> Optional[BaselineCapture]:
        """Capture a single baseline request"""
        try:
            headers = {"User-Agent": "DKrypt-Baseline/1.0", **extra_headers}
            
            async with httpx.AsyncClient(
                timeout=DEFAULT_TIMEOUT, 
                verify=self.verify_tls, 
                follow_redirects=False
            ) as client:
                
                start_time = time.time()
                resp = await client.request(self.method, self.url, headers=headers)
                response_time = time.time() - start_time
                
                # Follow redirects manually to capture chain
                redirect_chain = []
                current_resp = resp
                redirect_count = 0
                
                while current_resp.is_redirect and redirect_count < 5:
                    redirect_chain.append(current_resp.headers.get('location', ''))
                    if 'location' in current_resp.headers:
                        current_resp = await client.get(current_resp.headers['location'])
                        redirect_count += 1
                    else:
                        break
                
                body_content = current_resp.content
                body_hash = hashlib.sha256(body_content).hexdigest()[:16]
                body_snippet = current_resp.text[:500] if current_resp.text else ""
                
                # Extract title
                title = None
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', body_snippet, re.IGNORECASE)
                if title_match:
                    title = title_match.group(1).strip()
                
                # Detect WAF indicators
                waf_indicators = self._detect_waf_indicators(current_resp)
                
                return BaselineCapture(
                    method=self.method,
                    status_code=current_resp.status_code,
                    headers=dict(current_resp.headers),
                    content_length=len(body_content),
                    response_time=response_time,
                    body_hash=body_hash,
                    body_snippet=body_snippet,
                    title=title,
                    redirect_chain=redirect_chain,
                    waf_indicators=waf_indicators
                )
                
        except Exception as e:
            console.print(f"[red]Baseline capture failed: {e}[/red]")
            return None
    
    def _detect_waf_indicators(self, resp: httpx.Response) -> List[str]:
        """Detect WAF indicators in response"""
        indicators = []
        text_content = resp.text.lower() if resp.text else ""
        
        # Check headers
        for header, value in resp.headers.items():
            for vendor, patterns in WAF_FINGERPRINTS.items():
                for pattern in patterns:
                    if re.search(pattern, f"{header}:{value}".lower()):
                        indicators.append(f"header:{vendor}:{header}")
        
        # Check body content
        for pattern in WAF_ERROR_PATTERNS:
            if re.search(pattern, text_content):
                indicators.append(f"body:{pattern}")
        
        return indicators


class FingerprintStage:
    """Stage 2: WAF detection and vendor identification"""
    
    def __init__(self, baselines: List[BaselineCapture]):
        self.baselines = baselines
    
    def analyze(self) -> WAFFingerprint:
        """Analyze baselines to detect WAF presence"""
        vendor_scores = {}
        all_indicators = []
        
        for baseline in self.baselines:
            all_indicators.extend(baseline.waf_indicators)
        
        # Score vendors based on indicators
        for indicator in all_indicators:
            if indicator.startswith("header:"):
                _, vendor, _ = indicator.split(":", 2)
                vendor_scores[vendor] = vendor_scores.get(vendor, 0) + 2
            elif indicator.startswith("body:"):
                # Generic body patterns - boost all vendors slightly
                for vendor in WAF_FINGERPRINTS.keys():
                    vendor_scores[vendor] = vendor_scores.get(vendor, 0) + 0.5
        
        # Determine best match
        detected = len(all_indicators) > 0
        vendor = None
        confidence = 0.0
        
        if vendor_scores:
            vendor = max(vendor_scores, key=vendor_scores.get)
            confidence = min(vendor_scores[vendor] / 5.0, 1.0)  # Normalize to 0-1
        
        # Determine blocking behavior
        blocking_behavior = None
        status_codes = [b.status_code for b in self.baselines]
        if any(code in [403, 401, 429, 503] for code in status_codes):
            blocking_behavior = "blocking"
        elif any(code in [301, 302] for code in status_codes):
            blocking_behavior = "redirect"
        else:
            blocking_behavior = "pass-through"
        
        return WAFFingerprint(
            detected=detected,
            vendor=vendor,
            confidence=confidence,
            indicators=list(set(all_indicators)),
            blocking_behavior=blocking_behavior
        )


class MutationEngine:
    """Stage 3: Generate header combinations and variations"""
    
    def __init__(self, max_combinations: int = 3):
        self.max_combinations = max_combinations
    
    def generate_mutations(self, 
                         selected_packs: List[str] = None,
                         custom_headers: List[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """Generate all header mutations"""
        mutations = []
        test_id = 1
        
        # Add selected preset packs
        if selected_packs:
            for pack_name in selected_packs:
                if pack_name in HEADER_PACKS:
                    for headers in HEADER_PACKS[pack_name]:
                        mutations.append({
                            "id": test_id,
                            "name": f"{pack_name.replace('_', ' ').title()} - {list(headers.keys())[0]}",
                            "headers": headers,
                            "pack": pack_name
                        })
                        test_id += 1
        
        # Add custom headers
        if custom_headers:
            for custom in custom_headers:
                mutations.append({
                    "id": test_id,
                    "name": f"Custom - {list(custom.keys())[0]}",
                    "headers": custom,
                    "pack": "custom"
                })
                test_id += 1
        
        # Generate combinations
        base_mutations = mutations.copy()
        for i, mut1 in enumerate(base_mutations):
            for j, mut2 in enumerate(base_mutations[i+1:], i+1):
                if len(mutations) >= 100:  # Limit total mutations
                    break
                
                combined_headers = {**mut1["headers"], **mut2["headers"]}
                mutations.append({
                    "id": test_id,
                    "name": f"Combo - {mut1['pack']}/{mut2['pack']}",
                    "headers": combined_headers,
                    "pack": "combination"
                })
                test_id += 1
        
        # Generate case variations for key headers
        case_variants = []
        important_headers = ["X-Forwarded-For", "X-Real-IP", "Host", "User-Agent"]
        
        for mutation in mutations[:20]:  # Only vary first 20 to avoid explosion
            for header_name in mutation["headers"]:
                if header_name in important_headers:
                    variants = [
                        header_name.lower(),
                        header_name.upper(),
                        header_name.replace('-', '_'),
                        header_name.replace('-', '')
                    ]
                    
                    for variant in variants:
                        if variant != header_name:
                            new_headers = mutation["headers"].copy()
                            value = new_headers.pop(header_name)
                            new_headers[variant] = value
                            
                            case_variants.append({
                                "id": test_id,
                                "name": f"Case Variant - {variant}",
                                "headers": new_headers,
                                "pack": "case_variant"
                            })
                            test_id += 1
        
        mutations.extend(case_variants)
        return mutations


class DecisionEngine:
    """Stage 4: Scoring and bypass confirmation"""
    
    def __init__(self, baselines: List[BaselineCapture]):
        self.baselines = baselines
        self.primary_baseline = baselines[0] if baselines else None
    
    def calculate_bypass_score(self, result: TestResult) -> Tuple[float, List[str]]:
        """Calculate bypass score using multiple metrics"""
        if not self.primary_baseline:
            return 0.0, ["No baseline available"]
        
        score = 0.0
        signals = []
        
        # Status Code Change (High Weight: 40 points)
        if self._is_status_improvement(self.primary_baseline.status_code, result.status_code):
            score += 40
            signals.append(f"Status improved: {self.primary_baseline.status_code} → {result.status_code}")
        
        # Content Length Change (Medium Weight: 20 points)
        length_ratio = self._calculate_length_ratio(
            self.primary_baseline.content_length, 
            result.content_length
        )
        if length_ratio > 0.3:  # Significant change
            score += 20 * min(length_ratio, 1.0)
            signals.append(f"Content length changed by {length_ratio:.1%}")
        
        # Title/Content Change (Medium Weight: 15 points)
        if self._has_content_change(result):
            score += 15
            signals.append("Content structure changed")
        
        # Redirect Chain Change (Low Weight: 10 points)
        if self._has_redirect_change(result):
            score += 10
            signals.append("Redirect behavior changed")
        
        # WAF Signature Disappearance (High Weight: 25 points)
        if self._waf_signature_disappeared(result):
            score += 25
            signals.append("WAF signatures disappeared")
        
        return min(score, 100.0), signals
    
    def _is_status_improvement(self, baseline_status: int, test_status: int) -> bool:
        """Check if status code improved (blocking → success)"""
        blocking_codes = [401, 403, 429, 503, 451]
        success_codes = range(200, 300)
        
        return baseline_status in blocking_codes and test_status in success_codes
    
    def _calculate_length_ratio(self, baseline_length: int, test_length: int) -> float:
        """Calculate content length change ratio"""
        if baseline_length == 0:
            return 1.0 if test_length > 0 else 0.0
        
        return abs(test_length - baseline_length) / baseline_length
    
    def _has_content_change(self, result: TestResult) -> bool:
        """Check for significant content changes"""
        if not self.primary_baseline:
            return False
        
        # Compare body hashes
        if result.body_hash != self.primary_baseline.body_hash:
            # Compare titles if available
            if self.primary_baseline.title and result.title:
                return self.primary_baseline.title != result.title
            return True
        
        return False
    
    def _has_redirect_change(self, result: TestResult) -> bool:
        """Check for redirect chain changes"""
        if not self.primary_baseline:
            return False
        
        return result.redirect_chain != self.primary_baseline.redirect_chain
    
    def _waf_signature_disappeared(self, result: TestResult) -> bool:
        """Check if WAF signatures present in baseline are missing in test"""
        if not self.primary_baseline or not self.primary_baseline.waf_indicators:
            return False
        
        # Simple heuristic: if baseline had WAF indicators in body and test doesn't
        baseline_body_indicators = [ind for ind in self.primary_baseline.waf_indicators if ind.startswith("body:")]
        
        if baseline_body_indicators:
            # Check if same patterns exist in test result
            test_text = result.body_snippet.lower()
            for indicator in baseline_body_indicators:
                pattern = indicator.split(":", 1)[1]
                if not re.search(pattern, test_text):
                    return True
        
        return False


class TestRunner:
    """Enhanced test runner with scoring and replay"""
    
    def __init__(self, url: str, method: str, baselines: List[BaselineCapture], 
                 config: Dict[str, Any]):
        self.url = url
        self.method = method
        self.baselines = baselines
        self.config = config
        self.decision_engine = DecisionEngine(baselines)
    
    async def run_test(self, test: Dict[str, Any]) -> TestResult:
        """Execute a single test with retry and scoring"""
        try:
            async with httpx.AsyncClient(
                timeout=self.config.get('timeout', DEFAULT_TIMEOUT),
                verify=self.config.get('verify_tls', False),
                follow_redirects=False
            ) as client:
                
                # Add jitter
                if self.config.get('jitter', 0) > 0:
                    await asyncio.sleep(random.uniform(0, self.config['jitter']))
                
                resp = await client.request(self.method, self.url, headers=test["headers"])
                
                # Follow redirects manually
                redirect_chain = []
                current_resp = resp
                redirect_count = 0
                
                while current_resp.is_redirect and redirect_count < 5:
                    location = current_resp.headers.get('location', '')
                    redirect_chain.append(location)
                    if location:
                        current_resp = await client.get(location)
                        redirect_count += 1
                    else:
                        break
                
                # Extract data
                body_content = current_resp.content
                body_hash = hashlib.sha256(body_content).hexdigest()[:16]
                body_snippet = current_resp.text[:500] if current_resp.text else ""
                
                title = None
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', body_snippet, re.IGNORECASE)
                if title_match:
                    title = title_match.group(1).strip()
                
                # Create initial result
                result = TestResult(
                    test_id=str(test["id"]),
                    name=test["name"],
                    headers=test["headers"],
                    status_code=current_resp.status_code,
                    content_length=len(body_content),
                    response_time=resp.elapsed.total_seconds(),
                    body_hash=body_hash,
                    body_snippet=body_snippet,
                    title=title,
                    redirect_chain=redirect_chain,
                    bypass_score=0.0,
                    bypass_confirmed=False,
                    contributing_signals=[]
                )
                
                # Calculate score
                score, signals = self.decision_engine.calculate_bypass_score(result)
                result.bypass_score = score
                result.contributing_signals = signals
                
                # Replay for confirmation if score is high
                if score >= 50.0:
                    confirmed = await self._replay_test(test, result)
                    result.bypass_confirmed = confirmed
                
                return result
                
        except Exception as e:
            return TestResult(
                test_id=str(test.get("id", "unknown")),
                name=test.get("name", "Unknown Test"),
                headers=test.get("headers", {}),
                status_code=0,
                content_length=0,
                response_time=0.0,
                body_hash="",
                body_snippet=f"Error: {str(e)}",
                title=None,
                redirect_chain=[],
                bypass_score=0.0,
                bypass_confirmed=False,
                contributing_signals=[f"Error: {str(e)}"]
            )
    
    async def _replay_test(self, test: Dict[str, Any], original_result: TestResult) -> bool:
        """Replay test to confirm bypass"""
        try:
            # Run the same test again
            replay_result = await self.run_test(test)
            replay_result.replay_count = 1
            
            # Compare results
            status_consistent = replay_result.status_code == original_result.status_code
            length_similar = abs(replay_result.content_length - original_result.content_length) < 100
            hash_same = replay_result.body_hash == original_result.body_hash
            
            # Confirm if results are consistent
            return status_consistent and (length_similar or hash_same)
            
        except Exception:
            return False


class WAFBypassTester:
    """Main orchestrator for the pipeline"""
    
    def __init__(self):
        self.config = {
            'timeout': DEFAULT_TIMEOUT,
            'retries': DEFAULT_RETRIES,
            'delay': DEFAULT_DELAY,
            'max_concurrency': DEFAULT_MAX_CONCURRENCY,
            'jitter': DEFAULT_JITTER,
            'verify_tls': False
        }
        self.last_results: Optional[ScanResults] = None
    
    async def run_pipeline(self, url: str, method: str = "GET", 
                          selected_packs: List[str] = None,
                          custom_headers: List[Dict[str, str]] = None) -> ScanResults:
        """Execute the complete pipeline"""
        
        # Stage 1: Baseline
        console.print("🔍 [bold]Stage 1: Capturing Baseline...[/bold]")
        baseline_stage = BaselineStage(url, method, self.config['verify_tls'])
        baselines = await baseline_stage.capture()
        
        if not baselines:
            raise Exception("Failed to capture baseline")
        
        # Stage 2: Fingerprint
        console.print("🕵️ [bold]Stage 2: WAF Fingerprinting...[/bold]")
        fingerprint_stage = FingerprintStage(baselines)
        waf_fingerprint = fingerprint_stage.analyze()
        
        if waf_fingerprint.detected:
            vendor_text = f" ({waf_fingerprint.vendor})" if waf_fingerprint.vendor else ""
            console.print(f"   WAF Detected{vendor_text} - Confidence: {waf_fingerprint.confidence:.1%}")
        else:
            console.print("   No WAF detected")
        
        # Stage 3: Mutation Engine
        console.print("🧬 [bold]Stage 3: Generating Mutations...[/bold]")
        mutation_engine = MutationEngine()
        mutations = mutation_engine.generate_mutations(selected_packs, custom_headers)
        console.print(f"   Generated {len(mutations)} test cases")
        
        # Stage 4: Decision & Replay
        console.print("⚡ [bold]Stage 4: Testing & Scoring...[/bold]")
        runner = TestRunner(url, method, baselines, self.config)
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.config['max_concurrency'])
        
        async def run_single_test(test):
            async with semaphore:
                return await runner.run_test(test)
        
        # Run tests with progress tracking
        with Progress() as progress:
            task = progress.add_task("[cyan]Running tests...", total=len(mutations))
            
            tasks = [run_single_test(test) for test in mutations]
            results = []
            
            for coro in asyncio.as_completed(tasks):
                result = await coro
                results.append(result)
                progress.update(task, advance=1)
        
        # Create final results structure
        scan_results = ScanResults(
            target_url=url,
            method=method,
            timestamp=time.time(),
            baseline=baselines,
            waf_fingerprint=waf_fingerprint,
            tests=results,
            config=self.config.copy()
        )
        
        self.last_results = scan_results
        return scan_results
    
    def export_json(self, results: ScanResults, filename: str = None) -> str:
        """Export results to JSON"""
        if not filename:
            timestamp = int(time.time())
            domain = urlparse(results.target_url).netloc.replace('.', '_')
            filename = f"waf_scan_{domain}_{timestamp}.json"
        
        filepath = os.path.join(RESULTS_DIR, filename)
        
        # Convert dataclasses to dicts
        data = asdict(results)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        
        return filepath
    
    def export_csv(self, results: ScanResults, filename: str = None) -> str:
        """Export results to CSV with sanitization"""
        if not filename:
            timestamp = int(time.time())
            domain = urlparse(results.target_url).netloc.replace('.', '_')
            filename = f"waf_scan_{domain}_{timestamp}.csv"
        
        filepath = os.path.join(RESULTS_DIR, filename)
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'test_id', 'name', 'headers', 'status_code', 'content_length',
                'response_time', 'bypass_score', 'bypass_confirmed', 
                'contributing_signals', 'body_hash'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for test in results.tests:
                row = {
                    'test_id': self._sanitize_csv_field(test.test_id),
                    'name': self._sanitize_csv_field(test.name),
                    'headers': self._sanitize_csv_field(str(test.headers)),
                    'status_code': test.status_code,
                    'content_length': test.content_length,
                    'response_time': round(test.response_time, 3),
                    'bypass_score': round(test.bypass_score, 2),
                    'bypass_confirmed': test.bypass_confirmed,
                    'contributing_signals': self._sanitize_csv_field('; '.join(test.contributing_signals)),
                    'body_hash': test.body_hash
                }
                writer.writerow(row)
        
        return filepath
    
    def _sanitize_csv_field(self, value: str) -> str:
        """Sanitize CSV fields to prevent injection"""
        if isinstance(value, str) and value.startswith(('=', '+', '-', '@')):
            return "'" + value
        return value


# --- TUI ---

class WAFTUI:
    """Enhanced Terminal User Interface"""
    
    def __init__(self):
        self.tester = WAFBypassTester()
        self.url: Optional[str] = None
        self.method: str = "GET"
        self.selected_packs: List[str] = []
        self.custom_headers: List[Dict[str, str]] = []
    
    def run(self):
        """Main application entry point"""
        try:
            self._main_loop()
        except KeyboardInterrupt:
            console.print("\n[bold yellow]👋 Goodbye![/bold yellow]")
        except Exception as e:
            console.print(f"\n[bold red]❌ Error: {e}[/bold red]")
    
    def _main_loop(self):
        """Main application loop"""
        self._show_header()
        
        if not self._configure_target():
            return
        
        while True:
            self._show_dashboard()
            choice = Prompt.ask(
                "Choose an action",
                choices=["1", "2", "3", "4", "5", "6", "s", "q"],
                default="s"
            )
            
            if choice == "1":
                self._select_header_packs()
            elif choice == "2":
                self._manage_custom_headers()
            elif choice == "3":
                self._configure_settings()
            elif choice == "4":
                self._load_profile()
            elif choice == "5":
                self._save_profile()
            elif choice == "6":
                self._view_results()
            elif choice.lower() == "s":
                asyncio.run(self._start_pipeline())
            elif choice.lower() == "q":
                break
    
    def _show_header(self):
        """Display application header"""
        clear_console()
        header_text = Text("WAF Bypass Tester", style="bold cyan")
        console.print(Panel(header_text, border_style="blue"))
    
    def _configure_target(self) -> bool:
        """Configure target URL and method"""
        self.url = Prompt.ask(
            "[bold]🎯 Target URL[/bold]",
            default="https://example.com/admin"
        )
        
        if not (self.url.startswith("http://") or self.url.startswith("https://")):
            self.url = "https://" + self.url
        
        self.method = Prompt.ask(
            "[bold]📡 HTTP Method[/bold]",
            choices=["GET", "POST", "PUT", "DELETE"],
            default="GET"
        )
        
        return True
    
    def _show_dashboard(self):
        """Display main dashboard"""
        self._show_header()
        
        # Target info
        console.print(f"🎯 [bold]Target:[/bold] {self.url} ([cyan]{self.method}[/cyan])")
        
        # Configuration status
        config_table = Table.grid(padding=(0, 2))
        config_table.add_column(style="bold")
        config_table.add_column()
        
        packs_status = f"[green]{len(self.selected_packs)} packs[/green]" if self.selected_packs else "[dim]None[/dim]"
        custom_status = f"[green]{len(self.custom_headers)} headers[/green]" if self.custom_headers else "[dim]None[/dim]"
        
        config_table.add_row("Header Packs:", packs_status)
        config_table.add_row("Custom Headers:", custom_status)
        config_table.add_row("Concurrency:", f"{self.tester.config['max_concurrency']}")
        config_table.add_row("TLS Verify:", f"{'✅' if self.tester.config['verify_tls'] else '❌'}")
        
        console.print(Panel(config_table, title="Configuration", border_style="blue"))
        
        # Actions menu
        actions = Table.grid(padding=(0, 1))
        actions.add_column(style="yellow bold")
        actions.add_column()
        
        actions.add_row("[1]", "Select Header Packs")
        actions.add_row("[2]", "Manage Custom Headers")
        actions.add_row("[3]", "Configure Settings")
        actions.add_row("[4]", "Load Profile")
        actions.add_row("[5]", "Save Profile")
        actions.add_row("[6]", "View Last Results")
        actions.add_row("")
        actions.add_row("[S]", "[bold green]🚀 START TEST[/bold green]")
        actions.add_row("[Q]", "Quit")
        
        console.print(Panel(actions, title="Actions", border_style="green"))
    
    def _select_header_packs(self):
        """Select predefined header packs"""
        console.print("\n--- [bold]Header Pack Selection[/bold] ---")
        console.print("[dim]Available packs with their purposes:[/dim]\n")
        
        pack_info = {
            'identity_spoof': 'IP spoofing and client identity manipulation',
            'routing_path': 'Host and path routing bypass attempts',
            'parser_tricks': 'Content-type and encoding manipulation',
            'tool_evasion': 'User-agent and request fingerprint evasion'
        }
        
        table = Table()
        table.add_column("Pack", style="cyan bold")
        table.add_column("Description")
        table.add_column("Selected", justify="center")
        
        for pack, desc in pack_info.items():
            selected = "✅" if pack in self.selected_packs else "❌"
            table.add_row(pack, desc, selected)
        
        console.print(table)
        
        selection = Prompt.ask(
            "\n[bold]Enter pack names (comma-separated) or 'all'[/bold]",
            default=",".join(self.selected_packs)
        )
        
        if selection.lower() == "all":
            self.selected_packs = list(pack_info.keys())
        else:
            selected = [p.strip() for p in selection.split(",") if p.strip() in pack_info]
            self.selected_packs = selected
        
        console.print(f"[green]✅ Selected: {self.selected_packs}[/green]")
        time.sleep(1)
    
    def _manage_custom_headers(self):
        """Manage custom header definitions"""
        while True:
            console.print("\n--- [bold]Custom Headers[/bold] ---")
            
            if not self.custom_headers:
                console.print("[dim]No custom headers defined.[/dim]")
            else:
                table = Table()
                table.add_column("#", style="cyan")
                table.add_column("Header", style="magenta")
                table.add_column("Value")
                
                for i, header in enumerate(self.custom_headers, 1):
                    key, value = list(header.items())[0]
                    table.add_row(str(i), key, value)
                
                console.print(table)
            
            action = Prompt.ask(
                "\n[bold]Action[/bold]",
                choices=["a", "d", "c", "b"],
                default="b"
            )
            
            if action == "a":  # Add
                key = Prompt.ask("Header name (e.g., X-Custom-Bypass)")
                value = Prompt.ask(f"Value for {key}")
                if key and value:
                    self.custom_headers.append({key: value})
                    console.print(f"[green]✅ Added {key}[/green]")
            
            elif action == "d":  # Delete
                if self.custom_headers:
                    choices = [str(i) for i in range(1, len(self.custom_headers) + 1)]
                    idx = int(Prompt.ask("Enter number to delete", choices=choices))
                    deleted = self.custom_headers.pop(idx - 1)
                    console.print(f"[red]🗑️ Deleted {list(deleted.keys())[0]}[/red]")
            
            elif action == "c":  # Clear
                if Confirm.ask("[yellow]Clear all custom headers?[/yellow]"):
                    self.custom_headers.clear()
                    console.print("[red]🗑️ All custom headers cleared[/red]")
            
            elif action == "b":  # Back
                break
    
    def _configure_settings(self):
        """Configure advanced settings"""
        console.print("\n--- [bold]Advanced Settings[/bold] ---")
        
        settings_table = Table()
        settings_table.add_column("Setting", style="bold")
        settings_table.add_column("Current Value", style="cyan")
        settings_table.add_column("Description")
        
        settings_table.add_row("Max Concurrency", str(self.tester.config['max_concurrency']), "Parallel requests")
        settings_table.add_row("Timeout", f"{self.tester.config['timeout']}s", "Request timeout")
        settings_table.add_row("Jitter", f"{self.tester.config['jitter']}s", "Random delay between requests")
        settings_table.add_row("TLS Verify", str(self.tester.config['verify_tls']), "Verify SSL certificates")
        
        console.print(settings_table)
        
        if Confirm.ask("\n[bold]Modify settings?[/bold]"):
            self.tester.config['max_concurrency'] = int(Prompt.ask(
                "Max Concurrency", default=str(self.tester.config['max_concurrency'])
            ))
            self.tester.config['timeout'] = int(Prompt.ask(
                "Timeout (seconds)", default=str(self.tester.config['timeout'])
            ))
            self.tester.config['jitter'] = float(Prompt.ask(
                "Jitter (seconds)", default=str(self.tester.config['jitter'])
            ))
            self.tester.config['verify_tls'] = Confirm.ask(
                "Verify TLS certificates?", default=self.tester.config['verify_tls']
            )
            
            console.print("[green]✅ Settings updated[/green]")
        
        time.sleep(1)
    
    def _save_profile(self):
        """Save current configuration to profile"""
        if not self.url:
            console.print("[red]❌ No target configured[/red]")
            return
        
        profile_name = Prompt.ask(
            "Profile name",
            default=urlparse(self.url).netloc.replace('.', '_')
        )
        
        if not profile_name:
            return
        
        profile_data = {
            "url": self.url,
            "method": self.method,
            "selected_packs": self.selected_packs,
            "custom_headers": self.custom_headers,
            "config": self.tester.config
        }
        
        filepath = os.path.join(PROFILES_DIR, f"{profile_name}.json")
        with open(filepath, 'w') as f:
            json.dump(profile_data, f, indent=2)
        
        console.print(f"[green]✅ Profile saved: {filepath}[/green]")
        time.sleep(1)
    
    def _load_profile(self):
        """Load configuration from profile"""
        profiles = [f.replace('.json', '') for f in os.listdir(PROFILES_DIR) if f.endswith('.json')]
        
        if not profiles:
            console.print("[yellow]⚠️ No profiles found[/yellow]")
            time.sleep(1)
            return
        
        profile_name = Prompt.ask("Select profile", choices=profiles)
        filepath = os.path.join(PROFILES_DIR, f"{profile_name}.json")
        
        with open(filepath, 'r') as f:
            profile_data = json.load(f)
        
        self.url = profile_data.get("url")
        self.method = profile_data.get("method", "GET")
        self.selected_packs = profile_data.get("selected_packs", [])
        self.custom_headers = profile_data.get("custom_headers", [])
        
        if "config" in profile_data:
            self.tester.config.update(profile_data["config"])
        
        console.print(f"[green]✅ Profile '{profile_name}' loaded[/green]")
        time.sleep(1)
    
    async def _start_pipeline(self):
        """Execute the complete testing pipeline"""
        if not self.selected_packs and not self.custom_headers:
            console.print("[red]❌ No tests configured! Select header packs or add custom headers.[/red]")
            time.sleep(2)
            return
        
        try:
            results = await self.tester.run_pipeline(
                self.url,
                self.method,
                self.selected_packs,
                self.custom_headers
            )
            
            self._display_pipeline_results(results)
            
        except Exception as e:
            console.print(f"[bold red]❌ Pipeline failed: {e}[/bold red]")
            time.sleep(2)
    
    def _display_pipeline_results(self, results: ScanResults):
        """Display comprehensive pipeline results"""
        console.print("\n" + "="*60)
        console.print("🎉 [bold green]Pipeline Complete![/bold green]")
        console.print("="*60)
        
        # WAF Fingerprint Summary
        waf = results.waf_fingerprint
        if waf.detected:
            vendor_text = f" - {waf.vendor.upper()}" if waf.vendor else ""
            console.print(f"🛡️ [bold red]WAF Detected{vendor_text}[/bold red] (Confidence: {waf.confidence:.1%})")
            console.print(f"   Blocking Behavior: {waf.blocking_behavior}")
        else:
            console.print("🔓 [bold green]No WAF Detected[/bold green]")
        
        # Results Summary
        total_tests = len(results.tests)
        bypasses_found = sum(1 for t in results.tests if t.bypass_confirmed)
        high_scores = sum(1 for t in results.tests if t.bypass_score >= 50)
        
        summary_table = Table.grid(padding=(0, 2))
        summary_table.add_column(style="bold")
        summary_table.add_column()
        
        summary_table.add_row("Total Tests:", str(total_tests))
        summary_table.add_row("High Scores (≥50):", f"[yellow]{high_scores}[/yellow]")
        summary_table.add_row("Confirmed Bypasses:", f"[red]{bypasses_found}[/red]" if bypasses_found else f"[green]{bypasses_found}[/green]")
        
        console.print(Panel(summary_table, title="📊 Summary", border_style="blue"))
        
        # Top Results Table
        top_results = sorted(results.tests, key=lambda x: x.bypass_score, reverse=True)[:10]
        
        results_table = Table(title="🏆 Top 10 Results by Score")
        results_table.add_column("ID", style="cyan")
        results_table.add_column("Test Name")
        results_table.add_column("Score", justify="right")
        results_table.add_column("Status", justify="center")
        results_table.add_column("Confirmed", justify="center")
        results_table.add_column("Key Signals")
        
        for result in top_results:
            score_style = "red" if result.bypass_score >= 70 else "yellow" if result.bypass_score >= 50 else "dim"
            confirmed_icon = "🔥" if result.bypass_confirmed else "❓" if result.bypass_score >= 50 else "❌"
            
            # Truncate signals for display
            signals = "; ".join(result.contributing_signals[:2])
            if len(result.contributing_signals) > 2:
                signals += f" (+{len(result.contributing_signals) - 2} more)"
            
            results_table.add_row(
                result.test_id,
                result.name[:30] + "..." if len(result.name) > 30 else result.name,
                f"[{score_style}]{result.bypass_score:.1f}[/{score_style}]",
                str(result.status_code),
                confirmed_icon,
                signals[:50] + "..." if len(signals) > 50 else signals
            )
        
        console.print(results_table)
        
        # Action prompt
        if bypasses_found > 0:
            console.print(f"\n[bold red]⚠️ {bypasses_found} confirmed bypass(es) detected![/bold red]")
        
        action = Prompt.ask(
            "\n[bold]Next action[/bold]",
            choices=["d", "e", "j", "c", "m"],
            default="m"
        )
        
        if action == "d":
            self._detailed_results_view(results)
        elif action == "e":
            self._export_results(results)
        elif action == "j":
            self._export_results(results, format="json")
        elif action == "c":
            self._export_results(results, format="csv")
        # elif action == "m": return to main menu
    
    def _detailed_results_view(self, results: ScanResults):
        """Show detailed drill-down view"""
        while True:
            # Show all results
            table = Table(title="📋 All Test Results")
            table.add_column("ID", style="cyan")
            table.add_column("Name")
            table.add_column("Score", justify="right")
            table.add_column("Status")
            table.add_column("Confirmed")
            
            for result in sorted(results.tests, key=lambda x: x.bypass_score, reverse=True):
                score_style = "red" if result.bypass_score >= 70 else "yellow" if result.bypass_score >= 50 else "dim"
                confirmed = "🔥" if result.bypass_confirmed else "❓" if result.bypass_score >= 50 else "❌"
                
                table.add_row(
                    result.test_id,
                    result.name[:40] + "..." if len(result.name) > 40 else result.name,
                    f"[{score_style}]{result.bypass_score:.1f}[/{score_style}]",
                    str(result.status_code),
                    confirmed
                )
            
            console.print(table)
            
            choices = [r.test_id for r in results.tests] + ["b"]
            selection = Prompt.ask(
                "\n[bold]Select test ID for details (or 'b' for back)[/bold]",
                choices=choices,
                default="b"
            )
            
            if selection == "b":
                break
            
            # Show detailed view
            result = next((r for r in results.tests if r.test_id == selection), None)
            if result:
                self._show_test_details(result, results.baseline[0] if results.baseline else None)
    
    def _show_test_details(self, result: TestResult, baseline: Optional[BaselineCapture]):
        """Show detailed information for a single test"""
        console.print(f"\n📋 [bold]Test Details: {result.name}[/bold]")
        
        # Test info
        info_table = Table.grid(padding=(0, 2))
        info_table.add_column(style="bold")
        info_table.add_column()
        
        info_table.add_row("Test ID:", result.test_id)
        info_table.add_row("Headers:", str(result.headers))
        info_table.add_row("Bypass Score:", f"[red]{result.bypass_score:.1f}/100[/red]" if result.bypass_score >= 50 else f"{result.bypass_score:.1f}/100")
        info_table.add_row("Confirmed:", "🔥 YES" if result.bypass_confirmed else "❌ No")
        info_table.add_row("Replay Count:", str(result.replay_count))
        
        console.print(Panel(info_table, title="Test Information"))
        
        # Comparison table
        if baseline:
            comp_table = Table()
            comp_table.add_column("Metric", style="bold")
            comp_table.add_column("Baseline", style="dim")
            comp_table.add_column("Test Result", style="cyan")
            comp_table.add_column("Change")
            
            comp_table.add_row(
                "Status Code",
                str(baseline.status_code),
                str(result.status_code),
                "🔥" if baseline.status_code != result.status_code else "➖"
            )
            
            length_change = result.content_length - baseline.content_length
            comp_table.add_row(
                "Content Length",
                f"{baseline.content_length}B",
                f"{result.content_length}B",
                f"{'📈' if length_change > 0 else '📉' if length_change < 0 else '➖'} ({length_change:+d}B)"
            )
            
            time_change = result.response_time - baseline.response_time
            comp_table.add_row(
                "Response Time",
                f"{baseline.response_time*1000:.0f}ms",
                f"{result.response_time*1000:.0f}ms",
                f"{'🐌' if time_change > 0.5 else '⚡' if time_change < -0.1 else '➖'} ({time_change*1000:+.0f}ms)"
            )
            
            comp_table.add_row(
                "Body Hash",
                baseline.body_hash,
                result.body_hash,
                "🔄" if baseline.body_hash != result.body_hash else "➖"
            )
            
            console.print(Panel(comp_table, title="📊 Baseline Comparison"))
        
        # Contributing signals
        if result.contributing_signals:
            signals_text = "\n".join([f"• {signal}" for signal in result.contributing_signals])
            console.print(Panel(signals_text, title="🔍 Contributing Signals", border_style="yellow"))
        
        # Response preview
        preview = result.body_snippet[:300] + "..." if len(result.body_snippet) > 300 else result.body_snippet
        console.print(Panel(preview, title="📄 Response Preview", border_style="dim"))
        
        Prompt.ask("\n[dim]Press Enter to continue...[/dim]", default="")
    
    def _export_results(self, results: ScanResults, format: str = "both"):
        """Export results in specified format"""
        if format in ["both", "json"]:
            json_path = self.tester.export_json(results)
            console.print(f"[green]✅ JSON exported: {json_path}[/green]")
        
        if format in ["both", "csv"]:
            csv_path = self.tester.export_csv(results)
            console.print(f"[green]✅ CSV exported: {csv_path}[/green]")
        
        time.sleep(2)
    
    def _view_results(self):
        """View last results if available"""
        if not self.tester.last_results:
            console.print("[yellow]⚠️ No results available. Run a scan first.[/yellow]")
            time.sleep(2)
            return
        
        self._display_pipeline_results(self.tester.last_results)


# --- CLI Interface ---

async def cli_mode(url: str, method: str = "GET", 
                  packs: List[str] = None, 
                  output: str = None,
                  max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
                  verify_tls: bool = False):
    """Command-line interface for automated scanning"""
    
    console.print("🚀 [bold]DKrypt WAF Bypass Tester - CLI Mode[/bold]\n")
    
    tester = WAFBypassTester()
    tester.config.update({
        'max_concurrency': max_concurrency,
        'verify_tls': verify_tls
    })
    
    # Use all packs if none specified
    if not packs:
        packs = list(HEADER_PACKS.keys())
    
    try:
        results = await tester.run_pipeline(url, method, packs)
        
        # Display summary
        bypasses = sum(1 for t in results.tests if t.bypass_confirmed)
        high_scores = sum(1 for t in results.tests if t.bypass_score >= 50)
        
        console.print(f"\n📊 [bold]Results Summary[/bold]")
        console.print(f"   Total Tests: {len(results.tests)}")
        console.print(f"   High Scores: [yellow]{high_scores}[/yellow]")
        console.print(f"   Confirmed Bypasses: [red]{bypasses}[/red]")
        
        if results.waf_fingerprint.detected:
            vendor = results.waf_fingerprint.vendor or "Unknown"
            console.print(f"   WAF Detected: [red]{vendor.upper()}[/red]")
        
        # Auto-export
        if output:
            if output.endswith('.json'):
                json_path = tester.export_json(results, output)
                console.print(f"\n[green]✅ Results exported to: {json_path}[/green]")
            elif output.endswith('.csv'):
                csv_path = tester.export_csv(results, output)
                console.print(f"\n[green]✅ Results exported to: {csv_path}[/green]")
        else:
            # Export both formats with auto-naming
            json_path = tester.export_json(results)
            csv_path = tester.export_csv(results)
            console.print(f"\n[green]✅ Results exported:[/green]")
            console.print(f"   JSON: {json_path}")
            console.print(f"   CSV: {csv_path}")
        
        return results
        
    except Exception as e:
        console.print(f"[bold red]❌ Scan failed: {e}[/bold red]")
        return None


# --- Main Entry Point ---

def main():
    """Main application entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="DKrypt WAF Bypass Tester")
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--method", default="GET", choices=["GET", "POST", "PUT", "DELETE"])
    parser.add_argument("--packs", nargs="+", choices=list(HEADER_PACKS.keys()), 
                       help="Header packs to use")
    parser.add_argument("--output", help="Output file (JSON/CSV)")
    parser.add_argument("--max-concurrency", type=int, default=DEFAULT_MAX_CONCURRENCY)
    parser.add_argument("--verify-tls", action="store_true", help="Verify TLS certificates")
    parser.add_argument("--cli", action="store_true", help="Use CLI mode (non-interactive)")
    
    args = parser.parse_args()
    
    if args.cli and args.url:
        # CLI mode
        asyncio.run(cli_mode(
            args.url, 
            args.method, 
            args.packs, 
            args.output,
            args.max_concurrency,
            args.verify_tls
        ))
    else:
        # Interactive TUI mode
        tui = WAFTUI()
        tui.run()


if __name__ == "__main__":
    main()