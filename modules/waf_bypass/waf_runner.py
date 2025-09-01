# modules/waf_bypass/waf_runner.py
"""
Handles the execution and orchestration of the WAF bypass tests.
- TestRunner: Executes a single test case with scoring and replay logic.
- WAFBypassTester: The main orchestrator that runs the entire pipeline.
"""

import asyncio
import httpx
import time
import hashlib
import re
import json
import csv
import sys
import os
import random
from urllib.parse import urlparse
from dataclasses import asdict
from typing import List, Dict, Any, Optional
from rich.progress import Progress

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from .waf_utils import (
    TestResult, ScanResults, BaselineCapture, DEFAULT_TIMEOUT, RESULTS_DIR,
    console, HeaderFactory, DEFAULT_MAX_CONCURRENCY, DEFAULT_JITTER, DEFAULT_DELAY, DEFAULT_RETRIES
)

from engine.baseline import BaselineStage
from engine.waf_fingerprint import FingerprintStage
from engine.headers_mutation import MutationEngine
from engine.scoring import DecisionEngine

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
        self.header_factory = HeaderFactory(pool_size=500)  
    
    async def run_pipeline(self, url: str, method: str = "GET", 
                          selected_packs: List[str] = None,
                          custom_headers: List[Dict[str, str]] = None) -> ScanResults:
        """Execute the complete pipeline"""
        
        # Stage 1: Baseline
        console.print("🔍 [bold]Stage 1: Capturing Baseline...[/bold]")
        baseline_stage = BaselineStage(url, method, self.config['verify_tls'], self.header_factory)
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
        mutations = mutation_engine.generate_mutations(
            selected_packs, custom_headers, waf_fingerprint, self.header_factory, method
        )
        
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