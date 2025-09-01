import re
import asyncio
import httpx
import hashlib
import time
import urllib.parse
import sys
from typing import List, Dict, Any, Optional, Tuple
sys.path.append("..")
from waf_utils import (BaselineCapture, console, 
                       HeaderFactory, DEFAULT_TIMEOUT, 
                       WAF_FINGERPRINTS, WAF_ERROR_PATTERNS)

class BaselineStage:
    """Stage 1: Capture multiple baseline requests"""
    
    def __init__(self, url: str, method: str = "GET", verify_tls: bool = False, factory: HeaderFactory = None):
        self.url = url
        self.method = method.upper()
        self.verify_tls = verify_tls
        self.factory = factory or HeaderFactory(pool_size=200)
        
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
            base_headers = self.factory.get_headers()
            headers = {**base_headers, **extra_headers}
            
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

    async def _single_baseline(self, extra_headers: Dict[str, str]) -> Optional[BaselineCapture]:
        """Capture a single baseline request"""
        try:
            base_headers = self.factory.get_headers()
            headers = {**base_headers, **extra_headers}

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