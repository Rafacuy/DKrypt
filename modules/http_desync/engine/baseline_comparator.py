# modules/http_desync/engine/baseline_comparator.py
import difflib
import statistics
import time
import httpx
import re
from typing import Dict, List, Any, Tuple, Optional, Set
from collections import Counter

from payload_generator import BaselineResponse, ConfidenceLevel, RANDOMIZER_AVAILABLE


# ============================================================================
# CORE CLASSES
# ============================================================================

class BaselineComparator:
    """
    An enhanced baseline comparison system that accounts for dynamic content,
    WAF blocking, and statistical timing deviations to provide more accurate desync detection
    with reduced false positives.
    """

    def __init__(self):
        self.baselines: List[BaselineResponse] = []
        self.dynamic_patterns: Set[str] = set()  # Store learned dynamic patterns
        self.normalized_baselines: List[str] = []  # Store normalized baseline bodies
        self.timing_anomaly_count = 0  # Track sustained timing anomalies
        self.header_anomaly_count = 0  # Track sustained header anomalies
        
        # Enhanced WAF/blocking patterns with confidence weights
        self.waf_patterns = {
            # High confidence indicators
            "blocked": 0.9, "forbidden": 0.9, "not acceptable": 0.8, "not authorized": 0.8,
            "access denied": 0.9, "security policy": 0.8, "firewall": 0.9, "waf": 0.9,
            "rate limit": 0.7, "too many requests": 0.7, "cloudflare": 0.6,
            # Medium confidence indicators  
            "error 403": 0.6, "permission denied": 0.6, "unauthorized": 0.5
        }
        
        # Volatile headers that should be ignored during comparison
        self.volatile_headers = {
            'date', 'set-cookie', 'server-timing', 'x-request-id', 'x-trace-id',
            'x-correlation-id', 'etag', 'last-modified', 'expires', 'x-served-by',
            'x-cache', 'x-timer', 'x-runtime', 'request-id', 'cf-ray'
        }
        
        # Regex patterns for dynamic content normalization
        self.normalization_patterns = [
            # Timestamps (various formats)
            (re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'), '[TIMESTAMP]'),
            (re.compile(r'\d{10,13}'), '[UNIX_TIMESTAMP]'),  # Unix timestamps
            # UUIDs and GUIDs
            (re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'), '[UUID]'),
            # Session IDs and tokens (common patterns)
            (re.compile(r'[sS]ess(?:ion)?[iI]d[=:]\s*[a-zA-Z0-9+/=]{20,}'), '[SESSION_ID]'),
            (re.compile(r'[tT]oken[=:]\s*[a-zA-Z0-9+/=]{20,}'), '[TOKEN]'),
            (re.compile(r'[cC]srf[=:]\s*[a-zA-Z0-9+/=]{20,}'), '[CSRF_TOKEN]'),
            # Random strings (likely nonces, request IDs)
            (re.compile(r'\b[a-zA-Z0-9]{32,}\b'), '[RANDOM_STRING]'),
            # IP addresses in logs/debug info
            (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[IP_ADDRESS]'),
            # Request timing in milliseconds
            (re.compile(r'\b\d+(?:\.\d+)?\s*ms\b'), '[TIMING_MS]'),
        ]

    def _normalize_content(self, content: str) -> str:
        """
        Normalize dynamic content by replacing timestamps, UUIDs, session IDs, etc.
        with standardized placeholders to improve similarity comparison accuracy.
        """
        normalized = content
        
        # predefined normalization patterns
        for pattern, replacement in self.normalization_patterns:
            normalized = pattern.sub(replacement, normalized)
        
        # learned dynamic patterns from baseline analysis
        for dynamic_pattern in self.dynamic_patterns:
            if len(dynamic_pattern.strip()) > 5:  # Only apply meaningful patterns
                # Escape special regex characters and create pattern
                escaped_pattern = re.escape(dynamic_pattern.strip())
                normalized = re.sub(escaped_pattern, '[DYNAMIC_CONTENT]', normalized)
        
        return normalized

    def establish_baselines(self, url: str, port: int, console, headers_factory: Optional[Any] = None, count: int = 5) -> bool:
        """
        Establish multiple baseline responses to account for dynamic content.
        Enhanced to better learn dynamic patterns and normalize content.

        Args:
            url: Target URL
            port: Target port
            headers_factory: HeaderFactory instance for stealth headers
            count: Number of baseline requests to send
        """
        console.print(f"[cyan]Establishing {count} baseline responses...[/cyan]")

        try:
            for i in range(count):
                headers = {}
                if headers_factory and RANDOMIZER_AVAILABLE:
                    headers = headers_factory.get_headers()
                else:
                    headers = {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                    }

                with httpx.Client(http2=False, verify=False, timeout=15) as client:
                    response = client.get(f"{url}:{port}", headers=headers)

                    baseline = BaselineResponse(
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        body=response.text,
                        elapsed=response.elapsed.total_seconds(),
                        content_length=len(response.text),
                        protocol="HTTP/1.1"
                    )

                    self.baselines.append(baseline)
                    # Store normalized version for better comparison
                    self.normalized_baselines.append(self._normalize_content(baseline.body))
                    time.sleep(1)  # Space out baseline requests

            self._analyze_dynamic_content()
            console.print(f"[green]✅ {len(self.baselines)} baselines established[/green]")
            return True

        except Exception as e:
            console.print(f"[red]❌ Failed to establish baselines: {e}[/red]")
            return False

    def _analyze_dynamic_content(self):
        """
        Enhanced analysis to identify dynamic content patterns that should be ignored
        during similarity comparison. Uses statistical analysis to find consistent differences.
        """
        if len(self.baselines) < 2:
            return

        # Collect all differences between baseline pairs
        difference_patterns = []
        
        for i in range(len(self.baselines)):
            for j in range(i + 1, len(self.baselines)):
                body1 = self.baselines[i].body
                body2 = self.baselines[j].body
                
                # Use difflib to find line-level differences
                diff = difflib.unified_diff(
                    body1.splitlines(),
                    body2.splitlines(),
                    lineterm=''
                )

                for line in diff:
                    if line.startswith('+') or line.startswith('-'):
                        # Extract the actual content (remove diff prefixes)
                        content = line[1:].strip()
                        if len(content) > 3:  # Only consider meaningful differences
                            difference_patterns.append(content)

        # Find patterns that appear frequently (likely dynamic content)
        pattern_counts = Counter(difference_patterns)
        
        # Consider a pattern "dynamic" if it appears in multiple baseline comparisons
        threshold = max(1, len(self.baselines) // 3)  # At least 1/3 of comparisons
        
        for pattern, count in pattern_counts.items():
            if count >= threshold:
                self.dynamic_patterns.add(pattern)
        
        # Renormalize baselines with learned patterns
        self.normalized_baselines = [self._normalize_content(b.body) for b in self.baselines]

    def _calculate_adaptive_threshold(self) -> float:
        """
        Calculate adaptive similarity threshold based on baseline variance.
        Uses median similarity between baselines to set a more robust threshold.
        """
        if len(self.normalized_baselines) < 2:
            return 0.7  # Default threshold
        
        similarities = []
        for i in range(len(self.normalized_baselines)):
            for j in range(i + 1, len(self.normalized_baselines)):
                similarity = difflib.SequenceMatcher(
                    None, self.normalized_baselines[i], self.normalized_baselines[j]
                ).ratio()
                similarities.append(similarity)
        
        if not similarities:
            return 0.7
        
        # median similarity minus a buffer based on variance
        median_sim = statistics.median(similarities)
        variance = statistics.variance(similarities) if len(similarities) > 1 else 0
        
        # Adaptive threshold: median - (variance * 2) but not below 0.5
        threshold = max(0.5, median_sim - (variance * 2))
        return threshold

    def _is_waf_response(self, response: Dict[str, Any]) -> Tuple[bool, float]:
        """
        WAF detection that combines multiple by checking if WAF patterns appear consistently in normal responses.
        
        Returns: (is_waf, confidence_score)
        """
        status_code = response.get('status_code', 0)
        body = response.get('body', '').lower()
        headers = response.get('headers', {})
        
        waf_indicators = []
        
        # 1. Status code analysis
        if status_code in [403, 406, 429, 503]:
            waf_indicators.append(0.6)
        elif status_code == 418:  
            waf_indicators.append(0.8)
        
        # Body content analysis with weighted patterns
        body_confidence = 0
        for pattern, weight in self.waf_patterns.items():
            if pattern in body:
                body_confidence = max(body_confidence, weight)
        
        if body_confidence > 0:
            # Check if this pattern also appears in baseline responses (reduce false positives)
            pattern_in_baselines = False
            for baseline in self.baselines:
                if any(pattern in baseline.body.lower() for pattern in self.waf_patterns.keys()):
                    pattern_in_baselines = True
                    break
            
            if not pattern_in_baselines:  # Pattern not in normal responses
                waf_indicators.append(body_confidence)
            else:
                waf_indicators.append(body_confidence * 0.3)  # Reduce confidence if seen in baselines
        
        # Header analysis for WAF signatures
        waf_headers = {'cf-ray', 'x-sucuri-id', 'server'} # Common WAF headers
        header_matches = sum(1 for h in waf_headers if h.lower() in [k.lower() for k in headers.keys()])
        
        if header_matches > 0:
            # Check server header for WAF signatures
            server_header = headers.get('server', '').lower()
            if any(waf in server_header for waf in ['cloudflare', 'sucuri', 'incapsula']):
                waf_indicators.append(0.7)
        
        # Content length analysis 
        content_length = len(response.get('body', ''))
        avg_baseline_length = sum(b.content_length for b in self.baselines) / len(self.baselines) if self.baselines else 1000
        
        if content_length < avg_baseline_length * 0.1 and status_code >= 400:  # Very short error response
            waf_indicators.append(0.5)
        
        # Calculate overall WAF confidence
        if not waf_indicators:
            return False, 0.0
        
        max_confidence = max(waf_indicators)
        avg_confidence = sum(waf_indicators) / len(waf_indicators)
        
        # Combined score favoring maximum confidence but considering average
        combined_confidence = (max_confidence * 0.7) + (avg_confidence * 0.3)
        
        return combined_confidence >= 0.6, combined_confidence

    def _filter_volatile_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Filter out headers that are known to be volatile/dynamic."""
        return {k: v for k, v in headers.items() 
                if k.lower() not in self.volatile_headers}

    def _analyze_timing_with_iqr(self, test_time: float) -> Tuple[bool, str]:
        """
        Use median + IQR for more robust timing analysis instead of mean + standard deviation.
        This reduces false positives from timing outliers.
        """
        if not self.baselines:
            return False, ""
        
        baseline_times = [b.elapsed for b in self.baselines]
        
        if len(baseline_times) < 3:
            # Fall back to simple comparison for small datasets
            avg_time = sum(baseline_times) / len(baseline_times)
            if test_time > avg_time * 2:
                return True, f"Significant delay: {test_time:.2f}s vs avg {avg_time:.2f}s"
            return False, ""
        
        # Calculate median and IQR
        baseline_times.sort()
        q1 = baseline_times[len(baseline_times) // 4]
        median = baseline_times[len(baseline_times) // 2]
        q3 = baseline_times[3 * len(baseline_times) // 4]
        iqr = q3 - q1
        
        # Define outlier boundaries
        upper_bound = q3 + (2.5 * iqr)
        lower_bound = q1 - (2.5 * iqr)
        
        if test_time > upper_bound:
            return True, f"Significant delay: {test_time:.2f}s (median: {median:.2f}s, upper bound: {upper_bound:.2f}s)"
        elif test_time < lower_bound and test_time < median * 0.5:  # Also check for unusually fast
            return True, f"Unusually fast response: {test_time:.2f}s (median: {median:.2f}s, lower bound: {lower_bound:.2f}s)"
        
        return False, ""

    def compare_response(self, test_response: Dict[str, Any]) -> Tuple[ConfidenceLevel, str]:
        """
        response comparison with reduced false positives through:
        - Dynamic content normalization
        - Adaptive similarity thresholds  
        - Robust timing analysis with IQR
        - Sustained anomaly tracking
        - Enhanced WAF detection
        """
        if not self.baselines:
            return ConfidenceLevel.LOW, "No baseline established"

        test_status = test_response.get('status_code', 0)
        
        # Quick check for expected server responses
        if test_status in [400, 501]:
            return ConfidenceLevel.INFO, f"Server rejected request with status {test_status}, which is expected for a secure server."

        # WAF detection
        is_waf, waf_confidence = self._is_waf_response(test_response)
        if is_waf:
            return ConfidenceLevel.INFO, f"Request appears to be blocked by WAF/security policy (Status: {test_status}, Confidence: {waf_confidence:.2f})."

        baseline_status_codes = set(b.status_code for b in self.baselines)
        
        details = []
        confidence_factors = []

        # Timing Analysis with IQR
        test_time = test_response.get('elapsed', 0)
        timing_anomaly, timing_detail = self._analyze_timing_with_iqr(test_time)
        
        if timing_anomaly:
            self.timing_anomaly_count += 1
            if self.timing_anomaly_count >= 2:
                confidence_factors.append(0.8)
                details.append(timing_detail + f" (sustained anomaly count: {self.timing_anomaly_count})")
        else:
            # Reset counter on normal timing
            self.timing_anomaly_count = max(0, self.timing_anomaly_count - 1)

        # Status Code Analysis
        if test_status not in baseline_status_codes:
            confidence_factors.append(0.9)
            details.append(f"Status code changed: {test_status} not in baseline {list(baseline_status_codes)}")

        # Content Length Analysis with adaptive thresholds
        test_content_length = len(test_response.get('body', ''))
        baseline_lengths = [b.content_length for b in self.baselines]
        median_baseline_length = statistics.median(baseline_lengths)
        
        if median_baseline_length > 0:
            length_diff_ratio = abs(test_content_length - median_baseline_length) / median_baseline_length
            if length_diff_ratio > 0.8:  
                confidence_factors.append(0.7)
                details.append(f"Significant content length difference: {test_content_length} vs median {median_baseline_length:.0f} (ratio: {length_diff_ratio:.2f})")

        # Body Content Analysis
        test_body_normalized = self._normalize_content(test_response.get('body', ''))
        body_similarities = []

        for normalized_baseline in self.normalized_baselines:
            similarity = difflib.SequenceMatcher(None, normalized_baseline, test_body_normalized).ratio()
            body_similarities.append(similarity)

        if body_similarities:
            # Use median similarity 
            median_similarity = statistics.median(body_similarities)
            adaptive_threshold = self._calculate_adaptive_threshold()
            
            if median_similarity < adaptive_threshold:
                confidence_factors.append(0.6)
                details.append(f"Body content differs significantly (median similarity: {median_similarity:.2%}, threshold: {adaptive_threshold:.2%})")

        test_headers = self._filter_volatile_headers(test_response.get('headers', {}))
        baseline_headers = self._filter_volatile_headers(self.baselines[0].headers)

        missing_headers = set(baseline_headers.keys()) - set(test_headers.keys())
        extra_headers = set(test_headers.keys()) - set(baseline_headers.keys())
        
        significant_header_changes = False
        
        # Only flag if we have meaningful missing headers 
        if missing_headers:
            # Check if these headers are consistently missing 
            self.header_anomaly_count += 1
            if self.header_anomaly_count >= 2:
                significant_header_changes = True
                confidence_factors.append(0.5)
                details.append(f"Consistently missing headers: {', '.join(missing_headers)} (count: {self.header_anomaly_count})")
        else:
            self.header_anomaly_count = max(0, self.header_anomaly_count - 1)
        
        # Flag significant extra headers
        if len(extra_headers) > 3:  # Only if many new headers appear
            confidence_factors.append(0.4)
            details.append(f"Many extra headers present: {len(extra_headers)} new headers")

        # Calculate overall confidence with improved logic
        if not confidence_factors:
            return ConfidenceLevel.LOW, "Response appears normal (no significant anomalies detected)"

        # Use weighted average instead of just maximum for more nuanced confidence
        max_confidence = max(confidence_factors)
        avg_confidence = sum(confidence_factors) / len(confidence_factors)
        weighted_confidence = (max_confidence * 0.6) + (avg_confidence * 0.4)

        # Adjust thresholds to be more conservative (reduce false positives)
        if weighted_confidence >= 0.85:
            return ConfidenceLevel.HIGH, "; ".join(details)
        elif weighted_confidence >= 0.65:
            return ConfidenceLevel.MEDIUM, "; ".join(details)
        else:
            return ConfidenceLevel.LOW, "; ".join(details)