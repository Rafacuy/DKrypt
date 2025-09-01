import re
import sys
from typing import List, Dict, Any, Tuple, Optional

sys.path.append("..")
from waf_utils import BaselineCapture, TestResult

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