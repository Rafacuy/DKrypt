import re
import sys
from typing import Dict, List, Any, Tuple
sys.path.append("..")
from waf_utils import (BaselineCapture, WAFFingerprint,
                       console, HeaderFactory, WAF_ERROR_PATTERNS,
                       WAF_FINGERPRINTS)


class FingerprintStage:
    """
    Stage 2: WAF detection and vendor identification
    """

    # Vendor fingerprints — extends global WAF_FINGERPRINTS
    _EXTRA_VENDOR_PRINTS = {
        # Imperva 
        "imperva": [r"incap[_-]?ses", r"visid[_-]?incap", r"incapsula", r"x-iinfo", r"x-cdn"],
        # Fortinet
        "fortinet": [r"fortiwaf", r"fortiguard", r"fw_sessionid", r"forti.*(gate|web)"],
        # Citrix / NetScaler / ADC
        "citrix": [r"citrix", r"ns_af", r"citrix_ns_id", r"ns_cook"],
        # Radware
        "radware": [r"radware", r"akav_pr", r"rdwr", r"airee"],
        # Palo Alto
        "paloalto": [r"akamai[_-]?ghost.*paloalto", r"x-panw", r"pan[_-]?os"],
        # Sophos
        "sophos": [r"sophos", r"utm", r"astaro"],
        # Azure Front Door / AppGW
        "azure": [r"azure", r"x-azure-(ref|fdid)", r"afdm?z"],
        # Fastly 
        "fastly": [r"fastly", r"via:.*fastly", r"x-served-by:.*fastly"],
        # StackPath / Sucuri 
        "stackpath": [r"stackpath", r"sp_request_id"],
        "sucuri": [r"sucuri", r"x-sucuri", r"sucuri[_-]?cloudproxy"],
    }

    # Body & challenge patterns (generic)
    _BODY_PATTERNS = [
        r"web application firewall",
        r"blocked by.*firewall",
        r"access denied.*security",
        r"forbidden.*waf",
        r"request blocked",
        r"security policy violation",
        # Challenge/CAPTCHA/JS interstitials
        r"checking your browser before accessing",
        r"cf-?ray",  # rarely appear on the body
        r"attention required.*cloudflare",
        r"one more step",
        r"captcha", r"recaptcha", r"hcaptcha",
        r"bot detection",
        r"incident id",  # Imperva/Incapsula
    ]

    # Header tokens that often signal challenges
    _CHALLENGE_HEADERS = [
        r"cf-.*(ray|bm|chl|bmid|bmt)",
        r"x-?akamai-.*(ghost|bps|pragma|abck)",
        r"x-?iinfo",
        r"x-?cdn",
        r"set-cookie:.*(_abck|ak_bmsc|bm_sv|cf[_-]?duid|incap_ses|visid_incap|fortiwafsid)",
    ]

    # Singal weights
    _WEIGHTS = {
        "header": 3.0,      
        "cookie": 4.0,       
        "body": 2.0,         
        "status_block": 5.0, 
        "rate_limit": 4.0,   
        "challenge": 6.0,    
        "redirect": 2.5,     
        "variance": 2.0,     
    }

    # Status code that show indicate of blocing / rate-limit
    _BLOCKING_CODES = {401, 403, 451, 406, 503}
    _RATE_LIMIT_CODES = {429}

    def __init__(self, baselines: List[BaselineCapture], **kwargs):
        self.baselines = baselines or []
        # gabungkan fingerprint global dengan ekstra
        self.vendor_prints = self._merge_vendor_fingerprints()

    def _merge_vendor_fingerprints(self) -> Dict[str, List[str]]:
        merged = {k.lower(): v[:] for k, v in WAF_FINGERPRINTS.items()}
        for vendor, pats in self._EXTRA_VENDOR_PRINTS.items():
            key = vendor.lower()
            merged.setdefault(key, [])
            merged[key].extend(pats)
        # dedup + compile-later (pakai str regex di loop)
        for k in list(merged.keys()):
            merged[k] = list(dict.fromkeys(merged[k]))
        return merged

    def analyze(self) -> WAFFingerprint:
        if not self.baselines:
            return WAFFingerprint(False, None, 0.0, [], "pass-through")

        vendor_scores: Dict[str, float] = {}
        indicators: List[str] = []
        global_score = 0.0

        # --- Scan every baselines ---
        status_codes = []
        content_lengths = []
        redirects_count = []

        for b in self.baselines:
            status_codes.append(b.status_code)
            content_lengths.append(b.content_length)
            redirects_count.append(len(b.redirect_chain))

            # Headers (Server, Set-Cookie, X-*)
            hdr_kv = [f"{h}:{v}" for h, v in (b.headers or {}).items()]
            # Separate detail header to search Set-Cookie by name
            hdr_lower = {str(h).lower(): str(v).lower() for h, v in (b.headers or {}).items()}
            set_cookie_val = hdr_lower.get("set-cookie", "")

            # Vendor matches via header lines
            for line in hdr_kv:
                ll = line.lower()
                for vendor, patterns in self.vendor_prints.items():
                    for pat in patterns:
                        if re.search(pat, ll):
                            vendor_scores[vendor] = vendor_scores.get(vendor, 0.0) + self._WEIGHTS["header"]
                            indicators.append(f"header:{vendor}:{line[:80]}")

            # Cookie/Set-Cookie name hints 
            if set_cookie_val:
                for vendor, patterns in self.vendor_prints.items():
                    for pat in patterns:
                        if re.search(pat, set_cookie_val):
                            vendor_scores[vendor] = vendor_scores.get(vendor, 0.0) + self._WEIGHTS["cookie"]
                            indicators.append(f"cookie:{vendor}:Set-Cookie~{pat}")

            # Body signals (error page, challenge, captcha)
            body_text = (b.body_snippet or "").lower()
            for pat in self._BODY_PATTERNS + WAF_ERROR_PATTERNS:
                if re.search(pat, body_text):
                    global_score += self._WEIGHTS["body"]
                    indicators.append(f"body:{pat}")

            # Challenge headers (Cloudflare/Akamai/Incapsula dsb.)
            for h, v in (b.headers or {}).items():
                hv = f"{h}:{v}".lower()
                for pat in self._CHALLENGE_HEADERS:
                    if re.search(pat, hv):
                        global_score += self._WEIGHTS["challenge"]
                        indicators.append(f"challenge:{h}={str(v)[:50]}")

            # Status-based signals
            if b.status_code in self._BLOCKING_CODES:
                global_score += self._WEIGHTS["status_block"]
                indicators.append(f"status:block:{b.status_code}")
            if b.status_code in self._RATE_LIMIT_CODES or "ratelimit" in " ".join(hdr_lower.keys()):
                global_score += self._WEIGHTS["rate_limit"]
                indicators.append(f"status:rate_limit:{b.status_code}")

            # Redirect signal
            if b.status_code in (301, 302, 303, 307, 308):
                global_score += self._WEIGHTS["redirect"]
                indicators.append(f"redirect:len={len(b.redirect_chain)}")

        # --- Cross-baseline behavior (variance) ---
        if len(self.baselines) >= 2:
            variance_points = 0.0

            if len(set(status_codes)) > 1:
                variance_points += 0.7

            try:
                base_len = max(1, min(content_lengths))  
                max_len = max(content_lengths)
                if (abs(max_len - base_len) / float(base_len)) > 0.3:
                    variance_points += 0.7
            except Exception:
                pass
            
            if len(set(redirects_count)) > 1:
                variance_points += 0.6

            if variance_points > 0:
                global_score += self._WEIGHTS["variance"] * variance_points
                indicators.append(f"variance:status={len(set(status_codes))},len~{len(set(content_lengths))},redir~{len(set(redirects_count))}")

        detected = bool(indicators)

        vendor = None
        vendor_conf_component = 0.0
        if vendor_scores:
            vendor = max(vendor_scores, key=vendor_scores.get)
            vendor_conf_component = min(vendor_scores[vendor] / 12.0, 1.0)

        global_conf_component = min(global_score / 40.0, 1.0)

        confidence = max(0.0, min(1.0, 0.35 * vendor_conf_component + 0.65 * global_conf_component))
        blocking_behavior = self._classify_mode(status_codes, indicators)

        indicators = list(dict.fromkeys(indicators))

        return WAFFingerprint(
            detected=detected,
            vendor=vendor,
            confidence=confidence,
            indicators=indicators,
            blocking_behavior=blocking_behavior
        )

    # ===================== helpers =====================

    def _classify_mode(self, status_codes: List[int], indicators: List[str]) -> str:
        """
        Urutan prioritas:
        - challenge (captcha/js) 
        - rate-limit if 429/RateLimit
        - blocking if the dominant is 401/403/451/503/406 
        - redirect if majority 30x
        - pass-through 
        """
        sc_set = set(status_codes)

        has_challenge = any(ind.startswith("challenge:") or "captcha" in ind or "checking your browser" in ind
                            for ind in indicators)
        has_rate_limit = any(code in self._RATE_LIMIT_CODES for code in sc_set) or \
                         any(ind.startswith("status:rate_limit") for ind in indicators)
        has_blocking = any(code in self._BLOCKING_CODES for code in sc_set) or \
                       any(ind.startswith("status:block") for ind in indicators)
        has_redirect = any(str(code).startswith("30") for code in sc_set)

        if has_challenge:
            return "challenge"
        if has_rate_limit:
            return "rate-limit"
        if has_blocking:
            return "blocking"
        if has_redirect:
            return "redirect"
        return "pass-through"
