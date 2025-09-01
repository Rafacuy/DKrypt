#!/usr/bin/env python3
"""
Core utilities, configurations, data structures, and helpers for the WAF bypass tester.
"""

import os
import json
import time
import hashlib
import re
import random
import urllib.parse
from typing import List, Set, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

from rich.console import Console

from core.utils import clear_console
from core.randomizer import HeaderFactory

console = Console()

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.abspath(os.path.join(BASE_DIR, "../../reports"))

PROFILES_DIR = os.path.join(REPORTS_DIR, "waf_profiles")
RESULTS_DIR = os.path.join(REPORTS_DIR, "waf_results")
os.makedirs(PROFILES_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# --- Header Packs loader ---
pack_path = os.path.join(BASE_DIR, "../../wordlists", "packs", "header_packs.json")

try:
    with open(pack_path, "r") as f:
        HEADER_PACKS = json.load(f)
except FileNotFoundError:
    print(f"Warning: Header packs file not found at {pack_path}. Mutations will be limited.")
    HEADER_PACKS = {}


# --- Network settings ---
DEFAULT_TIMEOUT = 10
DEFAULT_RETRIES = 2
DEFAULT_DELAY = 1
DEFAULT_MAX_CONCURRENCY = 10
DEFAULT_JITTER = 0.5


# --- WAF Detection Patterns ---
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

@dataclass
class MutationPriority:
    """Priority scoring for mutations based on WAF fingerprinting"""
    technique_name: str
    base_score: float
    waf_vendor_bonus: Dict[str, float]
    behavior_bonus: Dict[str, float]

    def calculate_score(self, vendor: Optional[str], behavior: Optional[str]) -> float:
        score = self.base_score
        if vendor and vendor.lower() in self.waf_vendor_bonus:
            score += self.waf_vendor_bonus[vendor.lower()]
        if behavior and behavior in self.behavior_bonus:
            score += self.behavior_bonus[behavior]
        return score

@dataclass
class HeaderMutation:
    """Enhanced mutation with metadata and deduplication support"""
    id: str
    name: str
    headers: Dict[str, str]
    pack: str
    priority_score: float
    techniques: List[str]
    hash_key: str

    @classmethod
    def create(cls, id_num: int, name: str, headers: Dict[str, str],
               pack: str, priority_score: float, techniques: List[str]) -> 'HeaderMutation':
        # Create deterministic hash for deduplication
        header_str = '|'.join(f"{k}:{v}" for k, v in sorted(headers.items()))
        hash_key = hashlib.md5(header_str.encode()).hexdigest()[:12]

        return cls(
            id=str(id_num),
            name=name,
            headers=headers,
            pack=pack,
            priority_score=priority_score,
            techniques=techniques,
            hash_key=hash_key
        )

