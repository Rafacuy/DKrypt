# core/menu.py - Configuration and utility constants for DKrypt

import sys
import time
import subprocess
import sys
import os
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
from rich.console import Console
from rich.table import Table
from rich.text import Text
from datetime import datetime
from pathlib import Path

@dataclass
class MenuOption:
    """Represents a single menu option"""
    id: int
    name: str
    description: str


class MenuConfig:
    """Core configuration for the menu system"""

    # Application metadata
    APP_NAME = "DKrypt"
    VERSION = "1.4.0"
    STATUS = "STABLE"
    COPYRIGHT = "© 2025 DKrypt Security"

    MODULES_LIST = [
        {"name": "sqli", "display": "SQLI Scanner", "desc": "Detect SQL injection vulnerabilities"},
        {"name": "xss", "display": "XSS Scanner", "desc": "Detect Cross-Site Scripting vulnerabilities"},
        {"name": "graphql", "display": "GraphQL Introspector", "desc": "Introspect queries from GraphQL endpoints"},
        {"name": "portscanner", "display": "Port Scanner", "desc": "Advanced Port Scanner (based on NMAP)"},
        {"name": "subdomain", "display": "Subdomain Scanner", "desc": "Discover target subdomains comprehensively"},
        {"name": "crawler", "display": "Website Crawler", "desc": "Extract and analyze website content"},
        {"name": "headers", "display": "Security Header Audit", "desc": "Evaluate HTTP security headers"},
        {"name": "dirbrute", "display": "Directory Bruteforcer", "desc": "Search for hidden directories and files"},
        {"name": "sslinspect", "display": "SSL/TLS Inspector", "desc": "Analyze website security certificates"},
        {"name": "corstest", "display": "CORS Misconfig Auditor", "desc": "Identify CORS configuration issues"},
        {"name": "smuggler", "display": "HTTP Desync Tester", "desc": "Test for HTTP request smuggling"},
        {"name": "tracepulse", "display": "Tracepulse", "desc": "Trace network routes and identify issues"},
        {"name": "js-crawler", "display": "JS Crawler", "desc": "Extract endpoints from JavaScript files"},
        {"name": "py-obfuscator", "display": "Python Obfuscator", "desc": "Obfuscate Python code for protection"},
        {"name": "waftester", "display": "WAF Bypass Tester", "desc": "Test Web Application Firewall bypasses"},
    ]

    COLORS = {
        'primary': 'red',
        'secondary': 'white',
        'accent': 'bright_red',
        'success': 'green',
        'warning': 'yellow',
        'error': 'red',
        'muted': 'dim white',
        'highlight': 'bright_white'
    }
