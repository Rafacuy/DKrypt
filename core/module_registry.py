#!/usr/bin/env python3
import asyncio
from modules import (
    subdomain, ssl_inspector, dir_bruteforcer, header_audit, port_scanner,
    cors_scan, sqli_scan, tracepulse, jscrawler, py_obfuscator, graphql_introspect
)
from modules.crawler_engine import crawler_utils
from modules.waf_bypass import tui
from modules.http_desync import main_runner
from modules.xss import scanner

class ModuleRegistry:
    """Central registry for all DKrypt modules"""
    
    @staticmethod
    def get_modules():
        return {
            'sqli': {
                'name': 'SQLI Scanner',
                'description': 'Detect SQL injection vulnerabilities in web applications',
                'category': 'scanner',
                'author': 'Rafacuy',
                'function': sqli_scan.run_sqli_scan,
                'options': {
                    'URL': {'required': True, 'description': 'Target URL to scan', 'type': 'string'},
                    'TEST_FORMS': {'required': False, 'description': 'Test POST forms', 'default': False, 'type': 'bool'},
                    'TEST_HEADERS': {'required': False, 'description': 'Test HTTP headers', 'default': False, 'type': 'bool'},
                    'TEST_APIS': {'required': False, 'description': 'Test API endpoints', 'default': False, 'type': 'bool'},
                    'EXPORT': {'required': False, 'description': 'Export format (html/csv/none)', 'default': 'html', 'type': 'string'}
                }
            },
            'xss': {
                'name': 'XSS Scanner',
                'description': 'Detect Cross-Site Scripting vulnerabilities in web applications',
                'category': 'scanner',
                'author': 'Rafacuy',
                'function': lambda **kwargs: asyncio.run(scanner.run_xss_scan(
                    url=kwargs.get('url', kwargs.get('URL', 'http://example.com')),
                    threads=int(kwargs.get('threads', kwargs.get('THREADS', 20))),
                    rate_limit=int(kwargs.get('rate_limit', kwargs.get('RATE_LIMIT', 5))),
                    max_payloads=int(kwargs.get('max_payloads', kwargs.get('MAX_PAYLOADS', 15))),
                    batch_size=int(kwargs.get('batch_size', kwargs.get('BATCH_SIZE', 100))),
                    smart_mode=kwargs.get('smart_mode', kwargs.get('SMART_MODE', False)),
                    stealth_mode=kwargs.get('stealth_mode', kwargs.get('STEALTH_MODE', False)),
                    test_headers=kwargs.get('test_headers', kwargs.get('TEST_HEADERS', False)),
                    verbose=kwargs.get('verbose', kwargs.get('VERBOSE', False))
                )),
                'options': {
                    'URL': {'required': True, 'description': 'Target URL to scan', 'type': 'string'},
                    'THREADS': {'required': False, 'description': 'Number of threads', 'default': 20, 'type': 'int'},
                    'RATE_LIMIT': {'required': False, 'description': 'Requests per second', 'default': 5, 'type': 'int'},
                    'MAX_PAYLOADS': {'required': False, 'description': 'Max payloads per context', 'default': 15, 'type': 'int'},
                    'SMART_MODE': {'required': False, 'description': 'Enable smart mode', 'default': False, 'type': 'bool'},
                    'STEALTH_MODE': {'required': False, 'description': 'Enable stealth mode', 'default': False, 'type': 'bool'},
                    'VERBOSE': {'required': False, 'description': 'Verbose output', 'default': False, 'type': 'bool'}
                }
            },
            'graphql': {
                'name': 'GraphQL Introspector',
                'description': 'Introspect queries from GraphQL endpoints',
                'category': 'scanner',
                'author': 'Rafacuy',
                'function': graphql_introspect.run_cli,
                'options': {
                    'URL': {'required': True, 'description': 'GraphQL endpoint URL', 'type': 'string'},
                    'HEADERS': {'required': False, 'description': 'Custom headers (JSON)', 'default': '{}', 'type': 'string'},
                    'TIMEOUT': {'required': False, 'description': 'Request timeout', 'default': 30, 'type': 'int'},
                    'VERBOSE': {'required': False, 'description': 'Verbose output', 'default': False, 'type': 'bool'}
                }
            },
            'portscanner': {
                'name': 'Port Scanner',
                'description': 'Advanced Port Scanner (based on NMAP)',
                'category': 'recon',
                'author': 'Rafacuy',
                'function': lambda **kwargs: asyncio.run(port_scanner.main_menu(kwargs)),
                'options': {
                    'TARGET': {'required': True, 'description': 'Target host to scan', 'type': 'string'},
                    'PORTS': {'required': False, 'description': 'Ports to scan', 'default': '1-1024', 'type': 'string'},
                    'SCAN_TYPE': {'required': False, 'description': 'Scan type (SYN/CON/UDP)', 'default': 'SYN', 'type': 'string'},
                    'TIMING': {'required': False, 'description': 'Timing profile', 'default': 'normal', 'type': 'string'}
                }
            },
            'subdomain': {
                'name': 'Subdomain Scanner',
                'description': 'Discover target subdomains comprehensively',
                'category': 'recon',
                'author': 'Rafacuy',
                'function': lambda **kwargs: asyncio.run(subdomain.main_menu(kwargs)),
                'options': {
                    'TARGET': {'required': True, 'description': 'Target domain', 'type': 'string'},
                    'RATE_LIMIT': {'required': False, 'description': 'DNS queries rate', 'default': 200, 'type': 'int'},
                    'API_ONLY': {'required': False, 'description': 'Use only API sources', 'default': False, 'type': 'bool'},
                    'BRUTEFORCE_ONLY': {'required': False, 'description': 'Use only bruteforce', 'default': False, 'type': 'bool'}
                }
            },
            'crawler': {
                'name': 'Website Crawler',
                'description': 'Extract and analyze website content',
                'category': 'recon',
                'author': 'Rafacuy',
                'function': lambda **kwargs: asyncio.run(crawler_utils.main(kwargs)),
                'options': {
                    'URL': {'required': True, 'description': 'Starting URL', 'type': 'string'},
                    'DEPTH': {'required': False, 'description': 'Crawl depth', 'default': 3, 'type': 'int'},
                    'MAX_URLS': {'required': False, 'description': 'Maximum URLs', 'default': 100, 'type': 'int'},
                    'JS_RENDER': {'required': False, 'description': 'Enable JS rendering', 'default': False, 'type': 'bool'}
                }
            },
            'headers': {
                'name': 'Security Header Audit',
                'description': 'Evaluate HTTP security headers',
                'category': 'audit',
                'author': 'Rafacuy',
                'function': lambda **kwargs: header_audit.HeaderAuditor().run(kwargs),
                'options': {
                    'URL': {'required': True, 'description': 'Target URL', 'type': 'string'},
                    'VERBOSE': {'required': False, 'description': 'Verbose output', 'default': False, 'type': 'bool'},
                    'TIMEOUT': {'required': False, 'description': 'Request timeout', 'default': 15, 'type': 'int'}
                }
            },
            'dirbrute': {
                'name': 'Directory Bruteforcer',
                'description': 'Search for hidden directories and files',
                'category': 'recon',
                'author': 'Rafacuy',
                'function': dir_bruteforcer.main,
                'options': {
                    'URL': {'required': True, 'description': 'Target URL', 'type': 'string'},
                    'WORDLIST': {'required': False, 'description': 'Wordlist path', 'default': 'wordlists/directory-brute.txt', 'type': 'string'},
                    'EXTENSIONS': {'required': False, 'description': 'File extensions', 'default': '.php,.html', 'type': 'string'},
                    'MAX_WORKERS': {'required': False, 'description': 'Concurrent threads', 'default': 20, 'type': 'int'}
                }
            },
            'sslinspect': {
                'name': 'SSL/TLS Inspector',
                'description': 'Analyze website security certificates',
                'category': 'audit',
                'author': 'Rafacuy',
                'function': ssl_inspector.run_ssl_inspector,
                'options': {
                    'TARGET': {'required': True, 'description': 'Target host:port', 'type': 'string'},
                    'EXPORT': {'required': False, 'description': 'Export format (json/txt)', 'default': 'json', 'type': 'string'}
                }
            },
            'corstest': {
                'name': 'CORS Misconfig Auditor',
                'description': 'Identify CORS configuration issues',
                'category': 'audit',
                'author': 'Rafacuy',
                'function': cors_scan.main,
                'options': {
                    'URL': {'required': True, 'description': 'Target URL', 'type': 'string'},
                    'EXPORT': {'required': False, 'description': 'Export format', 'default': 'json', 'type': 'string'}
                }
            },
            'smuggler': {
                'name': 'HTTP Desync Tester',
                'description': 'Test for HTTP request smuggling',
                'category': 'exploit',
                'author': 'Rafacuy',
                'function': main_runner.run,
                'options': {
                    'URL': {'required': True, 'description': 'Target URL', 'type': 'string'},
                    'PORT': {'required': False, 'description': 'Target port', 'default': 80, 'type': 'int'},
                    'HEADERS': {'required': False, 'description': 'Custom headers', 'default': '', 'type': 'string'}
                }
            },
            'tracepulse': {
                'name': 'Tracepulse',
                'description': 'Trace network routes and identify issues',
                'category': 'recon',
                'author': 'Rafacuy',
                'function': tracepulse.main,
                'options': {
                    'DESTINATION': {'required': True, 'description': 'Target host/IP', 'type': 'string'},
                    'PROTOCOL': {'required': False, 'description': 'Protocol (icmp/tcp/udp)', 'default': 'icmp', 'type': 'string'},
                    'MAX_HOPS': {'required': False, 'description': 'Maximum hops', 'default': 30, 'type': 'int'}
                }
            },
            'js-crawler': {
                'name': 'JS Crawler',
                'description': 'Extract endpoints from JavaScript files',
                'category': 'recon',
                'author': 'Rafacuy',
                'function': jscrawler.main,
                'options': {
                    'URL': {'required': True, 'description': 'Target URL', 'type': 'string'},
                    'SELENIUM': {'required': False, 'description': 'Use Selenium', 'default': False, 'type': 'bool'},
                    'OUTPUT': {'required': False, 'description': 'Output file', 'default': '', 'type': 'string'}
                }
            },
            'py-obfuscator': {
                'name': 'Python Obfuscator',
                'description': 'Obfuscate Python code for protection',
                'category': 'utility',
                'author': 'Rafacuy',
                'function': py_obfuscator.main,
                'options': {
                    'INPUT': {'required': True, 'description': 'Input Python file', 'type': 'string'},
                    'OUTPUT': {'required': False, 'description': 'Output file path', 'default': '', 'type': 'string'},
                    'LEVEL': {'required': False, 'description': 'Protection level (1-3)', 'default': 2, 'type': 'int'},
                    'KEY': {'required': False, 'description': 'Encryption key', 'default': '', 'type': 'string'}
                }
            },
            'waftester': {
                'name': 'WAF Bypass Tester',
                'description': 'Test Web Application Firewall bypasses',
                'category': 'exploit',
                'author': 'Rafacuy',
                'function': lambda **kwargs: tui.WAFTUI().run(kwargs),
                'options': {
                    'URL': {'required': True, 'description': 'Target URL', 'type': 'string'},
                    'METHOD': {'required': False, 'description': 'HTTP method', 'default': 'GET', 'type': 'string'},
                    'CONCURRENCY': {'required': False, 'description': 'Concurrent requests', 'default': 10, 'type': 'int'}
                }
            }
        }
    
    @staticmethod
    def get_module(name):
        modules = ModuleRegistry.get_modules()
        return modules.get(name)
    
    @staticmethod
    def search_modules(term):
        modules = ModuleRegistry.get_modules()
        results = []
        term = term.lower()
        for key, module in modules.items():
            if (term in key.lower() or 
                term in module['name'].lower() or 
                term in module['description'].lower() or
                term in module['category'].lower()):
                results.append((key, module))
        return results
    
    @staticmethod
    def get_categories():
        modules = ModuleRegistry.get_modules()
        categories = {}
        for key, module in modules.items():
            cat = module['category']
            if cat not in categories:
                categories[cat] = []
            categories[cat].append((key, module))
        return categories
