# DKrypt CLI Reference

This document provides a complete reference for all available commands and their options in the DKrypt CLI.

## Global Commands

These commands are built into the DKrypt core and can be run from anywhere.

### `interactive`
Starts the interactive CLI shell. This is the recommended way to use DKrypt.
- **Alias:** `i`
- **Usage:** `python dkrypt.py interactive`

### `version`
Shows the current version of the DKrypt framework.
- **Usage:** `python dkrypt.py version`

### `diagnostic`
Runs a series of system and environment checks to ensure DKrypt is installed correctly and all dependencies are met.
- **Usage:** `python dkrypt.py diagnostic`

### `list-modules`
Displays a list of all available security modules.
- **Usage:** `python dkrypt.py list-modules`

### `quick-start`
Shows a brief guide on how to get started with DKrypt.
- **Usage:** `python dkrypt.py quick-start`

### `tips`
Provides useful tips and tricks for using the framework effectively.
- **Usage:** `python dkrypt.py tips`

---

## Module Commands

These commands correspond to the security modules available in DKrypt.

### `sqli`
**SQL Injection Scanner:** Detects SQL injection vulnerabilities in web applications.

| Parameter | Description | Default |
|---|---|---|
| `--url` | Target URL to scan for SQL injection (e.g., `https://example.com/vulnerable?id=1`) | **Required** |
| `--test-forms` | Enable testing of POST forms for SQL injection | `False` |
| `--test-headers` | Enable testing of HTTP headers for SQL injection | `False` |
| `--test-apis` | Enable testing of API endpoints for SQL injection | `False` |
| `--export` | Export format: `html`, `csv`, or `none` | `html` |

### `xss`
**XSS Scanner:** Detects Cross-Site Scripting vulnerabilities in web applications.

| Parameter | Description | Default |
|---|---|---|
| `--url` | Target URL to scan for XSS | **Required** |
| `--threads` | Number of concurrent threads | `20` |
| `--rate-limit`| Requests per second | `5` |
| `--max-payloads`| Maximum XSS payloads per context | `15` |
| `--batch-size`| Payloads per batch | `100` |
| `--smart-mode`| Enable smart mode | `False` |
| `--stealth-mode`| Enable stealth mode | `False` |
| `--test-headers`| Test HTTP headers | `False` |
| `--verbose` | Verbose output | `False` |

### `graphql`
**GraphQL Introspector:** GraphQL endpoint analysis and vulnerability detection.

| Parameter | Description | Default |
|---|---|---|
| `--url` | GraphQL endpoint URL | **Required** |
| `--headers` | Custom headers as JSON | `{}` |
| `--timeout` | Request timeout in seconds | `30` |
| `--export` | Export formats (comma-separated) | `json,csv,txt` |
| `--output` | Output filename prefix | `None` |
| `--verbose` | Verbose output | `False` |
| `--export-raw`| Export raw response on failure | `False` |
| `--no-header-factory`| Disable HeaderFactory | `False` |
| `--header-pool-size`| HeaderFactory pool size | `None` |
| `--rotate-headers`| Enable header rotation | `False` |

### `portscanner`
**Port Scanner:** Scans target hosts for open ports and services using NMAP.

| Parameter | Description | Default |
|---|---|---|
| `command` | Subcommand: `single` or `batch` | **Required** |
| `--target` | Target host to scan | `None` |
| `--ports` | Ports to scan | `1-1024` |
| `--scan-type`| Scan type: `SYN`, `CON`, or `UDP` | `SYN` |
| `--timing` | Timing profile | `normal` |
| `--service-detection`| Enable service detection | `False` |
| `--os-detection`| Enable OS detection | `False` |
| `--script-scan`| NSE scan: `default`, `vuln`, or `none` | `none` |
| `--custom-args`| Custom NMAP arguments | `""` |
| `--verbosity`| Verbosity level (0-2) | `1` |
| `--output` | Output format: `json`, `csv`, or `no` | `no` |
| `--file` | File with target hosts | `None` |

### `waftester`
**WAF Bypass Tester:** Tests Web Application Firewalls for bypass vulnerabilities.

| Parameter | Description | Default |
|---|---|---|
| `--url` | Target URL | **Required** |
| `--method` | HTTP method | `GET` |
| `--packs` | Header packs to use | `None` |
| `--custom-headers`| Custom headers as JSON | `None` |
| `--concurrency`| Concurrent requests | `10` |
| `--timeout` | Request timeout | `10` |
| `--jitter` | Delay between requests | `0.1` |
| `--verify-tls`| Verify TLS certificates | `False` |
| `--profile` | Profile name | `None` |
| `--export` | Export format | `both` |

### `subdomain`
**Subdomain Enumeration:** Advanced subdomain discovery with multiple scan modes.

| Parameter | Description | Default |
|---|---|---|
| `command` | Subcommand: `single` or `batch` | **Required** |
| `--target` | Target domain | `None` |
| `--api-only`| Use only API sources | `False` |
| `--bruteforce-only`| Use only wordlist bruteforce | `False` |
| `--rate-limit`| Concurrent DNS queries | `200` |
| `--dns-timeout`| DNS timeout in seconds | `2` |
| `--dns-threads`| DNS thread pool size | `200` |
| `--api-keys`| API keys as JSON | `None` |
| `--proxy-type`| Proxy type | `None` |
| `--proxy-host`| Proxy host | `None` |
| `--proxy-port`| Proxy port | `None` |
| `--wordlist`| Wordlist file | `wordlists/subdomain.txt` |
| `--output-formats`| Output formats | `json,csv,txt` |
| `--file` | File with target domains | `None` |

### `crawler`
**Web Crawler:** Crawls websites to discover pages, links, and resources.

| Parameter | Description | Default |
|---|---|---|
| `command` | Subcommand: `single` or `batch` | **Required** |
| `--url` | Starting URL | `None` |
| `--depth` | Crawl depth | `3` |
| `--concurrency`| Concurrent requests | `10` |
| `--max-urls`| Maximum URLs to crawl | `100` |
| `--js-render`| Enable JavaScript rendering | `False` |
| `--no-robots`| Ignore robots.txt | `False` |
| `--output` | Output format | `None` |
| `--file` | File with URLs | `None` |
| `--output-file`| Output file path | `None` |

### `headers`
**Header Audit:** Audits HTTP security headers of web applications.

| Parameter | Description | Default |
|---|---|---|
| `command` | Subcommand: `single` or `batch` | **Required** |
| `--url` | Target URL | `None` |
| `--verbose` | Verbose output | `False` |
| `--allow-private`| Allow private IPs | `False` |
| `--timeout` | Request timeout | `15` |
| `--file` | File with URLs | `None` |

### `dirbrute`
**Dirbrute:** Directory and file brute-forcer for web applications.

| Parameter | Description | Default |
|---|---|---|
| `--url` | Base URL | **Required** |
| `--wordlist`| Wordlist file | `wordlists/directory-brute.txt` |
| `--threads` | Concurrent threads | `10` |
| `--extensions`| File extensions | `.php,.html,.js,.css,.txt,.zip,.bak,.sql` |
| `--status-codes`| Valid status codes | `200,204,301,302,403` |
| `--timeout` | Request timeout | `10` |
| `--delay` | Delay between requests | `0.0` |
| `--output` | Output file | `None` |
| `--verbose` | Verbose output | `False` |

### `sslinspect`
**SSLInspect:** SSL/TLS Certificate Inspector.

| Parameter | Description | Default |
|---|---|---|
| `--target` | Target host:port | **Required** |
| `--export` | Export format: `json` or `txt` | `json` |
| `--verbose` | Verbose output | `False` |

### `corstest`
**CORS Test:** Cross-Origin Resource Sharing (CORS) Misconfiguration Auditor.

| Parameter | Description | Default |
|---|---|---|
| `--url` | Target URL | **Required** |
| `--export` | Export format | `json` |
| `--verbose` | Verbose output | `False` |
| `--custom-origin`| Custom origin header | `None` |

### `smuggler`
**HTTP Request Smuggling Tester.**

| Parameter | Description | Default |
|---|---|---|
| `--url` | Target URL | **Required** |
| `--port` | Target port | `80` |
| `--method` | HTTP method | `GET` |
| `--verbose` | Verbose output | `False` |

### `tracepulse`
**Tracepulse:** Network Traceroute Utility.

| Parameter | Description | Default |
|---|---|---|
| `--destination`| Target host/IP | **Required** |
| `--protocol`| Protocol: `icmp`, `tcp`, or `udp` | `icmp` |
| `--max-hops`| Maximum hops | `30` |
| `--port` | Target port | `33434` |

### `js-crawler`
**JS Crawler:** JavaScript File Crawler and Endpoint Extractor.

| Parameter | Description | Default |
|---|---|---|
| `--url` | Target URL | **Required** |
| `--output` | Output file | `None` |
| `--depth` | Crawl depth | `3` |
| `--selenium`| Use Selenium | `False` |
| `--extensions`| File extensions | `.js` |
| `--user-agent`| User agent string for requests | `Mozilla/5.0...` |

### `py-obfuscator`
**Python Code Obfuscator.**

| Parameter | Description | Default |
|---|---|---|
| `--input` | Input Python file | **Required** |
| `--output` | Output file | `None` |
| `--level` | Obfuscation level (1-3) | `2` |
| `--rename-vars`| Rename variables | `True` |
| `--rename-funcs`| Rename functions | `True` |
| `--flow-obfuscation`| Apply flow obfuscation | `True` |
