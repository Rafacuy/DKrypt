# DKrypt CLI Guide

DKrypt offers a Command Line Interface (CLI) for automating penetration testing and reconnaissance tasks. This guide will walk you through its usage, available modules, and their respective options

## Table of Contents
- [DKrypt CLI Guide](#dkrypt-cli-guide)
  - [Table of Contents](#table-of-contents)
  - [1. General Usage](#1-general-usage)
  - [2. Modules](#2-modules)
    - [SQL Injection Scanner (`sqli`)](#sql-injection-scanner-sqli)
    - [XSS Scanner (`xss`)](#xss-scanner-xss)
    - [Port Scanner (`portscanner`)](#port-scanner-portscanner)
      - [`single` - Scan a single target host.](#single---scan-a-single-target-host)
      - [`batch` - Scan multiple targets from a file.](#batch---scan-multiple-targets-from-a-file)
    - [WAF Bypass Tester (`waftester`)](#waf-bypass-tester-waftester)
    - [Subdomain Enumeration (`subdomain`)](#subdomain-enumeration-subdomain)
      - [`single` - Enumerate subdomains for a single target domain.](#single---enumerate-subdomains-for-a-single-target-domain)
      - [`batch` - Enumerate subdomains for multiple targets listed in a file.](#batch---enumerate-subdomains-for-multiple-targets-listed-in-a-file)
    - [Web Crawler (`crawler`)](#web-crawler-crawler)
      - [`single` - Crawl a single URL.](#single---crawl-a-single-url)
      - [`batch` - Crawl multiple URLs listed in a file.](#batch---crawl-multiple-urls-listed-in-a-file)
    - [Header Audit (`headers`)](#header-audit-headers)
      - [`single` - Audit security headers for a single URL.](#single---audit-security-headers-for-a-single-url)
      - [`batch` - Audit security headers for multiple URLs listed in a file.](#batch---audit-security-headers-for-multiple-urls-listed-in-a-file)
    - [Directory Bruteforcer (`dirbrute`)](#directory-bruteforcer-dirbrute)
    - [SSL Inspector (`sslinspect`)](#ssl-inspector-sslinspect)
    - [CORS Scanner (`corstest`)](#cors-scanner-corstest)
    - [HTTP Desync Attack Tester (`smuggler`)](#http-desync-attack-tester-smuggler)
    - [Tracepulse (`tracepulse`)](#tracepulse-tracepulse)
    - [JS Crawler \& Endpoint Extractor (`js-crawler`)](#js-crawler--endpoint-extractor-js-crawler)
    - [Python Obfuscator (`py-obfuscator`)](#python-obfuscator-py-obfuscator)
    - [GraphQL Introspection \& Vulnerability Scanner (`graphql`)](#graphql-introspection--vulnerability-scanner-graphql)
  - [3. Output and Reporting](#3-output-and-reporting)

---

## 1. General Usage

The DKrypt CLI follows a standard structure:

```bash
python dkrypt.py <module> [options]
```

-   `<module>`: Specifies the penetration testing module you want to use (e.g., `sqli`, `xss`, `portscanner`).
-   `[options]`: These are arguments specific to the chosen module.

To get help for the main CLI:

```bash
python dkrypt.py --help
```

To get help for a specific module:

```bash
python dkrypt.py <module> --help
```

**Example:**
```bash
python dkrypt.py sqli --help
```

## 2. Modules

Here's a detailed breakdown of each available module and its options.

### SQL Injection Scanner (`sqli`)

Detects SQL injection vulnerabilities in web applications.

**Usage:**
```bash
python dkrypt.py sqli --url <target_url> [options]
```

| Option           | Type    | Default | Description                                                                                             | Required |
| :--------------- | :------ | :------ | :------------------------------------------------------------------------------------------------------ | :------- |
| `--url`          | string  |         | Target URL to scan for SQL injection (e.g., `https://example.com/vulnerable?id=1`)                      | Yes      |
| `--test-forms`   | flag    | False   | Enable testing of POST forms for SQL injection. The scanner will attempt to find and inject into forms. | No       |
| `--test-headers` | flag    | False   | Enable testing of HTTP headers for SQL injection. Useful for blind SQLi in headers.                     | No       |
| `--test-apis`    | flag    | False   | Enable testing of API endpoints for SQL injection. Requires the URL to point to an API endpoint.        | No       |
| `--export`       | string  | `html`  | Specify the format for exporting scan results. Options: `html`, `csv`, or `none`.                       | No       |

**Example:**
```bash
python dkrypt.py sqli --url https://example.com/search?id=1 --test-forms --export csv
```

### XSS Scanner (`xss`)

Detects Cross-Site Scripting vulnerabilities in web applications.

**Usage:**
```bash
python dkrypt.py xss --url <target_url> [options]
```

| Option           | Type    | Default | Description                                                                                             | Required |
| :--------------- | :------ | :------ | :------------------------------------------------------------------------------------------------------ | :------- |
| `--url`          | string  |         | Target URL to scan for XSS (e.g., `https://example.com/search?query=test`)                              | Yes      |
| `--threads`      | integer | `20`    | Number of concurrent threads to use for scanning. Higher values can speed up the scan but may be detected by WAFs. | No       |
| `--rate-limit`   | integer | `5`     | Maximum number of requests per second to send. Helps in avoiding rate limiting by the target server.    | No       |
| `--max-payloads` | integer | `15`    | Maximum number of XSS payloads to test per context (e.g., per input field).                             | No       |
| `--batch-size`   | integer | `100`   | Number of payloads to send in a single batch.                                                           | No       |
| `--smart-mode`   | flag    | False   | Enable smart mode for more intelligent payload generation and detection, reducing false positives.      | No       |
| `--stealth-mode` | flag    | False   | Enable stealth mode to make the scan less detectable by WAFs and intrusion detection systems.           | No       |
| `--test-headers` | flag    | False   | Test HTTP headers for XSS vulnerabilities. Useful for reflected XSS in headers.                         | No       |
| `--verbose`      | flag    | False   | Enable verbose output to display detailed information during the scan.                                  | No       |

**Example:**
```bash
python dkrypt.py xss --url https://example.com/comments --threads 50 --smart-mode
```

### Port Scanner (`portscanner`)

Scans target hosts for open ports and services using NMAP.

**Usage:**
```bash
python dkrypt.py portscanner <command> [options]
```

**Commands:**

#### `single` - Scan a single target host.

**Usage:**
```bash
python dkrypt.py portscanner single --target <host> [options]
```

| Option              | Type    | Default      | Description                                                                                             | Required |
| :------------------ | :------ | :----------- | :------------------------------------------------------------------------------------------------------ | :------- |
| `--target`          | string  |              | Target host to scan (e.g., `example.com` or `192.168.1.1`)                                              | Yes      |
| `--ports`           | string  | `1-1024`     | Ports to scan (e.g., `1-1024`, `80,443,8080`, or `all`).                                                | No       |
| `--scan-type`       | string  | `SYN`        | Type of NMAP scan to perform. Options: `SYN` (stealthy), `CON` (connect), `UDP`.                        | No       |
| `--timing`          | string  | `normal`     | Timing profile for the scan. Options: `paranoid`, `sneaky`, `polite`, `normal`, `aggressive`, `insane`. | No       |
| `--service-detection` | flag    | False        | Enable service and version detection on open ports.                                                     | No       |
| `--os-detection`    | flag    | False        | Enable operating system detection.                                                                      | No       |
| `--script-scan`     | string  | `none`       | Perform an NMAP Scripting Engine (NSE) scan. Options: `default` (safe scripts), `vuln` (vulnerability scripts), or `none`. | No       |
| `--custom-args`     | string  | `""`         | Additional custom NMAP arguments to pass directly to NMAP (e.g., `-sV -O`).                             | No       |
| `--verbosity`       | integer | `1`          | Verbosity level of NMAP output (0=silent, 1=normal, 2=detailed).                                        | No       |
| `--output`          | string  | `no`         | Output format for scan results. Options: `json`, `csv`, or `no` (no file output).                       | No       |

**Example:**
```bash
python dkrypt.py portscanner single --target scanme.nmap.org --ports 22,80,443 --scan-type SYN --service-detection --output json
```

#### `batch` - Scan multiple targets from a file.

**Usage:**
```bash
python dkrypt.py portscanner batch --file <path_to_file> [options]
```

| Option              | Type    | Default      | Description                                                                                             | Required |
| :------------------ | :------ | :----------- | :------------------------------------------------------------------------------------------------------ | :------- |
| `--file`            | string  |              | Path to a file containing target hosts, one per line.                                                   | Yes      |
| `--ports`           | string  | `1-1024`     | Ports to scan (e.g., `1-1024`, `80,443,8080`, or `all`).                                                | No       |
| `--scan-type`       | string  | `SYN`        | Type of NMAP scan to perform. Options: `SYN` (stealthy), `CON` (connect), `UDP`.                        | No       |
| `--timing`          | string  | `normal`     | Timing profile for the scan. Options: `paranoid`, `sneaky`, `polite`, `normal`, `aggressive`, `insane`. | No       |
| `--service-detection` | flag    | False        | Enable service and version detection on open ports.                                                     | No       |
| `--os-detection`    | flag    | False        | Enable operating system detection.                                                                      | No       |
| `--script-scan`     | string  | `none`       | Perform an NMAP Scripting Engine (NSE) scan. Options: `default` (safe scripts), `vuln` (vulnerability scripts), or `none`. | No       |
| `--custom-args`     | string  | `""`         | Additional custom NMAP arguments to pass directly to NMAP (e.g., `-sV -O`).                             | No       |
| `--verbosity`       | integer | `1`          | Verbosity level of NMAP output (0=silent, 1=normal, 2=detailed).                                        | No       |
| `--output`          | string  | `json`       | Output format for scan results. Options: `json`, `csv`, or `no` (no file output).                       | No       |

**Example:**
```bash
python dkrypt.py portscanner batch --file targets.txt --ports 80,443 --output csv
```

### WAF Bypass Tester (`waftester`)

Tests Web Application Firewalls for bypass vulnerabilities.

**Usage:**
```bash
python dkrypt.py waftester --url <target_url> [options]
```

| Option           | Type    | Default   | Description                                                                                             | Required |
| :--------------- | :------ | :-------- | :------------------------------------------------------------------------------------------------------ | :------- |
| `--url`          | string  |           | Target URL to test against the WAF (e.g., `https://example.com/login`)                                  | Yes      |
| `--method`       | string  | `GET`     | HTTP method to use for requests (GET, POST, PUT, etc.).                                                 | No       |
| `--packs`        | string  |           | Comma-separated list of header packs to use for WAF bypass testing (e.g., `x-forwarded-for,user-agent`). | No       |
| `--custom-headers` | string  |           | JSON string of custom headers to include in requests (e.g., `{"X-Custom-Header": "value"}`).           | No       |
| `--concurrency`  | integer | `10`      | Number of concurrent requests to send.                                                                  | No       |
| `--timeout`      | integer | `10`      | Request timeout in seconds.                                                                             | No       |
| `--jitter`       | float   | `0.1`     | Random delay between requests in seconds to avoid detection.                                            | No       |
| `--verify-tls`   | flag    | False     | Verify TLS certificates for HTTPS connections.                                                          | No       |
| `--profile`      | string  |           | Name of the WAF bypass profile to load (e.g., `cloudflare`, `sucuri`).                                  | No       |
| `--export`       | string  | `both`    | Export format for test results. Options: `json`, `csv`, or `both`.                                      | No       |

**Example:**
```bash
python dkrypt.py waftester --url https://example.com/admin --method POST --packs x-forwarded-for --profile cloudflare --export json
```

### Subdomain Enumeration (`subdomain`)

subdomain discovery tool with multiple scan modes and performance optimizations for large-scale enumeration.

**Usage:**
```bash
python dkrypt.py subdomain <command> [options]
```

**Commands:**

#### `single` - Enumerate subdomains for a single target domain.

**Usage:**
```bash
python dkrypt.py subdomain single --target <domain> [options]
```

| Option              | Type    | Default                 | Description                                                                              | Required |
|---------------------|---------|-------------------------|------------------------------------------------------------------------------------------|----------|
| `--target`          | string  | None                    | Target domain to enumerate subdomains for                                                | Yes      |
| `--api-only`        | flag    | False                   | Use only API sources for enumeration (fast, stealthy, less noisy)                        | No       |
| `--bruteforce-only` | flag    | False                   | Use only wordlist bruteforce for enumeration (thorough, comprehensive)                   | No       |
| `--rate-limit`      | integer | 200                     | Number of concurrent DNS queries (recommended: 100-500 for large wordlists)              | No       |
| `--dns-timeout`     | integer | 2                       | DNS timeout in seconds (lower = faster, higher = more reliable)                          | No       |
| `--dns-threads`     | integer | 200                     | DNS thread pool size for concurrent processing                                           | No       |
| `--api-keys`        | string  | None                    | JSON string of API keys for premium sources (e.g., '{"virustotal": "your_api_key"}')    | No       |
| `--proxy-type`      | string  | None                    | Type of proxy to use for DNS resolution (socks4, socks5, http)                          | No       |
| `--proxy-host`      | string  | None                    | Proxy host address (required if --proxy-type is specified)                              | No       |
| `--proxy-port`      | integer | None                    | Proxy port number (uses defaults: 1080 for SOCKS, 8080 for HTTP)                       | No       |
| `--wordlist`        | string  | wordlists/subdomain.txt | Path to custom wordlist file for subdomain brute-forcing                                | No       |
| `--output-formats`  | string  | json,csv,txt            | Comma-separated list of output formats to generate                                       | No       |

**Examples:**
```bash
# Fast API-only enumeration (recommended for quick reconnaissance)
python dkrypt.py subdomain single --target example.com --api-only

# High-performance bruteforce with large wordlist  
python dkrypt.py subdomain single --target example.com --bruteforce-only --rate-limit 400 --dns-timeout 1

# Comprehensive hybrid scan with custom wordlist
python dkrypt.py subdomain single --target example.com --wordlist custom.txt --rate-limit 300

# Stealth mode with proxy
python dkrypt.py subdomain single --target example.com --proxy-type socks5 --proxy-host 127.0.0.1 --proxy-port 9050

# API enumeration with premium keys
python dkrypt.py subdomain single --target example.com --api-only --api-keys '{"virustotal": "your_key"}'
```

#### `batch` - Enumerate subdomains for multiple targets listed in a file.

**Usage:**
```bash
python dkrypt.py subdomain batch --file <path_to_file> [options]
```

| Option              | Type    | Default                 | Description                                                                              | Required |
|---------------------|---------|-------------------------|------------------------------------------------------------------------------------------|----------|
| `--file`            | string  | None                    | Path to file containing target domains, one per line                                     | Yes      |
| `--api-only`        | flag    | False                   | Use only API sources for enumeration (fast, stealthy, less noisy)                        | No       |
| `--bruteforce-only` | flag    | False                   | Use only wordlist bruteforce for enumeration (thorough, comprehensive)                   | No       |
| `--rate-limit`      | integer | 200                     | Number of concurrent DNS queries (recommended: 100-500 for large wordlists)              | No       |
| `--dns-timeout`     | integer | 2                       | DNS timeout in seconds (lower = faster, higher = more reliable)                          | No       |
| `--dns-threads`     | integer | 200                     | DNS thread pool size for concurrent processing                                           | No       |
| `--api-keys`        | string  | None                    | JSON string of API keys for premium sources (e.g., '{"virustotal": "your_api_key"}')    | No       |
| `--proxy-type`      | string  | None                    | Type of proxy to use for DNS resolution (socks4, socks5, http)                          | No       |
| `--proxy-host`      | string  | None                    | Proxy host address (required if --proxy-type is specified)                              | No       |
| `--proxy-port`      | integer | None                    | Proxy port number (uses defaults: 1080 for SOCKS, 8080 for HTTP)                       | No       |
| `--wordlist`        | string  | wordlists/subdomain.txt | Path to custom wordlist file for subdomain brute-forcing                                | No       |
| `--output-formats`  | string  | json,csv,txt            | Comma-separated list of output formats to generate                                       | No       |

**Examples:**
```bash
# Fast API-only batch scan
python dkrypt.py subdomain batch --file domains.txt --api-only --output-formats json,csv

# High-performance batch bruteforce  
python dkrypt.py subdomain batch --file domains.txt --bruteforce-only --rate-limit 500 --dns-threads 300

# Comprehensive batch scan with all modes
python dkrypt.py subdomain batch --file domains.txt --rate-limit 300 --output-formats json,csv,txt

# Batch scan with proxy for anonymity
python dkrypt.py subdomain batch --file domains.txt --proxy-type socks5 --proxy-host 127.0.0.1
```


### Web Crawler (`crawler`)

Crawls websites to discover pages, links, and resources.

**Usage:**
```bash
python dkrypt.py crawler <command> [options]
```

**Commands:**

#### `single` - Crawl a single URL.

**Usage:**
```bash
python dkrypt.py crawler single --url <target_url> [options]
```

| Option        | Type    | Default | Description                                                                                             | Required |
| :------------ | :------ | :------ | :------------------------------------------------------------------------------------------------------ | :------- |
| `--url`       | string  |         | URL to start crawling from (e.g., `https://example.com`)                                                | Yes      |
| `--depth`     | integer | `3`     | Maximum depth to crawl from the starting URL.                                                           | No       |
| `--concurrency` | integer | `10`    | Number of concurrent requests to make during crawling.                                                  | No       |
| `--max-urls`  | integer | `100`   | Maximum number of unique URLs to crawl.                                                                 | No       |
| `--js-render` | flag    | False   | Enable JavaScript rendering for pages to discover dynamically loaded content.                           | No       |
| `--no-robots` | flag    | False   | Ignore robots.txt directives during crawling.                                                           | No       |
| `--output`    | string  |         | Output format for crawl results. Options: `json` or `csv`.                                              | No       |
| `--file`      | string  |         | File path to save the crawl results to.                                                                 | No       |

**Example:**
```bash
python dkrypt.py crawler single --url https://example.com --depth 5 --js-render --output json --file example_crawl.json
```

#### `batch` - Crawl multiple URLs listed in a file.

**Usage:**
```bash
python dkrypt.py crawler batch --file <path_to_file> [options]
```

| Option        | Type    | Default | Description                                                                                             | Required |
| :------------ | :------ | :------ | :------------------------------------------------------------------------------------------------------ | :------- |
| `--file`      | string  |         | Path to a file containing URLs to crawl, one per line.                                                  | Yes      |
| `--depth`     | integer | `3`     | Maximum depth to crawl from each starting URL.                                                          | No       |
| `--concurrency` | integer | `10`    | Number of concurrent requests to make during crawling.                                                  | No       |
| `--max-urls`  | integer | `100`   | Maximum number of unique URLs to crawl per target.                                                      | No       |
| `--js-render` | flag    | False   | Enable JavaScript rendering for pages to discover dynamically loaded content.                           | No       |
| `--no-robots` | flag    | False   | Ignore robots.txt directives during crawling.                                                           | No       |
| `--output`    | string  |         | Output format for crawl results. Options: `json` or `csv`.                                              | No       |
| `--output-file` | string  |         | File path to save the crawl results to.                                                                 | No       |

**Example:**
```bash
python dkrypt.py crawler batch --file urls.txt --concurrency 20 --output csv --output-file batch_crawl.csv
```

### Header Audit (`headers`)

Audits HTTP security headers of web applications.

**Usage:**
```bash
python dkrypt.py headers <command> [options]
```

**Commands:**

#### `single` - Audit security headers for a single URL.

**Usage:**
```bash
python dkrypt.py headers single --url <target_url> [options]
```

| Option          | Type    | Default | Description                                                                                             | Required |
| :-------------- | :------ | :------ | :------------------------------------------------------------------------------------------------------ | :------- |
| `--url`         | string  |         | URL to audit (e.g., `https://example.com`)                                                              | Yes      |
| `--verbose`     | flag    | False   | Enable verbose mode to display detailed header information.                                             | No       |
| `--allow-private` | flag    | False   | Allow auditing of private IP addresses (e.g., localhost, internal networks).                            | No       |
| `--timeout`     | integer | `15`    | Request timeout in seconds.                                                                             | No       |

**Example:**
```bash
python dkrypt.py headers single --url https://example.com --verbose
```

#### `batch` - Audit security headers for multiple URLs listed in a file.

**Usage:**
```bash
python dkrypt.py headers batch --file <path_to_file> [options]
```

| Option          | Type    | Default | Description                                                                                             | Required |
| :-------------- | :------ | :------ | :------------------------------------------------------------------------------------------------------ | :------- |
| `--file`        | string  |         | Path to a file containing URLs to audit, one per line.                                                  | Yes      |
| `--verbose`     | flag    | False   | Enable verbose mode to display detailed header information.                                             | No       |
| `--allow-private` | flag    | False   | Allow auditing of private IP addresses (e.g., localhost, internal networks).                            | No       |
| `--timeout`     | integer | `15`    | Request timeout in seconds.                                                                             | No       |
| `--output`      | string  |         | Output format for audit results. Options: `json` or `csv`.                                              | No       |
| `--output-file` | string  |         | File path to save the audit results to.                                                                 | No       |

**Example:**
```bash
python dkrypt.py headers batch --file urls_to_audit.txt --output csv --output-file header_audit_results.csv
```

### Directory Bruteforcer (`dirbrute`)

Discovers hidden directories and files on a web server.

**Usage:**
```bash
python dkrypt.py dirbrute --url <target_url> [options]
```

| Option          | Type    | Default                                     | Description                                                                                             | Required |
| :-------------- | :------ | :------------------------------------------ | :------------------------------------------------------------------------------------------------------ | :------- |
| `--url`         | string  |                                             | Target URL to bruteforce (e.g., `https://example.com/`)                                                 | Yes      |
| `--wordlist`    | string  | `wordlists/directory-brute.txt`             | Path to a custom wordlist file for directory brute-forcing.                                             | No       |
| `--extensions`  | string  | `/,.php,.html,...`                          | Comma-separated list of file extensions to test (e.g., `.php,.html,.bak`). Default includes common extensions. | No       |
| `--valid-codes` | string  | `200,301,302,...`                           | Comma-separated list of HTTP status codes to consider as valid (e.g., `200,301,403`). Default includes common success and redirection codes. | No       |
| `--max-workers` | integer | `20`                                        | Number of concurrent threads to use for brute-forcing.                                                  | No       |
| `--report`      | string  | `dir_reports.txt`                           | File path to save the brute-forcing report to.                                                          | No       |

**Example:**
```bash
python dkrypt.py dirbrute --url https://example.com --wordlist common.txt --extensions .php,.txt --valid-codes 200,403
```

### SSL Inspector (`sslinspect`)

Analyzes SSL/TLS certificates and configurations of a target host.

**Usage:**
```bash
python dkrypt.py sslinspect --target <host:port> [options]
```

| Option   | Type    | Default | Description                                                                                             | Required |
| :------- | :------ | :------ | :------------------------------------------------------------------------------------------------------ | :------- |
| `--target` | string  |         | Target host and port to inspect (e.g., `google.com:443`, `192.168.1.1:8443`)                            | Yes      |
| `--export` | string  |         | Export format for SSL inspection results. Options: `json` or `txt`.                                     | No       |

**Example:**
```bash
python dkrypt.py sslinspect --target example.com:443 --export json
```

### CORS Scanner (`corstest`)

Audits Cross-Origin Resource Sharing (CORS) configurations for misconfigurations.

**Usage:**
```bash
python dkrypt.py corstest --url <target_url> [options]
```

| Option   | Type    | Default | Description                                                                                             | Required |
| :------- | :------ | :------ | :------------------------------------------------------------------------------------------------------ | :------- |
| `--url`    | string  |         | Target URL to scan for CORS misconfigurations (e.g., `https://example.com`)                             | Yes      |
| `--export` | string  |         | Export format for CORS scan results. Options: `json`, `csv`, `txt` or `all`.                                  | No       |
| `--output` | string  |         | File path to save the CORS scan report to.                                                              | No       |

**Example:**
```bash
python dkrypt.py corstest --url https://api.example.com --export json --output cors_report.json
```

### HTTP Desync Attack Tester (`smuggler`)

Tests for HTTP Request Smuggling vulnerabilities.

**Usage:**
```bash
python dkrypt.py smuggler --url <target_url> [options]
```

| Option    | Type    | Default | Description                                                                                             | Required |
| :-------- | :------ | :------ | :------------------------------------------------------------------------------------------------------ | :------- |
| `--url`     | string  |         | Target URL for HTTP Desync testing (e.g., `https://example.com`)                                        | Yes      |
| `--port`    | integer |         | Target port for the HTTP Desync test. If not specified, defaults to 80 for HTTP and 443 for HTTPS.      | No       |
| `--headers` | string  |         | Custom headers to include in the requests, in key:val,key2:val2 format (e.g., `X-Custom:1,User-Agent:Test`). | No       |

**Example:**
```bash
python dkrypt.py smuggler --url https://example.com --port 80 --headers "X-Forwarded-Host:evil.com"
```

### Tracepulse (`tracepulse`)

A network traceroute utility to map network paths.

**Usage:**
```bash
python dkrypt.py tracepulse --destination <host_or_ip> [options]
```

| Option          | Type    | Default | Description                                                                                             | Required |
| :-------------- | :------ | :------ | :------------------------------------------------------------------------------------------------------ | :------- |
| `--destination` | string  |         | Destination domain or IP address to trace (e.g., `google.com`, `8.8.8.8`)                               | Yes      |
| `--protocol`    | string  | `icmp`  | Protocol to use for traceroute. Options: `icmp`, `tcp`, or `udp`.                                       | No       |
| `--port`        | integer |         | Destination port for TCP and UDP probes. Required for tcp/udp protocols.                                | No       |
| `--max-hops`    | integer | `30`    | Maximum number of hops to trace.                                                                        | No       |
| `--timeout`     | float   | `2.0`   | Timeout per probe in seconds.                                                                           | No       |
| `--probe-delay` | float   | `0.1`   | Delay between probes in seconds.                                                                        | No       |
| `--allow-private` | flag    | False   | Allow traceroute to private, loopback, and multicast addresses.                                         | No       |
| `--save`        | flag    | False   | Save the traceroute results to a file.                                                                  | No       |
| `--output`      | string  |         | File path to save the traceroute results to. Used with `--save`.                                        | No       |

**Example:**
```bash
python dkrypt.py tracepulse --destination 8.8.8.8 --protocol tcp --port 443 --save --output trace_google.txt
```

### JS Crawler & Endpoint Extractor (`js-crawler`)

Crawls JavaScript files to extract hidden endpoints and sensitive information.

**Usage:**
```bash
python dkrypt.py js-crawler --url <target_url> [options]
```

| Option      | Type    | Default | Description                                                                                             | Required |
| :---------- | :------ | :------ | :------------------------------------------------------------------------------------------------------ | :------- |
| `--url`       | string  |         | Target URL to start crawling JavaScript files from (e.g., `https://example.com`)                        | Yes      |
| `--selenium`  | flag    | False   | Enable JavaScript rendering using Selenium for dynamic content analysis.                                | No       |
| `--output`    | string  |         | File path to save the extracted endpoints and information to.                                           | No       |
| `--format`    | string  | `text`  | Output format for the extracted data. Options: `json`, `csv`, or `text`.                                | No       |
| `--no-robots` | flag    | False   | Disable robots.txt compliance when crawling JavaScript files.                                           | No       |

**Example:**
```bash
python dkrypt.py js-crawler --url https://example.com --selenium --output endpoints.json --format json
```

### Python Obfuscator (`py-obfuscator`)

Obfuscates Python code to protect against reverse-engineering.

**Usage:**
```bash
python dkrypt.py py-obfuscator --input <input_file> [options]
```

| Option    | Type    | Default | Description                                                                                             | Required |
| :-------- | :------ | :------ | :------------------------------------------------------------------------------------------------------ | :------- |
| `--input`   | string  |         | Path to the Python file to obfuscate (e.g., `my_script.py`)                                             | Yes      |
| `--output`  | string  |         | Path to save the obfuscated Python file. If not specified, a default name will be used.                 | No       |
| `--key`     | string  |         | Custom encryption passphrase to use for obfuscation. Enhances protection.                               | No       |
| `--level`   | integer | `2`     | Protection level for obfuscation. Higher levels provide stronger protection but may increase file size. Options: 1, 2, or 3. | No       |

**Example:**
```bash
python dkrypt.py py-obfuscator --input my_script.py --output obfuscated_script.py --level 3 --key "mysecretkey"
```

### GraphQL Introspection & Vulnerability Scanner (`graphql`)

Analyzes GraphQL endpoints for exposed schemas, queries, and possible misconfigurations. Useful for identifying sensitive fields, hidden mutations, and testing endpoint security.

**Usage:**

```bash
python dkrypt.py graphql --url <graphql_endpoint> [options]
```

| Option                | Type    | Default        | Description                                                                               | Required |
| --------------------- | ------- | -------------- | ----------------------------------------------------------------------------------------- | -------- |
| `--url`               | string  |                | GraphQL endpoint URL to introspect (e.g., `https://example.com/graphql`).                 | Yes      |
| `--headers`           | string  | `{}`           | Custom headers as JSON string (e.g., `{"Authorization": "Bearer token"}`).                | No       |
| `--timeout`           | integer | `30`           | Request timeout in seconds (increase for slow endpoints).                                 | No       |
| `--export`            | string  | `json,csv,txt` | Export formats (comma-separated). Options: `json`, `csv`, `txt`.                          | No       |
| `--output`            | string  | auto           | Output filename prefix for results. Auto-generated if not specified.                      | No       |
| `--verbose`           | flag    | False          | Display detailed results in console including queries, mutations, and analysis details.   | No       |
| `--export-raw`        | flag    | False          | Export raw GraphQL responses even on failure for manual debugging.                        | No       |
| `--no-header-factory` | flag    | False          | Disable HeaderFactory. Uses static headers instead of realistic rotating headers.         | No       |
| `--header-pool-size`  | int     | config-based   | Size of HeaderFactory pool for generating browser-like headers.                           | No       |
| `--rotate-headers`    | flag    | False          | Enable rotating headers per request to mimic different browser sessions (anti-detection). | No       |

**Examples:**

```bash
# Basic introspection scan
python dkrypt.py graphql --url https://example.com/graphql

# With custom headers and verbose output
python dkrypt.py graphql --url https://example.com/graphql --headers '{"Authorization": "Bearer abc123"}' --verbose

# Export results to JSON and TXT with custom filename
python dkrypt.py graphql --url https://example.com/graphql --export json,txt --output graphql_audit
```


## 3. Output and Reporting

Many modules support various output formats (JSON, CSV, HTML, TXT) and allow specifying an output file. Always check the `--help` for each module to see available options.

Reports are typically saved in the `reports/` directory by default, or to a specified path if the `--output` or `--file` option is used.
