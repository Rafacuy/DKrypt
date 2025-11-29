# DKrypt Module Guide

This guide provides a detailed overview of each security module available in DKrypt. For a complete list of all command-line options, please see the [CLI Reference](./CLI-REFERENCE.md).

---

## Web Application Modules

### `sqli` - SQL Injection Scanner
- **Description:** A powerful scanner to detect SQL injection vulnerabilities. It can test URL parameters, POST forms, and even HTTP headers.
- **Example:**
  ```bash
  # Basic scan on a URL
  python dkrypt.py sqli --url "http://testphp.vulnweb.com/listproducts.php?cat=1"

  # Scan with form and header testing
  python dkrypt.py sqli --url "http://example.com/login" --test-forms --test-headers
  ```

### `xss` - Cross-Site Scripting Scanner
- **Description:** An advanced, asynchronous scanner for finding XSS vulnerabilities. It features smart context-aware payload generation and stealth options.
- **Example:**
  ```bash
  # Run a smart scan on a target URL
  python dkrypt.py xss --url "https://xss-game.appspot.com/level1/frame" --smart-mode

  # Run a more aggressive scan with more threads
  python dkrypt.py xss --url "https://example.com/search?q=test" --threads 50
  ```

### `graphql` - GraphQL Introspector
- **Description:** Analyzes a GraphQL endpoint to identify potential security issues like introspection being enabled, and maps out the schema.
- **Example:**
  ```bash
  # Introspect a GraphQL endpoint
  python dkrypt.py graphql --url "https://example.com/graphql"

  # Export the schema to a specific file
  python dkrypt.py graphql --url "https://countries.trevorblades.com/" --export json --output schema
  ```

### `dirbrute` - Directory Bruteforcer
- **Description:** Discovers hidden directories and files on a web server using a wordlist. It's multi-threaded and supports custom extensions.
- **Example:**
  ```bash
  # Brute-force a target with 50 threads
  python dkrypt.py dirbrute --url https://example.com --threads 50

  # Search for specific file extensions
  python dkrypt.py dirbrute --url https://example.com --extensions .php,.bak,.zip
  ```

### `headers` - Security Header Audit
- **Description:** Audits the HTTP security headers of a web application and provides a report on missing or misconfigured headers.
- **Example:**
  ```bash
  # Audit a single URL
  python dkrypt.py headers single --url https://github.com

  # Audit a list of URLs from a file
  python dkrypt.py headers batch --file urls.txt
  ```

### `corstest` - CORS Misconfiguration Auditor
- **Description:** Tests for Cross-Origin Resource Sharing (CORS) misconfigurations by sending requests with various `Origin` headers.
- **Example:**
  ```bash
  # Test a URL for CORS issues
  python dkrypt.py corstest --url https://example.com

  # Test with a specific custom origin
  python dkrypt.py corstest --url https://api.example.com --custom-origin "https://evil.com"
  ```

### `waftester` - WAF Bypass Tester
- **Description:** A tool to test a Web Application Firewall's (WAF) effectiveness by sending a variety of potentially malicious or malformed requests.
- **Example:**
  ```bash
  # Run a basic WAF test
  python dkrypt.py waftester --url https://example.com

  # Use specific header mutation packs
  python dkrypt.py waftester --url https://example.com --packs "x-forwarded-for, user-agent"
  ```

### `smuggler` - HTTP Request Smuggling Tester
- **Description:** Checks for vulnerabilities related to HTTP Request Smuggling (HRS) by sending specially crafted requests.
- **Example:**
  ```bash
  # Test a URL for HTTP smuggling vulnerabilities
  python dkrypt.py smuggler --url https://example.com
  ```

---

## Reconnaissance Modules

### `subdomain` - Subdomain Enumeration
- **Description:** Discovers subdomains using both passive (API-based) and active (brute-force) methods. It's highly concurrent and feature-rich.
- **Example:**
  ```bash
  # Run a hybrid scan on a single domain
  python dkrypt.py subdomain single --target example.com

  # Run a pure bruteforce scan using a custom wordlist
  python dkrypt.py subdomain single --target example.com --bruteforce-only --wordlist /path/to/my/wordlist.txt
  ```

### `portscanner` - Port Scanner
- **Description:** A comprehensive NMAP-based port scanner that supports various scan types, service/OS detection, and NSE scripts.
- **Example:**
  ```bash
  # Run a simple SYN scan on the top 1024 ports
  python dkrypt.py portscanner single --target scanme.nmap.org

  # Run an aggressive scan on all ports with service and OS detection
  python dkrypt.py portscanner single --target scanme.nmap.org --ports 1-65535 --service-detection --os-detection
  ```

### `crawler` - Web Crawler
- **Description:** A web crawler that discovers and maps a website's structure by following links. It can optionally render JavaScript.
- **Example:**
  ```bash
  # Crawl a website up to a depth of 5
  python dkrypt.py crawler single --url https://example.com --depth 5

  # Crawl a site with JavaScript rendering enabled
  python dkrypt.py crawler single --url https://modern-js-app.com --js-render
  ```

### `jscrawler` - JavaScript Crawler
- **Description:** Specifically designed to find and extract endpoints, secrets, and other interesting information from JavaScript files.
- **Example:**
  ```bash
  # Scan a website for JavaScript files and analyze them
  python dkrypt.py js-crawler --url https://example.com

  # Save the output to a file
  python dkrypt.py js-crawler --url https://example.com --output findings.txt
  ```

### `sslinspect` - SSL/TLS Inspector
- **Description:** Inspects the SSL/TLS certificate of a target server, providing details on the certificate chain, expiration, and supported protocols.
- **Example:**
  ```bash
  # Inspect the certificate for github.com
  python dkrypt.py sslinspect --target github.com:443
  ```

### `tracepulse` - Network Traceroute
- **Description:** A traceroute utility to map the network path from your machine to a destination host. It supports ICMP, TCP, and UDP protocols.
- **Example:**
  ```bash
  # Trace the route to a destination
  python dkrypt.py tracepulse --destination 8.8.8.8

  # Use TCP for the trace
  python dkrypt.py tracepulse --destination google.com --protocol tcp
  ```

---

## Utility Modules

### `py-obfuscator` - Python Code Obfuscator
- **Description:** A utility to obfuscate Python code, making it harder to read and reverse-engineer.
- **Example:**
  ```bash
  # Obfuscate a Python script with default settings
  python dkrypt.py py-obfuscator --input my_script.py --output my_script_obfuscated.py

  # Use the highest level of obfuscation
  python dkrypt.py py-obfuscator --input my_script.py --level 3
  ```
