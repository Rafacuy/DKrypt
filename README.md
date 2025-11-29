<p align="center">
<a href="#"><img alt="DKrypt Logo" src="./docs/logo.png" width="55%"></a>
</p>

<em><h6 align="center">Developed by Rafacuy (arazz.)</h6></em>

<p align="center">
    <img alt="Python 3.10+" src="https://img.shields.io/badge/Python-3.10+-FFD43B?style=for-the-badge&logo=python&logoColor=blue">
    <img alt="Version 1.4.0" src="https://img.shields.io/badge/Version-1.4.0-green?style=for-the-badge">
    <img alt="Status STABLE" src="https://img.shields.io/badge/Status-STABLE-brightgreen?style=for-the-badge">
    <img alt="Documentation" src="https://img.shields.io/badge/Docs-Passing-blue.svg?style=for-the-badge">
    <img alt="License GPL-3.0" src="https://img.shields.io/github/license/Rafacuy/DKrypt?color=orange&style=for-the-badge">
</p>

---

**DKrypt** is a modern penetration testing framework for security professionals and ethical hackers. Built with Python 3.10+, it provides a unified CLI and a rich interactive TUI for reconnaissance, vulnerability scanning, and security analysis.

## Table of Contents
- [🎯 Overview](#-overview)
- [✨ Key Features](#-key-features)
- [📦 Quick Start](#-quick-start)
- [🎨 Interactive CLI  Mode](#-interactive-mode)
- [📚 Documentation](#-documentation)
- [🔧 Available Modules](#-available-modules)
- [🏗️ Project Structure](#️-project-structure)
- [🤝 Contributing](#-contributing)
- [⚖️ Legal Notice](#️-legal-notice)
- [📜 License](#-license)

---

## 🎯 Overview

DKrypt is designed to be a comprehensive and extensible platform for security testing. It combines a powerful set of tools with a user-friendly interface, allowing both seasoned professionals and newcomers to conduct security assessments efficiently.

## ✨ Key Features

- 🔍 **15+ Security Modules** - A wide array of tools for SQLi, XSS, CORS, subdomain enumeration, port scanning, and more.
- ⚡ **High Performance** - Built with asynchronous operations for speed and intelligent rate limiting to avoid detection.
- 🎨 **Beautiful & Interactive TUI** - A rich, terminal-based user interface that provides a dashboard for running and managing scans in real-time.
- 📊 **Multiple Export Formats** - Generate reports in JSON, HTML, and CSV.
- 🛡️ **Production Ready** - With comprehensive error handling and over 105+ tests, DKrypt is built for stability.
- 🔧 **Modular Architecture** - The framework is designed to be easily extended. Adding new modules is straightforward.

---

## 📦 Quick Start

### Installation

```bash
git clone https://github.com/Rafacuy/DKrypt.git
cd DKrypt
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
pip install -r requirements.txt
```

### Basic Usage

While interactive mode is recommended, you can run modules directly from the command line.

```bash
# Run the SQLi scanner on a target URL
python dkrypt.py sqli --url https://example.com/vulnerable?id=1

# Discover subdomains for a domain
python dkrypt.py subdomain single --target example.com

# Scan a URL for XSS vulnerabilities in smart mode
python dkrypt.py xss --url https://example.com/search?q=test --smart-mode
```

---

## 🎨 Interactive CLI Mode (BETA)
The CLI Terminal has a user-friendly interface and rich features,
 making it suitable for those who want to learn DKrypt.

To run:
```bash
python dkrypt.py i # or interactive
``` 
---

## 📚 Documentation

Our documentation is now complete and covers everything from installation to development.

<details>
<summary><strong>Click to expand documentation links</strong></summary>

### 👤 User Documentation
- **[Installation Guide](docs/user-guide/INSTALLATION.md)** - Detailed setup instructions for all platforms.
- **[Quick Start Guide](docs/user-guide/QUICKSTART.md)** - Get up and running in less than 5 minutes.
- **[Module Guide](docs/user-guide/MODULES.md)** - A detailed guide to all 15+ security modules and their usage.
- **[CLI Reference](docs/user-guide/CLI-REFERENCE.md)** - A complete command reference for the CLI.

### 💻 Developer Documentation
- **[Architecture Overview](docs/developer-guide/ARCHITECTURE.md)** - A look into the system design and structure.
- **[Contributing Guide](docs/developer-guide/CONTRIBUTING.md)** - The primary guide for anyone who wants to contribute.
- **[Testing Guide](docs/developer-guide/TESTING.md)** - Instructions on how to run and write tests.

</details>

---

## 🔧 Available Modules

| Module | Description | Command |
|--------|-------------|---------|
| **sqli** | SQL Injection Scanner | `dkrypt.py sqli --url <target>` |
| **xss** | XSS Vulnerability Scanner | `dkrypt.py xss --url <target>` |
| **subdomain** | Subdomain Enumeration | `dkrypt.py subdomain --domain <target>` |
| **dirbrute** | Directory Bruteforcer | `dkrypt.py dirbrute --url <target>` |
| **portscanner** | Advanced Port Scanner | `dkrypt.py portscanner single --target <host>` |
| **corstest** | CORS Misconfiguration Auditor | `dkrypt.py corstest --url <target>` |
| **headers** | Security Header Audit | `dkrypt.py headers --url <target>` |
| **sslinspect** | SSL/TLS Inspector | `dkrypt.py sslinspect --target <host>` |
| **graphql** | GraphQL Introspection | `dkrypt.py graphql --url <endpoint>` |
| **waftester** | WAF Bypass Tester | `dkrypt.py waftester --url <target>` |
| **smuggler** | HTTP Desync Tester | `dkrypt.py smuggler --url <target>` |
| **crawler** | Website Crawler | `dkrypt.py crawler --url <target>` |
| **jscrawler** | JS Endpoint Extractor | `dkrypt.py jscrawler --url <target>` |
| **tracepulse** | Network Route Tracer | `dkrypt.py tracepulse --destination <host>` |
| **pyobfuscator** | Python Code Obfuscator | `dkrypt.py pyobfuscator --input <file>` |

*For detailed usage and examples, see the [Module Guide](docs/user-guide/MODULES.md).*

---

## 🏗️ Project Structure
```
DKrypt-CLI/
├── core/         # Core framework (engine, config, logger, etc.)
├── modules/      # All security testing modules
├── docs/         # All documentation
├── tests/        # Test suite (105+ tests)
├── wordlists/    # Curated wordlists for scanning
└── dkrypt.py     # Main entry point
```

---

## 🤝 Contributing & Community

We welcome contributions of all forms, from documentation to new features. This project thrives on community involvement.

- **[Contributing Guide](docs/developer-guide/CONTRIBUTING.md)**: Learn how to set up your development environment, our coding standards, and the pull request process.
- **[Code of Conduct](CODE_OF_CONDUCT.md)**: We are committed to fostering an open and welcoming environment.

---

## ⚖️ Legal Notice

**IMPORTANT**: DKrypt is intended for authorized and ethical security testing purposes only.
- ✅ Obtain explicit written permission from the target owner before scanning.
- ✅ Comply with all applicable local, state, and federal laws.
- ✅ Use this tool responsibly.
- ❌ Do not use this tool for malicious purposes.

The developers and contributors assume no liability and are not responsible for any misuse or damage caused by this program.

---

## 📜 License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.
See the [LICENSE](./LICENSE) file for full details.

---
<p align="center">
<strong>Made with ❤️ for the Security Community</strong>
</p>
