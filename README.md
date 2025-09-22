<p align="center">
<a href="#"><img alt="Dkrypt-logo" src="./docs/logo.png" width="55%" height="55%"></a>
</p>

<em><h5 align="center">Developed by Rafacuy (arazz.)</h5></em>

<p align="center">
    <a href="#">
        <img alt="Python" src="https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue">
    </a>
    <a href="#">
        <img alt="last commit (main)" src="https://img.shields.io/github/last-commit/Rafacuy/DKrypt/main?color=green&style=for-the-badge">
    </a>
    <a href="#">
        <img alt="DKrypt License" src="https://img.shields.io/github/license/Rafacuy/DKrypt?color=orange&style=for-the-badge">
    </a>
    <a href="https://github.com/Rafacuy/DKrypt/issues">
        <img alt="DKrypt issues" src="https://img.shields.io/github/issues/Rafacuy/DKrypt?color=purple&style=for-the-badge">
    </a>
</p>



<h1 align="center">Introduction</h1>
DKrypt is an advanced, all-in-one penetration testing framework designed for security professionals, ethical hackers, and IT administrators. Built with modularity and efficiency at its core, DKrypt integrates cutting-edge reconnaissance, vulnerability scanning, and exploitation tools into a unified Text-based user interface (TUI) and a powerful Command Line Interface (CLI). With its real-time visualization and intelligent automation, DKrypt transforms complex security assessments into streamlined workflows.

## _Features_
- **Directory Bruteforcer**: _Discover hidden directories on target web servers._
- **Subdomain Discovery**: _Identify subdomains using a wordlist-based scanner._
- **Security Header Audit**: _Analyze HTTP response headers for security best practices._
- **SSL/TLS Inspector**: _Get deep insights into SSL/TLS certificate configurations._
- **Website Crawler**: _Extract page content and links quickly._
- **JS Crawler & Endpoint Extractor**: _Extract a endpoints and analyze API Key/Token within JS file._
- **Port Scanner**: _Discover hidden port on the target website._
- **WAF Bypass tester**: _Bypass WAF on a website to find weaknesses on the website's WAF._
- **CORS Misconfiguration Auditor**: _Find a vulnerabilites on the CORS Configuration._
- **HTTP Desync Attack Tester**: _Manipulating header content to inject hidden requests._
- **SQLi Scanner**: _Scan for SQLi vulnerability within website._
- **XSS Scanner**: _Scan for XSS vulnerability within website._
- **Python Obfuscator**: _Protect a python file and make it unreadable._
- **Tracepulse**: _Trace the route and identify a network problems._

---

## Installation

To get DKrypt up and running on your system, follow these steps:

### Prerequisites
Ensure you have **Python 3.10+** and `git` installed on your system.

1.  **Clone the Repository**
    Start by cloning the DKrypt repository to your local machine:
    ```bash
    git clone https://github.com/Rafacuy/DKrypt.git
    cd DKrypt
    ```

2.  **Set Up Virtual Environment (Recommended)**
    It's highly recommended to use a virtual environment to manage project dependencies and avoid conflicts with your system's Python packages.
    ```bash
    python -m venv venv
    # Activate the virtual environment
    # On Windows: .\venv\Scripts\activate
    # On macOS/Linux: source venv/bin/activate
    ```

3.  **Install Dependencies**
    Install all required Python packages using `pip`:
    ```bash
    pip install -r requirements.txt
    ```
    Alternatively, you can use the provided `install.sh` script (for Linux/macOS) which automates the dependency installation:
    ```bash
    bash install.sh
    ```

### Trouble installing on Termux?

If you're facing issues with `cryptography` or build tools on Termux, just run:
```bash
bash FIX.sh # Only for termux users
```
This script will auto-install Termux dependencies for you.

---

## Usage

DKrypt offers two primary modes of operation: a Text-based User Interface (TUI) for beginners and a Command Line Interface (CLI) for advanced users and pipeline integration.

### TUI Mode
For an interactive, menu-driven experience, simply run DKrypt without any arguments:
```bash
python dkrypt.py
```
This will launch the TUI, allowing you to select and run modules through an easy-to-navigate menu.

### CLI Mode
For direct execution of modules with specific arguments, use the CLI mode. This is ideal for scripting and automation.
```bash
python dkrypt.py <module> [options]
```
For detailed instructions on how to use each module via the CLI, including all available options and examples, please refer to the comprehensive [CLI Guide](./CLI-guide.md).

---

## Documentation
*   **CLI Guide**: A complete guide to using DKrypt's Command Line Interface, including module-specific options and examples.
    *   [CLI-guide.md](./CLI-guide.md)
*   **Contributor Guide**: Information for developers interested in contributing to DKrypt, covering setup, code structure, and contribution process.
    *   [CONTRIBUTOR.md](./CONTRIBUTOR.md)

---

## Requirements
- Python 3.10+
- `rich`, `requests`, `beautifulsoup4`, and other libraries listed in `requirements.txt`

## Wordlists
DKrypt utilizes various wordlists for tasks like directory brute-forcing and subdomain enumeration.
Custom wordlists for:

*   Directory brute-forcing
*   Subdomain enumeration
*   Admin panel discovery
*   Headers Pack

_Located in /wordlists/_

## Contributing
We welcome contributions to DKrypt! If you're interested in improving the framework, please refer to our [Contributor Guide](./CONTRIBUTOR.md) for detailed instructions on how to set up your environment, code style, and the pull request process.

If you find bugs or want to suggest features, please open an issue on the [GitHub Issues page](https://github.com/Rafacuy/DKrypt/issues).

## Author
Copyright (C) 2025 Rafacuy (arazz.) 

### _Contact_
- **Telegram**: [@ArashCuy](https://t.me/@ArashCuy)
- **TikTok**: [@rafardhancuy](https://tiktok.com/@rafardhancuy)
- **GitHub**: [@Rafacuy](https://github.com/Rafacuy)


## License
This tool is under the GPL-3.0 License. See the [LICENSE](./LICENSE) for details.

---