# Quick Start Guide

Get started with DKrypt in 5 minutes.

## Table of Contents

- [First Run](#first-run)
- [Interactive Mode](#interactive-mode)
- [Direct CLI Mode](#direct-cli-mode)
- [Common Workflows](#common-workflows)
- [Next Steps](#next-steps)

---

## First Run

### 1. Activate Virtual Environment

```bash
cd DKrypt
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows
```

### 2. Launch DKrypt

```bash
python dkrypt.py
```

You'll see the DKrypt banner and interactive shell.

---

## Interactive Mode

Interactive mode is recommended for beginners and exploratory testing.

### Basic Commands

```bash
# Start interactive mode
python dkrypt.py

# Inside the shell:
dkrypt> help                    # Show help
dkrypt> show modules            # List all modules
dkrypt> search sql              # Search for modules
```

### Using a Module

```bash
dkrypt> use sqli                # Select SQL injection module
dkrypt[sqli]> show options      # View module options
dkrypt[sqli]> set URL https://example.com
dkrypt[sqli]> set TEST_FORMS true
dkrypt[sqli]> run               # Execute the module
dkrypt[sqli]> back              # Return to main menu
```

### Example Session

```bash
# Subdomain enumeration
dkrypt> use subdomain
dkrypt[subdomain]> set DOMAIN example.com
dkrypt[subdomain]> set THREADS 50
dkrypt[subdomain]> run

# Port scanning
dkrypt> use portscanner
dkrypt[portscanner]> set TARGET example.com
dkrypt[portscanner]> set PORTS 1-1000
dkrypt[portscanner]> set SCAN_TYPE SYN
dkrypt[portscanner]> run

# Exit
dkrypt> exit
```

---

## Direct CLI Mode

Direct CLI mode is ideal for automation and scripting.

### Basic Syntax

```bash
python dkrypt.py <module> --option value
```

### Quick Examples

#### SQL Injection Scan

```bash
python dkrypt.py sqli \
  --url https://example.com \
  --test-forms \
  --export html
```

#### Subdomain Discovery

```bash
python dkrypt.py subdomain \
  --domain example.com \
  --threads 50 \
  --timeout 10
```

#### XSS Scanning

```bash
python dkrypt.py xss \
  --url https://example.com \
  --smart-mode \
  --threads 20
```

#### Port Scanning

```bash
python dkrypt.py portscanner single \
  --target example.com \
  --ports 1-65535 \
  --scan-type SYN
```

#### Directory Bruteforce

```bash
python dkrypt.py dirbrute \
  --url https://example.com \
  --threads 30
```

---

## Common Workflows

### Workflow 1: Web Application Assessment

```bash
# Step 1: Subdomain discovery
python dkrypt.py subdomain --domain example.com --threads 50

# Step 2: Port scanning on discovered subdomains
python dkrypt.py portscanner single --target sub.example.com --ports 1-1000

# Step 3: Directory bruteforce
python dkrypt.py dirbrute --url https://sub.example.com

# Step 4: Security headers check
python dkrypt.py headers --url https://sub.example.com

# Step 5: Vulnerability scanning
python dkrypt.py sqli --url https://sub.example.com --test-forms
python dkrypt.py xss --url https://sub.example.com --smart-mode
```

### Workflow 2: API Security Testing

```bash
# Step 1: GraphQL introspection
python dkrypt.py graphql --url https://api.example.com/graphql

# Step 2: CORS misconfiguration check
python dkrypt.py corstest --url https://api.example.com

# Step 3: HTTP desync testing
python dkrypt.py smuggler --url https://api.example.com
```

### Workflow 3: Network Reconnaissance

```bash
# Step 1: Port scanning
python dkrypt.py portscanner single \
  --target example.com \
  --ports 1-65535 \
  --service-detection

# Step 2: SSL/TLS inspection
python dkrypt.py sslinspect --target example.com --port 443

# Step 3: Network tracing
python dkrypt.py tracepulse --destination example.com
```

---

## Useful Commands

### Get Help

```bash
# General help
python dkrypt.py --help

# Module-specific help
python dkrypt.py sqli --help

# List all modules
python dkrypt.py list-modules

# Show version
python dkrypt.py version

# Run diagnostics
python dkrypt.py diagnostic

# Tips and tricks
python dkrypt.py tips
```

### Interactive Shell Commands

| Command | Description |
|---------|-------------|
| `use <module>` | Select a module |
| `set <option> <value>` | Set option value |
| `unset <option>` | Clear option |
| `show options` | Display module options |
| `show modules` | List all modules |
| `run` | Execute module |
| `back` | Return to main menu |
| `search <term>` | Search modules |
| `help` | Show help |
| `exit` / `quit` | Exit DKrypt |

---

## Output and Reports

### Default Output Locations

- **Reports**: `reports/` directory
- **Logs**: `.dkrypt/logs/` directory
- **Results**: `.dkrypt/results/` directory

### Export Formats

Most modules support multiple export formats:

```bash
# JSON export
python dkrypt.py sqli --url https://example.com --export json

# HTML export
python dkrypt.py xss --url https://example.com --export html

# CSV export
python dkrypt.py subdomain --domain example.com --export csv

# Multiple formats
python dkrypt.py graphql --url https://api.example.com --export json,csv,txt
```

### View Results

```bash
# List recent scans
ls -lh reports/

# View JSON report
cat reports/sqli/report_example_com_20250128.json

# View HTML report in browser
firefox reports/xss/report_example_com_20250128.html
```

---

## Tips for Beginners

### 1. Start with Safe Targets

Always test on systems you own or have explicit permission to test:

```bash
# Use test environments
python dkrypt.py sqli --url http://testphp.vulnweb.com
```

### 2. Use Verbose Mode

Enable verbose output to understand what's happening:

```bash
python dkrypt.py xss --url https://example.com --verbose
```

### 3. Adjust Thread Count

Start with lower thread counts to avoid overwhelming targets:

```bash
# Conservative
python dkrypt.py subdomain --domain example.com --threads 10

# Aggressive (use with caution)
python dkrypt.py subdomain --domain example.com --threads 100
```

### 4. Use Rate Limiting

Prevent detection and avoid overloading targets:

```bash
python dkrypt.py xss --url https://example.com --rate-limit 2
```

### 5. Check Logs

If something goes wrong, check the logs:

```bash
tail -f .dkrypt/logs/dkrypt_$(date +%Y%m%d).log
```

---

## Common Issues

### Issue: "Permission denied"

**Solution**: Don't run with sudo. Use virtual environment.

### Issue: "Module not found"

**Solution**: Ensure virtual environment is activated and dependencies are installed.

```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Issue: "Connection timeout"

**Solution**: Increase timeout value:

```bash
python dkrypt.py subdomain --domain example.com --timeout 30
```

### Issue: "Too many requests"

**Solution**: Reduce threads and add rate limiting:

```bash
python dkrypt.py dirbrute --url https://example.com --threads 10 --rate-limit 5
```

---

## Next Steps

Now that you're familiar with the basics:

1. **Explore Modules**: Read the [Module Guide](MODULES.md) for detailed information
2. **Learn CLI**: Check the [CLI Reference](CLI-REFERENCE.md) for all commands
3. **Customize**: Review [Configuration](CONFIGURATION.md) options
4. **Advanced Usage**: See [Developer Guide](../developer-guide/ARCHITECTURE.md)

---

## Getting Help

- **Documentation**: Check `docs/` directory
- **GitHub Issues**: [Report bugs](https://github.com/Rafacuy/DKrypt/issues)
- **Telegram**: [@ArashCuy](https://t.me/ArashCuy)
- **Built-in Help**: `python dkrypt.py --help`

---

<p align="center">
<a href="../../README.md">Back to Main README</a>
</p>
