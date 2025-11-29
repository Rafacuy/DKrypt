# Installation Guide

Complete installation instructions for DKrypt on various platforms.

## Table of Contents

- [System Requirements](#system-requirements)
- [Standard Installation](#standard-installation)
- [Platform-Specific Instructions](#platform-specific-instructions)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

---

## System Requirements

### Minimum Requirements

- **Python**: 3.10 or higher
- **RAM**: 2GB minimum, 4GB recommended
- **Disk Space**: 500MB for installation
- **Network**: Internet connection for installation

### Supported Operating Systems

- Linux (Ubuntu 20.04+, Debian 10+, Kali Linux, Arch Linux)
- macOS (10.15+)
- Windows (10/11)
- Android (via Termux)

---

## Standard Installation

### 1. Install Python

Ensure Python 3.10+ is installed:

```bash
python --version
# or
python3 --version
```

If not installed, download from [python.org](https://www.python.org/downloads/)

### 2. Clone Repository

```bash
git clone https://github.com/Rafacuy/DKrypt.git
cd DKrypt
```

### 3. Create Virtual Environment

```bash
python -m venv venv
```

### 4. Activate Virtual Environment

**Linux/macOS:**
```bash
source venv/bin/activate
```

**Windows (CMD):**
```cmd
venv\Scripts\activate.bat
```

**Windows (PowerShell):**
```powershell
venv\Scripts\Activate.ps1
```

### 5. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 6. Verify Installation

```bash
python dkrypt.py version
```

---

## Platform-Specific Instructions

### Linux (Ubuntu/Debian)

```bash
# Install system dependencies
sudo apt update
sudo apt install python3 python3-pip python3-venv git

# Clone and install
git clone https://github.com/Rafacuy/DKrypt.git
cd DKrypt
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Kali Linux

```bash
# Kali usually has Python pre-installed
git clone https://github.com/Rafacuy/DKrypt.git
cd DKrypt
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### macOS

```bash
# Install Homebrew if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python@3.11

# Clone and install
git clone https://github.com/Rafacuy/DKrypt.git
cd DKrypt
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Windows

1. **Install Python from [python.org](https://www.python.org/downloads/)**
   - Check "Add Python to PATH" during installation

2. **Install Git from [git-scm.com](https://git-scm.com/download/win)**

3. **Open Command Prompt or PowerShell:**

```cmd
git clone https://github.com/Rafacuy/DKrypt.git
cd DKrypt
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Android (Termux)

```bash
# Update Termux packages
pkg update && pkg upgrade

# Install dependencies
pkg install python git

# Run the fix script
bash FIX.sh

# Clone and install
git clone https://github.com/Rafacuy/DKrypt.git
cd DKrypt
pip install -r requirements.txt
```

---

## Verification

### Check Installation

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# Check version
python dkrypt.py version

# Run diagnostics
python dkrypt.py diagnostic

# List modules
python dkrypt.py list-modules
```

### Expected Output

```
DKrypt v1.4.0 (STABLE)
Advanced Penetration Testing Framework
Developed by Rafacuy (arazz.)
```

---

## Troubleshooting

### Python Version Issues

**Problem**: `python: command not found` or wrong version

**Solution**:
```bash
# Try python3 instead
python3 --version

# Or install Python 3.10+
sudo apt install python3.10  # Ubuntu/Debian
brew install python@3.11     # macOS
```

### Permission Errors

**Problem**: Permission denied during installation

**Solution**:
```bash
# Don't use sudo with pip in virtual environment
# If you must install globally:
pip install --user -r requirements.txt
```

### SSL Certificate Errors

**Problem**: SSL certificate verification failed

**Solution**:
```bash
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```

### Module Import Errors

**Problem**: `ModuleNotFoundError` when running DKrypt

**Solution**:
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install --force-reinstall -r requirements.txt
```

### Scapy Installation Issues (Linux)

**Problem**: Scapy requires root privileges

**Solution**:
```bash
# Install system dependencies
sudo apt install libpcap-dev

# Reinstall scapy
pip install --upgrade scapy
```

### Windows Long Path Issues

**Problem**: File path too long errors

**Solution**:
1. Enable long paths in Windows:
   - Run as Administrator: `gpedit.msc`
   - Navigate to: Computer Configuration > Administrative Templates > System > Filesystem
   - Enable "Enable Win32 long paths"

2. Or clone to shorter path:
```cmd
cd C:\
git clone https://github.com/Rafacuy/DKrypt.git
```

---

## Updating DKrypt

### Update to Latest Version

```bash
cd DKrypt
git pull origin main
source venv/bin/activate  # Activate venv
pip install --upgrade -r requirements.txt
```

### Check for Updates

```bash
git fetch origin
git status
```

---

## Uninstallation

### Remove DKrypt

```bash
# Deactivate virtual environment
deactivate

# Remove directory
cd ..
rm -rf DKrypt  # Linux/macOS
# or
rmdir /s DKrypt  # Windows
```

---

## Next Steps

After successful installation:

1. Read the [Quick Start Guide](QUICKSTART.md)
2. Explore the [CLI Reference](CLI-REFERENCE.md)
3. Check out [Module Guide](MODULES.md)
4. Review [Configuration](CONFIGURATION.md)

---

## Getting Help

If you encounter issues:

1. Check [Troubleshooting](#troubleshooting) section above
2. Review [FAQ](../FAQ.md)
3. Open an issue on [GitHub](https://github.com/Rafacuy/DKrypt/issues)
4. Contact via [Telegram](https://t.me/ArashCuy)

---

<p align="center">
<a href="../../README.md">Back to Main README</a>
</p>
