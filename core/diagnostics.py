#!/usr/bin/env python3
"""
DKrypt Diagnostic and Health Check System
"""

import sys
import os
import json
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from .config import config
from .logger import logger


class DiagnosticReport:
    """Generate comprehensive diagnostic reports"""
    
    def __init__(self):
        self.console = Console()
        self.issues = []
        self.warnings = []
        self.info = []
    
    def run_all_checks(self) -> dict:
        """Run all diagnostic checks"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "system": self._check_system(),
            "python": self._check_python(),
            "dependencies": self._check_dependencies(),
            "configuration": self._check_configuration(),
            "filesystem": self._check_filesystem(),
            "network": self._check_network(),
            "issues": self.issues,
            "warnings": self.warnings
        }
        return report
    
    def _check_system(self) -> dict:
        """Check system information"""
        import platform
        return {
            "platform": platform.system(),
            "platform_release": platform.release(),
            "machine": platform.machine(),
            "processor": platform.processor()
        }
    
    def _check_python(self) -> dict:
        """Check Python environment"""
        return {
            "version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "executable": sys.executable,
            "prefix": sys.prefix,
            "is_venv": hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
        }
    
    def _check_dependencies(self) -> dict:
        """Check required dependencies"""
        required_packages = [
            'rich', 'requests', 'beautifulsoup4', 'cryptography',
            'dnspython', 'tenacity', 'colorama', 'aiohttp',
            'whois', 'pyopenssl', 'scapy', 'asyncio'
        ]
        
        installed = {}
        for package in required_packages:
            try:
                mod = __import__(package)
                version = getattr(mod, '__version__', 'unknown')
                installed[package] = {"status": "installed", "version": version}
            except ImportError:
                installed[package] = {"status": "missing"}
                self.issues.append(f"Missing dependency: {package}")
        
        return installed
    
    def _check_configuration(self) -> dict:
        """Check configuration status"""
        checks = {
            "config_loaded": config is not None,
            "config_file_exists": Path.home() / ".dkrypt" / "config.json" in [Path(p).expanduser() for p in [str(Path.home() / ".dkrypt" / "config.json")]],
            "default_values_present": len(config.DEFAULT_CONFIG) > 0
        }
        
        if not checks["config_loaded"]:
            self.warnings.append("Configuration not properly loaded")
        
        return checks
    
    def _check_filesystem(self) -> dict:
        """Check filesystem setup"""
        directories = {
            "logs": Path(".dkrypt/logs"),
            "outputs": Path(".dkrypt/outputs"),
            "cache": Path(".dkrypt/cache"),
            "config": Path.home() / ".dkrypt"
        }
        
        checks = {}
        for name, path in directories.items():
            checks[name] = {
                "exists": path.exists(),
                "writable": os.access(path, os.W_OK) if path.exists() else False
            }
            
            if not checks[name]["exists"]:
                self.info.append(f"Directory does not exist: {path}")
            elif not checks[name]["writable"]:
                self.warnings.append(f"Directory not writable: {path}")
        
        return checks
    
    def _check_network(self) -> dict:
        """Check network connectivity"""
        checks = {
            "dns_resolution": self._test_dns(),
            "http_connectivity": self._test_http()
        }
        return checks
    
    def _test_dns(self) -> bool:
        """Test DNS resolution"""
        try:
            import socket
            socket.gethostbyname("google.com")
            return True
        except:
            self.warnings.append("DNS resolution failed")
            return False
    
    def _test_http(self) -> bool:
        """Test HTTP connectivity"""
        try:
            import requests
            requests.get("https://www.google.com", timeout=5)
            return True
        except:
            self.warnings.append("HTTP connectivity failed")
            return False
    
    def print_report(self, report: dict):
        """Print formatted diagnostic report"""
        self.console.print(
            Panel(
                "[bold cyan]DKrypt System Diagnostic Report[/bold cyan]",
                style="blue"
            )
        )
        
        # System Info
        sys_info = report["system"]
        self.console.print(f"\n[bold]System Information:[/bold]")
        self.console.print(f"  Platform: {sys_info['platform']} {sys_info['platform_release']}")
        self.console.print(f"  Machine: {sys_info['machine']}")
        
        # Python Info
        py_info = report["python"]
        self.console.print(f"\n[bold]Python Environment:[/bold]")
        self.console.print(f"  Version: {py_info['version']}")
        self.console.print(f"  Executable: {py_info['executable']}")
        self.console.print(f"  Virtual Environment: {'Yes' if py_info['is_venv'] else 'No'}")
        
        # Dependencies
        self.console.print(f"\n[bold]Dependencies:[/bold]")
        table = Table()
        table.add_column("Package", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Version", style="yellow")
        
        for package, info in report["dependencies"].items():
            status = "[green]✓[/green]" if info["status"] == "installed" else "[red]✗[/red]"
            version = info.get("version", "unknown")
            table.add_row(package, status, version)
        
        self.console.print(table)
        
        # Filesystem
        self.console.print(f"\n[bold]Filesystem Setup:[/bold]")
        for dir_name, check in report["filesystem"].items():
            status = "[green]✓[/green]" if check["exists"] else "[red]✗[/red]"
            writable = "[green]✓[/green]" if check["writable"] else "[red]✗[/red]"
            self.console.print(f"  {dir_name:10} {status}  (writable: {writable})")
        
        # Network
        self.console.print(f"\n[bold]Network Connectivity:[/bold]")
        dns_status = "[green]✓[/green]" if report["network"]["dns_resolution"] else "[red]✗[/red]"
        http_status = "[green]✓[/green]" if report["network"]["http_connectivity"] else "[red]✗[/red]"
        self.console.print(f"  DNS Resolution {dns_status}")
        self.console.print(f"  HTTP Connectivity {http_status}")
        
        # Issues and Warnings
        if report["issues"]:
            self.console.print(f"\n[bold red]Issues:[/bold red]")
            for issue in report["issues"]:
                self.console.print(f"  ⨯ {issue}")
        
        if report["warnings"]:
            self.console.print(f"\n[bold yellow]Warnings:[/bold yellow]")
            for warning in report["warnings"]:
                self.console.print(f"  ⚠ {warning}")
        
        if not report["issues"] and not report["warnings"]:
            self.console.print(f"\n[bold green]No issues detected![/bold green]")
        
        self.console.print(f"\n[dim]Timestamp: {report['timestamp']}[/dim]")
    
    def save_report(self, report: dict, filename: str = None) -> Path:
        """Save diagnostic report to file"""
        if filename is None:
            filename = f"diagnostic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report_path = Path(".dkrypt/logs") / filename
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report_path


def run_diagnostics():
    """Run full diagnostic check"""
    diagnostic = DiagnosticReport()
    report = diagnostic.run_all_checks()
    diagnostic.print_report(report)
    
    # Save report
    report_path = diagnostic.save_report(report)
    diagnostic.console.print(f"\n[dim]Report saved to: {report_path}[/dim]")
    
    return report
