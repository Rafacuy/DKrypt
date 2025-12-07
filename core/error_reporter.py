#!/usr/bin/env python3
"""
DKrypt Local Error Logging System
Simple, local-only error logging with sanitization
"""

import re
import json
import time
import hashlib
import traceback
import platform
from typing import Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime


@dataclass
class ErrorReport:
    """Represents an error report"""
    error_type: str
    message: str
    traceback: str
    module: str
    timestamp: str
    system_info: Dict[str, str]
    error_hash: str


class DataSanitizer:
    """Sanitizes sensitive data from error reports"""
    
    PATTERNS = [
        (r'https?://[^\s<>"{}|\\^`\[\]]+', '[URL]'),
        (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP]'),
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]'),
        (r'(?:password|token|key|secret)["\s:=]+[^\s,;}\]]+', '[CREDENTIAL]'),
        (r'/home/[^/\s]+', '/home/[USER]'),
        (r'C:\\Users\\[^\\]+', 'C:\\Users\\[USER]'),
    ]
    
    def __init__(self):
        self._patterns = [(re.compile(p, re.IGNORECASE), r) for p, r in self.PATTERNS]
    
    def sanitize(self, text: str) -> str:
        """Remove sensitive data from text"""
        if not text:
            return text
        result = str(text)
        for pattern, replacement in self._patterns:
            try:
                result = pattern.sub(replacement, result)
            except:
                pass
        return result


class ErrorLogger:
    """Local error logging system"""
    
    def __init__(self, log_dir: str = ".dkrypt/logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.sanitizer = DataSanitizer()
        self._reported = self._load_reported()
    
    def _load_reported(self) -> set:
        """Load reported error hashes"""
        hash_file = self.log_dir / "reported.json"
        if hash_file.exists():
            try:
                with open(hash_file) as f:
                    return set(json.load(f).get('hashes', []))
            except:
                pass
        return set()
    
    def _save_reported(self):
        """Save reported error hashes"""
        try:
            with open(self.log_dir / "reported.json", 'w') as f:
                json.dump({'hashes': list(self._reported)[-100:]}, f)
        except:
            pass
    
    def _compute_hash(self, error_type: str, message: str) -> str:
        """Compute unique hash for error"""
        content = f"{error_type}:{message[:100]}"
        return hashlib.sha256(content.encode()).hexdigest()[:12]
    
    def _get_system_info(self) -> Dict[str, str]:
        """Get system information"""
        return {
            'python': platform.python_version(),
            'os': platform.system(),
            'arch': platform.machine(),
        }
    
    def prepare_report(self, exception: BaseException, module: str = "unknown") -> ErrorReport:
        """Prepare error report"""
        error_type = type(exception).__name__
        message = str(exception)
        tb = traceback.format_exc()
        
        return ErrorReport(
            error_type=error_type,
            message=self.sanitizer.sanitize(message),
            traceback=self.sanitizer.sanitize(tb),
            module=module,
            timestamp=datetime.now().isoformat(),
            system_info=self._get_system_info(),
            error_hash=self._compute_hash(error_type, message)
        )
    
    def log_error(self, error: ErrorReport) -> tuple[bool, str]:
        """Log error to file"""
        if error.error_hash in self._reported:
            return False, "Already logged"
        
        try:
            log_file = self.log_dir / f"error_{error.error_hash}.log"
            
            with open(log_file, 'w') as f:
                f.write(f"Error Type: {error.error_type}\n")
                f.write(f"Module: {error.module}\n")
                f.write(f"Time: {error.timestamp}\n")
                f.write(f"Hash: {error.error_hash}\n")
                f.write(f"System: {error.system_info}\n")
                f.write(f"\nMessage:\n{error.message}\n")
                f.write(f"\nTraceback:\n{error.traceback}\n")
            
            self._reported.add(error.error_hash)
            self._save_reported()
            
            return True, str(log_file)
        except Exception as e:
            return False, f"Failed: {e}"
    
    def list_errors(self, limit: int = 10) -> list:
        """List recent error logs"""
        logs = sorted(self.log_dir.glob("error_*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
        return logs[:limit]
    
    def view_error(self, error_hash: str) -> Optional[str]:
        """View specific error log"""
        log_file = self.log_dir / f"error_{error_hash}.log"
        if log_file.exists():
            return log_file.read_text()
        return None
    
    def clear_old_logs(self, days: int = 30):
        """Clear logs older than specified days"""
        cutoff = time.time() - (days * 86400)
        for log_file in self.log_dir.glob("error_*.log"):
            if log_file.stat().st_mtime < cutoff:
                log_file.unlink()


def prompt_error_report(exception: BaseException, module: str = "unknown", console=None) -> Optional[bool]:
    """Prompt user to log error"""
    if console is None:
        from rich.console import Console
        console = Console()
    
    logger = ErrorLogger()
    error = logger.prepare_report(exception, module)
    
    console.print(f"\n[yellow]Error occurred: {error.error_type}[/yellow]")
    console.print(f"[dim]{error.message[:100]}...[/dim]")
    
    try:
        response = console.input("\n[cyan]Save error log? (y/N): [/cyan]").strip().lower()
    except:
        response = 'n'
    
    if response in ('y', 'yes'):
        success, path = logger.log_error(error)
        if success:
            console.print(f"[green]Logged to: {path}[/green]")
            return True
        else:
            console.print(f"[red]{path}[/red]")
            return False
    return False
