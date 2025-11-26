#!/usr/bin/env python3
"""
DKrypt Logging System
Centralized logging with file rotation and multiple levels
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.logging import RichHandler


class DKryptLogger:
    """Centralized logging system for DKrypt"""
    
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if DKryptLogger._initialized:
            return
        
        self.console = Console()
        self.logs_dir = Path(".dkrypt/logs")
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        
        # Create main logger
        self.logger = logging.getLogger("dkrypt")
        self.logger.setLevel(logging.DEBUG)
        
        # Remove existing handlers
        self.logger.handlers.clear()
        
        # File handler with rotation
        log_file = self.logs_dir / f"dkrypt_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Console handler (only for errors and above in non-verbose mode)
        console_handler = RichHandler(console=self.console, show_level=True, show_time=True)
        console_handler.setLevel(logging.INFO)
        self.logger.addHandler(console_handler)
        
        DKryptLogger._initialized = True
    
    def get_logger(self, name=None):
        """Get a logger instance"""
        if name:
            return logging.getLogger(f"dkrypt.{name}")
        return self.logger
    
    def debug(self, message, **kwargs):
        """Log debug message"""
        self.logger.debug(message, **kwargs)
    
    def info(self, message, **kwargs):
        """Log info message"""
        self.logger.info(message, **kwargs)
    
    def warning(self, message, **kwargs):
        """Log warning message"""
        self.logger.warning(message, **kwargs)
    
    def error(self, message, **kwargs):
        """Log error message"""
        self.logger.error(message, **kwargs)
    
    def critical(self, message, **kwargs):
        """Log critical message"""
        self.logger.critical(message, **kwargs)
    
    def set_level(self, level):
        """Set logging level"""
        self.logger.setLevel(level)
    
    def clear_old_logs(self, days=7):
        """Clear logs older than specified days"""
        import time
        current_time = time.time()
        for log_file in self.logs_dir.glob("*.log*"):
            if os.path.getmtime(log_file) < current_time - days * 86400:
                try:
                    os.remove(log_file)
                    self.info(f"Removed old log file: {log_file}")
                except Exception as e:
                    self.error(f"Failed to remove old log file: {e}")


# Singleton instance
logger = DKryptLogger()
