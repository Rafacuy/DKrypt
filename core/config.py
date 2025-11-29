#!/usr/bin/env python3
"""
(ALPHA) DKrypt Configuration Management System
Handles configuration files, environment variables, and defaults
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional
from .exceptions import ConfigurationError
from .logger import logger


class ConfigManager:
    """Manage DKrypt configuration"""
    
    _instance = None
    _initialized = False
    
    # Default configuration
    DEFAULT_CONFIG = {
        "tool": {
            "name": "DKrypt",
            "version": "1.4.0",
            "timeout": 30,
            "max_retries": 3,
            "verbose": False,
            "color": True
        },
        "http": {
            "timeout": 30,
            "retries": 3,
            "user_agent": "DKrypt/1.4.0",
            "verify_ssl": True,
            "follow_redirects": True,
            "max_redirects": 5
        },
        "dns": {
            "timeout": 2,
            "retries": 1,
            "nameservers": ["8.8.8.8", "8.8.4.4"]
        },
        "scanning": {
            "thread_pool_size": 10,
            "rate_limit": 100,
            "batch_size": 50,
            "max_concurrent_requests": 20
        },
        "output": {
            "directory": ".dkrypt/outputs",
            "formats": ["json", "csv"],
            "timestamp_format": "%Y-%m-%d_%H-%M-%S"
        },
        "logging": {
            "level": "INFO",
            "directory": ".dkrypt/logs",
            "max_size_mb": 10,
            "backup_count": 5
        },
        "cache": {
            "enabled": True,
            "directory": ".dkrypt/cache",
            "ttl_seconds": 3600,
            "max_size_mb": 100
        },
        "security": {
            "disable_insecure_ssl_warnings": False,
            "min_tls_version": "1.2",
            "allowed_ports": "1,21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,5984,6379,8080,8443,9200,9300,11211,27017,27018,27019,27020,28017,50070"
        }
    }
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if ConfigManager._initialized:
            return
        
        self.config_dir = Path.home() / ".dkrypt"
        self.config_file = self.config_dir / "config.json"
        self.env_file = self.config_dir / ".env"
        
        # Create config directory
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Load configuration
        self.config = self._load_config()
        
        ConfigManager._initialized = True
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from files and environment"""
        config = self.DEFAULT_CONFIG.copy()
        
        # Load from config file if exists
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                    self._deep_merge(config, file_config)
                    logger.info(f"Loaded configuration from {self.config_file}")
            except Exception as e:
                logger.warning(f"Failed to load config file: {e}")
        
        # Load from environment variables
        self._load_from_env(config)
        
        return config
    
    def _deep_merge(self, base: Dict, overlay: Dict):
        """Deep merge overlay config into base"""
        for key, value in overlay.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def _load_from_env(self, config: Dict):
        """Load configuration from environment variables"""
        # Pattern: DKRYPT_SECTION_KEY=value
        for env_key, env_value in os.environ.items():
            if env_key.startswith("DKRYPT_"):
                parts = env_key[7:].lower().split("_", 1)  # Remove DKRYPT_ prefix
                if len(parts) == 2:
                    section, key = parts
                    if section in config:
                        config[section][key] = self._parse_env_value(env_value)
    
    @staticmethod
    def _parse_env_value(value: str) -> Any:
        """Parse environment variable value to appropriate type"""
        if value.lower() in ('true', 'yes', '1'):
            return True
        elif value.lower() in ('false', 'no', '0'):
            return False
        elif value.isdigit():
            return int(value)
        else:
            try:
                return float(value)
            except ValueError:
                return value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value with dot notation
        
        Args:
            key: Configuration key (e.g., "http.timeout")
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        parts = key.split(".")
        value = self.config
        
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """
        Set configuration value with dot notation
        
        Args:
            key: Configuration key (e.g., "http.timeout")
            value: Value to set
        """
        parts = key.split(".")
        config = self.config
        
        # Navigate to parent dict
        for part in parts[:-1]:
            if part not in config:
                config[part] = {}
            config = config[part]
        
        # Set value
        config[parts[-1]] = value
        logger.debug(f"Configuration updated: {key} = {value}")
    
    def save(self) -> Path:
        """
        Save configuration to file
        
        Returns:
            Path to saved configuration file
        """
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            logger.info(f"Configuration saved to {self.config_file}")
            return self.config_file
        except Exception as e:
            raise ConfigurationError(f"Failed to save configuration: {e}")
    
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        self.config = self.DEFAULT_CONFIG.copy()
        logger.info("Configuration reset to defaults")
    
    def validate(self):
        """Validate configuration"""
        # Check required directories exist
        directories = [
            self.get("output.directory"),
            self.get("logging.directory"),
            self.get("cache.directory")
        ]
        
        for directory in directories:
            if directory:
                Path(directory).mkdir(parents=True, exist_ok=True)
        
        # Validate timeout values
        if self.get("http.timeout") <= 0:
            raise ConfigurationError("http.timeout must be greater than 0")
        
        logger.debug("Configuration validation passed")
    
    def to_dict(self) -> Dict[str, Any]:
        """Get entire configuration as dictionary"""
        return self.config.copy()
    
    def print_config(self):
        """Print configuration in readable format"""
        from rich.console import Console
        from rich.syntax import Syntax
        
        console = Console()
        config_str = json.dumps(self.config, indent=2)
        syntax = Syntax(config_str, "json", theme="monokai", line_numbers=False)
        console.print(syntax)


# Singleton instance
config = ConfigManager()
