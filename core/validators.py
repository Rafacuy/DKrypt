#!/usr/bin/env python3
"""
DKrypt Input Validation Framework
Comprehensive validation for CLI arguments and module parameters
"""

import re
import ipaddress
from urllib.parse import urlparse
from pathlib import Path
from typing import Any, Callable, Optional
from .exceptions import ValidationError


class Validator:
    """Base validator class"""
    
    @staticmethod
    def validate_url(url: str, allow_protocols=None) -> str:
        """
        Validate and normalize URLs
        
        Args:
            url: URL to validate
            allow_protocols: List of allowed protocols (default: ['http', 'https'])
        
        Returns:
            Validated URL
            
        Raises:
            ValidationError: If URL is invalid
        """
        if allow_protocols is None:
            allow_protocols = ['http', 'https']
        
        url = url.strip()
        if not url:
            raise ValidationError("URL cannot be empty", field="url")
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        try:
            parsed = urlparse(url)
            if parsed.scheme not in allow_protocols:
                raise ValidationError(
                    f"Protocol must be one of {allow_protocols}",
                    field="url",
                    value=parsed.scheme
                )
            if not parsed.netloc:
                raise ValidationError("Invalid URL: missing domain", field="url")
            return url
        except Exception as e:
            raise ValidationError(f"Invalid URL format: {str(e)}", field="url", value=url)
    
    @staticmethod
    def validate_domain(domain: str) -> str:
        """
        Validate domain name
        
        Args:
            domain: Domain to validate
            
        Returns:
            Validated domain
            
        Raises:
            ValidationError: If domain is invalid
        """
        domain = domain.strip().lower()
        
        if not domain:
            raise ValidationError("Domain cannot be empty", field="domain")
        
        # Simple domain validation regex
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        
        if not re.match(domain_pattern, domain):
            raise ValidationError(f"Invalid domain format", field="domain", value=domain)
        
        return domain
    
    @staticmethod
    def validate_ip(ip: str) -> str:
        """
        Validate IP address (IPv4 or IPv6)
        
        Args:
            ip: IP address to validate
            
        Returns:
            Validated IP address
            
        Raises:
            ValidationError: If IP is invalid
        """
        ip = ip.strip()
        
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            raise ValidationError(f"Invalid IP address format", field="ip", value=ip)
    
    @staticmethod
    def validate_port(port: Any, allow_zero=False) -> int:
        """
        Validate port number
        
        Args:
            port: Port to validate
            allow_zero: Allow port 0
            
        Returns:
            Validated port number
            
        Raises:
            ValidationError: If port is invalid
        """
        try:
            port_num = int(port)
            min_port = 0 if allow_zero else 1
            if not (min_port <= port_num <= 65535):
                raise ValidationError(
                    f"Port must be between {min_port} and 65535",
                    field="port",
                    value=port
                )
            return port_num
        except (ValueError, TypeError):
            raise ValidationError(f"Port must be a valid number", field="port", value=port)
    
    @staticmethod
    def validate_host(host: str) -> str:
        """
        Validate host (domain, IP, or hostname)
        
        Args:
            host: Host to validate
            
        Returns:
            Validated host
            
        Raises:
            ValidationError: If host is invalid
        """
        host = host.strip()
        
        if not host:
            raise ValidationError("Host cannot be empty", field="host")
        
        # Try to validate as IP
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        
        # Try to validate as domain
        try:
            return Validator.validate_domain(host)
        except ValidationError:
            pass
        
        raise ValidationError(f"Invalid host format", field="host", value=host)
    
    @staticmethod
    def validate_file_path(filepath: str, must_exist=True, must_be_readable=True) -> Path:
        """
        Validate file path
        
        Args:
            filepath: Path to validate
            must_exist: File must exist
            must_be_readable: File must be readable
            
        Returns:
            Validated Path object
            
        Raises:
            ValidationError: If path is invalid
        """
        path = Path(filepath).expanduser()
        
        if must_exist and not path.exists():
            raise ValidationError(f"File not found: {filepath}", field="filepath")
        
        if must_be_readable and path.exists() and not os.access(path, os.R_OK):
            raise ValidationError(f"File is not readable: {filepath}", field="filepath")
        
        return path
    
    @staticmethod
    def validate_integer(value: Any, min_val=None, max_val=None) -> int:
        """
        Validate integer value
        
        Args:
            value: Value to validate
            min_val: Minimum value (inclusive)
            max_val: Maximum value (inclusive)
            
        Returns:
            Validated integer
            
        Raises:
            ValidationError: If value is invalid
        """
        try:
            int_val = int(value)
            
            if min_val is not None and int_val < min_val:
                raise ValidationError(
                    f"Value must be >= {min_val}",
                    field="value",
                    value=value
                )
            
            if max_val is not None and int_val > max_val:
                raise ValidationError(
                    f"Value must be <= {max_val}",
                    field="value",
                    value=value
                )
            
            return int_val
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid integer value", field="value", value=value)
    
    @staticmethod
    def validate_choice(value: str, choices: list) -> str:
        """
        Validate choice from list
        
        Args:
            value: Value to validate
            choices: List of valid choices
            
        Returns:
            Validated choice
            
        Raises:
            ValidationError: If value is not in choices
        """
        if value not in choices:
            raise ValidationError(
                f"Value must be one of: {', '.join(choices)}",
                field="choice",
                value=value
            )
        return value
    
    @staticmethod
    def validate_non_empty(value: str, field_name="value") -> str:
        """
        Validate non-empty string
        
        Args:
            value: Value to validate
            field_name: Name of field for error message
            
        Returns:
            Validated value
            
        Raises:
            ValidationError: If value is empty
        """
        if not value or not str(value).strip():
            raise ValidationError(f"{field_name} cannot be empty", field=field_name)
        return str(value).strip()


import os
