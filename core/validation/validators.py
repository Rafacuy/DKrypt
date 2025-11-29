#!/usr/bin/env python3
"""
DKrypt Input Validation Framework
Comprehensive validation for CLI arguments and module parameters
"""

import os
import re
import ipaddress
from urllib.parse import urlparse
from pathlib import Path
from typing import Any, Callable, Optional, Union, List
from core.exceptions import ValidationError


class Validator:
    """Enhanced validator class with improved validation and error handling"""

    @staticmethod
    def validate_url(url: str, allow_protocols: Optional[List[str]] = None, allow_empty: bool = False) -> str:
        """
        Validate and normalize URLs

        Args:
            url: URL to validate
            allow_protocols: List of allowed protocols (default: ['http', 'https'])
            allow_empty: Allow empty URLs

        Returns:
            Validated URL

        Raises:
            ValidationError: If URL is invalid
        """
        if allow_protocols is None:
            allow_protocols = ['http', 'https']

        if not url and allow_empty:
            return url

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

            # Validate the domain part of the URL
            Validator.validate_domain(parsed.netloc)

            return url
        except ValidationError as e:
            raise ValidationError(f"Invalid URL: {e.message}", field="url", value=url)
        except Exception as e:
            raise ValidationError(f"Invalid URL format: {str(e)}", field="url", value=url)

    @staticmethod
    def validate_domain(domain: str, allow_empty: bool = False) -> str:
        """
        Validate domain name

        Args:
            domain: Domain to validate
            allow_empty: Allow empty domains

        Returns:
            Validated domain

        Raises:
            ValidationError: If domain is invalid
        """
        if not domain and allow_empty:
            return domain

        domain = domain.strip().lower()

        if not domain:
            raise ValidationError("Domain cannot be empty", field="domain")

        # Simple domain validation regex
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'

        if not re.match(domain_pattern, domain):
            raise ValidationError(f"Invalid domain format", field="domain", value=domain)

        return domain

    @staticmethod
    def validate_ip(ip: str, allow_empty: bool = False) -> str:
        """
        Validate IP address (IPv4 or IPv6)

        Args:
            ip: IP address to validate
            allow_empty: Allow empty IP

        Returns:
            Validated IP address

        Raises:
            ValidationError: If IP is invalid
        """
        if not ip and allow_empty:
            return ip

        ip = ip.strip()

        if not ip:
            raise ValidationError("IP cannot be empty", field="ip")

        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            raise ValidationError(f"Invalid IP address format", field="ip", value=ip)

    @staticmethod
    def validate_port(port: Any, allow_zero: bool = False, allow_empty: bool = False) -> int:
        """
        Validate port number

        Args:
            port: Port to validate
            allow_zero: Allow port 0
            allow_empty: Allow empty port

        Returns:
            Validated port number

        Raises:
            ValidationError: If port is invalid
        """
        if port == "" and allow_empty:
            return port

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
    def validate_host(host: str, allow_empty: bool = False) -> str:
        """
        Validate host (domain, IP, hostname, or host:port format)

        Args:
            host: Host to validate
            allow_empty: Allow empty host

        Returns:
            Validated host

        Raises:
            ValidationError: If host is invalid
        """
        if not host and allow_empty:
            return host

        host = host.strip()

        if not host:
            raise ValidationError("Host cannot be empty", field="host")

        # Check if it's in host:port format
        if ':' in host:
            parts = host.rsplit(':', 1)  # Split from right to handle IPv6 cases with multiple colons
            if len(parts) == 2:
                host_part, port_part = parts

                # Validate the host part
                try:
                    # Try IP first
                    ipaddress.ip_address(host_part)
                except ValueError:
                    # If not IP, try domain
                    try:
                        Validator.validate_domain(host_part)
                    except ValidationError:
                        raise ValidationError(f"Invalid host format", field="host", value=host)

                # Validate the port part
                try:
                    Validator.validate_port(port_part)
                except ValidationError:
                    raise ValidationError(f"Invalid host format - invalid port", field="host", value=host)

                return host

        # If not in host:port format, treat as regular host
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
    def validate_file_path(filepath: str, must_exist: bool = True, must_be_readable: bool = True, allow_empty: bool = False) -> Path:
        """
        Validate file path

        Args:
            filepath: Path to validate
            must_exist: File must exist
            must_be_readable: File must be readable
            allow_empty: Allow empty paths

        Returns:
            Validated Path object

        Raises:
            ValidationError: If path is invalid
        """
        if (not filepath or filepath.strip() == "") and allow_empty:
            # Return a Path object that represents an empty string
            path_obj = Path("")
            # The string representation of empty Path is "." but we handle this in tests
            return path_obj

        if not filepath:
            raise ValidationError("File path cannot be empty", field="filepath")

        path = Path(filepath).expanduser()

        if must_exist and not path.exists():
            raise ValidationError(f"File not found: {filepath}", field="filepath")

        if must_be_readable and path.exists() and not os.access(path, os.R_OK):
            raise ValidationError(f"File is not readable: {filepath}", field="filepath")

        return path

    @staticmethod
    def validate_integer(value: Any, min_val: Optional[int] = None, max_val: Optional[int] = None, allow_empty: bool = False) -> int:
        """
        Validate integer value

        Args:
            value: Value to validate
            min_val: Minimum value (inclusive)
            max_val: Maximum value (inclusive)
            allow_empty: Allow empty values

        Returns:
            Validated integer

        Raises:
            ValidationError: If value is invalid
        """
        if value == "" and allow_empty:
            return value

        try:
            if value is None:
                raise ValidationError("Value cannot be None", field="value")

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
    def validate_choice(value: str, choices: list, allow_empty: bool = False) -> str:
        """
        Validate choice from list

        Args:
            value: Value to validate
            choices: List of valid choices
            allow_empty: Allow empty values

        Returns:
            Validated choice

        Raises:
            ValidationError: If value is not in choices
        """
        if not value and allow_empty:
            return value

        if value not in choices:
            raise ValidationError(
                f"Value must be one of: {', '.join(choices)}",
                field="choice",
                value=value
            )
        return value

    @staticmethod
    def validate_boolean(value: Any, allow_empty: bool = False) -> bool:
        """
        Validate boolean value

        Args:
            value: Value to validate
            allow_empty: Allow empty values

        Returns:
            Validated boolean

        Raises:
            ValidationError: If value is not a valid boolean
        """
        if value == "" and allow_empty:
            return None

        if isinstance(value, bool):
            return value

        lowered_value = str(value).lower().strip()

        if lowered_value in ['true', '1', 'yes', 'on']:
            return True
        if lowered_value in ['false', '0', 'no', 'off']:
            return False

        raise ValidationError(
            "Value must be a valid boolean (true/false, yes/no, 1/0, on/off)",
            field="boolean",
            value=value
        )

    @staticmethod
    def validate_non_empty(value: str, field_name: str = "value") -> str:
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

    @staticmethod
    def validate_regex(value: str, pattern: str, allow_empty: bool = False) -> str:
        """
        Validate value against a regex pattern

        Args:
            value: Value to validate
            pattern: Regex pattern to match against
            allow_empty: Allow empty values

        Returns:
            Validated value

        Raises:
            ValidationError: If value doesn't match pattern
        """
        if not value and allow_empty:
            return value

        value = str(value).strip()

        if not re.match(pattern, value):
            raise ValidationError(
                f"Value '{value}' doesn't match pattern '{pattern}'",
                field="regex",
                value=value
            )
        return value

    @staticmethod
    def validate_range(value: Union[int, float], min_val: Union[int, float] = None,
                      max_val: Union[int, float] = None, allow_empty: bool = False) -> Union[int, float]:
        """
        Validate numeric value within a range

        Args:
            value: Value to validate
            min_val: Minimum value (inclusive)
            max_val: Maximum value (inclusive)
            allow_empty: Allow empty values

        Returns:
            Validated value

        Raises:
            ValidationError: If value is not within range
        """
        if value == "" and allow_empty:
            return value

        try:
            if value is None:
                raise ValidationError("Value cannot be None", field="value")

            if min_val is not None and value < min_val:
                raise ValidationError(
                    f"Value must be >= {min_val}",
                    field="range",
                    value=value
                )

            if max_val is not None and value > max_val:
                raise ValidationError(
                    f"Value must be <= {max_val}",
                    field="range",
                    value=value
                )

            return value
        except TypeError:
            raise ValidationError(f"Value must be a number", field="range", value=value)
