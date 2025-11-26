#!/usr/bin/env python3
"""
DKrypt Exception Hierarchy
Centralized exception handling for production-ready error management
"""

class DKryptException(Exception):
    """Base exception for all DKrypt errors"""
    def __init__(self, message, code=None, details=None):
        self.message = message
        self.code = code or "UNKNOWN_ERROR"
        self.details = details or {}
        super().__init__(self.message)
    
    def to_dict(self):
        """Convert exception to dict for logging/output"""
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details
        }


class ValidationError(DKryptException):
    """Raised when input validation fails"""
    def __init__(self, message, field=None, value=None):
        details = {}
        if field:
            details["field"] = field
        if value:
            details["value"] = str(value)
        super().__init__(message, "VALIDATION_ERROR", details)


class ConfigurationError(DKryptException):
    """Raised when configuration is invalid or missing"""
    def __init__(self, message, config_key=None):
        details = {"config_key": config_key} if config_key else {}
        super().__init__(message, "CONFIG_ERROR", details)


class ModuleExecutionError(DKryptException):
    """Raised when module execution fails"""
    def __init__(self, message, module=None, target=None):
        details = {}
        if module:
            details["module"] = module
        if target:
            details["target"] = target
        super().__init__(message, "MODULE_ERROR", details)


class NetworkError(DKryptException):
    """Raised when network operations fail"""
    def __init__(self, message, target=None, port=None):
        details = {}
        if target:
            details["target"] = target
        if port:
            details["port"] = port
        super().__init__(message, "NETWORK_ERROR", details)


class TimeoutError(DKryptException):
    """Raised when operations timeout"""
    def __init__(self, message, timeout=None, operation=None):
        details = {}
        if timeout:
            details["timeout_seconds"] = timeout
        if operation:
            details["operation"] = operation
        super().__init__(message, "TIMEOUT_ERROR", details)


class RateLimitError(DKryptException):
    """Raised when rate limit is exceeded"""
    def __init__(self, message, retry_after=None):
        details = {}
        if retry_after:
            details["retry_after_seconds"] = retry_after
        super().__init__(message, "RATE_LIMIT_ERROR", details)


class AuthenticationError(DKryptException):
    """Raised when authentication fails"""
    def __init__(self, message, auth_type=None):
        details = {"auth_type": auth_type} if auth_type else {}
        super().__init__(message, "AUTH_ERROR", details)


class FileOperationError(DKryptException):
    """Raised when file operations fail"""
    def __init__(self, message, filepath=None, operation=None):
        details = {}
        if filepath:
            details["filepath"] = filepath
        if operation:
            details["operation"] = operation
        super().__init__(message, "FILE_ERROR", details)


class DatabaseError(DKryptException):
    """Raised when database operations fail"""
    def __init__(self, message, operation=None):
        details = {"operation": operation} if operation else {}
        super().__init__(message, "DATABASE_ERROR", details)


class UserCancelledError(DKryptException):
    """Raised when user cancels an operation"""
    def __init__(self, message="Operation cancelled by user"):
        super().__init__(message, "USER_CANCELLED", {})
