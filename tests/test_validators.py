"""
Tests for the validators module in DKrypt
"""

import pytest
from core.validators import Validator
from core.exceptions import ValidationError


def test_validate_url():
    """Test URL validation"""
    # Test valid URL with protocol
    result = Validator.validate_url("https://example.com")
    assert result == "https://example.com"

    # Test valid URL without protocol (should add https)
    result = Validator.validate_url("example.com")
    assert result == "https://example.com"

    # Test invalid URL - URL with invalid domain format should raise error
    with pytest.raises(ValidationError):
        Validator.validate_url("invalid..domain.com")  # Double dots make invalid domain

    # Test empty URL with allow_empty
    result = Validator.validate_url("", allow_empty=True)
    assert result == ""

    # Test empty URL without allow_empty
    with pytest.raises(ValidationError):
        Validator.validate_url("", allow_empty=False)


def test_validate_domain():
    """Test domain validation"""
    # Test valid domains
    assert Validator.validate_domain("example.com") == "example.com"
    assert Validator.validate_domain("sub.example.com") == "sub.example.com"
    assert Validator.validate_domain("EXAMPLE.COM") == "example.com"  # Should be lowercased
    
    # Test invalid domains
    with pytest.raises(ValidationError):
        Validator.validate_domain("invalid..domain")
    
    with pytest.raises(ValidationError):
        Validator.validate_domain("")
    
    # Test empty domain with allow_empty
    result = Validator.validate_domain("", allow_empty=True)
    assert result == ""


def test_validate_ip():
    """Test IP address validation"""
    # Test valid IPv4
    assert Validator.validate_ip("192.168.1.1") == "192.168.1.1"
    
    # Test valid IPv6
    assert Validator.validate_ip("::1") == "::1"
    
    # Test invalid IP
    with pytest.raises(ValidationError):
        Validator.validate_ip("999.999.999.999")
    
    # Test empty IP with allow_empty
    result = Validator.validate_ip("", allow_empty=True)
    assert result == ""


def test_validate_port():
    """Test port validation"""
    # Test valid ports
    assert Validator.validate_port(80) == 80
    assert Validator.validate_port("443") == 443
    assert Validator.validate_port(65535) == 65535
    
    # Test invalid ports
    with pytest.raises(ValidationError):
        Validator.validate_port(70000)  # Too high
    
    with pytest.raises(ValidationError):
        Validator.validate_port(-1)  # Too low
    
    # Test with allow_zero
    assert Validator.validate_port(0, allow_zero=True) == 0
    with pytest.raises(ValidationError):
        Validator.validate_port(0, allow_zero=False)
    
    # Test empty port with allow_empty
    result = Validator.validate_port("", allow_empty=True)
    assert result == ""


def test_validate_host():
    """Test host validation"""
    # Test valid hosts (IP and domain)
    assert Validator.validate_host("192.168.1.1") == "192.168.1.1"
    assert Validator.validate_host("example.com") == "example.com"
    
    # Test invalid host
    with pytest.raises(ValidationError):
        Validator.validate_host("invalid_host_123")
    
    # Test empty host with allow_empty
    result = Validator.validate_host("", allow_empty=True)
    assert result == ""


def test_validate_file_path():
    """Test file path validation"""
    import tempfile
    import os

    # Test valid file path (non-existent but can be checked for format)
    # This test checks basic path format validation
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = temp_file.name

    try:
        # Test with must_exist=False (should pass for valid format)
        result = Validator.validate_file_path("some/path/file.txt", must_exist=False)
        assert str(result) == "some/path/file.txt"

        # Test with must_exist=True for existing file
        result = Validator.validate_file_path(temp_path, must_exist=True)
        assert str(result) == temp_path

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

    # Test with allow_empty - when allow_empty is True and path is empty,
    # Path("") returns current directory which is '.'
    result = Validator.validate_file_path("", allow_empty=True)
    assert str(result) == "."


def test_validate_integer():
    """Test integer validation"""
    # Test valid integers
    assert Validator.validate_integer(42) == 42
    assert Validator.validate_integer("123") == 123
    
    # Test with range validation
    assert Validator.validate_integer(5, min_val=1, max_val=10) == 5
    
    # Test out of range
    with pytest.raises(ValidationError):
        Validator.validate_integer(15, min_val=1, max_val=10)
    
    with pytest.raises(ValidationError):
        Validator.validate_integer(0, min_val=1, max_val=10)
    
    # Test empty with allow_empty
    result = Validator.validate_integer("", allow_empty=True)
    assert result == ""


def test_validate_choice():
    """Test choice validation"""
    choices = ["http", "https", "ftp"]
    
    # Test valid choices
    assert Validator.validate_choice("http", choices) == "http"
    assert Validator.validate_choice("ftp", choices) == "ftp"
    
    # Test invalid choice
    with pytest.raises(ValidationError):
        Validator.validate_choice("ssh", choices)
    
    # Test empty with allow_empty
    result = Validator.validate_choice("", choices, allow_empty=True)
    assert result == ""


def test_validate_boolean():
    """Test boolean validation"""
    # Test various true values
    assert Validator.validate_boolean(True) is True
    assert Validator.validate_boolean("true") is True
    assert Validator.validate_boolean("1") is True
    assert Validator.validate_boolean("yes") is True
    assert Validator.validate_boolean("on") is True
    
    # Test various false values
    assert Validator.validate_boolean(False) is False
    assert Validator.validate_boolean("false") is False
    assert Validator.validate_boolean("0") is False
    assert Validator.validate_boolean("no") is False
    assert Validator.validate_boolean("off") is False
    
    # Test invalid boolean
    with pytest.raises(ValidationError):
        Validator.validate_boolean("maybe")
    
    # Test empty with allow_empty
    result = Validator.validate_boolean("", allow_empty=True)
    assert result is None


def test_validate_non_empty():
    """Test non-empty validation"""
    # Test valid non-empty string
    assert Validator.validate_non_empty("hello") == "hello"
    assert Validator.validate_non_empty("  hello  ") == "hello"  # Should strip
    
    # Test invalid empty strings
    with pytest.raises(ValidationError):
        Validator.validate_non_empty("")
    
    with pytest.raises(ValidationError):
        Validator.validate_non_empty("   ")
    
    with pytest.raises(ValidationError):
        Validator.validate_non_empty(None)


def test_validate_regex():
    """Test regex validation"""
    # Test with valid email pattern
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    assert Validator.validate_regex("test@example.com", email_pattern) == "test@example.com"
    
    # Test invalid email
    with pytest.raises(ValidationError):
        Validator.validate_regex("invalid-email", email_pattern)
    
    # Test empty with allow_empty
    result = Validator.validate_regex("", r".*", allow_empty=True)
    assert result == ""


def test_validate_range():
    """Test range validation"""
    # Test integer range
    assert Validator.validate_range(5, min_val=1, max_val=10) == 5
    assert Validator.validate_range(1.5, min_val=1.0, max_val=2.0) == 1.5
    
    # Test out of range
    with pytest.raises(ValidationError):
        Validator.validate_range(15, min_val=1, max_val=10)
    
    with pytest.raises(ValidationError):
        Validator.validate_range(0.5, min_val=1.0, max_val=2.0)
    
    # Test with allow_empty
    result = Validator.validate_range("", min_val=1, max_val=10, allow_empty=True)
    assert result == ""