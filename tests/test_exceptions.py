"""
Tests for the exceptions module in DKrypt
"""

import pytest
from core.exceptions import ValidationError, DKryptException, UserCancelledError


def test_validation_error():
    """Test ValidationError functionality"""
    with pytest.raises(ValidationError) as exc_info:
        raise ValidationError("Invalid input", field="test_field", value="test_value")

    error = exc_info.value
    assert str(error) == "Invalid input"
    assert error.code == "VALIDATION_ERROR"
    # Field and value are stored in details dict
    assert error.details["field"] == "test_field"
    assert error.details["value"] == "test_value"


def test_dkrypt_exception():
    """Test DKryptException functionality"""
    with pytest.raises(DKryptException) as exc_info:
        raise DKryptException(code="TEST_ERROR", message="Test error message", details="Additional details")
    
    error = exc_info.value
    assert error.code == "TEST_ERROR"
    assert error.message == "Test error message"
    assert error.details == "Additional details"


def test_user_cancelled_error():
    """Test UserCancelledError functionality"""
    with pytest.raises(UserCancelledError):
        raise UserCancelledError()
    
    # Test with custom message
    with pytest.raises(UserCancelledError) as exc_info:
        raise UserCancelledError("Operation was cancelled by user")
    
    error = exc_info.value
    assert str(error) == "Operation was cancelled by user"