
import pytest
from core.command_engine import CommandValidator
from core.validators import Validator

@pytest.fixture
def modules_config():
    return {
        'test_module': {
            'options': {
                'URL': {'required': True, 'validator': 'validate_url'},
                'CHOICE': {'required': True, 'validator': 'validate_choice', 'choices': ['a', 'b', 'c']},
                'INTEGER': {'required': False, 'validator': 'validate_integer', 'min_val': 1, 'max_val': 10},
                'BOOL': {'required': False, 'validator': 'validate_boolean'}
            }
        }
    }

def test_valid_input(modules_config):
    validator = CommandValidator(modules_config)
    is_valid, errors = validator.validate_module_options('test_module', {'URL': 'http://example.com', 'CHOICE': 'a'})
    assert is_valid
    assert not errors

def test_invalid_url(modules_config):
    validator = CommandValidator(modules_config)
    is_valid, errors = validator.validate_module_options('test_module', {'URL': 'not_a_url', 'CHOICE': 'a'})
    assert not is_valid
    assert "Option 'URL': Invalid URL: Invalid domain format" in errors[0]

def test_invalid_choice(modules_config):
    validator = CommandValidator(modules_config)
    is_valid, errors = validator.validate_module_options('test_module', {'URL': 'http://example.com', 'CHOICE': 'd'})
    assert not is_valid
    assert "Option 'CHOICE': Value must be one of: a, b, c" in errors[0]

def test_invalid_integer(modules_config):
    validator = CommandValidator(modules_config)
    is_valid, errors = validator.validate_module_options('test_module', {'URL': 'http://example.com', 'CHOICE': 'a', 'INTEGER': '11'})
    assert not is_valid
    assert "Option 'INTEGER': Value must be <= 10" in errors[0]

def test_invalid_boolean(modules_config):
    validator = CommandValidator(modules_config)
    is_valid, errors = validator.validate_module_options('test_module', {'URL': 'http://example.com', 'CHOICE': 'a', 'BOOL': 'not_a_bool'})
    assert not is_valid
    assert "Option 'BOOL': Value must be a valid boolean" in errors[0]

def test_missing_required_option(modules_config):
    # This should be handled by CommandParser, not CommandValidator
    pass
