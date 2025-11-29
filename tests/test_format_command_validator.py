#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.abspath('.'))

from core.validation.validators import Validator
from core.cli.command_engine import CommandValidator

# Create mock module config for sslinspect
modules_config = {
    'sslinspect': {
        'name': 'SSL/TLS Inspector',
        'description': 'Analyze website security certificates',
        'category': 'audit',
        'options': {
            'TARGET': {'required': True, 'description': 'Target host:port', 'validator': 'validate_host'},
            'EXPORT': {'required': False, 'description': 'Export format (json/txt)', 'default': 'json', 'validator': 'validate_choice', 'choices': ['json', 'txt']}
        },
    }
}

# Test the CommandValidator with the sslinspect module
validator = CommandValidator(modules_config)

test_cases = [
    {"TARGET": "detik.com:443"},
    {"TARGET": "google.com:80"},
    {"TARGET": "invalid:99999"},  # Invalid port
    {"TARGET": "invalid_format"}  # Invalid host
]

print("Testing CommandValidator with sslinspect module...")

for i, options in enumerate(test_cases):
    print(f"\nTest case {i+1}: {options}")
    is_valid, errors = validator.validate_module_options('sslinspect', options)
    if is_valid:
        print(f"  ✓ Valid")
    else:
        print(f"  ✗ Invalid: {errors}")

print("\nCommandValidator test completed!")