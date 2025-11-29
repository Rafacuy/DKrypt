#!/usr/bin/env python3

from core.validation.validators import Validator

print("Testing various validator functions to ensure they still work...")

# Test validate_url
try:
    result = Validator.validate_url("https://example.com")
    print(f"✓ validate_url('https://example.com') -> {result}")
except Exception as e:
    print(f"✗ validate_url('https://example.com') -> {str(e)}")

# Test validate_domain
try:
    result = Validator.validate_domain("example.com")
    print(f"✓ validate_domain('example.com') -> {result}")
except Exception as e:
    print(f"✗ validate_domain('example.com') -> {str(e)}")

# Test validate_ip
try:
    result = Validator.validate_ip("192.168.1.1")
    print(f"✓ validate_ip('192.168.1.1') -> {result}")
except Exception as e:
    print(f"✗ validate_ip('192.168.1.1') -> {str(e)}")

# Test the updated validate_host with various formats
test_hosts = [
    "example.com",      # Regular domain
    "192.168.1.1",      # Regular IP
    "example.com:443",  # Domain with port
    "192.168.1.1:8080", # IP with port
    "localhost:3000"    # localhost with port
]

print("\nTesting updated validate_host function:")
for host in test_hosts:
    try:
        result = Validator.validate_host(host)
        print(f"✓ validate_host('{host}') -> {result}")
    except Exception as e:
        print(f"✗ validate_host('{host}') -> {str(e)}")

print("\nAll validation tests completed!")