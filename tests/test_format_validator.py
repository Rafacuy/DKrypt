#!/usr/bin/env python3

from core.validation.validators import Validator

# Test the fix for validate_host
print("Testing validate_host function with host:port formats...")

test_cases = [
    "detik.com:443",
    "google.com:80",
    "192.168.1.1:8080",
    "localhost:3000",
    "example.com",
    "192.168.1.1"
]

for case in test_cases:
    try:
        result = Validator.validate_host(case)
        print(f"✓ '{case}' -> Valid: {result}")
    except Exception as e:
        print(f"✗ '{case}' -> Invalid: {str(e)}")

print("\nAll tests completed!")