#!/usr/bin/env python3
"""Test script to verify the tracepulse fix"""

import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the module to test
from modules.tracepulse import main

def test_from_sync():
    """Test calling main from synchronous context (should work fine)"""
    print("Testing from synchronous context...")
    
    # Mock args for testing
    class MockArgs:
        destination = "google.com"
        protocol = "icmp"
        port = 80
        max_hops = 10
        timeout = 2.0
        probe_delay = 0.1
        save = False
        output = "test_output.json"
        allow_private = False
    
    mock_args = MockArgs()
    
    try:
        # This should work fine now
        main(mock_args)
        print("✓ Sync call completed successfully")
    except Exception as e:
        print(f"✗ Sync call failed: {e}")

async def test_from_async():
    """Test calling main from async context (this was causing the error)"""
    print("\nTesting from async context (the problematic case)...")
    
    # Mock args for testing
    class MockArgs:
        destination = "google.com"
        protocol = "icmp"
        port = 80
        max_hops = 10
        timeout = 2.0
        probe_delay = 0.1
        save = False
        output = "test_output.json"
        allow_private = False
    
    mock_args = MockArgs()
    
    try:
        # This was the problematic call that caused the error
        main(mock_args)
        print("✓ Async context call completed successfully")
    except Exception as e:
        print(f"✗ Async context call failed: {e}")

async def run_tests():
    """Run all tests"""
    print("Testing TracePulse async fix...\n")
    
    test_from_sync()
    
    await test_from_async()
    
    print("\nTesting completed!")

if __name__ == "__main__":
    # Run tests
    asyncio.run(run_tests())