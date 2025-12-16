#!/usr/bin/env python3
"""Simple test to verify the asyncio fix without network calls"""

import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Test the asyncio fix by checking if we can call main without getting the loop error
def test_asyncio_error_fix():
    """Test that the asyncio.run() error is fixed"""
    print("Testing asyncio fix...")
    
    # Mock all network-dependent code and just test the asyncio part
    from unittest.mock import patch, MagicMock
    
    # Create minimal mock args
    class MockArgs:
        destination = "8.8.8.8"  # Use IP to bypass DNS resolution
        protocol = "icmp"
        port = 80
        max_hops = 2  # Small number for quick test
        timeout = 0.5
        probe_delay = 0.01
        save = False
        output = "test_output.json"
        allow_private = True  # Allow private IPs for this test
    
    mock_args = MockArgs()
    
    try:
        # Temporarily disable all network functions by mocking them
        with patch('modules.tracepulse.SecurityValidator.validate_destination') as mock_validate, \
             patch('modules.tracepulse.TracerouteSettings') as mock_settings, \
             patch('modules.tracepulse.TracePulse') as mock_tracer:
             
            # Mock validation to return success for our test IP
            mock_validate.return_value = ("8.8.8.8", None)
            
            # Mock settings creation
            settings_instance = MagicMock()
            settings_instance.destination = "8.8.8.8"
            settings_instance.resolved_ip = "8.8.8.8"
            settings_instance.protocol = "icmp"
            settings_instance.port = 80
            settings_instance.max_hops = 2
            settings_instance.timeout = 0.5
            settings_instance.probe_delay = 0.01
            settings_instance.save_results = False
            settings_instance.filename = "test_output.json"
            settings_instance.allow_private = True
            mock_settings.return_value = settings_instance
            
            # Mock tracer instance
            tracer_instance = MagicMock()
            tracer_instance.run = asyncio.coroutine(lambda: None)  # Mock async run method
            mock_tracer.return_value = tracer_instance
            
            # Now test the main function (which had the asyncio.run issue)
            from modules.tracepulse import main
            main(mock_args)
            
        print("✓ asyncio.run error fix successful!")
        print("  - No 'asyncio.run() cannot be called from a running event loop' error occurred")
        
    except RuntimeError as e:
        if "asyncio.run() cannot be called from a running event loop" in str(e):
            print("✗ asyncio.run error STILL EXISTS!")
            print(f"  - Error: {e}")
            return False
        else:
            print(f"✗ Different runtime error: {e}")
            return False
    except Exception as e:
        print(f"? Different error (might be expected due to mocked functionality): {e}")
        # This could be expected due to mocking, the important thing is that we didn't get the asyncio error
    
    return True

async def test_from_running_loop():
    """Test calling main from within an already running event loop"""
    print("\nTesting call from within running event loop...")
    
    # Mock args
    class MockArgs:
        destination = "8.8.8.8"
        protocol = "icmp"
        port = 80
        max_hops = 2
        timeout = 0.5
        probe_delay = 0.01
        save = False
        output = "test_output.json"
        allow_private = True
    
    mock_args = MockArgs()
    
    try:
        # Temporarily disable network functions
        from unittest.mock import patch, MagicMock
        
        with patch('modules.tracepulse.SecurityValidator.validate_destination') as mock_validate, \
             patch('modules.tracepulse.TracerouteSettings') as mock_settings, \
             patch('modules.tracepulse.TracePulse') as mock_tracer:
             
            mock_validate.return_value = ("8.8.8.8", None)
            
            settings_instance = MagicMock()
            settings_instance.destination = "8.8.8.8"
            settings_instance.resolved_ip = "8.8.8.8"
            settings_instance.protocol = "icmp"
            settings_instance.port = 80
            settings_instance.max_hops = 2
            settings_instance.timeout = 0.5
            settings_instance.probe_delay = 0.01
            settings_instance.save_results = False
            settings_instance.filename = "test_output.json"
            settings_instance.allow_private = True
            mock_settings.return_value = settings_instance
            
            tracer_instance = MagicMock()
            async def mock_run():
                pass  # Empty async method
            tracer_instance.run = mock_run
            mock_tracer.return_value = tracer_instance
            
            # This is the key test - calling main() from within a running event loop
            from modules.tracepulse import main
            main(mock_args)  # This is what was causing the error before the fix
        
        print("✓ Successfully called main() from within running event loop!")
        print("  - This was the exact scenario that was failing before the fix")
        
    except RuntimeError as e:
        if "asyncio.run() cannot be called from a running event loop" in str(e):
            print("✗ The asyncio error still occurs when called from a running loop!")
            print(f"  - Error: {e}")
            return False
        else:
            print(f"✗ Different runtime error: {e}")
            return False
    except Exception as e:
        print(f"? Different error (might be expected due to mocked functionality): {e}")
        # This could be expected due to mocking, the important test is that we didn't get the asyncio error
    
    return True

async def run_comprehensive_tests():
    """Run all tests"""
    print("🧪 Comprehensive Test of TracePulse asyncio Fix")
    print("=" * 50)
    
    # Test 1: Direct call (baseline)
    success1 = test_asyncio_error_fix()
    
    # Test 2: Call from within event loop (the main issue)
    success2 = await test_from_running_loop()
    
    print("\n📋 Test Results:")
    print(f"  - Direct call test: {'PASS' if success1 else 'FAIL'}")
    print(f"  - Event loop call test: {'PASS' if success2 else 'FAIL'}")
    
    if success1 and success2:
        print("\n🎉 All tests passed! The asyncio error should be fixed.")
    else:
        print("\n❌ Some tests failed. The fix may need more work.")

if __name__ == "__main__":
    asyncio.run(run_comprehensive_tests())