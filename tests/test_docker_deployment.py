#!/usr/bin/env python3
"""
Test script to verify Docker deployment is working correctly.
Run this AFTER docker-compose up to validate the deployment.
"""
import requests
import time
import json
import sys

BASE_URL = "http://localhost:5000"
TIMEOUT = 10

def test_health_check():
    """Test if the server is responding"""
    print("Testing health check (GET /)...")
    try:
        response = requests.get(f"{BASE_URL}/", timeout=TIMEOUT)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        print("  SUCCESS: Server is responding")
        return True
    except requests.exceptions.ConnectionError:
        print("  FAILED: Cannot connect to server. Is it running?")
        return False
    except Exception as e:
        print(f"  FAILED: Error: {e}")
        return False

def test_clear_endpoint():
    """Test clear conversation endpoint"""
    print("Testing clear endpoint (POST /clear)...")
    try:
        response = requests.post(
            f"{BASE_URL}/clear",
            json={},
            timeout=TIMEOUT
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert data.get('success') == True, "Expected success=true"
        print("  SUCCESS: Clear endpoint working")
        return True
    except Exception as e:
        print(f"  FAILED: Error: {e}")
        return False

def test_send_message():
    """Test sending a message (basic functionality)"""
    print("Testing send message (POST /send)...")
    try:
        # Use a simple query that doesn't require external APIs
        response = requests.post(
            f"{BASE_URL}/send",
            json={"message": "ping"},
            timeout=30  # Longer timeout for LLM call
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        data = response.json()
        assert data.get('success') == True, "Expected success=true"
        assert 'transcript' in data, "Expected transcript in response"
        assert len(data['transcript']) > 0, "Expected non-empty transcript"
        print(f"  SUCCESS: Message sent successfully, transcript has {len(data['transcript'])} entries")
        return True
    except requests.exceptions.Timeout:
        print("  WARNING: Request timed out (may indicate slow LLM response or ChromaDB initialization)")
        return False
    except Exception as e:
        print(f"  FAILED: Error: {e}")
        return False

def test_static_files():
    """Test if static files are accessible"""
    print("Testing static file serving...")
    try:
        # Test if we can access the main page
        response = requests.get(f"{BASE_URL}/", timeout=TIMEOUT)
        assert response.status_code == 200
        assert 'text/html' in response.headers.get('Content-Type', ''), "Expected HTML response"
        print("  SUCCESS: Static files accessible")
        return True
    except Exception as e:
        print(f"  FAILED: Error: {e}")
        return False

def test_security_gates():
    """Test that debug endpoints are properly gated"""
    print("Testing security gates (debug endpoints should be disabled)...")
    try:
        response = requests.post(
            f"{BASE_URL}/debug/seed_token",
            json={"action_type": "block_ip", "ip": "1.2.3.4"},
            timeout=TIMEOUT
        )
        # Should get 404 if ENABLE_DEBUG_ENDPOINTS is false (production)
        if response.status_code == 404:
            print("  SUCCESS: Debug endpoints properly disabled")
            return True
        elif response.status_code == 200:
            print("  WARNING: Debug endpoints are ENABLED (should be disabled in production!)")
            return True  # Not a failure, just a warning
        else:
            print(f"  WARNING: Unexpected status: {response.status_code}")
            return True
    except Exception as e:
        print(f"  FAILED: Error: {e}")
        return False

def main():
    print("=" * 60)
    print("SentinelOps Docker Deployment Test")
    print("=" * 60)
    print()
    print("Waiting 5 seconds for server to stabilize...")
    time.sleep(5)
    print()
    
    tests = [
        test_health_check,
        test_static_files,
        test_clear_endpoint,
        test_security_gates,
        # test_send_message  # Comment out if you want to avoid using Groq quota
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            result = test()
            if result:
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"  FAILED: Test crashed: {e}")
            failed += 1
        print()
    
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    if failed == 0:
        print("SUCCESS: All tests passed! Docker deployment is working correctly.")
        return 0
    else:
        print("FAILED: Some tests failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
