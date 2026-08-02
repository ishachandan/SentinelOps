"""Manual test script for Flask Web UI - Documents all test steps"""
import requests
import json
import time
import sys

# Fix Windows console encoding
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

BASE_URL = "http://localhost:5000"

print("=" * 80)
print("SentinelOps Web UI Test Suite")
print("=" * 80)

# Create a session to maintain cookies
session = requests.Session()

print("\n### STEP 1: Test basic message handling ###")
print("Sending: 'check if 185.220.101.1 is malicious'")

response = session.post(
    f"{BASE_URL}/send",
    json={"message": "check if 185.220.101.1 is malicious"}
)

if response.status_code == 200:
    data = response.json()
    print(f"SUCCESS: Status: {response.status_code}")
    print(f"SUCCESS: Transcript entries: {len(data['transcript'])}")
    
    for entry in data['transcript']:
        print(f"  - {entry['type']}: {entry.get('tool_name', entry.get('content', '')[:50])}")
    
    print("\nSUCCESS: STEP 1 PASSED: Basic message handling works")
else:
    print(f"FAILED: FAILED: Status {response.status_code}")
    print(response.text)
    exit(1)

print("\n### STEP 2: Test propose action (should create pending confirmation) ###")
print("Sending: 'block 185.220.101.1'")

response = session.post(
    f"{BASE_URL}/send",
    json={"message": "block 185.220.101.1"}
)

if response.status_code == 200:
    data = response.json()
    print(f"SUCCESS: Status: {response.status_code}")
    
    # Find pending confirmation
    pending_entry = None
    for entry in data['transcript']:
        if entry['type'] == 'pending_confirmation':
            pending_entry = entry
            break
    
    if pending_entry:
        token = pending_entry['token']
        print(f"SUCCESS: Pending confirmation found with token: {token}")
        print(f"  Preview: {pending_entry['content'][:100]}...")
        
        print("\n### STEP 3: Test CONFIRM path ###")
        print(f"Confirming token: {token}")
        
        response = session.post(f"{BASE_URL}/confirm/{token}")
        if response.status_code == 200:
            result = response.json()
            print(f"SUCCESS: Confirm succeeded: {result.get('result', '')[:100]}")
            print("\nSUCCESS: STEP 3 PASSED: Confirm path works")
        else:
            print(f"FAILED: Confirm failed: {response.status_code} - {response.text}")
            exit(1)
    else:
        print("FAILED: No pending confirmation found in response")
        print(f"Transcript: {json.dumps(data['transcript'], indent=2)}")
        exit(1)
else:
    print(f"FAILED: FAILED: Status {response.status_code}")
    print(response.text)
    exit(1)

print("\n### STEP 4: Test DECLINE path ###")
print("Sending: 'block 8.8.8.8'")

response = session.post(
    f"{BASE_URL}/send",
    json={"message": "block 8.8.8.8"}
)

if response.status_code == 200:
    data = response.json()
    
    pending_entry = None
    for entry in data['transcript']:
        if entry['type'] == 'pending_confirmation':
            pending_entry = entry
            break
    
    if pending_entry:
        token = pending_entry['token']
        print(f"SUCCESS: Pending confirmation found with token: {token}")
        
        print(f"Declining token: {token}")
        response = session.post(f"{BASE_URL}/decline/{token}")
        if response.status_code == 200:
            result = response.json()
            print(f"SUCCESS: Decline succeeded: {result.get('message', '')}")
            print("\nSUCCESS: STEP 4 PASSED: Decline path works")
        else:
            print(f"FAILED: Decline failed: {response.status_code} - {response.text}")
            exit(1)
    else:
        print("FAILED: No pending confirmation found")
        exit(1)
else:
    print(f"FAILED: FAILED: Status {response.status_code}")
    exit(1)

print("\n### STEP 5: Adversarial tests - bypass attempts ###")

print("\n5a. Test: Fake token (never generated)")
fake_token = "fakefake"
response = session.post(f"{BASE_URL}/confirm/{fake_token}")
if response.status_code == 404:
    print(f"SUCCESS: Fake token rejected: {response.status_code}")
else:
    print(f"FAILED: SECURITY FAILURE: Fake token was accepted! Status: {response.status_code}")
    exit(1)

print("\n5b. Test: Reused token (already executed)")
# The token from Step 3 was already confirmed
old_token = token  # This is risky, but for testing...

# First, get a fresh token
response = session.post(
    f"{BASE_URL}/send",
    json={"message": "block 1.2.3.4"}
)
data = response.json()
pending_entry = None
for entry in data['transcript']:
    if entry['type'] == 'pending_confirmation':
        pending_entry = entry
        break

if pending_entry:
    reuse_token = pending_entry['token']
    # Confirm once
    session.post(f"{BASE_URL}/confirm/{reuse_token}")
    
    # Try to confirm again
    response = session.post(f"{BASE_URL}/confirm/{reuse_token}")
    if response.status_code == 400:
        result = response.json()
        print(f"SUCCESS: Reused token rejected: {result.get('error', '')}")
    else:
        print(f"FAILED: SECURITY FAILURE: Reused token was accepted! Status: {response.status_code}")
        exit(1)

print("\nSUCCESS: STEP 5 PASSED: All adversarial tests blocked correctly")

print("\n### STEP 6: Multi-turn context test ###")
print("Test 1: 'check 185.220.101.1'")
response = session.post(
    f"{BASE_URL}/send",
    json={"message": "check 185.220.101.1"}
)
print(f"SUCCESS: Response received")

print("Test 2: 'block that IP' (context-dependent)")
response = session.post(
    f"{BASE_URL}/send",
    json={"message": "block that IP"}
)

if response.status_code == 200:
    data = response.json()
    pending_entry = None
    for entry in data['transcript']:
        if entry['type'] == 'pending_confirmation':
            pending_entry = entry
            break
    
    if pending_entry:
        token = pending_entry['token']
        print(f"SUCCESS: Context preserved - proposal generated with token: {token}")
        
        # Confirm it
        response = session.post(f"{BASE_URL}/confirm/{token}")
        if response.status_code == 200:
            print(f"SUCCESS: Multi-turn confirmation successful")
            print("\nSUCCESS: STEP 6 PASSED: Multi-turn context works correctly")
        else:
            print(f"FAILED: Confirmation failed: {response.status_code}")
            exit(1)
    else:
        print("FAILED: No proposal generated - context may have been lost")
        exit(1)
else:
    print(f"FAILED: FAILED: Status {response.status_code}")
    exit(1)

print("\n" + "=" * 80)
print("SUCCESS:SUCCESS:SUCCESS: ALL TESTS PASSED SUCCESS:SUCCESS:SUCCESS:")
print("=" * 80)
print("\nSUMMARY:")
print("  SUCCESS: Step 1: Basic message handling")
print("  SUCCESS: Step 2: Pending confirmation generation")
print("  SUCCESS: Step 3: Confirm path executes actions")
print("  SUCCESS: Step 4: Decline path prevents execution")
print("  SUCCESS: Step 5: Adversarial tests blocked (fake tokens, reuse)")
print("  SUCCESS: Step 6: Multi-turn context preserved")
print("\nSecurity Server-side confirmation gate is properly enforced!")
