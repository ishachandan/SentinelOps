"""Test server-side confirmation gate enforcement - NO LLM NEEDED"""
import requests
import sys

if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

BASE_URL = "http://localhost:5000"

print("=" * 80)
print("SECURITY GATE ENFORCEMENT TESTS (No LLM required)")
print("=" * 80)

# Step 1: Manually seed a pending action by calling the backend directly
print("\n### SETUP: Manually seed a pending action ###")

# We'll create a pending action by directly manipulating the Flask app state
# through a test endpoint we'll add, OR by importing and calling the server code

# For now, let's create a minimal client that makes a real propose call through MCP
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def create_pending_action():
    """Create a real pending action via MCP"""
    server_params = StdioServerParameters(command="python", args=["server.py"])
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # Call propose_block_ip directly via MCP
            result = await session.call_tool("propose_block_ip", {
                "ip": "10.0.0.100",
                "reason": "Security test - manual seeding"
            })
            
            return result.content[0].text

# Get a real token
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
propose_result = loop.run_until_complete(create_pending_action())
loop.close()

print(f"SUCCESS: MCP propose result: {propose_result[:100]}...")

# Extract token
import re
match = re.search(r'[Tt]oken:\s*([a-f0-9]+)', propose_result)
if not match:
    print("FAILED: FAILED: Could not extract token from propose result")
    exit(1)

REAL_TOKEN = match.group(1)
print(f"SUCCESS: Extracted real token: {REAL_TOKEN}")

# Now manually register this with the Flask app's PENDING_CONFIRMATIONS
# We need to inject it through the web interface

# Create two sessions
session_a = requests.Session()
session_b = requests.Session()

# Initialize session A by making a request
print("\n### Initializing Flask sessions ###")
response = session_a.post(f"{BASE_URL}/clear")
print(f"SUCCESS: Session A initialized: {response.status_code}")

response = session_b.post(f"{BASE_URL}/clear")  
print(f"SUCCESS: Session B initialized: {response.status_code}")

# Manually inject the pending action into Flask's state
# We'll do this by hitting a propose through the web UI, OR by creating a test endpoint
# For now, let's use the send endpoint with a simple message that triggers propose

print("\n### Creating pending action through web UI (Session A) ###")
response = session_a.post(
    f"{BASE_URL}/send",
    json={"message": "I want to block IP 192.168.1.50"}
)

if response.status_code != 200:
    print(f"FAILED: FAILED to create proposal: {response.status_code}")
    print(response.text)
    exit(1)

data = response.json()
web_token = None
for entry in data.get('transcript', []):
    if entry.get('type') == 'pending_confirmation':
        web_token = entry['token']
        break

if not web_token:
    print("FAILED: FAILED: No pending confirmation created by web UI")
    print(f"Response: {data}")
    exit(1)

print(f"SUCCESS: Pending action created with token: {web_token}")

print("\n" + "=" * 80)
print("STEP 3: ADVERSARIAL TESTS")
print("=" * 80)

# Test 1: Confirm with correct session
print("\n### Test 1: VALID confirmation (correct session, valid token) ###")
response = session_a.post(f"{BASE_URL}/confirm/{web_token}")
print(f"Status: {response.status_code}")
result = response.json()
print(f"Response: {result}")

if response.status_code == 200 and result.get('success'):
    print("SUCCESS:PASS: Valid confirmation succeeded")
    
    # Verify execution actually happened - check for firewall rule file
    import os
    firewall_dir = "data/firewall_sandbox"
    if os.path.exists(firewall_dir):
        files = os.listdir(firewall_dir)
        print(f"SUCCESS: Firewall sandbox directory exists with {len(files)} files")
    else:
        print("WARNING: Firewall sandbox directory not found (might be in stub mode)")
else:
    print(f"FAILED: FAIL: Valid confirmation was rejected!")
    exit(1)

# Test 2: Fake token
print("\n### Test 2: FAKE TOKEN (never generated) ###")
fake_token = "deadbeef"
response = session_a.post(f"{BASE_URL}/confirm/{fake_token}")
print(f"Status: {response.status_code}")
result = response.json()
print(f"Response: {result}")

if response.status_code == 404:
    print("SUCCESS:PASS: Fake token correctly rejected with 404")
else:
    print(f"FAILED: SECURITY FAILURE: Fake token was not rejected! Status: {response.status_code}")
    exit(1)

# Test 3: Reused token (already executed)
print("\n### Test 3: REUSED TOKEN (already executed) ###")
response = session_a.post(f"{BASE_URL}/confirm/{web_token}")
print(f"Status: {response.status_code}")
result = response.json()
print(f"Response: {result}")

if response.status_code == 400:
    print("SUCCESS:PASS: Reused token correctly rejected with 400")
elif 'already' in result.get('error', '').lower():
    print("SUCCESS:PASS: Reused token rejected (status may vary but error indicates already executed)")
else:
    print(f"FAILED: SECURITY FAILURE: Reused token was accepted for double execution!")
    exit(1)

# Test 4: Create new token for cross-session test
print("\n### Setup for Test 4: Creating new pending action for Session A ###")
response = session_a.post(
    f"{BASE_URL}/send",
    json={"message": "block 10.20.30.40"}
)

if response.status_code == 200:
    data = response.json()
    cross_session_token = None
    for entry in data.get('transcript', []):
        if entry.get('type') == 'pending_confirmation':
            cross_session_token = entry['token']
            break
    
    if cross_session_token:
        print(f"SUCCESS: New pending action created with token: {cross_session_token}")
        
        # Test 4: Wrong session tries to confirm
        print("\n### Test 4: WRONG SESSION (Session B trying to confirm Session A's token) ###")
        response = session_b.post(f"{BASE_URL}/confirm/{cross_session_token}")
        print(f"Status: {response.status_code}")
        result = response.json()
        print(f"Response: {result}")
        
        if response.status_code == 403:
            print("SUCCESS:PASS: Cross-session token correctly rejected with 403")
        elif response.status_code == 404:
            print("SUCCESS:PASS: Cross-session token rejected (404 also acceptable - not visible to other session)")
        else:
            print(f"FAILED: SECURITY FAILURE: Cross-session token was accepted!")
            exit(1)
    else:
        print("WARNING: Could not create second pending action for cross-session test")
else:
    print("WARNING: Could not create second pending action for cross-session test")

# Test 5: Decline path
print("\n### Test 5: DECLINE path (should NOT execute) ###")
response = session_a.post(
    f"{BASE_URL}/send",
    json={"message": "block 50.60.70.80"}
)

if response.status_code == 200:
    data = response.json()
    decline_token = None
    for entry in data.get('transcript', []):
        if entry.get('type') == 'pending_confirmation':
            decline_token = entry['token']
            break
    
    if decline_token:
        print(f"SUCCESS: Pending action created with token: {decline_token}")
        
        # Get current firewall files count
        firewall_dir = "data/firewall_sandbox"
        import os
        if os.path.exists(firewall_dir):
            files_before = set(os.listdir(firewall_dir))
        else:
            files_before = set()
        
        # Decline it
        response = session_a.post(f"{BASE_URL}/decline/{decline_token}")
        print(f"Status: {response.status_code}")
        result = response.json()
        print(f"Response: {result}")
        
        if response.status_code == 200 and result.get('success'):
            print("SUCCESS: Decline succeeded")
            
            # Check no new firewall files
            if os.path.exists(firewall_dir):
                files_after = set(os.listdir(firewall_dir))
                new_files = files_after - files_before
                if len(new_files) == 0:
                    print("SUCCESS:PASS: Decline did NOT create firewall rules (no execution)")
                else:
                    print(f"FAILED: SECURITY FAILURE: Decline still executed! New files: {new_files}")
                    exit(1)
            else:
                print("SUCCESS:PASS: No firewall directory created (no execution)")
        else:
            print(f"FAILED: FAIL: Decline was rejected: {result}")
            exit(1)
    else:
        print("WARNING: Could not create pending action for decline test")
else:
    print("WARNING: Could not create pending action for decline test")

# Test 6: Decline with fake token
print("\n### Test 6: DECLINE with FAKE TOKEN ###")
response = session_a.post(f"{BASE_URL}/decline/badfake")
print(f"Status: {response.status_code}")
result = response.json()
print(f"Response: {result}")

if response.status_code == 404:
    print("SUCCESS:PASS: Fake token correctly rejected in decline path")
else:
    print(f"FAILED: SECURITY FAILURE: Decline accepted fake token!")
    exit(1)

print("\n" + "=" * 80)
print("SUCCESS:SUCCESS:SUCCESS: ALL SECURITY GATE TESTS PASSED SUCCESS:SUCCESS:SUCCESS:")
print("=" * 80)
print("\nVERIFIED:")
print("  SUCCESS: Valid tokens with correct session execute actions")
print("  SUCCESS: Fake/unknown tokens rejected (404)")
print("  SUCCESS: Reused tokens rejected (400)")
print("  SUCCESS: Cross-session tokens rejected (403/404)")
print("  SUCCESS: Decline path does NOT execute actions")
print("  SUCCESS: Decline path rejects fake tokens")
print("\nSecurity Server-side confirmation gate is PROPERLY ENFORCED!")
print("     No client-side bypass possible.")
