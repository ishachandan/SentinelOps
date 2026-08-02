#!/usr/bin/env python3
"""
Adversarial testing for web UI confirmation gates.
Tests server-side validation WITHOUT needing Groq/LLM.

Uses /debug/seed_token to create test tokens, then validates /confirm and /decline routes.

WHAT THIS TESTS (Step 5 requirements):
1. Valid token + correct session → executes (firewall rule created)
2. Fake token → 404 rejection
3. Reused token (already executed) → 400 rejection  
4. Cross-session token → 403 rejection
5. Decline → does NOT execute (no firewall rule)
"""
import requests
import json
import os
import time
from datetime import datetime

BASE_URL = "http://localhost:5000"
FIREWALL_DIR = "data/firewall_sandbox"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def print_test_header(test_num, description):
    print(f"\n{'='*70}")
    print(f"{Colors.BLUE}TEST {test_num}: {description}{Colors.RESET}")
    print('='*70)

def print_pass(message):
    print(f"{Colors.GREEN}SUCCESS:PASS: {message}{Colors.RESET}")

def print_fail(message):
    print(f"{Colors.RED}FAILED: FAIL: {message}{Colors.RESET}")

def print_info(message):
    print(f"{Colors.YELLOW}[INFO] {message}{Colors.RESET}")

def count_firewall_rules():
    """Count number of firewall rules in sandbox"""
    if not os.path.exists(FIREWALL_DIR):
        return 0
    return len([f for f in os.listdir(FIREWALL_DIR) if f.endswith('.rule')])

def seed_token(session, token, action_type="block_ip", ip="1.2.3.4", status="pending", custom_session_id=None):
    """Seed a test token using debug endpoint"""
    payload = {
        "token": token,
        "action_type": action_type,
        "ip": ip,
        "status": status
    }
    
    if custom_session_id:
        payload["use_session_id"] = custom_session_id
    
    resp = session.post(f"{BASE_URL}/debug/seed_token", json=payload)
    
    if resp.status_code != 200:
        print_fail(f"Failed to seed token: {resp.text}")
        return None
    
    data = resp.json()
    print_info(f"Seeded token '{data['token']}' for session '{data['session_id']}'")
    return data

def test_1_valid_confirm():
    """TEST 1: Valid token with correct session should execute"""
    print_test_header(1, "Valid token + correct session → should execute")
    
    # Create session
    session = requests.Session()
    session.get(f"{BASE_URL}/")  # Get session cookie
    
    # Count rules before
    rules_before = count_firewall_rules()
    print_info(f"Firewall rules before: {rules_before}")
    
    # Seed token for THIS session
    token = "test_valid_1"
    seed_data = seed_token(session, token, ip="10.0.0.1")
    
    if not seed_data:
        return False
    
    # Confirm the action
    print_info(f"Confirming token '{token}'...")
    resp = session.post(f"{BASE_URL}/confirm/{token}")
    
    print_info(f"Response status: {resp.status_code}")
    print_info(f"Response body: {resp.json()}")
    
    # Count rules after
    time.sleep(0.1)  # Brief pause for file system
    rules_after = count_firewall_rules()
    print_info(f"Firewall rules after: {rules_after}")
    
    # Validate
    if resp.status_code == 200 and rules_after > rules_before:
        print_pass(f"Action executed! Created firewall rule. Rules: {rules_before} → {rules_after}")
        
        # Verify the specific rule file exists
        expected_file = os.path.join(FIREWALL_DIR, "block_10_0_0_1.rule")
        if os.path.exists(expected_file):
            with open(expected_file, 'r') as f:
                rule_content = json.load(f)
            print_pass(f"Rule file verified: {expected_file}")
            print_info(f"Rule content: {json.dumps(rule_content, indent=2)}")
        
        return True
    else:
        print_fail(f"Expected execution (status=200, new rule created), got status={resp.status_code}, rules={rules_before}→{rules_after}")
        return False

def test_2_fake_token():
    """TEST 2: Fake token should get 404"""
    print_test_header(2, "Fake token → should reject with 404")
    
    session = requests.Session()
    session.get(f"{BASE_URL}/")
    
    fake_token = "NONEXISTENT_TOKEN_XYZ"
    print_info(f"Trying to confirm fake token '{fake_token}'...")
    
    resp = session.post(f"{BASE_URL}/confirm/{fake_token}")
    
    print_info(f"Response status: {resp.status_code}")
    print_info(f"Response body: {resp.json()}")
    
    if resp.status_code == 404:
        print_pass(f"Fake token correctly rejected with 404")
        return True
    else:
        print_fail(f"Expected 404, got {resp.status_code}")
        return False

def test_3_reused_token():
    """TEST 3: Already-executed token should get 400"""
    print_test_header(3, "Reused token (already executed) → should reject with 400")
    
    session = requests.Session()
    session.get(f"{BASE_URL}/")
    
    # Seed token with status='confirmed' (already executed)
    token = "test_reused_3"
    seed_data = seed_token(session, token, ip="10.0.0.3", status="confirmed")
    
    if not seed_data:
        return False
    
    print_info(f"Token '{token}' seeded with status='confirmed' (already executed)")
    print_info(f"Attempting to execute again...")
    
    resp = session.post(f"{BASE_URL}/confirm/{token}")
    
    print_info(f"Response status: {resp.status_code}")
    print_info(f"Response body: {resp.json()}")
    
    if resp.status_code == 400:
        print_pass(f"Reused token correctly rejected with 400")
        return True
    else:
        print_fail(f"Expected 400, got {resp.status_code}")
        return False

def test_4_cross_session():
    """TEST 4: Token from different session should get 403"""
    print_test_header(4, "Cross-session token → should reject with 403")
    
    # Create first session and seed token for it
    session1 = requests.Session()
    session1.get(f"{BASE_URL}/")
    
    token = "test_cross_4"
    seed_data = seed_token(session1, token, ip="10.0.0.4", custom_session_id="owner-session-123")
    
    if not seed_data:
        return False
    
    print_info(f"Token '{token}' created for session 'owner-session-123'")
    
    # Create DIFFERENT session
    session2 = requests.Session()
    session2.get(f"{BASE_URL}/")
    
    print_info(f"Attempting to confirm from different session...")
    
    resp = session2.post(f"{BASE_URL}/confirm/{token}")
    
    print_info(f"Response status: {resp.status_code}")
    print_info(f"Response body: {resp.json()}")
    
    if resp.status_code == 403:
        print_pass(f"Cross-session token correctly rejected with 403")
        return True
    else:
        print_fail(f"Expected 403, got {resp.status_code}")
        return False

def test_5_decline_no_execute():
    """TEST 5: Decline should NOT create firewall rules"""
    print_test_header(5, "Decline path → should NOT execute action")
    
    session = requests.Session()
    session.get(f"{BASE_URL}/")
    
    # Count rules before
    rules_before = count_firewall_rules()
    print_info(f"Firewall rules before: {rules_before}")
    
    # Seed token
    token = "test_decline_5"
    seed_data = seed_token(session, token, ip="10.0.0.5")
    
    if not seed_data:
        return False
    
    # DECLINE the action
    print_info(f"Declining token '{token}'...")
    resp = session.post(f"{BASE_URL}/decline/{token}")
    
    print_info(f"Response status: {resp.status_code}")
    print_info(f"Response body: {resp.json()}")
    
    # Count rules after
    time.sleep(0.1)
    rules_after = count_firewall_rules()
    print_info(f"Firewall rules after: {rules_after}")
    
    # Validate: should be 200 success, but NO new rules
    if resp.status_code == 200 and rules_after == rules_before:
        print_pass(f"Decline succeeded, no execution. Rules unchanged: {rules_before} = {rules_after}")
        return True
    else:
        print_fail(f"Expected status=200 with no new rules, got status={resp.status_code}, rules={rules_before}→{rules_after}")
        return False

def test_6_decline_wrong_session():
    """TEST 6: Decline from wrong session should get 403"""
    print_test_header(6, "Decline from wrong session → should reject with 403")
    
    # Create first session and seed token
    session1 = requests.Session()
    session1.get(f"{BASE_URL}/")
    
    token = "test_decline_6"
    seed_data = seed_token(session1, token, ip="10.0.0.6", custom_session_id="owner-session-456")
    
    if not seed_data:
        return False
    
    print_info(f"Token '{token}' created for session 'owner-session-456'")
    
    # Try to decline from DIFFERENT session
    session2 = requests.Session()
    session2.get(f"{BASE_URL}/")
    
    print_info(f"Attempting to decline from different session...")
    
    resp = session2.post(f"{BASE_URL}/decline/{token}")
    
    print_info(f"Response status: {resp.status_code}")
    print_info(f"Response body: {resp.json()}")
    
    if resp.status_code == 403:
        print_pass(f"Cross-session decline correctly rejected with 403")
        return True
    else:
        print_fail(f"Expected 403, got {resp.status_code}")
        return False

def test_7_decline_fake_token():
    """TEST 7: Decline with fake token should get 404"""
    print_test_header(7, "Decline with fake token → should reject with 404")
    
    session = requests.Session()
    session.get(f"{BASE_URL}/")
    
    fake_token = "FAKE_DECLINE_TOKEN"
    print_info(f"Trying to decline fake token '{fake_token}'...")
    
    resp = session.post(f"{BASE_URL}/decline/{fake_token}")
    
    print_info(f"Response status: {resp.status_code}")
    print_info(f"Response body: {resp.json()}")
    
    if resp.status_code == 404:
        print_pass(f"Fake token correctly rejected with 404 on decline")
        return True
    else:
        print_fail(f"Expected 404, got {resp.status_code}")
        return False

def main():
    print(f"""
{Colors.BLUE}╔══════════════════════════════════════════════════════════════════════╗
║  ADVERSARIAL SECURITY GATE TESTING - No LLM Required                 ║
║  Tests web UI confirmation enforcement via direct token seeding      ║
╚══════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.YELLOW}Prerequisites:{Colors.RESET}
SUCCESS: Flask web_ui.py running on http://localhost:5000
SUCCESS: /debug/seed_token endpoint available
SUCCESS: data/firewall_sandbox directory exists

{Colors.YELLOW}What we're testing:{Colors.RESET}
SUCCESS: Server-side token validation (not client bypass)
SUCCESS: Session ownership enforcement
SUCCESS: Status-based access control (no double execution)
SUCCESS: Decline path never executes

Starting tests in 3 seconds...
""")
    
    time.sleep(3)
    
    # Check if server is running
    try:
        resp = requests.get(f"{BASE_URL}/", timeout=2)
        if resp.status_code != 200:
            print_fail(f"Server not responding correctly at {BASE_URL}")
            return
    except requests.exceptions.RequestException as e:
        print_fail(f"Cannot connect to server at {BASE_URL}")
        print_info(f"Error: {e}")
        print_info("Please start web_ui.py first: python web_ui.py")
        return
    
    # Ensure firewall sandbox exists
    os.makedirs(FIREWALL_DIR, exist_ok=True)
    
    # Run all tests
    results = []
    
    results.append(("Valid confirm", test_1_valid_confirm()))
    results.append(("Fake token reject", test_2_fake_token()))
    results.append(("Reused token reject", test_3_reused_token()))
    results.append(("Cross-session reject", test_4_cross_session()))
    results.append(("Decline no-execute", test_5_decline_no_execute()))
    results.append(("Decline wrong session", test_6_decline_wrong_session()))
    results.append(("Decline fake token", test_7_decline_fake_token()))
    
    # Summary
    print(f"\n{Colors.BLUE}{'='*70}")
    print("TEST SUMMARY")
    print(f"{'='*70}{Colors.RESET}\n")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = f"{Colors.GREEN}PASS{Colors.RESET}" if result else f"{Colors.RED}FAIL{Colors.RESET}"
        print(f"  {status}  {name}")
    
    print(f"\n{Colors.BLUE}{'='*70}{Colors.RESET}")
    
    if passed == total:
        print(f"{Colors.GREEN}SUCCESS: ALL {total} TESTS PASSED!{Colors.RESET}")
        print(f"{Colors.GREEN}Server-side confirmation gates are working correctly.{Colors.RESET}")
        print(f"\n{Colors.YELLOW}Step 2 security requirements: VERIFIED SUCCESS:{Colors.RESET}")
    else:
        print(f"{Colors.RED}FAILED: {total - passed} of {total} tests FAILED{Colors.RESET}")
        print(f"{Colors.RED}Security gates have issues that need fixing.{Colors.RESET}")
    
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")

if __name__ == "__main__":
    main()
