#!/usr/bin/env python3
"""
Test Flask/MCP pending-action consistency.

Verifies that declining a pending action through Flask /decline/<token>
correctly updates BOTH:
1. Flask's in-memory PENDING_CONFIRMATIONS
2. MCP's pending_actions.json file

This test directly seeds an action via MCP, then declines via Flask,
then checks the MCP file to confirm it's marked as declined in both places.
"""
import asyncio
import requests
import json
import os
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PENDING_ACTIONS_FILE = "data/pending_actions.json"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def print_header(text):
    print(f"\n{Colors.BLUE}{'='*70}")
    print(f"{text}")
    print(f"{'='*70}{Colors.RESET}")

def print_pass(message):
    print(f"{Colors.GREEN}SUCCESS:PASS: {message}{Colors.RESET}")

def print_fail(message):
    print(f"{Colors.RED}FAILED: FAIL: {message}{Colors.RESET}")

def print_info(message):
    print(f"{Colors.YELLOW}[INFO] {message}{Colors.RESET}")

def read_pending_actions_file():
    """Read the MCP pending_actions.json file"""
    if not os.path.exists(PENDING_ACTIONS_FILE):
        return {}
    with open(PENDING_ACTIONS_FILE, 'r') as f:
        return json.load(f)

async def seed_action_via_mcp(token):
    """Seed a pending action directly via MCP debug tool"""
    print_info(f"Seeding action via MCP with token: {token}")
    
    # Set environment to enable debug endpoints
    os.environ['ENABLE_DEBUG_ENDPOINTS'] = 'true'
    
    try:
        server_params = StdioServerParameters(
            command='python',
            args=['server.py'],
            env=dict(os.environ)
        )
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                
                result = await session.call_tool(
                    'debug_seed_pending_action',
                    {
                        'token': token,
                        'action_type': 'block_ip',
                        'ip': '10.20.30.40',
                        'reason': 'Consistency test action',
                        'status': 'pending'
                    }
                )
                
                result_text = result.content[0].text
                print_info(f"MCP seed result: {result_text}")
                
                if "DEBUG: Seeded pending action" in result_text:
                    return True
                else:
                    print_fail(f"MCP seed failed: {result_text}")
                    return False
    finally:
        if 'ENABLE_DEBUG_ENDPOINTS' in os.environ:
            del os.environ['ENABLE_DEBUG_ENDPOINTS']

def decline_action_via_flask(token):
    """Decline the action via Flask /decline/<token> endpoint"""
    print_info(f"Declining action via Flask: {token}")
    
    try:
        response = requests.post(
            f'http://localhost:5000/decline/{token}',
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            print_info(f"Flask decline response: {data}")
            return data.get('success', False)
        else:
            print_fail(f"Flask decline failed with status {response.status_code}: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print_fail(f"Flask request failed: {e}")
        return False

async def test_consistency():
    """Main test: seed via MCP, decline via Flask, verify both are updated"""
    print_header("FLASK/MCP PENDING-ACTION CONSISTENCY TEST")
    
    test_token = "consistency_test_123"
    
    # Step 1: Seed action via MCP
    print_header("Step 1: Seed pending action via MCP")
    seed_success = await seed_action_via_mcp(test_token)
    
    if not seed_success:
        print_fail("Cannot proceed - MCP seeding failed")
        return False
    
    # Step 2: Verify action exists in MCP file with status="pending"
    print_header("Step 2: Verify action is in MCP pending_actions.json (status=pending)")
    actions = read_pending_actions_file()
    
    if test_token not in actions:
        print_fail(f"Token {test_token} not found in pending_actions.json after MCP seed")
        print_info(f"File contents: {actions}")
        return False
    
    if actions[test_token].get('status') != 'pending':
        print_fail(f"Token {test_token} has wrong status: {actions[test_token].get('status')}")
        return False
    
    print_pass(f"Token {test_token} exists in MCP file with status=pending")
    
    # Step 3: Decline action via Flask
    print_header("Step 3: Decline action via Flask /decline/<token>")
    decline_success = decline_action_via_flask(test_token)
    
    if not decline_success:
        print_fail("Flask decline failed")
        return False
    
    print_pass("Flask decline succeeded")
    
    # Step 4: Verify action is marked as declined in MCP file
    print_header("Step 4: Verify action is marked declined in MCP pending_actions.json")
    actions_after = read_pending_actions_file()
    
    if test_token not in actions_after:
        print_fail(f"Token {test_token} disappeared from pending_actions.json after decline")
        return False
    
    final_status = actions_after[test_token].get('status')
    print_info(f"Final status in MCP file: {final_status}")
    
    if final_status == 'declined':
        print_pass(f"Token {test_token} correctly marked as 'declined' in MCP file")
        return True
    elif final_status == 'pending':
        print_fail(f"Token {test_token} still marked as 'pending' in MCP file - CONSISTENCY BUG!")
        print_fail("Flask updated its in-memory dict but MCP file was not updated")
        return False
    else:
        print_fail(f"Token {test_token} has unexpected status: {final_status}")
        return False

async def main():
    print(f"""
{Colors.BLUE}╔══════════════════════════════════════════════════════════════════════╗
║  FLASK/MCP PENDING-ACTION CONSISTENCY TEST                           ║
║  Verifies declining via Flask also updates MCP pending_actions.json  ║
╚══════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.YELLOW}Testing the consistency between Flask's in-memory PENDING_CONFIRMATIONS
and MCP's persistent pending_actions.json file.{Colors.RESET}
""")
    
    result = await test_consistency()
    
    print_header("TEST RESULT")
    
    if result:
        print(f"{Colors.GREEN}SUCCESS: CONSISTENCY TEST PASSED{Colors.RESET}")
        print("Flask /decline route correctly updates both Flask memory and MCP file.")
    else:
        print(f"{Colors.RED}FAILED: CONSISTENCY TEST FAILED{Colors.RESET}")
        print("There is a consistency bug between Flask and MCP pending action storage.")
    
    print(f"\n{Colors.BLUE}{'='*70}{Colors.RESET}\n")

if __name__ == "__main__":
    asyncio.run(main())
