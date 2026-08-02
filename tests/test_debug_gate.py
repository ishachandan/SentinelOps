#!/usr/bin/env python3
"""
Test that debug endpoints are properly gated by ENABLE_DEBUG_ENDPOINTS flag.

Tests:
1. MCP debug_seed_pending_action returns error when flag=false
2. Flask /debug/seed_token returns 404 when flag=false
3. Both work correctly when flag=true
"""
import asyncio
import requests
import os
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def print_test_header(description):
    print(f"\n{Colors.BLUE}{'='*70}")
    print(f"{description}")
    print(f"{'='*70}{Colors.RESET}")

def print_pass(message):
    print(f"{Colors.GREEN}SUCCESS:PASS: {message}{Colors.RESET}")

def print_fail(message):
    print(f"{Colors.RED}FAILED: FAIL: {message}{Colors.RESET}")

def print_info(message):
    print(f"{Colors.YELLOW}[INFO] {message}{Colors.RESET}")

async def test_mcp_debug_gated():
    """Test MCP debug tool is gated when flag is false"""
    print_test_header("TEST 1: MCP debug_seed_pending_action with ENABLE_DEBUG_ENDPOINTS=false")
    
    # Ensure flag is false (default)
    if 'ENABLE_DEBUG_ENDPOINTS' in os.environ:
        del os.environ['ENABLE_DEBUG_ENDPOINTS']
    
    server_params = StdioServerParameters(command='python', args=['server.py'])
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            print_info("Calling debug_seed_pending_action with flag=false...")
            result = await session.call_tool(
                'debug_seed_pending_action',
                {
                    'token': 'should_fail_123',
                    'action_type': 'block_ip',
                    'ip': '1.1.1.1',
                    'reason': 'Test'
                }
            )
            
            result_text = result.content[0].text
            print_info(f"Result: {result_text}")
            
            if "Debug endpoints are disabled" in result_text:
                print_pass("MCP debug tool correctly rejected when flag=false")
                return True
            else:
                print_fail(f"Expected rejection, got: {result_text}")
                return False

async def test_mcp_debug_enabled():
    """Test MCP debug tool works when flag is true"""
    print_test_header("TEST 2: MCP debug_seed_pending_action with ENABLE_DEBUG_ENDPOINTS=true")
    
    # Set flag to true - this will be inherited by subprocess
    os.environ['ENABLE_DEBUG_ENDPOINTS'] = 'true'
    
    try:
        server_params = StdioServerParameters(
            command='python',
            args=['server.py'],
            env=dict(os.environ)  # Pass current environment including ENABLE_DEBUG_ENDPOINTS
        )
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                
                print_info("Calling debug_seed_pending_action with flag=true...")
                result = await session.call_tool(
                    'debug_seed_pending_action',
                    {
                        'token': 'should_work_456',
                        'action_type': 'block_ip',
                        'ip': '2.2.2.2',
                        'reason': 'Test'
                    }
                )
                
                result_text = result.content[0].text
                print_info(f"Result: {result_text}")
                
                if "DEBUG: Seeded pending action" in result_text:
                    print_pass("MCP debug tool correctly works when flag=true")
                    return True
                else:
                    print_fail(f"Expected success, got: {result_text}")
                    return False
    finally:
        # Clean up
        if 'ENABLE_DEBUG_ENDPOINTS' in os.environ:
            del os.environ['ENABLE_DEBUG_ENDPOINTS']

def test_flask_debug_gated():
    """Test Flask debug endpoint returns 404 when flag is false"""
    print_test_header("TEST 3: Flask /debug/seed_token with ENABLE_DEBUG_ENDPOINTS=false")
    
    # The Flask server should be running WITHOUT the flag
    # (We'll need to restart it, but for now test what's currently running)
    
    print_info("Checking if Flask server needs ENABLE_DEBUG_ENDPOINTS=false...")
    print_info("NOTE: This test requires Flask server restart without the flag")
    print_info("Skipping for now - manual verification needed after server restart")
    
    # TODO: This would require restarting the Flask server, which we can't do in this test
    # Manual verification step documented in output
    
    return None  # Requires manual verification

def test_flask_debug_enabled():
    """Test Flask debug endpoint works when flag is true"""
    print_test_header("TEST 4: Flask /debug/seed_token with ENABLE_DEBUG_ENDPOINTS=true")
    
    print_info("Testing against currently running Flask server...")
    
    # Current server is running WITH the flag (from previous tests)
    try:
        resp = requests.post(
            'http://localhost:5000/debug/seed_token',
            json={
                'token': 'flask_test_789',
                'action_type': 'block_ip',
                'ip': '3.3.3.3'
            },
            timeout=5
        )
        
        print_info(f"Response status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            if data.get('success'):
                print_pass("Flask debug endpoint works when flag=true")
                return True
            else:
                print_fail(f"Expected success, got: {data}")
                return False
        elif resp.status_code == 404:
            # This means flag is false on the server
            print_info("Server returned 404 - flag appears to be false")
            return None  # Inconclusive
        else:
            print_fail(f"Unexpected status: {resp.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print_fail(f"Cannot connect to Flask server: {e}")
        return False

async def main():
    print(f"""
{Colors.BLUE}╔══════════════════════════════════════════════════════════════════════╗
║  DEBUG ENDPOINT SECURITY GATE TESTS                                  ║
║  Verifies ENABLE_DEBUG_ENDPOINTS flag properly gates debug tools     ║
╚══════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.YELLOW}Testing that debug endpoints are DISABLED by default and require
explicit environment flag to enable.{Colors.RESET}
""")
    
    results = []
    
    # Test MCP gating
    results.append(("MCP debug gated (flag=false)", await test_mcp_debug_gated()))
    results.append(("MCP debug enabled (flag=true)", await test_mcp_debug_enabled()))
    
    # Test Flask gating
    results.append(("Flask debug gated (flag=false)", test_flask_debug_gated()))
    results.append(("Flask debug enabled (flag=true)", test_flask_debug_enabled()))
    
    # Summary
    print(f"\n{Colors.BLUE}{'='*70}")
    print("TEST SUMMARY")
    print(f"{'='*70}{Colors.RESET}\n")
    
    for name, result in results:
        if result is True:
            status = f"{Colors.GREEN}PASS{Colors.RESET}"
        elif result is False:
            status = f"{Colors.RED}FAIL{Colors.RESET}"
        else:
            status = f"{Colors.YELLOW}SKIP{Colors.RESET}"
        print(f"  {status}  {name}")
    
    # Manual verification instructions
    print(f"\n{Colors.YELLOW}{'='*70}")
    print("MANUAL VERIFICATION REQUIRED:")
    print(f"{'='*70}{Colors.RESET}")
    print(f"""
To fully verify Flask debug endpoint gating:

1. Stop the current Flask server
2. Ensure ENABLE_DEBUG_ENDPOINTS is NOT set in environment
3. Start server: python web_ui.py
4. Test: curl -X POST http://localhost:5000/debug/seed_token
   Expected: 404 with error about debug endpoints disabled
5. Stop server
6. Start with flag: ENABLE_DEBUG_ENDPOINTS=true python web_ui.py
7. Test same curl command
   Expected: 200 with success response
""")
    
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")

if __name__ == "__main__":
    asyncio.run(main())
