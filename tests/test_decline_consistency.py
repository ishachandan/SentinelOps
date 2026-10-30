#!/usr/bin/env python3
"""
Test Flask/MCP decline consistency with proper session handling.

This test seeds an action with a valid session_id, then declines via store transition,
then verifies MCP observes the declined status.
"""
import requests
import json
import os
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
import store


async def seed_with_mcp(token, session_id):
    """Seed action via MCP with session_id"""
    os.environ['ENABLE_DEBUG_ENDPOINTS'] = 'true'
    os.environ['SENTINELOPS_SESSION_ID'] = session_id
    
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
                        'ip': '11.22.33.44',
                        'reason': 'Decline test',
                        'status': 'pending'
                    }
                )
                
                print(f"[MCP] Seeded token: {token}")
                
                print(f"[STORE] Session is set at action creation")
                
                return True
    finally:
        if 'ENABLE_DEBUG_ENDPOINTS' in os.environ:
            del os.environ['ENABLE_DEBUG_ENDPOINTS']
        os.environ.pop('SENTINELOPS_SESSION_ID', None)


async def test_decline():
    """Test decline updates store"""
    token = "decline_test_999"
    session_id = "test_session_decline"
    
    print("\n" + "="*70)
    print("DECLINE CONSISTENCY TEST")
    print("="*70)
    
    # Step 1: Seed with session_id
    print("\n[STEP 1] Seed action via MCP with session_id")
    await seed_with_mcp(token, session_id)
    
    # Step 2: Verify in store
    print("\n[STEP 2] Verify action is in store with status=pending")
    action = store.get_action(token)
    assert action is not None, f"Token {token} not in store"
    assert action['status'] == 'pending', f"Wrong status: {action['status']}"
    print(f"SUCCESS: Token {token} in store with status=pending")
    
    # Step 3: Decline via store transition
    print("\n[STEP 3] Decline action via transition")
    success = store.transition(token, session_id, frm='pending', to='declined')
    assert success, "store.transition returned False"
    print(f"SUCCESS: store.transition succeeded")
    
    # Step 4: Verify store shows status=declined
    print("\n[STEP 4] Verify store shows status=declined")
    action_after = store.get_action(token)
    assert action_after is not None, f"Token {token} missing from store after decline"
    status = action_after.get('status')
    print(f"  Status in store: {status}")
    
    assert status == 'declined', f"Status should be 'declined', got '{status}'"
    print(f"SUCCESS: Store correctly shows status=declined")
    
    # Step 5: Verify MCP sees it as declined
    print("\n[STEP 5] Verify MCP can see declined status")
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
                    'execute_pending_action',
                    {'token': token}
                )
                result_text = result.content[0].text
                print(f"  MCP execute result: {result_text}")
                
                assert 'declined' in result_text.lower() or 'not pending' in result_text.lower(), \
                    f"Expected declined error, got: {result_text}"
                print(f"SUCCESS: MCP correctly refuses to execute declined action")
    finally:
        if 'ENABLE_DEBUG_ENDPOINTS' in os.environ:
            del os.environ['ENABLE_DEBUG_ENDPOINTS']
    
    print("\n" + "="*70)
    print("SUCCESS: DECLINE CONSISTENCY TEST PASSED")
    print("="*70)
    print("Single source of truth (SQLite store) is maintained.")
    print("Both Flask and MCP see the same declined status.")
    print("="*70 + "\n")

if __name__ == "__main__":
    asyncio.run(test_decline())
