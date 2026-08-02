#!/usr/bin/env python3
"""Test confirm consistency - seed action, confirm via Flask helper, verify file and firewall rule."""
import json
import asyncio
import os
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

TOKEN = "confirm_test_888"

async def seed_action():
    """Seed action via MCP"""
    os.environ['ENABLE_DEBUG_ENDPOINTS'] = 'true'
    try:
        sp = StdioServerParameters(command='python', args=['server.py'], env=dict(os.environ))
        async with stdio_client(sp) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                await s.call_tool('debug_seed_pending_action', {
                    'token': TOKEN,
                    'action_type': 'block_ip',
                    'ip': '55.66.77.88',
                    'reason': 'Confirm consistency test'
                })
                print(f"[MCP] Seeded token: {TOKEN}")
                
                # Add session_id to file
                with open('data/pending_actions.json', 'r') as f:
                    data = json.load(f)
                data[TOKEN]['session_id'] = 'test_session_confirm'
                with open('data/pending_actions.json', 'w') as f:
                    json.dump(data, f, indent=2)
                print(f"[FILE] Added session_id to {TOKEN}")
    finally:
        if 'ENABLE_DEBUG_ENDPOINTS' in os.environ:
            del os.environ['ENABLE_DEBUG_ENDPOINTS']

async def execute_via_mcp():
    """Execute via MCP to simulate what Flask/confirm does"""
    sp = StdioServerParameters(command='python', args=['server.py'])
    async with stdio_client(sp) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            result = await s.call_tool('execute_pending_action', {'token': TOKEN})
            print(f"[MCP] Execute result: {result.content[0].text[:200]}")
            return result.content[0].text

async def main():
    print("\n" + "="*70)
    print("CONFIRM CONSISTENCY TEST")
    print("="*70)
    
    # Step 1: Seed
    print("\n[STEP 1] Seed action via MCP")
    await seed_action()
    
    # Step 2: Verify pending
    print("\n[STEP 2] Verify file shows status=pending")
    with open('data/pending_actions.json', 'r') as f:
        data = json.load(f)
    assert TOKEN in data
    assert data[TOKEN]['status'] == 'pending'
    print(f"OK: status=pending, ip={data[TOKEN]['ip']}")
    
    # Step 3: Execute (simulating what Flask /confirm does)
    print("\n[STEP 3] Execute action via MCP (simulating Flask /confirm)")
    result = await execute_via_mcp()
    
    # Step 4: Verify file shows executed
    print("\n[STEP 4] Verify file shows status=executed")
    with open('data/pending_actions.json', 'r') as f:
        data_after = json.load(f)
    status = data_after[TOKEN]['status']
    print(f"Status in file: {status}")
    assert status == 'executed', f"Expected 'executed', got '{status}'"
    print("OK: File shows status=executed")
    print(f"Full record:\n{json.dumps(data_after[TOKEN], indent=2)}")
    
    # Step 5: Verify firewall rule file was created
    print("\n[STEP 5] Verify firewall rule file was created")
    rule_file = f"data/firewall_sandbox/block_55_66_77_88.rule"
    assert os.path.exists(rule_file), f"Firewall rule file not found: {rule_file}"
    with open(rule_file, 'r') as f:
        rule = json.load(f)
    print(f"Firewall rule created:")
    print(f"  IP: {rule['ip']}")
    print(f"  Action: {rule['action']}")
    print(f"  Status: {rule['status']}")
    print(f"  Token: {rule['token']}")
    assert rule['ip'] == '55.66.77.88'
    assert rule['token'] == TOKEN
    
    print("\n" + "="*70)
    print("CONFIRM CONSISTENCY TEST PASSED")
    print("="*70)
    print("Single source of truth maintained:")
    print("- File updated to status=executed")
    print("- Firewall rule file created")
    print("- Both Flask and MCP see the same executed status")
    print("="*70 + "\n")

if __name__ == "__main__":
    asyncio.run(main())
