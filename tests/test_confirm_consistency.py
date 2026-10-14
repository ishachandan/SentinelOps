#!/usr/bin/env python3
"""Manually verify confirmation state and execution audit persistence across MCP sessions."""
import json
import asyncio
import os
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

TOKEN = "confirm_test_888"

async def seed_action():
    """Seed action via MCP"""
    os.environ['ENABLE_DEBUG_ENDPOINTS'] = 'true'
    try:
        sp = StdioServerParameters(command=sys.executable, args=['server.py'], env=dict(os.environ))
        async with stdio_client(sp) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                result = await s.call_tool('debug_seed_pending_action', {
                    'token': TOKEN,
                    'action_type': 'block_ip',
                    'ip': '55.66.77.88',
                    'reason': 'Confirm consistency test'
                })
                assert 'DEBUG: Seeded pending action' in result.content[0].text
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
    sp = StdioServerParameters(command=sys.executable, args=['server.py'])
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

    # Flask /confirm performs this transition after the human approves.
    data[TOKEN]['status'] = 'confirmed'
    with open('data/pending_actions.json', 'w') as f:
        json.dump(data, f, indent=2)
    print("[FILE] Human confirmation set status=confirmed")
    
    # Step 3: Execute (simulating what Flask /confirm does)
    print("\n[STEP 3] Execute action via MCP (simulating Flask /confirm)")
    result = await execute_via_mcp()
    assert "SUCCESS" in result, f"Expected confirmed action to execute, got: {result}"
    
    # Step 4: Verify file shows executed
    print("\n[STEP 4] Verify file shows status=executed")
    with open('data/pending_actions.json', 'r') as f:
        data_after = json.load(f)
    status = data_after[TOKEN]['status']
    print(f"Status in file: {status}")
    assert status == 'executed', f"Expected 'executed', got '{status}'"
    print("OK: File shows status=executed")
    print(f"Full record:\n{json.dumps(data_after[TOKEN], indent=2)}")
    
    # Step 5: Verify an execution audit entry was written (stub and real modes).
    print("\n[STEP 5] Verify execution was recorded in the audit log")
    with open('data/action_log.jsonl', 'r', encoding='utf-8') as audit_file:
        audit_entries = [json.loads(line) for line in audit_file if line.strip()]
    assert any(
        entry.get('action') == 'block_ip'
        and entry.get('status') == 'executed'
        and entry.get('ip') == '55.66.77.88'
        for entry in audit_entries
    ), "No execution audit entry found"
    
    print("\n" + "="*70)
    print("CONFIRM CONSISTENCY TEST PASSED")
    print("="*70)
    print("Single source of truth maintained:")
    print("- File updated to status=executed")
    print("- Execution recorded in data/action_log.jsonl")
    print("- Both Flask and MCP see the same executed status")
    print("="*70 + "\n")

if __name__ == "__main__":
    asyncio.run(main())
