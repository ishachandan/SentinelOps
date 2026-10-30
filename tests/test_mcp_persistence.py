#!/usr/bin/env python3
"""Test that MCP actions persist across independent connections."""
import asyncio
import json
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def connection_1_seed():
    """Connection 1: Seed a token"""
    print("[CONN 1] Creating MCP connection and seeding token...")
    env = dict(os.environ)
    env["ENABLE_DEBUG_ENDPOINTS"] = "true"
    env["USE_REAL_APIS"] = "false"
    server_path = str(Path(__file__).resolve().parents[1] / "server.py")
    server_params = StdioServerParameters(command=sys.executable, args=[server_path], env=env, cwd=str(Path(__file__).resolve().parents[1]))
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            result = await session.call_tool(
                'debug_seed_pending_action',
                {
                    'token': 'persist_test_XYZ',
                    'action_type': 'block_ip',
                    'ip': '2.2.2.2',
                    'reason': 'Persistence test'
                }
            )
            print(f"[CONN 1] {result.content[0].text}")
            assert "DEBUG: Seeded pending action" in result.content[0].text
    print("[CONN 1] Connection closed\n")

import store

def confirm_seeded_action():
    """Simulate Flask's confirmation update between MCP subprocesses."""
    action = store.get_action("persist_test_XYZ")
    session_id = action.get("session_id", "default") if action else "default"
    assert store.transition("persist_test_XYZ", session_id, frm="pending", to="confirmed")
    print("[STORE] Marked persist_test_XYZ as confirmed")

async def connection_2_execute():
    """Connection 2: Try to execute the token from connection 1"""
    print("[CONN 2] Creating NEW MCP connection and trying to execute token...")
    env = dict(os.environ)
    env["USE_REAL_APIS"] = "false"
    server_path = str(Path(__file__).resolve().parents[1] / "server.py")
    server_params = StdioServerParameters(command=sys.executable, args=[server_path], env=env, cwd=str(Path(__file__).resolve().parents[1]))
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            result = await session.call_tool(
                'execute_pending_action',
                {'token': 'persist_test_XYZ'}
            )
            result_text = result.content[0].text
            print(f"[CONN 2] {result_text}")
            assert "SUCCESS" in result_text
    print("[CONN 2] Connection closed\n")

async def main():
    print("="*70)
    print("Testing MCP actions persistence across connections")
    print("="*70 + "\n")
    
    # Connection 1: seed
    await connection_1_seed()
    
    # Confirm between subprocesses, as the Flask /confirm route does.
    confirm_seeded_action()

    # Connection 2: execute
    await connection_2_execute()

    action = store.get_action("persist_test_XYZ")
    assert action is not None
    assert action["status"] == "executed"
    print("[SUCCESS] Confirmed action persisted across MCP subprocesses and executed.")

asyncio.run(main())
