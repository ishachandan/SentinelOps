#!/usr/bin/env python3
"""Test that MCP PENDING_ACTIONS persist across connections"""
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def connection_1_seed():
    """Connection 1: Seed a token"""
    print("[CONN 1] Creating MCP connection and seeding token...")
    server_params = StdioServerParameters(command='python', args=['server.py'])
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
    print("[CONN 1] Connection closed\n")

async def connection_2_execute():
    """Connection 2: Try to execute the token from connection 1"""
    print("[CONN 2] Creating NEW MCP connection and trying to execute token...")
    server_params = StdioServerParameters(command='python', args=['server.py'])
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            result = await session.call_tool(
                'execute_pending_action',
                {'token': 'persist_test_XYZ'}
            )
            print(f"[CONN 2] {result.content[0].text}")
    print("[CONN 2] Connection closed\n")

async def main():
    print("="*70)
    print("Testing MCP PENDING_ACTIONS persistence across connections")
    print("="*70 + "\n")
    
    # Connection 1: seed
    await connection_1_seed()
    
    # Brief pause
    await asyncio.sleep(0.5)
    
    # Connection 2: execute
    await connection_2_execute()
    
    # Check if firewall rule was created
    import os
    firewall_dir = "data/firewall_sandbox"
    if os.path.exists(firewall_dir):
        rules = [f for f in os.listdir(firewall_dir) if 'block_2_2_2_2' in f]
        if rules:
            print(f"[SUCCESS] SUCCESS: Firewall rule created: {rules}")
        else:
            print(f"[FAIL] FAILED: No firewall rule found for 2.2.2.2")
    else:
        print(f"[FAIL] FAILED: Firewall directory doesn't exist")

asyncio.run(main())
