#!/usr/bin/env python3
"""Manual check that Flask decline state is observed by a fresh MCP process."""
import asyncio
import json
import os
from pathlib import Path
import sys

import requests
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

BASE_URL = "http://localhost:5000"
TOKEN = "c0515701"


async def verify_mcp_refuses_declined_action():
    server_path = Path(__file__).resolve().parents[1] / "server.py"
    env = dict(os.environ)
    env["USE_REAL_APIS"] = "false"
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(server_path)],
        env=env,
        cwd=str(server_path.parent),
    )
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool(
                "execute_pending_action", {"token": TOKEN}
            )
            text = result.content[0].text
            assert "declined" in text.lower(), text
            print("PASS: fresh MCP process refused the declined action")


def main():
    session = requests.Session()
    session.get(BASE_URL, timeout=5)
    seed = session.post(
        f"{BASE_URL}/debug/seed_token",
        json={
            "token": TOKEN,
            "action_type": "block_ip",
            "ip": "10.20.30.40",
            "reason": "Flask/MCP state consistency check",
        },
        timeout=5,
    )
    assert seed.status_code == 200, seed.text
    assert seed.json()["status"] == "pending"
    print("PASS: Flask debug route seeded a pending action for this session")

    decline = session.post(f"{BASE_URL}/decline/{TOKEN}", timeout=5)
    assert decline.status_code == 200, decline.text
    assert decline.json()["success"] is True
    with open("data/pending_actions.json", encoding="utf-8") as actions_file:
        actions = json.load(actions_file)
    assert actions[TOKEN]["status"] == "declined"
    print("PASS: Flask decline persisted declined status")

    asyncio.run(verify_mcp_refuses_declined_action())
    print("PASS: Flask/MCP persisted-state consistency check passed")


if __name__ == "__main__":
    main()
