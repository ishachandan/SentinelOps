"""Manual, offline end-to-end verification through the real MCP stdio server."""
import asyncio
import json
import os
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent_shared import HUMAN_ONLY_TOOLS, convert_mcp_tools_to_groq_format


async def main():
    project_root = Path(__file__).resolve().parents[1]
    with TemporaryDirectory(prefix="sentinelops-e2e-") as temp_dir:
        work_dir = Path(temp_dir)
        db_path = work_dir / "data" / "sentinelops.db"
        env = dict(os.environ)
        env["USE_REAL_APIS"] = "false"
        env["ENABLE_DEBUG_ENDPOINTS"] = "false"
        env["SENTINELOPS_DB_PATH"] = str(db_path)
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(project_root / "server.py")],
            env=env,
            cwd=str(work_dir),
        )

        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                tools_response = await session.list_tools()
                exposed_tools = convert_mcp_tools_to_groq_format(
                    tools_response, exclude=HUMAN_ONLY_TOOLS
                )
                exposed_names = {
                    tool["function"]["name"] for tool in exposed_tools
                }
                assert HUMAN_ONLY_TOOLS.isdisjoint(exposed_names)
                assert "expire_blocks" not in exposed_names
                assert "execute_pending_action" not in exposed_names
                assert "check_ip_reputation" in exposed_names
                print("PASS: model tool schemas exclude all human-only tools (including expire_blocks)")

                reputation = json.loads(
                    (await session.call_tool(
                        "check_ip_reputation", {"ip": "45.33.22.11"}
                    )).content[0].text
                )
                evidence_token = reputation["result_token"]
                assert reputation["is_malicious"] is True
                print("PASS: stub reputation returned malicious evidence and a token")

                mismatch = (await session.call_tool(
                    "create_incident",
                    {
                        "summary": "Mismatched evidence test",
                        "severity": "high",
                        "related_ip": "8.8.8.8",
                        "evidence_token": evidence_token,
                    },
                )).content[0].text
                assert "REJECTED" in mismatch
                print("PASS: high-severity incident with mismatched IP was rejected")

                missing_token = (await session.call_tool(
                    "create_incident",
                    {
                        "summary": "Missing evidence test",
                        "severity": "high",
                        "related_ip": "45.33.22.11",
                    },
                )).content[0].text
                assert "REJECTED" in missing_token
                print("PASS: high-severity incident without evidence was rejected")

                created = (await session.call_tool(
                    "create_incident",
                    {
                        "summary": "Matching evidence test",
                        "severity": "high",
                        "related_ip": "45.33.22.11",
                        "evidence_token": evidence_token,
                    },
                )).content[0].text
                assert "created successfully" in created.lower()
                print("PASS: matching malicious evidence created the incident")

                proposal = (await session.call_tool(
                    "propose_block_ip",
                    {"ip": "45.33.22.11", "reason": "stdio end-to-end check"},
                )).content[0].text
                match = re.search(r"Token:\s*([a-f0-9]+)", proposal)
                assert "PREVIEW" in proposal and match
                action_token = match.group(1)
                print("PASS: block proposal returned a confirmation token")

                pending_result = (await session.call_tool(
                    "execute_pending_action", {"token": action_token}
                )).content[0].text
                assert "pending and not confirmed" in pending_result.lower()
                print("PASS: execution before confirmation was refused")

                import store
                store.DB_PATH = db_path
                action_record = store.get_action(action_token)
                assert action_record is not None
                transition_ok = store.transition(
                    action_token, action_record["session_id"], "pending", "confirmed"
                )
                assert transition_ok
                print("PASS: action marked confirmed in the shared SQLite store")

                executed = (await session.call_tool(
                    "execute_pending_action", {"token": action_token}
                )).content[0].text
                assert "SUCCESS" in executed
                print("PASS: confirmed action executed successfully")

                reused = (await session.call_tool(
                    "execute_pending_action", {"token": action_token}
                )).content[0].text
                assert "already executed" in reused.lower()
                print("PASS: second execution was refused as already executed")

                audit = json.loads(
                    (await session.call_tool("get_action_log", {})).content[0].text
                )
                assert any(
                    entry.get("action") == "block_ip"
                    and entry.get("status") == "executed"
                    and entry.get("ip") == "45.33.22.11"
                    for entry in audit
                )
                rejection_actions = {
                    entry.get("action")
                    for entry in audit
                    if entry.get("status") == "rejected"
                }
                assert "create_incident" in rejection_actions
                assert "execute_pending_action" in rejection_actions
                print("PASS: audit log contains the executed action and rejections")

        print("PASS: all end-to-end stdio checks completed; temporary state removed")


if __name__ == "__main__":
    asyncio.run(main())
