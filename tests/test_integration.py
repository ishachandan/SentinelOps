"""Integration tests - full MCP stack with subprocess. Run rarely with: pytest tests/ -m integration"""
import pytest
import json
import os
from unittest.mock import patch
from dotenv import load_dotenv
from groq import Groq
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from tests.test_utils import mock_abuseipdb_malicious

load_dotenv()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_mcp_protocol_round_trip():
    """Test MCP protocol works end-to-end: subprocess, stdio transport, tool call"""
    server_params = StdioServerParameters(command="python", args=["server.py"])
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # Test tool discovery
            tools_resp = await session.list_tools()
            tool_names = [t.name for t in tools_resp.tools]
            assert "ping" in tool_names
            assert "check_ip_reputation" in tool_names
            assert "create_incident" in tool_names
            
            # Test basic round-trip
            result = await session.call_tool("ping", {})
            assert result.content[0].text == "pong"


@pytest.mark.integration
@pytest.mark.asyncio
@patch("server.requests.get")
async def test_full_agent_chain_with_llm(mock_get):
    """Test full agent loop: LLM + MCP + tool discovery + multi-turn execution"""
    mock_get.return_value = mock_abuseipdb_malicious()
    
    client = Groq(api_key=os.getenv("GROQ_API_KEY"))
    if not client.api_key:
        pytest.skip("GROQ_API_KEY not configured")
    
    server_params = StdioServerParameters(command="python", args=["server.py"])
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # Get tool schemas for LLM
            tools_resp = await session.list_tools()
            groq_tools = []
            for t in tools_resp.tools:
                params = t.inputSchema.copy() if t.inputSchema else {"type": "object", "properties": {}}
                if "additionalProperties" not in params:
                    params["additionalProperties"] = False
                tool = {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": params
                    }
                }
                groq_tools.append(tool)
            
            # Run agent loop
            prompt = "Check if 185.220.101.1 is malicious. If it is, create a high severity incident and send me a Telegram alert about it."
            messages = [{"role": "user", "content": prompt}]
            
            incident_created = False
            telegram_sent = False
            
            for turn in range(10):
                response = client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=messages,
                    tools=groq_tools,
                    max_tokens=1024
                )
                
                message = response.choices[0].message
                messages.append({
                    "role": "assistant",
                    "content": message.content,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments
                            }
                        } for tc in message.tool_calls
                    ] if message.tool_calls else None
                })
                
                if message.tool_calls:
                    tool_results = []
                    for tool_call in message.tool_calls:
                        tool_name = tool_call.function.name
                        tool_args = json.loads(tool_call.function.arguments)
                        
                        result = await session.call_tool(tool_name, tool_args)
                        result_text = result.content[0].text
                        
                        if tool_name == "create_incident" and "successfully" in result_text.lower():
                            incident_created = True
                        if tool_name == "notify_telegram" and "successfully" in result_text.lower():
                            telegram_sent = True
                        
                        tool_results.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": result_text
                        })
                    
                    messages.extend(tool_results)
                    continue
                
                break
            
            # Verify chain completed successfully
            assert incident_created, "Should have created incident for malicious IP"
            assert telegram_sent, "Should have sent Telegram notification for malicious IP"
