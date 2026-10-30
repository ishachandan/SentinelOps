"""SentinelOps CLI - Interactive multi-turn conversation interface"""
import asyncio
import os
import json
import re
import sys
import uuid
from dotenv import load_dotenv
from groq import Groq
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from agent_shared import HUMAN_ONLY_TOOLS, convert_mcp_tools_to_groq_format
import store

load_dotenv()


def update_pending_action_status(token: str, status: str):
    """Update an action's human resolution in the shared SQLite store."""
    action = store.get_action(token)
    if not action:
        return False
    session_id = action.get("session_id", "default")
    current_status = action.get("status")
    return store.transition(token, session_id, frm=current_status, to=status)


def mark_pending_action_confirmed(token: str):
    """Mark a pending action as confirmed in the shared SQLite store."""
    action = store.get_action(token)
    if not action:
        return False
    session_id = action.get("session_id", "default")
    return store.transition(token, session_id, frm="pending", to="confirmed")



async def run_cli(session_id: str = None):
    """Run interactive CLI with multi-turn conversation history."""
    effective_session_id = session_id or os.getenv("SENTINELOPS_SESSION_ID") or f"cli_{uuid.uuid4().hex[:12]}"
    client = Groq(api_key=os.getenv("GROQ_API_KEY"))
    if not client.api_key:
        print("Error: GROQ_API_KEY not configured in .env file")
        return
    
    print("="*70)
    print("SentinelOps - Security Copilot CLI")
    print(f"Session ID: {effective_session_id}")
    print("="*70)
    print("Type 'exit' or 'quit' to end the session")
    print("Type 'clear' to reset conversation history")
    print("="*70)
    
    server_env = dict(os.environ)
    server_env["SENTINELOPS_SESSION_ID"] = effective_session_id
    server_params = StdioServerParameters(command=sys.executable, args=["server.py"], env=server_env)
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # Get available tools from MCP server
            tools_resp = await session.list_tools()
            groq_tools = convert_mcp_tools_to_groq_format(tools_resp, exclude=HUMAN_ONLY_TOOLS)
            
            # Initialize conversation history
            messages = []
            
            while True:
                # Get user input
                try:
                    user_input = input("\nYou: ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\n\nExiting...")
                    break
                
                if not user_input:
                    continue
                
                # Handle commands
                if user_input.lower() in ('exit', 'quit'):
                    print("Goodbye!")
                    break
                
                if user_input.lower() == 'clear':
                    messages = []
                    print("Conversation history cleared.")
                    continue
                
                # Add user message to history
                messages.append({"role": "user", "content": user_input})
                
                try:
                    # Process with agent - up to 10 turns for tool chaining
                    for turn in range(10):
                        response = client.chat.completions.create(
                            model=os.getenv("GROQ_MODEL", "qwen/qwen3.8-27b"),
                            messages=messages,
                            tools=groq_tools,
                            max_tokens=1024
                        )
                        
                        message = response.choices[0].message
                        
                        # Add assistant message to history
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
                        
                        # Handle tool calls
                        if message.tool_calls:
                            print(f"\n[Agent calling tools...]")
                            tool_results = []
                            
                            for tool_call in message.tool_calls:
                                tool_name = tool_call.function.name
                                tool_args = json.loads(tool_call.function.arguments)

                                exposed_tool_names = {
                                    tool["function"]["name"] for tool in groq_tools
                                }
                                if tool_name not in exposed_tool_names:
                                    tool_results.append({
                                        "role": "tool",
                                        "tool_call_id": tool_call.id,
                                        "content": "Tool not available"
                                    })
                                    continue
                                
                                print(f"  - {tool_name}({', '.join(f'{k}={v}' for k, v in tool_args.items())})")
                                
                                # CRITICAL GUARDRAIL: Human confirmation for execute_pending_action
                                if tool_name == "execute_pending_action":
                                    token = tool_args.get("token", "unknown")

                                    print("\n" + "WARNING: "*35)
                                    print("DESTRUCTIVE ACTION REQUIRES CONFIRMATION")
                                    print("WARNING: "*35)
                                    print(f"Token: {token}")
                                    print("-"*70)

                                    confirmation = input("Type 'yes' to execute, anything else to decline: ").strip()

                                    if confirmation.lower() == "yes":
                                        print("APPROVED: Executing...")
                                        if mark_pending_action_confirmed(token):
                                            result = await session.call_tool(tool_name, tool_args)
                                            result_text = result.content[0].text
                                            print(f"Result: {result_text}\n")
                                            tool_results.append({
                                                "role": "tool",
                                                "tool_call_id": tool_call.id,
                                                "content": result_text
                                            })
                                        else:
                                            result_text = "Error: Token not found or already resolved."
                                            print(f"Result: {result_text}\n")
                                            tool_results.append({
                                                "role": "tool",
                                                "tool_call_id": tool_call.id,
                                                "content": result_text
                                            })
                                    else:
                                        print("DECLINED: Action NOT executed.\n")
                                        update_pending_action_status(token, "declined")
                                        declined_msg = "Human user declined to execute this action."
                                        tool_results.append({
                                            "role": "tool",
                                            "tool_call_id": tool_call.id,
                                            "content": declined_msg
                                        })
                                else:
                                    result = await session.call_tool(tool_name, tool_args)
                                    result_text = result.content[0].text

                                    if tool_name.startswith("propose_") and "PREVIEW" in result_text:
                                        token_match = re.search(
                                            r"[Tt]oken:\s*([a-f0-9]+)", result_text
                                        )
                                        if token_match:
                                            token = token_match.group(1)
                                            print(f"Preview: {result_text}")
                                            confirmation = input(
                                                "Type 'y' to execute, anything else to decline: "
                                            ).strip().lower()
                                            if confirmation in ("y", "yes"):
                                                if mark_pending_action_confirmed(token):
                                                    execution = await session.call_tool(
                                                        "execute_pending_action",
                                                        {"token": token},
                                                    )
                                                    result_text = execution.content[0].text
                                                    print(f"Result: {result_text}\n")
                                                else:
                                                    result_text = (
                                                        "Error: Token not found or already resolved."
                                                    )
                                            else:
                                                if update_pending_action_status(token, "declined"):
                                                    result_text = (
                                                        "Human user declined to execute this action."
                                                    )
                                                    print("DECLINED: Action NOT executed.\n")
                                                else:
                                                    result_text = (
                                                        "Error: Token not found or already resolved."
                                                    )
                                                    print(f"Result: {result_text}\n")

                                    tool_results.append({
                                        "role": "tool",
                                        "tool_call_id": tool_call.id,
                                        "content": result_text
                                    })
                            
                            # Add tool results to history
                            messages.extend(tool_results)
                            
                            # Continue to next turn for model to process results
                            continue
                        
                        # No tool calls - print response and break
                        if message.content:
                            print(f"\nAgent: {message.content}")
                        
                        break
                    
                except Exception as e:
                    if hasattr(e, 'status_code') and e.status_code == 429:
                        print("\nWARNING: Rate limit exceeded. Please wait a moment.")
                    else:
                        print(f"\nERROR: {e}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SentinelOps CLI")
    parser.add_argument("--session", dest="session_id", default=None, help="Custom session ID (defaults to a fresh session per run)")
    args = parser.parse_args()
    print("\nStarting SentinelOps CLI...")
    print("(Server startup may take ~30s for ChromaDB initialization)\n")
    asyncio.run(run_cli(session_id=args.session_id))
