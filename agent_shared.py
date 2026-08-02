"""Shared agent logic for CLI and web UI"""
import json
from typing import List, Dict, Any, Callable, Awaitable


def convert_mcp_tools_to_groq_format(tools_resp):
    """Convert MCP tool schema to OpenAI/Groq-compatible function calling format."""
    tools = []
    for t in tools_resp.tools:
        # Handle both camelCase (old) and snake_case (new) attribute names
        input_schema = getattr(t, 'input_schema', None) or getattr(t, 'inputSchema', None)
        params = input_schema.copy() if input_schema else {"type": "object", "properties": {}}
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
        tools.append(tool)
    return tools


async def run_agent_turn(
    client,
    messages: List[Dict[str, Any]],
    groq_tools: List[Dict],
    session,
    confirmation_callback: Callable[[str, Dict], Awaitable[bool]] = None,
    max_turns: int = 10
) -> tuple[List[Dict[str, Any]], str]:
    """
    Run agent processing loop until completion or max turns.
    
    Args:
        client: Groq client
        messages: Conversation history
        groq_tools: Tool schemas in Groq format
        session: MCP ClientSession
        confirmation_callback: Async function that takes (tool_name, tool_args) and returns bool
                             If None, execute_pending_action is automatically declined
        max_turns: Maximum tool-calling turns
    
    Returns:
        (updated_messages, final_response_text)
    """
    final_response = ""
    
    for turn in range(max_turns):
        try:
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=messages,
                tools=groq_tools,
                max_tokens=1024
            )
        except Exception as e:
            # Handle Groq API errors (e.g., malformed tool calls, rate limits)
            error_msg = f"Error from Groq API: {str(e)}"
            
            # Add error as assistant message so conversation can continue
            messages.append({
                "role": "assistant",
                "content": error_msg
            })
            
            final_response = error_msg
            break
        
        message = response.choices[0].message
        
        # Add assistant message to history
        assistant_msg = {
            "role": "assistant",
            "content": message.content
        }
        
        # Only add tool_calls if they exist
        if message.tool_calls:
            assistant_msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments
                    }
                } for tc in message.tool_calls
            ]
        
        messages.append(assistant_msg)
        
        # Handle tool calls
        if message.tool_calls:
            tool_results = []
            
            for tool_call in message.tool_calls:
                tool_name = tool_call.function.name
                tool_args = json.loads(tool_call.function.arguments)
                
                # CRITICAL GUARDRAIL: Human confirmation for execute_pending_action
                if tool_name == "execute_pending_action":
                    # If no callback provided, automatically decline
                    if confirmation_callback is None:
                        confirmed = False
                    else:
                        confirmed = await confirmation_callback(tool_name, tool_args)
                    
                    if confirmed:
                        result = await session.call_tool(tool_name, tool_args)
                        result_text = result.content[0].text
                        tool_results.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": result_text
                        })
                    else:
                        declined_msg = "Human user declined to execute this action."
                        tool_results.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": declined_msg
                        })
                else:
                    # Non-destructive tool - execute normally
                    result = await session.call_tool(tool_name, tool_args)
                    result_text = result.content[0].text
                    tool_results.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": result_text
                    })
            
            # Add tool results to history
            messages.extend(tool_results)
            
            # Continue to next turn
            continue
        
        # No tool calls - save response and break
        if message.content:
            final_response = message.content
        
        break
    
    return messages, final_response
