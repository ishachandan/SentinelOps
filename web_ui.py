"""Flask Web UI for SentinelOps - Server-side confirmation enforcement"""
import asyncio
import os
import json
import uuid
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session as flask_session
from dotenv import load_dotenv
from groq import Groq
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from agent_shared import HUMAN_ONLY_TOOLS, convert_mcp_tools_to_groq_format, run_agent_turn

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24).hex())

# Feature flag for debug endpoints (MUST be explicitly enabled)
ENABLE_DEBUG_ENDPOINTS = os.getenv("ENABLE_DEBUG_ENDPOINTS", "false").lower() in ("true", "1", "yes")


def is_flask_debug_enabled():
    """Return whether Flask debug mode is explicitly enabled."""
    return os.getenv("FLASK_DEBUG", "false").lower() in ("1", "true", "yes")


def mcp_server_parameters():
    """Pass runtime feature flags to MCP without copying application secrets."""
    server_env = {
        key: os.environ[key]
        for key in ("USE_REAL_APIS", "ENABLE_DEBUG_ENDPOINTS")
        if key in os.environ
    }
    return StdioServerParameters(
        command="python", args=["server.py"], env=server_env
    )


# SINGLE SOURCE OF TRUTH: File-based storage shared with MCP
# This is the SAME file that MCP server.py reads/writes
PENDING_ACTIONS_FILE = "data/pending_actions.json"

def load_pending_actions():
    """Load pending actions from file - single source of truth"""
    try:
        with open(PENDING_ACTIONS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_pending_actions(actions):
    """Save pending actions to file - single source of truth"""
    os.makedirs(os.path.dirname(PENDING_ACTIONS_FILE), exist_ok=True)
    with open(PENDING_ACTIONS_FILE, 'w') as f:
        json.dump(actions, f, indent=2)

def get_pending_action(token):
    """Get a single pending action by token"""
    actions = load_pending_actions()
    return actions.get(token)

def update_pending_action(token, updates):
    """Update a pending action's fields"""
    actions = load_pending_actions()
    if token in actions:
        actions[token].update(updates)
        save_pending_actions(actions)
        return True
    return False


def get_session_id():
    """Get or create session ID"""
    if 'session_id' not in flask_session:
        flask_session['session_id'] = str(uuid.uuid4())
    return flask_session['session_id']


def get_conversation_history():
    """Get conversation history for current session"""
    session_id = get_session_id()
    if 'conversations' not in flask_session:
        flask_session['conversations'] = {}
    if session_id not in flask_session['conversations']:
        flask_session['conversations'][session_id] = []
    
    # Clean up any messages with tool_calls: None (Groq doesn't accept this)
    messages = flask_session['conversations'][session_id]
    cleaned_messages = []
    for msg in messages:
        msg_copy = dict(msg)  # Make a copy of each message
        if msg_copy.get('role') == 'assistant':
            # Remove tool_calls if it's None or empty
            if 'tool_calls' in msg_copy and msg_copy['tool_calls'] is None:
                del msg_copy['tool_calls']
        cleaned_messages.append(msg_copy)
    
    # Return a NEW list, not a reference to the session's list
    return cleaned_messages


def save_conversation_history(messages):
    """Save conversation history for current session"""
    session_id = get_session_id()
    if 'conversations' not in flask_session:
        flask_session['conversations'] = {}
    flask_session['conversations'][session_id] = messages
    flask_session.modified = True


@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')


@app.route('/send', methods=['POST'])
def send_message():
    """Handle user message"""
    try:
        data = request.get_json()
        user_message = data.get('message', '').strip()
        
        if not user_message:
            return jsonify({'error': 'Empty message'}), 400
        
        session_id = get_session_id()
        
        # Get conversation history
        messages = get_conversation_history()
        
        # Capture the count BEFORE adding the user message (for transcript building)
        old_message_count = len(messages)
        
        messages.append({"role": "user", "content": user_message})
        
        # Run agent with fresh MCP connection
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def process():
            error_occurred = False
            error_msg = ""
            updated_messages = messages
            final_response = ""
            
            try:
                groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))
                
                server_params = mcp_server_parameters()
                async with stdio_client(server_params) as (read, write):
                    async with ClientSession(read, write) as mcp_session:
                        await mcp_session.initialize()
                        
                        tools_resp = await mcp_session.list_tools()
                        groq_tools = convert_mcp_tools_to_groq_format(tools_resp, exclude=HUMAN_ONLY_TOOLS)
                        
                        # Run agent with NO confirmation callback (Step 1: skip execute_pending_action)
                        updated_messages, final_response = await run_agent_turn(
                            groq_client,
                            messages,
                            groq_tools,
                            mcp_session,
                            confirmation_callback=None,
                            max_turns=10
                        )
            except* Exception as eg:
                # Handle ExceptionGroup from TaskGroup cleanup (Python 3.11+)
                # Also catches single exceptions wrapped in ExceptionGroup
                import traceback
                print(f"[DEBUG] Caught ExceptionGroup with {len(eg.exceptions)} exception(s)")
                
                # Extract the actual root cause by unwrapping nested ExceptionGroups
                def extract_real_exceptions(exc_group):
                    """Recursively unwrap nested ExceptionGroups to find real exceptions"""
                    real_exceptions = []
                    for exc in exc_group.exceptions:
                        if isinstance(exc, (ExceptionGroup, BaseExceptionGroup)):
                            # Nested ExceptionGroup - unwrap it
                            real_exceptions.extend(extract_real_exceptions(exc))
                        else:
                            # Real exception found
                            real_exceptions.append(exc)
                    return real_exceptions
                
                real_excs = extract_real_exceptions(eg)
                print(f"[DEBUG] Unwrapped to {len(real_excs)} real exception(s)")
                
                # Log all real exceptions
                for i, exc in enumerate(real_excs):
                    print(f"[DEBUG] Real exception {i}: {type(exc).__name__}: {exc}")
                    traceback.print_exception(type(exc), exc, exc.__traceback__)
                
                # Use the first real exception's message for the error response
                if real_excs:
                    first_exc = real_excs[0]
                    error_msg = f"Error: {type(first_exc).__name__}: {str(first_exc)}"
                else:
                    # Fallback if we couldn't unwrap
                    error_msg = f"System error: {str(eg.exceptions[0])}"
                
                error_occurred = True
            
            # Handle error if one occurred
            if error_occurred:
                messages.append({
                    "role": "assistant",
                    "content": error_msg
                })
                return messages, error_msg
            
            return updated_messages, final_response
        
        updated_messages, final_response = loop.run_until_complete(process())
        loop.close()
        
        print(f"[DEBUG] Agent completed. Messages count: {len(updated_messages)}, Final response length: {len(final_response) if final_response else 0}")
        print(f"[DEBUG] Final response: {final_response[:200] if final_response else '(empty)'}")
        
        # Save updated history
        save_conversation_history(updated_messages)
        
        # Build transcript entries (pass the count from before user message was added)
        transcript_entries = build_transcript_entries(
            old_message_count,
            updated_messages, 
            user_message,
            session_id
        )
        
        return jsonify({
            'success': True,
            'transcript': transcript_entries
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


def build_transcript_entries(old_message_count, new_messages, user_message, session_id):
    """Build transcript entries from message history
    
    Args:
        old_message_count: Number of messages BEFORE the current turn
        new_messages: Full message list AFTER the current turn
        user_message: The user's message from this turn
        session_id: Current session ID
    """
    transcript_entries = []
    
    # Add user message
    transcript_entries.append({
        'type': 'user',
        'content': user_message,
        'timestamp': datetime.now().isoformat()
    })
    
    # Parse new messages (everything after old count)
    start_idx = old_message_count
    print(f"[DEBUG] Building transcript. Old count: {old_message_count}, New messages: {len(new_messages)}, Processing from index {start_idx}")
    
    for msg in new_messages[start_idx:]:
        print(f"[DEBUG] Processing message role={msg['role']}, has_content={bool(msg.get('content'))}, has_tool_calls={bool(msg.get('tool_calls'))}")
        
        
        if msg['role'] == 'assistant':
            if msg.get('tool_calls'):
                for tc in msg['tool_calls']:
                    tool_name = tc['function']['name']
                    tool_args = json.loads(tc['function']['arguments'])
                    
                    transcript_entries.append({
                        'type': 'tool_call',
                        'tool_name': tool_name,
                        'tool_args': tool_args,
                        'timestamp': datetime.now().isoformat()
                    })
            
            # Always add assistant content if it exists (including error messages)
            if msg.get('content') and msg['content'].strip():
                transcript_entries.append({
                    'type': 'agent',
                    'content': msg['content'],
                    'timestamp': datetime.now().isoformat()
                })
        
        elif msg['role'] == 'tool':
            content = msg['content']
            
            # Check if this is a propose_* result with a token (Step 2 detection)
            if 'Token:' in content and 'PREVIEW' in content:
                # Extract token
                import re
                match = re.search(r'[Tt]oken:\s*([a-f0-9]+)', content)
                if match:
                    token = match.group(1)
                    
                    # Update the existing pending action in the file (single source of truth)
                    # MCP already created it, we just add Flask-specific metadata
                    update_pending_action(token, {
                        'session_id': session_id,
                        'preview_text': content
                    })
                    
                    transcript_entries.append({
                        'type': 'pending_confirmation',
                        'content': content,
                        'token': token,
                        'timestamp': datetime.now().isoformat()
                    })
                else:
                    # Regular tool result
                    transcript_entries.append({
                        'type': 'tool_result',
                        'content': content,
                        'timestamp': datetime.now().isoformat()
                    })
            else:
                # Regular tool result
                transcript_entries.append({
                    'type': 'tool_result',
                    'content': content,
                    'timestamp': datetime.now().isoformat()
                })
    
    return transcript_entries


@app.route('/confirm/<token>', methods=['POST'])
def confirm_action(token):
    """
    Step 2 CRITICAL: Server-side confirmation gate.
    This is the ONLY route that can execute a pending action.
    """
    try:
        session_id = get_session_id()
        
        # CRITICAL VALIDATION: Check token exists in file (single source of truth)
        pending = get_pending_action(token)
        if not pending:
            return jsonify({
                'success': False,
                'error': 'Invalid or unknown token. Action not found.'
            }), 404
        
        # CRITICAL VALIDATION: Check token belongs to this session
        if pending.get('session_id') != session_id:
            return jsonify({
                'success': False,
                'error': 'Token does not belong to your session.'
            }), 403
        
        # CRITICAL VALIDATION: Check token not already resolved
        if pending.get('status') != 'pending':
            return jsonify({
                'success': False,
                'error': f"Action already {pending['status']}. Cannot execute again."
            }), 400
        
        # Mark as confirmed BEFORE executing (write to single source of truth)
        update_pending_action(token, {
            'status': 'confirmed',
            'confirmed_at': datetime.now().isoformat()
        })
        
        # NOW execute the action via MCP
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def execute():
            server_params = mcp_server_parameters()
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as mcp_session:
                    await mcp_session.initialize()
                    result = await mcp_session.call_tool("execute_pending_action", {"token": token})
                    return result.content[0].text
        
        result_text = loop.run_until_complete(execute())
        loop.close()
        
        # MCP's execute_pending_action updates status to 'executed' in the file
        # No need to update here - single source of truth is maintained by MCP
        
        return jsonify({
            'success': True,
            'result': result_text,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/decline/<token>', methods=['POST'])
def decline_action(token):
    """
    Step 2: Decline a pending action.
    Never calls execute_pending_action.
    """
    try:
        session_id = get_session_id()
        
        # Validate token exists (read from single source of truth)
        pending = get_pending_action(token)
        if not pending:
            return jsonify({
                'success': False,
                'error': 'Invalid or unknown token.'
            }), 404
        
        # Validate session
        if pending.get('session_id') != session_id:
            return jsonify({
                'success': False,
                'error': 'Token does not belong to your session.'
            }), 403
        
        # Validate not already resolved
        if pending.get('status') != 'pending':
            return jsonify({
                'success': False,
                'error': f"Action already {pending['status']}."
            }), 400
        
        # Mark as declined in the file (single source of truth) - NO execution
        update_pending_action(token, {
            'status': 'declined',
            'declined_at': datetime.now().isoformat()
        })
        
        return jsonify({
            'success': True,
            'message': 'Action declined. Not executed.',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/clear', methods=['POST'])
def clear_conversation():
    """Clear conversation history"""
    session_id = get_session_id()
    if 'conversations' in flask_session:
        flask_session['conversations'][session_id] = []
        flask_session.modified = True
    return jsonify({'success': True})


@app.route('/debug/seed_token', methods=['POST'])
def debug_seed_token():
    """
    DEBUG ENDPOINT: Manually seed a pending confirmation for testing.
    
    SECURITY: Only available when ENABLE_DEBUG_ENDPOINTS=true in environment.
    This bypasses the LLM/agent completely - used for security gate testing.
    
    Writes directly to the single source of truth (pending_actions.json file).
    No subprocess spawning, no MCP client - just direct file manipulation.
    
    POST body:
    {
        "token": "testABC1" (optional, auto-generated if not provided),
        "action_type": "block_ip" (required),
        "ip": "1.2.3.4" (required for block_ip),
        "path": "data/sentinelops_sandbox/test.exe" (required for quarantine_file),
        "reason": "Test reason" (optional),
        "status": "pending" (optional, defaults to pending),
        "use_session_id": "custom-session" (optional, defaults to current session)
    }
    """
    # SECURITY GATE: Check if debug endpoints are enabled
    if not ENABLE_DEBUG_ENDPOINTS:
        return jsonify({
            'error': 'Debug endpoints are disabled. Set ENABLE_DEBUG_ENDPOINTS=true to enable.'
        }), 404
    try:
        data = request.get_json()
        
        # Get or generate token
        token = data.get('token', str(uuid.uuid4())[:8])
        
        # Get action details
        action_type = data.get('action_type')
        if not action_type:
            return jsonify({'error': 'action_type is required'}), 400
        
        # Determine session_id
        if 'use_session_id' in data:
            session_id = data['use_session_id']
        else:
            session_id = get_session_id()
        
        # Build pending action record matching MCP's schema
        ip = data.get('ip', '1.2.3.4')
        path = data.get('path', os.path.join("data", "sentinelops_sandbox", "test.exe"))
        reason = data.get('reason', 'Test action')
        status = data.get('status', 'pending')
        
        # Validate action-specific fields
        if action_type == 'block_ip' and not data.get('ip'):
            ip = '1.2.3.4'  # Default test IP
        elif action_type == 'quarantine_file' and not data.get('path'):
            path = os.path.join("data", "sentinelops_sandbox", "test.exe")
        elif action_type not in ['block_ip', 'quarantine_file']:
            return jsonify({'error': f'Unknown action_type: {action_type}'}), 400
        
        # Construct the action record (matching MCP's schema)
        action_record = {
            'action_type': action_type,
            'reason': reason,
            'status': status,
            'created_at': datetime.now().isoformat(),
            'session_id': session_id,  # Flask-specific field for session validation
            'debug_seed': True
        }
        
        # Add action-specific fields
        if action_type == 'block_ip':
            action_record['ip'] = ip
            preview_text = f"PREVIEW: Would block IP {ip}. Reason: {reason}\nToken: {token}\nAwaiting human confirmation."
        elif action_type == 'quarantine_file':
            action_record['path'] = path
            preview_text = f"PREVIEW: Would quarantine file: {path}. Reason: {reason}\nToken: {token}\nAwaiting human confirmation."
        
        action_record['preview_text'] = preview_text
        
        # Write directly to the single source of truth (pending_actions.json)
        actions = load_pending_actions()
        actions[token] = action_record
        save_pending_actions(actions)
        
        return jsonify({
            'success': True,
            'token': token,
            'session_id': session_id,
            'status': status,
            'message': f'Token {token} seeded directly into pending_actions.json (single source of truth)'
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("=" * 70)
    print("SentinelOps Web UI Starting...")
    print("=" * 70)
    print("IMPORTANT: Server startup may take ~30s for ChromaDB initialization")
    print("          on first request. Subsequent requests will be faster.")
    print("=" * 70)
    print("\nOpen http://localhost:5000 in your browser\n")
    app.run(debug=is_flask_debug_enabled(), port=5000, use_reloader=False)
