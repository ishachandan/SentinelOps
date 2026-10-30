"""Flask Web UI for SentinelOps - Server-side confirmation enforcement"""
import asyncio
import os
import sys
import json
import uuid
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session as flask_session, has_request_context
import store
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


def mcp_server_parameters(session_id=None):
    """Pass runtime feature flags and session context to MCP."""
    server_env = {
        key: os.environ[key]
        for key in ("USE_REAL_APIS", "ENABLE_DEBUG_ENDPOINTS", "SENTINELOPS_DB_PATH")
        if key in os.environ
    }
    if session_id:
        server_env["SENTINELOPS_SESSION_ID"] = session_id
    elif has_request_context() and 'session_id' in flask_session:
        server_env["SENTINELOPS_SESSION_ID"] = flask_session['session_id']
    return StdioServerParameters(
        command=sys.executable, args=["server.py"], env=server_env
    )


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
                # Extract token and params hash
                import re
                match = re.search(r'[Tt]oken:\s*([a-f0-9]+)', content)
                hash_match = re.search(r'Params Hash:\s*([a-f0-9]+)', content)
                params_hash_short = hash_match.group(1) if hash_match else ""

                if match:
                    token = match.group(1)
                    
                    transcript_entries.append({
                        'type': 'pending_confirmation',
                        'content': content,
                        'token': token,
                        'params_hash': params_hash_short,
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
        
        # CRITICAL VALIDATION: Check token exists in store
        pending = store.get_action(token)
        if not pending or pending.get('session_id') != session_id:
            return jsonify({
                'success': False,
                'error': 'Invalid or unknown token. Action not found.'
            }), 404

        # Parameter binding verification: check hash if provided by client/UI
        data = request.get_json(silent=True) or {}
        provided_hash = (
            request.args.get('hash')
            or request.args.get('params_hash')
            or data.get('params_hash')
            or data.get('hash')
        )
        if provided_hash:
            stored_hash = pending.get('params_hash', '')
            match = (
                stored_hash == provided_hash
                or stored_hash.startswith(provided_hash)
                or (len(provided_hash) >= 8 and stored_hash[:8] == provided_hash[:8])
            )
            if not match:
                import audit_chain
                audit_chain.append_audit_entry({
                    "action": "confirm_action",
                    "status": "refused",
                    "reason": "refusal:params_hash_mismatch",
                    "token": token,
                    "details": {"provided_hash": provided_hash, "stored_hash": stored_hash}
                })
                return jsonify({
                    'success': False,
                    'error': 'Parameter binding verification failed: params_hash mismatch.'
                }), 400

        # CRITICAL VALIDATION: Check token not already resolved
        if pending.get('status') not in ('pending', 'partially_approved'):
            return jsonify({
                'success': False,
                'error': f"Action already {pending['status']}. Cannot execute again."
            }), 409

        # Severity tier check: critical actions require two distinct confirmations
        # TODO (Step 8): Replace X-Operator-ID header with authenticated sessions / JWT tokens
        severity = str(pending.get('severity', 'medium')).lower()
        if severity == 'critical':
            approver_id = request.headers.get("X-Operator-ID") or data.get("operator_id") or session_id
            success, msg, updated = store.record_approval(token, session_id, approver_id)
            if not success:
                return jsonify({'success': False, 'error': msg}), 409
            if updated and updated['status'] == 'partially_approved':
                return jsonify({
                    'success': True,
                    'status': 'partially_approved',
                    'message': 'First approval recorded. Critical action requires confirmation from a second distinct operator.'
                }), 202

        else:
            # Mark as confirmed BEFORE executing via transition()
            if not store.transition(token, session_id, frm='pending', to='confirmed'):
                return jsonify({
                    'success': False,
                    'error': 'Action could not be confirmed (may be expired or already resolved).'
                }), 409
        
        # NOW execute the action via MCP
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def execute():
            server_params = mcp_server_parameters(session_id=session_id)
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as mcp_session:
                    await mcp_session.initialize()
                    result = await mcp_session.call_tool("execute_pending_action", {"token": token})
                    return result.content[0].text
        
        result_text = loop.run_until_complete(execute())
        loop.close()
        
        final = store.get_action(token)
        status_code = 200 if final and final.get('status') == 'executed' else 500
        return jsonify({
            'success': status_code == 200,
            'result': result_text,
            'status': final.get('status') if final else 'unknown',
            'timestamp': datetime.now().isoformat()
        }), status_code
        
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
        
        # Validate token exists in store
        pending = store.get_action(token)
        if not pending or pending.get('session_id') != session_id:
            return jsonify({
                'success': False,
                'error': 'Invalid or unknown token.'
            }), 404
        
        # Validate not already resolved
        if pending.get('status') != 'pending':
            return jsonify({
                'success': False,
                'error': f"Action already {pending['status']}."
            }), 409
        
        # Mark as declined via transition() - NO execution
        if not store.transition(token, session_id, frm='pending', to='declined'):
            return jsonify({
                'success': False,
                'error': 'Action could not be declined.'
            }), 409
        
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
    """
    if not ENABLE_DEBUG_ENDPOINTS:
        return jsonify({
            'error': 'Debug endpoints are disabled. Set ENABLE_DEBUG_ENDPOINTS=true to enable.'
        }), 404
    try:
        data = request.get_json()
        
        token = data.get('token', str(uuid.uuid4())[:8])
        action_type = data.get('action_type')
        if not action_type:
            return jsonify({'error': 'action_type is required'}), 400
        
        if 'use_session_id' in data:
            session_id = data['use_session_id']
        else:
            session_id = get_session_id()
        
        ip = data.get('ip', '1.2.3.4')
        path = data.get('path', os.path.join("data", "sentinelops_sandbox", "test.exe"))
        reason = data.get('reason', 'Test action')
        status = data.get('status', 'pending')
        
        if action_type == 'block_ip':
            params = {'ip': ip, 'reason': reason}
        elif action_type == 'quarantine_file':
            params = {'path': path, 'reason': reason}
        else:
            return jsonify({'error': f'Unknown action_type: {action_type}'}), 400
        
        store.create_action(token, session_id, action_type, params, status='pending')
        if status != 'pending':
            if status in ('confirmed', 'declined', 'expired'):
                store.transition(token, session_id, 'pending', status)
            elif status in ('executing', 'executed', 'failed'):
                store.transition(token, session_id, 'pending', 'confirmed')
                store.transition(token, session_id, 'confirmed', 'executing')
                if status in ('executed', 'failed'):
                    store.transition(token, session_id, 'executing', status)
        
        return jsonify({
            'success': True,
            'token': token,
            'session_id': session_id,
            'status': status,
            'message': f'Token {token} seeded directly into shared store'
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
