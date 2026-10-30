from mcp.server.fastmcp import FastMCP
from typing import Optional, List, Dict, Any, Tuple
import json
import datetime
import ipaddress
import os
import re
import uuid
import time
import store
from dotenv import load_dotenv
import requests

load_dotenv()
def get_session_id():
    return os.environ.get("SENTINELOPS_SESSION_ID", "default")

SESSION_ID = get_session_id()

# Feature flag for real API integrations
USE_REAL_APIS = os.getenv("USE_REAL_APIS", "false").lower() in ("true", "1", "yes")

# Feature flag for debug endpoints (MUST be explicitly enabled)
ENABLE_DEBUG_ENDPOINTS = os.getenv("ENABLE_DEBUG_ENDPOINTS", "false").lower() in ("true", "1", "yes")

mcp = FastMCP("SentinelOps")

# Phase 1: Dummy tool
@mcp.tool()
def ping() -> str:
    """Health check tool. Returns 'pong' if the server is alive."""
    return "pong"

# Phase 2: First real retrieval tool with fake data
FAKE_LOGS = [
    {"ip": "45.33.22.11", "event": "failed login", "count": 12},
    {"ip": "192.168.1.5", "event": "port scan", "count": 3},
]

# Real ChromaDB setup for semantic search
CHROMA_PERSIST_DIR = "data/chromadb_sentinelops"
CHROMA_COLLECTION = "security_logs"

# Global variables for ChromaDB (initialized at module load if USE_REAL_APIS=true)
_chroma_store = None
_embedding_generator = None

# Initialize immediately if real APIs are enabled (not lazily)
if USE_REAL_APIS:
    try:
        import sys
        sys.stderr.write("[STARTUP] USE_REAL_APIS=true, initializing ChromaDB...\n")
        sys.stderr.flush()
        
        import chromadb
        from chromadb.config import Settings
        from chromadb.utils import embedding_functions
        
        sys.stderr.write("[STARTUP] Loading ChromaDB ONNX embedding model...\n")
        sys.stderr.flush()
        _embedding_generator = embedding_functions.DefaultEmbeddingFunction()
        sys.stderr.write("[STARTUP] ChromaDB DefaultEmbeddingFunction loaded\n")
        sys.stderr.flush()
        
        sys.stderr.write("[STARTUP] Initializing ChromaDB client...\n")
        sys.stderr.flush()
        client = chromadb.PersistentClient(
            path=CHROMA_PERSIST_DIR,
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=False
            )
        )
        
        _chroma_store = client.get_or_create_collection(
            name=CHROMA_COLLECTION,
            metadata={"description": "Security log embeddings for SentinelOps"}
        )
        
        count = _chroma_store.count()
        sys.stderr.write(f"[STARTUP] ChromaDB initialized: {count} logs indexed\n")
        sys.stderr.flush()
        
    except ImportError as e:
        import sys
        sys.stderr.write(f"[STARTUP] WARNING: ChromaDB not available: {e}\n")
        sys.stderr.write("[STARTUP]    search_logs will fall back to stub mode\n")
        sys.stderr.flush()
        _chroma_store = None
        _embedding_generator = None
    except Exception as e:
        import sys
        sys.stderr.write(f"[STARTUP] WARNING: Error initializing ChromaDB: {e}\n")
        sys.stderr.flush()
        import traceback
        traceback.print_exc()
        _chroma_store = None
        _embedding_generator = None

def init_chromadb_store():
    """Check if ChromaDB store is initialized (no longer does lazy init)"""
    if _chroma_store is None or _embedding_generator is None:
        return False
    return True

def search_logs_real(query: str) -> str:
    """Search logs using real ChromaDB semantic search."""
    import sys
    
    # Check if ChromaDB is initialized
    if not init_chromadb_store():
        return json.dumps({"error": "ChromaDB not available. Install: pip install chromadb sentence-transformers"})
    
    try:
        import signal
        
        # Timeout handler
        def timeout_handler(signum, frame):
            raise TimeoutError("Query timed out after 30 seconds")
        
        # Set 30-second timeout for the entire operation
        # Note: signal.alarm only works on Unix; on Windows this is a no-op safety measure
        try:
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(30)
        except AttributeError:
            # Windows doesn't support SIGALRM, skip timeout mechanism
            pass
        
        # Search ChromaDB
        if hasattr(_embedding_generator, "encode"):
            query_embedding = _embedding_generator.encode(query, convert_to_numpy=True).tolist()
            results = _chroma_store.query(
                query_embeddings=[query_embedding],
                n_results=5
            )
        else:
            results = _chroma_store.query(
                query_texts=[query],
                n_results=5
            )
        
        # Cancel timeout
        try:
            signal.alarm(0)
        except AttributeError:
            pass
        
        # Format results
        if not results['documents'] or not results['documents'][0]:
            return json.dumps([])
        
        formatted_results = []
        for i in range(len(results['documents'][0])):
            result = {
                "text": results['documents'][0][i],
                "metadata": results['metadatas'][0][i] if results['metadatas'] else {},
                "distance": results['distances'][0][i] if results['distances'] else 0.0
            }
            formatted_results.append(result)
        
        return json.dumps(formatted_results)
        
    except TimeoutError as e:
        sys.stderr.write(f"[ERROR] search_logs_real timeout: {e}\n")
        sys.stderr.flush()
        return json.dumps({"error": "Search timed out after 30 seconds. Check ChromaDB performance."})
    except Exception as e:
        sys.stderr.write(f"[ERROR] search_logs_real exception: {e}\n")
        sys.stderr.flush()
        import traceback
        traceback.print_exc(file=sys.stderr)
        return json.dumps({"error": f"Search failed: {str(e)}"})

POISONED_LOGS_FILE = os.path.join("data", "poisoned_logs_fixture.json")


def load_poisoned_logs():
    """Load poisoned logs fixture if available."""
    if os.path.exists(POISONED_LOGS_FILE):
        try:
            with open(POISONED_LOGS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def wrap_untrusted_data(content: str, source: str = "logs", max_field_len: int = 1000) -> str:
    """Wrap untrusted external data in safe delimiters, neutralizing control sequences and truncating."""
    if content is None:
        return f'<untrusted_data source="{source}"></untrusted_data>'

    text = str(content)
    # Strip ANSI escape sequences: \x1b\[[0-9;]*[a-zA-Z]
    text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
    # Neutralize control characters
    text = text.replace('\x00', '').replace('\r', '')

    # Neutralize any attempts to close the untrusted_data tag prematurely
    text = text.replace('</untrusted_data>', '&lt;/untrusted_data&gt;')

    # Truncate overly long fields or lines
    lines = text.split('\n')
    sanitized_lines = []
    for line in lines:
        if len(line) > max_field_len:
            line = line[:max_field_len] + "... [field truncated]"
        sanitized_lines.append(line)
    text = '\n'.join(sanitized_lines)

    if len(text) > 4000:
        text = text[:4000] + "\n... [content truncated]"

    return f'<untrusted_data source="{source}">\n{text}\n</untrusted_data>'


def search_logs_stub(query: str) -> str:
    """Search logs using stubbed data (substring match)."""
    dataset = list(FAKE_LOGS)
    if os.getenv("USE_POISONED_LOGS", "false").lower() in ("true", "1", "yes") or "poison" in query.lower():
        dataset.extend(load_poisoned_logs())
    results = [l for l in dataset if query in json.dumps(l)]
    return json.dumps(results) if results else "No matches found."


@mcp.tool()
def search_logs(query: str) -> str:
    """Search recent security logs for a keyword (ip or event type)."""
    if USE_REAL_APIS:
        raw_result = search_logs_real(query)
    else:
        raw_result = search_logs_stub(query)

    # Record observed IPs ONLY from structured source/client IP fields of log records.
    # NEVER record IPs from query text, or free-text log fields (message, user_agent, raw_log, url, username, text).
    session_id = get_session_id()
    try:
        import policy
        parsed = json.loads(raw_result)
        if isinstance(parsed, list):
            structured_ip_keys = ("ip", "source_ip", "client_ip", "src_ip")
            for entry in parsed:
                if isinstance(entry, dict):
                    event_val = (
                        entry.get("event") or entry.get("event_type") or
                        entry.get("type") or entry.get("action")
                    )
                    meta = entry.get("metadata")
                    if not event_val and isinstance(meta, dict):
                        event_val = (
                            meta.get("event") or meta.get("event_type") or
                            meta.get("type") or meta.get("action")
                        )

                    if policy.is_suspicious_event(event_val):
                        slug = str(event_val).strip().lower().replace(" ", "_").replace("-", "_")
                        source_label = f"search_logs_match:{slug}"
                    else:
                        source_label = "search_logs_benign"

                    # Check structured fields directly on the log record
                    for key in structured_ip_keys:
                        val = entry.get(key)
                        if val and isinstance(val, str):
                            try:
                                norm_ip = normalize_ip(val)
                                store.record_observed_ip(session_id, norm_ip, source=source_label)
                            except Exception:
                                pass
                            break
                    # If ChromaDB or external source wrapped record with a structured metadata dict
                    if isinstance(meta, dict):
                        for key in structured_ip_keys:
                            val = meta.get(key)
                            if val and isinstance(val, str):
                                try:
                                    norm_ip = normalize_ip(val)
                                    store.record_observed_ip(session_id, norm_ip, source=source_label)
                                except Exception:
                                    pass
                                break
    except Exception:
        pass

    return wrap_untrusted_data(raw_result, source="logs")

# Phase 3: First action tool (dry-run only)
import audit_chain
ACTION_LOG_FILE = os.path.join("data", "action_log.jsonl")
ACTION_LOG = []

def load_action_log():
    """Read the JSONL audit log, skipping malformed entries."""
    return audit_chain.read_audit_log(ACTION_LOG_FILE)


def log_action(entry):
    """Append a sanitized, timestamped, chained action to the JSONL audit log."""
    record = audit_chain.append_audit_entry(entry, log_path=ACTION_LOG_FILE)
    ACTION_LOG.append(record)
    return record


def _log_rejection(action, reason, target=None):
    entry = {"action": action, "status": "rejected", "reason": reason}
    if target:
        entry["target"] = target
    log_action(entry)


ACTION_LOG = load_action_log()

def normalize_ip(value):
    """Parse an IPv4/IPv6 value and return its canonical string."""
    return store.normalize_ip(value)


def validate_ip(value):
    """Validate IP syntax only and return the normalized address."""
    return normalize_ip(value)


def validate_block_ip(value):
    """Validate an IP for a block proposal, rejecting non-target addresses."""
    normalized = validate_ip(value)
    address = ipaddress.ip_address(normalized)
    if address.is_loopback:
        raise ValueError(f"Loopback IP addresses cannot be blocked: {normalized}")
    if address.is_unspecified:
        raise ValueError(f"Unspecified IP addresses cannot be blocked: {normalized}")
    if address.is_multicast:
        raise ValueError(f"Multicast IP addresses cannot be blocked: {normalized}")
    return normalized


def safe_ip_rule_filename(ip):
    """Return a Windows-safe firewall rule filename for an IP."""
    normalized = normalize_ip(ip)
    safe_name = normalized.replace(':', '_').replace('.', '_')
    return f"block_{safe_name}.rule"


def is_execution_error(result):
    """Return True when the operation failed."""
    if not isinstance(result, str):
        return False
    lowered = result.lower()
    return 'error:' in lowered or 'error ' in lowered or 'failed' in lowered


def generate_action_token():
    """Generate a unique token for pending actions."""
    import uuid
    return str(uuid.uuid4())[:8]

@mcp.tool()
def propose_block_ip(ip: str, reason: str) -> str:
    """Propose blocking an IP address. This ONLY creates a preview - it does NOT execute the block.
    Returns a unique action token that must be confirmed by a human before execution.
    Use this when you want to block an IP but need human approval first."""
    try:
        validated_ip = validate_block_ip(ip)
    except ValueError as exc:
        _log_rejection("propose_block_ip", "invalid_block_ip")
        return f"Error: {exc}"

    # Step 1: Policy check - IP must have been observed in this session with justified evidence
    import policy
    allowed, reason_code = policy.evaluate_block_ip_policy(get_session_id(), validated_ip)
    if not allowed:
        _log_rejection("propose_block_ip", reason_code, target=validated_ip)
        return f"Error: Block proposal rejected by security policy ({reason_code}). Target: {validated_ip}."

    store.expire_stale()
    severity, required_approvals = policy.derive_block_severity(get_session_id(), validated_ip)
    token = generate_action_token()
    action_rec = store.create_action(
        token=token,
        session_id=get_session_id(),
        action_type="block_ip",
        params={"ip": validated_ip, "reason": reason},
        severity=severity,
        required_approvals=required_approvals
    )
    hash_short = action_rec.get("params_hash", "")[:8]

    return f"PREVIEW: Would block IP {validated_ip}. Reason: {reason}\nToken: {token}\nParams Hash: {hash_short}\nAwaiting human confirmation."

@mcp.tool()
def propose_quarantine_file(path: str, reason: str) -> str:
    """Propose quarantining a suspicious file. This ONLY creates a preview - it does NOT execute the quarantine.
    Returns a unique action token that must be confirmed by a human before execution.
    Use this when you want to quarantine a file but need human approval first.
    Only propose this for files that are confirmed or highly suspected to be malicious."""
    resolved_path = _resolve_in_sandbox(path)
    if resolved_path is None:
        _log_rejection("propose_quarantine_file", "outside_quarantine_sandbox")
        return "Error: File is outside the quarantine sandbox."
    if not os.path.exists(resolved_path):
        return "Error: File not found in quarantine sandbox."

    store.expire_stale()
    token = generate_action_token()
    action_rec = store.create_action(
        token=token,
        session_id=get_session_id(),
        action_type="quarantine_file",
        params={"path": resolved_path, "reason": reason}
    )
    hash_short = action_rec.get("params_hash", "")[:8]

    return f"PREVIEW: Would quarantine file: {resolved_path}. Reason: {reason}\nToken: {token}\nParams Hash: {hash_short}\nAwaiting human confirmation."

def is_ip_currently_blocked(ip: str) -> bool:
    """Check if an IP currently has an active block rule in the system."""
    try:
        canonical_ip = normalize_ip(ip)
    except ValueError:
        return False
    # 1. Check firewall sandbox filesystem rule
    rule_file = os.path.join(FIREWALL_SANDBOX_DIR, safe_ip_rule_filename(canonical_ip))
    if os.path.exists(rule_file):
        return True
    # 2. Check store for executed block_ip action that has not been unblocked
    try:
        with store.tx() as c:
            cur = c.execute(
                "SELECT params_json, resolved_at FROM actions WHERE action_type='block_ip' AND status='executed' ORDER BY resolved_at DESC"
            )
            rows = cur.fetchall()
            for r in rows:
                try:
                    p = json.loads(r["params_json"])
                    if normalize_ip(p.get("ip", "")) == canonical_ip:
                        block_time = r["resolved_at"] or 0
                        cur_unblock = c.execute(
                            "SELECT params_json, resolved_at FROM actions WHERE action_type='unblock_ip' AND status='executed' ORDER BY resolved_at DESC LIMIT 1"
                        )
                        u_row = cur_unblock.fetchone()
                        if u_row:
                            u_p = json.loads(u_row["params_json"])
                            if normalize_ip(u_p.get("ip", "")) == canonical_ip and (u_row["resolved_at"] or 0) >= block_time:
                                return False
                        return True
                except Exception:
                    pass
    except Exception:
        pass
    return False


def is_file_currently_quarantined(resolved_path: str) -> bool:
    """Check if a file target currently exists in the quarantine store."""
    norm_target = os.path.normcase(os.path.realpath(resolved_path))
    filename = os.path.basename(resolved_path)
    # 1. Check filesystem quarantine directory for metadata or candidate file
    if os.path.exists(QUARANTINE_DIR):
        for fname in os.listdir(QUARANTINE_DIR):
            if fname.endswith(".metadata"):
                meta_p = os.path.join(QUARANTINE_DIR, fname)
                try:
                    with open(meta_p, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    if os.path.normcase(os.path.realpath(meta.get("original_path", ""))) == norm_target:
                        q_path = meta.get("quarantined_path")
                        if q_path and os.path.exists(q_path):
                            return True
                except Exception:
                    pass
            elif fname.endswith(f"_{filename}") or fname == filename:
                cand = os.path.join(QUARANTINE_DIR, fname)
                if os.path.exists(cand):
                    return True
    # 2. Check store for executed quarantine action that has not been restored
    try:
        with store.tx() as c:
            cur = c.execute(
                "SELECT params_json, resolved_at FROM actions WHERE action_type='quarantine_file' AND status='executed' ORDER BY resolved_at DESC"
            )
            for r in cur.fetchall():
                try:
                    p = json.loads(r["params_json"])
                    if os.path.normcase(os.path.realpath(p.get("path", ""))) == norm_target:
                        q_time = r["resolved_at"] or 0
                        cur_restore = c.execute(
                            "SELECT params_json, resolved_at FROM actions WHERE action_type IN ('restore_quarantined_file', 'restore_file') AND status='executed' ORDER BY resolved_at DESC LIMIT 1"
                        )
                        rst_row = cur_restore.fetchone()
                        if rst_row:
                            rst_p = json.loads(rst_row["params_json"])
                            if os.path.normcase(os.path.realpath(rst_p.get("path", ""))) == norm_target and (rst_row["resolved_at"] or 0) >= q_time:
                                return False
                        return True
                except Exception:
                    pass
    except Exception:
        pass
    return False


@mcp.tool()
def propose_unblock_ip(ip: str, reason: str) -> str:
    """Propose unblocking a previously blocked IP address. This ONLY creates a preview - it does NOT execute the unblock.
    Returns a unique action token that must be confirmed by a human before execution."""
    try:
        validated_ip = validate_ip(ip)
    except ValueError as exc:
        _log_rejection("propose_unblock_ip", "invalid_ip")
        return f"Error: {exc}"

    if not is_ip_currently_blocked(validated_ip):
        _log_rejection("propose_unblock_ip", "policy_denied:not_blocked", target=validated_ip)
        return f"Error: Cannot propose unblock for IP {validated_ip}. No active block rule found."

    store.expire_stale()
    token = generate_action_token()
    action_rec = store.create_action(
        token=token,
        session_id=get_session_id(),
        action_type="unblock_ip",
        params={"ip": validated_ip, "reason": reason},
        severity="medium",
        required_approvals=1
    )
    hash_short = action_rec.get("params_hash", "")[:8]
    return f"PREVIEW: Would unblock IP {validated_ip}. Reason: {reason}\nToken: {token}\nParams Hash: {hash_short}\nAwaiting human confirmation."

@mcp.tool()
def propose_restore_quarantined_file(path: str, reason: str) -> str:
    """Propose restoring a previously quarantined file. This ONLY creates a preview - it does NOT execute the restore.
    Returns a unique action token that must be confirmed by a human before execution."""
    resolved_path = _resolve_in_sandbox(path)
    if resolved_path is None:
        _log_rejection("propose_restore_quarantined_file", "outside_quarantine_sandbox")
        return "Error: File is outside the quarantine sandbox."

    if not is_file_currently_quarantined(resolved_path):
        _log_rejection("propose_restore_quarantined_file", "policy_denied:not_quarantined", target=resolved_path)
        return f"Error: Cannot propose restore for {resolved_path}. No matching quarantined file found."

    store.expire_stale()
    token = generate_action_token()
    action_rec = store.create_action(
        token=token,
        session_id=get_session_id(),
        action_type="restore_quarantined_file",
        params={"path": resolved_path, "reason": reason},
        severity="medium",
        required_approvals=1
    )
    hash_short = action_rec.get("params_hash", "")[:8]
    return f"PREVIEW: Would restore file: {resolved_path}. Reason: {reason}\nToken: {token}\nParams Hash: {hash_short}\nAwaiting human confirmation."

@mcp.tool()
def expire_blocks() -> str:
    """Check and revert expired IP blocks whose TTL has elapsed."""
    expired = expire_active_blocks()
    store.expire_stale()
    if expired:
        return f"SUCCESS: Expired {len(expired)} block rules: {', '.join(expired)}"
    return "No active block rules have expired."

@mcp.tool()
def execute_pending_action(token: str) -> str:
    """Execute a previously proposed action using its token.
    This is a DESTRUCTIVE operation - only call this after explicit human approval.
    The action can only be executed once per token."""
    action = store.get_action(token)

    if not action:
        _log_rejection("execute_pending_action", "unknown_token")
        return f"Error: Token '{token}' not found. It may be invalid or already executed. Tokens are only valid within the same MCP server process/session."

    status = action.get("status")

    if status == "pending":
        _log_rejection("execute_pending_action", "not_confirmed")
        return f"Error: Action with token '{token}' is pending and not confirmed by a human."
    if status == "declined":
        _log_rejection("execute_pending_action", "declined")
        return f"Error: Action with token '{token}' was declined by a human."
    if status == "executed":
        _log_rejection("execute_pending_action", "already_executed")
        return f"Error: Action with token '{token}' was already executed."
    if status == "failed":
        _log_rejection("execute_pending_action", "already_failed")
        return f"Error: Action with token '{token}' failed execution."
    if status == "expired":
        _log_rejection("execute_pending_action", "expired")
        return f"Error: Action with token '{token}' has expired."
    if status != "confirmed":
        _log_rejection("execute_pending_action", "invalid_status")
        return f"Error: Action with token '{token}' is in an invalid state for execution: {status}."

    # Parameter binding re-verification from DB row immediately before executing
    stored_hash = action.get("params_hash")
    if stored_hash:
        target = action.get("ip") or action.get("path") or action.get("target") or ""
        reason = action.get("reason", "")
        expires_at = action.get("expires_at", 0.0)
        action_type = action.get("action_type", "")
        severity = action.get("severity", "medium")
        required_approvals = action.get("required_approvals", 1)
        computed_hash = store.compute_action_params_hash(
            action_type, target, reason, expires_at, severity, required_approvals
        )
        if computed_hash != stored_hash:
            store.transition(token, action.get("session_id", "default"), frm="confirmed", to="failed")
            _log_rejection("execute_pending_action", "refusal:params_hash_mismatch", target=target)
            return "Error: Parameter binding verification failed. Target or parameters were mutated after proposal."

    session_id = action.get("session_id", "default")

    # In MCP, claim the work atomically (confirmed -> executing) before the side effect
    if not store.transition(token, session_id, frm="confirmed", to="executing"):
        _log_rejection("execute_pending_action", "claim_failed")
        return f"Error: Failed to claim action with token '{token}' for execution (may have expired or changed status)."

    action_type = action.get("action_type")
    if action_type == "block_ip":
        target_ip = action.get("ip") or action.get("target") or ""
        import policy
        is_prot, prot_msg = policy.is_ip_protected(target_ip)
        if is_prot:
            store.transition(token, session_id, frm="executing", to="failed")
            _log_rejection("execute_pending_action", "refusal:protected_target", target=target_ip)
            return f"Error: Target IP {target_ip} is protected by policy allowlist and cannot be blocked."

        try:
            if USE_REAL_APIS:
                result = execute_block_ip_real(action, token)
            else:
                result = execute_block_ip_stub(action, token)
        except Exception as exc:
            store.transition(token, session_id, frm="executing", to="failed")
            _log_rejection("execute_pending_action", "execution_failed")
            return f"Error executing block_ip: {exc}"

        if is_execution_error(result):
            store.transition(token, session_id, frm="executing", to="failed")
            _log_rejection("execute_pending_action", "execution_failed")
            return result

        store.transition(token, session_id, frm="executing", to="executed")
        return result

    elif action_type == "quarantine_file":
        resolved_path = _resolve_in_sandbox(action.get("path", ""))
        if resolved_path is None:
            store.transition(token, session_id, frm="executing", to="failed")
            _log_rejection("execute_pending_action", "outside_quarantine_sandbox")
            return "Error: File is outside the quarantine sandbox."
        quarantine_target = os.path.join(QUARANTINE_DIR, f"{token}_{os.path.basename(resolved_path)}")
        already_quarantined = USE_REAL_APIS and os.path.exists(quarantine_target)
        if not os.path.exists(resolved_path) and not already_quarantined:
            store.transition(token, session_id, frm="executing", to="failed")
            return "Error: File not found in quarantine sandbox."

        action["path"] = resolved_path
        try:
            if USE_REAL_APIS:
                result = execute_quarantine_file_real(action, token)
            else:
                result = execute_quarantine_file_stub(action, token)
        except Exception as exc:
            store.transition(token, session_id, frm="executing", to="failed")
            _log_rejection("execute_pending_action", "execution_failed")
            return f"Error executing quarantine_file: {exc}"

        if is_execution_error(result):
            store.transition(token, session_id, frm="executing", to="failed")
            _log_rejection("execute_pending_action", "execution_failed")
            return result

        store.transition(token, session_id, frm="executing", to="executed")
        return result

    elif action_type == "unblock_ip":
        try:
            if USE_REAL_APIS:
                result = execute_unblock_ip_real(action, token)
            else:
                result = execute_unblock_ip_stub(action, token)
        except Exception as exc:
            store.transition(token, session_id, frm="executing", to="failed")
            _log_rejection("execute_pending_action", "execution_failed")
            return f"Error executing unblock_ip: {exc}"

        if is_execution_error(result):
            store.transition(token, session_id, frm="executing", to="failed")
            _log_rejection("execute_pending_action", "execution_failed")
            return result

        store.transition(token, session_id, frm="executing", to="executed")
        return result

    elif action_type in ("restore_quarantined_file", "restore_file"):
        resolved_path = _resolve_in_sandbox(action.get("path", ""))
        if resolved_path is None:
            store.transition(token, session_id, frm="executing", to="failed")
            _log_rejection("execute_pending_action", "outside_quarantine_sandbox")
            return "Error: Restore target is outside the quarantine sandbox."

        action["path"] = resolved_path
        try:
            if USE_REAL_APIS:
                result = execute_restore_quarantined_file_real(action, token)
            else:
                result = execute_restore_quarantined_file_stub(action, token)
        except Exception as exc:
            store.transition(token, session_id, frm="executing", to="failed")
            _log_rejection("execute_pending_action", "execution_failed")
            return f"Error executing restore_quarantined_file: {exc}"

        if is_execution_error(result):
            store.transition(token, session_id, frm="executing", to="failed")
            _log_rejection("execute_pending_action", "execution_failed")
            return result

        store.transition(token, session_id, frm="executing", to="executed")
        return result

    else:
        store.transition(token, session_id, frm="executing", to="failed")
        return f"Error: Unknown action type '{action_type}'"

# Sandbox directory for real firewall rule simulation
FIREWALL_SANDBOX_DIR = "data/firewall_sandbox"

def execute_block_ip_real(action: dict, token: str) -> str:
    """Execute real IP block in sandboxed environment idempotently."""
    import os

    try:
        os.makedirs(FIREWALL_SANDBOX_DIR, exist_ok=True)

        ip = action["ip"]
        reason = action["reason"]
        timestamp = str(datetime.datetime.now())
        rule_file = os.path.join(FIREWALL_SANDBOX_DIR, safe_ip_rule_filename(ip))

        rule_content = {
            "ip": ip,
            "reason": reason,
            "action": "DROP",
            "chain": "INPUT",
            "created_at": timestamp,
            "token": token,
            "status": "active"
        }

        try:
            with open(rule_file, 'x', encoding='utf-8') as f:
                json.dump(rule_content, f, indent=2)
        except FileExistsError:
            entry = {
                "action": "block_ip",
                "ip": ip,
                "reason": reason,
                "time": timestamp,
                "sandbox_file": rule_file,
                "status": "executed",
                "token": token
            }
            log_action(entry)
            return f"SUCCESS [SANDBOX]: IP {ip} is already blocked. Rule file: {rule_file}"

        entry = {
            "action": "block_ip",
            "ip": ip,
            "reason": reason,
            "time": timestamp,
            "sandbox_file": rule_file,
            "status": "executed",
            "token": token
        }
        log_action(entry)

        return f"SUCCESS [SANDBOX]: Blocked IP {ip}. Rule file created: {rule_file}\nReason: {reason}"

    except Exception as e:
        return f"Error executing block_ip: {str(e)}"

def execute_block_ip_stub(action: dict, token: str) -> str:
    """Execute stub IP block (dry-run mode)."""
    entry = {
        "action": "block_ip",
        "ip": action["ip"],
        "reason": action["reason"],
        "time": str(datetime.datetime.now()),
        "dry_run": True,
        "status": "executed",
        "token": token
    }
    log_action(entry)
    return f"SUCCESS [DRY RUN]: Blocked IP {action['ip']}. Reason: {action['reason']}"

# Quarantine sandbox directory
QUARANTINE_SANDBOX_DIR = "data/sentinelops_sandbox"
QUARANTINE_DIR = os.path.join(QUARANTINE_SANDBOX_DIR, "quarantine")


def _resolve_in_sandbox(path):
    """Return a real path inside the quarantine sandbox, excluding its root and quarantine."""
    real_sandbox = os.path.realpath(QUARANTINE_SANDBOX_DIR)
    real_path = os.path.realpath(path)
    real_quarantine = os.path.realpath(QUARANTINE_DIR)
    try:
        common_path = os.path.commonpath([real_sandbox, real_path])
        if os.path.normcase(common_path) != os.path.normcase(real_sandbox):
            return None
        if os.path.normcase(real_path) == os.path.normcase(real_sandbox):
            return None
        quarantine_common = os.path.commonpath([real_quarantine, real_path])
        if os.path.normcase(quarantine_common) == os.path.normcase(real_quarantine):
            return None
    except ValueError:
        return None
    return real_path


def execute_quarantine_file_real(action: dict, token: str) -> str:
    """Execute real file quarantine in sandboxed environment."""
    import os
    import shutil

    try:
        os.makedirs(QUARANTINE_SANDBOX_DIR, exist_ok=True)
        os.makedirs(QUARANTINE_DIR, exist_ok=True)

        path = _resolve_in_sandbox(action["path"])
        if path is None:
            _log_rejection("execute_quarantine_file", "outside_quarantine_sandbox")
            return "Error: File is outside the quarantine sandbox."
        reason = action["reason"]
        timestamp = str(datetime.datetime.now())

        filename = os.path.basename(path)
        quarantine_path = os.path.join(QUARANTINE_DIR, f"{token}_{filename}")
        if not os.path.exists(path):
            if os.path.exists(quarantine_path):
                return f"SUCCESS [SANDBOX]: File is already quarantined at {quarantine_path}"
            return "Error: File not found in quarantine sandbox."

        shutil.move(path, quarantine_path)

        metadata_file = quarantine_path + ".metadata"
        metadata = {
            "original_path": path,
            "quarantined_path": quarantine_path,
            "reason": reason,
            "timestamp": timestamp,
            "token": token,
            "status": "quarantined"
        }

        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)

        entry = {
            "action": "quarantine_file",
            "path": path,
            "quarantine_path": quarantine_path,
            "reason": reason,
            "time": timestamp,
            "status": "executed",
            "token": token
        }
        log_action(entry)

        return f"SUCCESS [SANDBOX]: Quarantined file: {path}\nMoved to: {quarantine_path}\nReason: {reason}"

    except Exception as e:
        import traceback
        import sys
        traceback.print_exc(file=sys.stderr)
        return f"Error executing quarantine_file: {str(e)}"

def execute_quarantine_file_stub(action: dict, token: str) -> str:
    """Execute stub file quarantine (dry-run mode)."""
    entry = {
        "action": "quarantine_file",
        "path": action["path"],
        "reason": action["reason"],
        "time": str(datetime.datetime.now()),
        "dry_run": True,
        "status": "executed",
        "token": token
    }
    log_action(entry)
    return f"SUCCESS [DRY RUN]: Quarantined file: {action['path']}. Reason: {action['reason']}"

def execute_unblock_ip_real(action: dict, token: str) -> str:
    """Execute real IP unblock by removing or deactivating firewall rule."""
    import os
    ip = action["ip"]
    reason = action.get("reason", "")
    rule_file = os.path.join(FIREWALL_SANDBOX_DIR, safe_ip_rule_filename(ip))
    if os.path.exists(rule_file):
        try:
            os.remove(rule_file)
        except Exception as exc:
            return f"Error removing firewall rule: {exc}"
    entry = {
        "action": "unblock_ip",
        "ip": ip,
        "reason": reason,
        "time": str(datetime.datetime.now()),
        "status": "executed",
        "token": token
    }
    log_action(entry)
    return f"SUCCESS [SANDBOX]: Unblocked IP {ip}. Firewall rule removed. Reason: {reason}"


def execute_unblock_ip_stub(action: dict, token: str) -> str:
    """Execute stub unblock (dry-run mode)."""
    entry = {
        "action": "unblock_ip",
        "ip": action["ip"],
        "reason": action.get("reason", ""),
        "time": str(datetime.datetime.now()),
        "dry_run": True,
        "status": "executed",
        "token": token
    }
    log_action(entry)
    return f"SUCCESS [DRY RUN]: Unblocked IP {action['ip']}. Reason: {action.get('reason', '')}"


def execute_restore_quarantined_file_real(action: dict, token: str) -> str:
    """Execute real file restore from quarantine sandbox."""
    import shutil
    raw_path = action.get("path", "")
    path = _resolve_in_sandbox(raw_path)
    if path is None:
        _log_rejection("execute_restore_quarantined_file", "outside_quarantine_sandbox", target=raw_path)
        return "Error: Restore target is outside quarantine sandbox."

    filename = os.path.basename(path)
    quarantine_candidate = None
    metadata_candidate = None

    if os.path.exists(QUARANTINE_DIR):
        for fname in os.listdir(QUARANTINE_DIR):
            if fname.endswith(".metadata"):
                meta_p = os.path.join(QUARANTINE_DIR, fname)
                try:
                    with open(meta_p, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    meta_orig = meta.get("original_path", "")
                    # Re-validate metadata destination against sandbox root
                    if meta_orig:
                        valid_meta_dest = _resolve_in_sandbox(meta_orig)
                        if valid_meta_dest is None:
                            _log_rejection("execute_restore_quarantined_file", "tampered_metadata_outside_sandbox", target=meta_orig)
                            return f"Error: Quarantined metadata file '{fname}' points outside quarantine sandbox ({meta_orig}). Refusing restore."
                    if os.path.normcase(os.path.realpath(meta_orig)) == os.path.normcase(os.path.realpath(path)):
                        metadata_candidate = meta_p
                        quarantine_candidate = meta.get("quarantined_path")
                        break
                except Exception:
                    pass
        if not quarantine_candidate:
            for fname in os.listdir(QUARANTINE_DIR):
                if not fname.endswith(".metadata") and (fname.endswith(f"_{filename}") or fname == filename):
                    quarantine_candidate = os.path.join(QUARANTINE_DIR, fname)
                    meta_p = quarantine_candidate + ".metadata"
                    if os.path.exists(meta_p):
                        metadata_candidate = meta_p
                    break

    if not quarantine_candidate or not os.path.exists(quarantine_candidate):
        return f"Error: Quarantined file for {path} not found in quarantine store."

    # Validate that quarantine_candidate is strictly inside QUARANTINE_DIR
    real_quarantine_dir = os.path.realpath(QUARANTINE_DIR)
    real_candidate = os.path.realpath(quarantine_candidate)
    try:
        if os.path.commonpath([real_quarantine_dir, real_candidate]) != real_quarantine_dir:
            _log_rejection("execute_restore_quarantined_file", "tampered_quarantine_path", target=quarantine_candidate)
            return "Error: Quarantined candidate file is outside quarantine directory."
    except ValueError:
        _log_rejection("execute_restore_quarantined_file", "tampered_quarantine_path", target=quarantine_candidate)
        return "Error: Quarantined candidate file is outside quarantine directory."

    os.makedirs(os.path.dirname(path), exist_ok=True)
    shutil.move(quarantine_candidate, path)
    if metadata_candidate and os.path.exists(metadata_candidate):
        try:
            os.remove(metadata_candidate)
        except Exception:
            pass

    entry = {
        "action": "restore_quarantined_file",
        "path": path,
        "restored_from": quarantine_candidate,
        "reason": action.get("reason", ""),
        "time": str(datetime.datetime.now()),
        "status": "executed",
        "token": token
    }
    log_action(entry)
    return f"SUCCESS [SANDBOX]: Restored file to {path} from {quarantine_candidate}"


def execute_restore_quarantined_file_stub(action: dict, token: str) -> str:
    """Execute stub file restore (dry-run mode)."""
    entry = {
        "action": "restore_quarantined_file",
        "path": action["path"],
        "reason": action.get("reason", ""),
        "time": str(datetime.datetime.now()),
        "dry_run": True,
        "status": "executed",
        "token": token
    }
    log_action(entry)
    return f"SUCCESS [DRY RUN]: Restored file: {action['path']}. Reason: {action.get('reason', '')}"


def expire_active_blocks(ttl: Optional[float] = None) -> List[str]:
    """Scan and expire active block rules whose TTL has elapsed, recording to the audit log."""
    expired_ips = []
    now = time.time()
    if ttl is None:
        try:
            ttl = float(os.getenv("SENTINELOPS_BLOCK_TTL", 3600))
        except ValueError:
            ttl = 3600.0

    if os.path.exists(FIREWALL_SANDBOX_DIR):
        for fname in os.listdir(FIREWALL_SANDBOX_DIR):
            if fname.startswith("block_") and fname.endswith(".rule"):
                rule_path = os.path.join(FIREWALL_SANDBOX_DIR, fname)
                try:
                    with open(rule_path, "r", encoding="utf-8") as f:
                        rule = json.load(f)
                    created_at_str = rule.get("created_at")
                    rule_ttl = float(rule.get("ttl", ttl))
                    rule_time = datetime.datetime.fromisoformat(created_at_str).timestamp() if created_at_str else 0
                    if rule_time > 0 and (now - rule_time) >= rule_ttl:
                        ip = rule.get("ip")
                        os.remove(rule_path)
                        entry = {
                            "action": "block_expired",
                            "ip": ip,
                            "reason": "TTL elapsed",
                            "status": "expired",
                            "time": str(datetime.datetime.now())
                        }
                        log_action(entry)
                        if ip:
                            expired_ips.append(ip)
                except Exception:
                    pass
    return expired_ips


@mcp.tool()
def get_action_log() -> str:
    """Return all actions taken so far, for audit purposes."""
    return json.dumps(load_action_log(), indent=2)

# Phase 5: IP reputation checking tool
FAKE_IP_REPUTATION = {
    "45.33.22.11": {"ip": "45.33.22.11", "abuse_score": 85, "is_malicious": True, "reason": "Known botnet C2 server"},
    "192.168.1.5": {"ip": "192.168.1.5", "abuse_score": 0, "is_malicious": False, "reason": "Private network IP"},
    "8.8.8.8": {"ip": "8.8.8.8", "abuse_score": 0, "is_malicious": False, "reason": "Google DNS - legitimate service"},
    "185.220.101.50": {"ip": "185.220.101.50", "abuse_score": 95, "is_malicious": True, "reason": "Tor exit node with abuse reports"},
}

# Chain-integrity tokens: store reputation check results for server-side validation
REPUTATION_RESULTS = {}

def check_ip_reputation_real(ip: str) -> str:
    """Check IP reputation using real AbuseIPDB API."""
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    
    # Validate API key is configured
    if not api_key or api_key == "your_abuseipdb_key_here":
        return json.dumps({
            "ip": ip,
            "abuse_score": -1,
            "is_malicious": False,
            "reason": "Error: ABUSEIPDB_API_KEY not configured in .env file"
        })
    
    try:
        # AbuseIPDB API endpoint
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": ""
        }
        
        # Make API request with timeout
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        # Handle different HTTP status codes
        if response.status_code == 200:
            data = response.json()
            
            if "data" not in data:
                return json.dumps({
                    "ip": ip,
                    "abuse_score": -1,
                    "is_malicious": False,
                    "reason": "Error: Malformed response from AbuseIPDB (missing 'data' field)"
                })
            
            abuse_data = data["data"]
            abuse_score = abuse_data.get("abuseConfidenceScore", 0)
            country_code = abuse_data.get("countryCode", "Unknown")
            total_reports = abuse_data.get("totalReports", 0)
            
            # Generate result_token and store for validation
            result_token = str(uuid.uuid4())[:8]
            session_id = os.getenv("SENTINELOPS_SESSION_ID", "default")
            store.save_evidence(
                token=result_token,
                session_id=session_id,
                ip=ip,
                is_malicious=abuse_score > 50,
                abuse_score=abuse_score
            )
            store.record_observed_ip(session_id, ip, source="check_ip_reputation")
            REPUTATION_RESULTS[result_token] = {
                "token": result_token,
                "session_id": session_id,
                "ip": ip,
                "abuse_score": abuse_score,
                "is_malicious": abuse_score > 50,
                "timestamp": str(datetime.datetime.now())
            }
            
            # Construct response in same format as fake data, plus result_token
            return json.dumps({
                "ip": ip,
                "abuse_score": abuse_score,
                "is_malicious": abuse_score > 50,  # Threshold: >50 is considered malicious
                "reason": f"AbuseIPDB: {abuse_score}% confidence, {total_reports} reports, Country: {country_code}",
                "result_token": result_token
            })
            
        elif response.status_code == 401:
            return json.dumps({
                "ip": ip,
                "abuse_score": -1,
                "is_malicious": False,
                "reason": "Error: Invalid ABUSEIPDB_API_KEY (401 Unauthorized)"
            })
            
        elif response.status_code == 429:
            return json.dumps({
                "ip": ip,
                "abuse_score": -1,
                "is_malicious": False,
                "reason": "Error: AbuseIPDB rate limit exceeded (429). Free tier limits apply."
            })
            
        else:
            return json.dumps({
                "ip": ip,
                "abuse_score": -1,
                "is_malicious": False,
                "reason": f"Error: AbuseIPDB API returned status {response.status_code}"
            })
            
    except requests.exceptions.Timeout:
        return json.dumps({
            "ip": ip,
            "abuse_score": -1,
            "is_malicious": False,
            "reason": "Error: AbuseIPDB API request timed out (>10 seconds)"
        })
        
    except requests.exceptions.RequestException:
        return json.dumps({
            "ip": ip,
            "abuse_score": -1,
            "is_malicious": False,
            "reason": f"Error: Network error contacting AbuseIPDB: {str(e)}"
        })
        
    except json.JSONDecodeError:
        return json.dumps({
            "ip": ip,
            "abuse_score": -1,
            "is_malicious": False,
            "reason": "Error: Could not parse AbuseIPDB response (invalid JSON)"
        })

def check_ip_reputation_stub(ip: str) -> str:
    """Check IP reputation using stubbed data (safe for testing)."""
    if ip in FAKE_IP_REPUTATION:
        result = FAKE_IP_REPUTATION[ip].copy()
    else:
        result = {
            "ip": ip,
            "abuse_score": -1,
            "is_malicious": False,
            "reason": "No reputation data available (stub mode)"
        }
    
    # Generate result_token and store for validation
    result_token = str(uuid.uuid4())[:8]
    session_id = os.getenv("SENTINELOPS_SESSION_ID", "default")
    store.save_evidence(
        token=result_token,
        session_id=session_id,
        ip=ip,
        is_malicious=result.get("is_malicious", False),
        abuse_score=result.get("abuse_score", -1)
    )
    store.record_observed_ip(session_id, ip, source="check_ip_reputation")
    REPUTATION_RESULTS[result_token] = {
        "token": result_token,
        "session_id": session_id,
        "ip": ip,
        "abuse_score": result.get("abuse_score", -1),
        "is_malicious": result.get("is_malicious", False),
        "timestamp": str(datetime.datetime.now())
    }
    
    result["result_token"] = result_token
    return json.dumps(result)

@mcp.tool()
def check_ip_reputation(ip: str) -> str:
    """Check the reputation of an IP address to determine if it is malicious or trustworthy.
    Use this tool when you need to verify whether an IP should be blocked or investigate its threat level.
    Returns abuse score (0-100 where higher is more malicious), malicious status, and a result_token.
    IMPORTANT: Pass the result_token to create_incident or notify_telegram when acting on this finding."""
    try:
        normalized_ip = validate_ip(ip)
    except ValueError as exc:
        return json.dumps({
            "ip": ip,
            "abuse_score": -1,
            "is_malicious": False,
            "reason": f"Error: {exc}"
        })

    if USE_REAL_APIS:
        return check_ip_reputation_real(normalized_ip)
    else:
        return check_ip_reputation_stub(normalized_ip)

# Phase 5: Incident tracking system
INCIDENTS_FILE = "incidents.json"
VALID_SEVERITIES = ["low", "medium", "high", "critical"]


def load_incidents():
    """Load incidents from JSON file."""
    try:
        with open(INCIDENTS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_incidents(incidents):
    """Save incidents to JSON file."""
    with open(INCIDENTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(incidents, f, indent=2)

@mcp.tool()
def create_incident(summary: str, severity: str, related_ip: str = None, evidence_token: str = None) -> str:
    """Create a formal security incident ticket that requires follow-up investigation or response.
    Use this to track security events that need human review or coordination, not for routine automated actions.
    Examples: persistent attack patterns, confirmed breaches, policy violations requiring escalation.
    Do NOT create incidents for every blocked IP or quarantined file - those are logged separately.

    Severity must be one of: low, medium, high, critical.

    For high or critical incidents, both related_ip and evidence_token are mandatory because the call must be tied to an observed malicious finding.
    """
    severity_lower = severity.lower()
    if severity_lower not in VALID_SEVERITIES:
        return f"Error: Invalid severity '{severity}'. Must be one of: {', '.join(VALID_SEVERITIES)}"

    normalized_ip = None
    if related_ip is not None:
        try:
            normalized_ip = validate_ip(related_ip)
        except ValueError as exc:
            _log_rejection("create_incident", "invalid_related_ip")
            return json.dumps({
                "error": "REJECTED: Invalid related_ip",
                "provided_ip": related_ip,
                "reason": str(exc)
            })

    if severity_lower in ("high", "critical"):
        if normalized_ip is None:
            _log_rejection("create_incident", "missing_related_ip")
            return json.dumps({
                "error": "REJECTED: High/critical severity incidents require related_ip",
                "severity": severity_lower,
                "summary": summary,
                "reason": "related_ip is required for high/critical incidents"
            })

        if not evidence_token:
            _log_rejection("create_incident", "missing_evidence_token")
            return json.dumps({
                "error": "REJECTED: High/critical severity incidents require evidence_token from check_ip_reputation",
                "severity": severity_lower,
                "summary": summary,
                "related_ip": normalized_ip,
                "reason": "Cannot create high-severity incident without validated evidence"
            })

        evidence = REPUTATION_RESULTS.get(evidence_token)
        if not evidence:
            ev = store.get_evidence(evidence_token)
            if ev and ev.get("expires_at", 0) > time.time():
                evidence = ev

        if not evidence:
            _log_rejection("create_incident", "unknown_evidence_token")
            return json.dumps({
                "error": "REJECTED: Invalid evidence_token (not found or expired)",
                "provided_token": evidence_token,
                "reason": "evidence_token must come from a recent check_ip_reputation call in the same MCP process"
            })

        evidence = REPUTATION_RESULTS[evidence_token]
        evidence_ip = evidence.get("ip")
        if not evidence.get("is_malicious", False):
            _log_rejection("create_incident", "non_malicious_evidence")
            return json.dumps({
                "error": "REJECTED: Evidence does not support malicious claim",
                "evidence_token": evidence_token,
                "ip": evidence_ip,
                "abuse_score": evidence.get("abuse_score"),
                "is_malicious": evidence.get("is_malicious"),
                "reason": f"Cannot create high-severity incident: IP {evidence_ip} has abuse_score {evidence.get('abuse_score')} (not malicious)"
            })

        try:
            evidence_normalized_ip = validate_ip(evidence_ip)
            if evidence_normalized_ip != normalized_ip:
                _log_rejection("create_incident", "evidence_ip_mismatch")
                return json.dumps({
                    "error": "REJECTED: Evidence IP mismatch",
                    "related_ip": normalized_ip,
                    "evidence_ip": evidence_normalized_ip,
                    "reason": "evidence_token must match the same IP address as related_ip"
                })
        except ValueError:
            _log_rejection("create_incident", "invalid_evidence_ip")
            return json.dumps({
                "error": "REJECTED: Invalid evidence IP",
                "evidence_ip": evidence_ip,
                "reason": "The evidence token contains an invalid IP"
            })

    incidents = load_incidents()
    incident_id = len(incidents) + 1
    incident = {
        "incident_id": incident_id,
        "summary": summary,
        "severity": severity_lower,
        "related_ip": normalized_ip,
        "timestamp": str(datetime.datetime.now()),
        "status": "open"
    }
    if evidence_token:
        incident["evidence_token"] = evidence_token
    incidents.append(incident)
    save_incidents(incidents)
    return f"Incident created successfully. ID: {incident_id}, Severity: {severity_lower}"

@mcp.tool()
def list_incidents() -> str:
    """List all security incidents that have been created."""
    incidents = load_incidents()
    if not incidents:
        return "No incidents found."
    return json.dumps(incidents, indent=2)

# Phase 5: Telegram notification system

@mcp.tool()
def debug_seed_pending_action(token: str, action_type: str, ip: str = None, path: str = None, reason: str = "Test action", status: str = "pending", session_id: str = None) -> str:
    """DEBUG TOOL: Manually seed a pending action for testing.
    This bypasses propose_* tools to directly create test tokens.

    SECURITY: Only available when ENABLE_DEBUG_ENDPOINTS=true in environment.
    """
    if not ENABLE_DEBUG_ENDPOINTS:
        return "Error: Debug endpoints are disabled. Set ENABLE_DEBUG_ENDPOINTS=true to enable."

    session = session_id or os.getenv("SENTINELOPS_SESSION_ID", "default")
    if action_type == "block_ip":
        if not ip:
            return "Error: ip is required for block_ip action_type"
        try:
            validated_ip = validate_ip(ip)
        except ValueError as exc:
            _log_rejection("debug_seed_pending_action", "invalid_block_ip")
            return f"Error: Invalid IP address '{ip}'. {exc}"
        
        params = {"ip": validated_ip, "reason": reason}
        store.create_action(token, session, "block_ip", params, status="pending")
        if status != "pending":
            if status in ("confirmed", "declined", "expired"):
                store.transition(token, session, "pending", status)
            elif status in ("executing", "executed", "failed"):
                store.transition(token, session, "pending", "confirmed")
                store.transition(token, session, "confirmed", "executing")
                if status in ("executed", "failed"):
                    store.transition(token, session, "executing", status)
        return f"DEBUG: Seeded pending action with token '{token}' (block_ip: {validated_ip}, status: {status})"

    elif action_type == "quarantine_file":
        if not path:
            return "Error: path is required for quarantine_file action_type"
        params = {"path": path, "reason": reason}
        store.create_action(token, session, "quarantine_file", params, status="pending")
        if status != "pending":
            if status in ("confirmed", "declined", "expired"):
                store.transition(token, session, "pending", status)
            elif status in ("executing", "executed", "failed"):
                store.transition(token, session, "pending", "confirmed")
                store.transition(token, session, "confirmed", "executing")
                if status in ("executed", "failed"):
                    store.transition(token, session, "executing", status)
        return f"DEBUG: Seeded pending action with token '{token}' (quarantine_file: {path}, status: {status})"

    else:
        return f"Error: Unknown action_type '{action_type}'. Must be 'block_ip' or 'quarantine_file'"

@mcp.tool()
def notify_telegram(message: str, evidence_token: str = None) -> str:
    """Send a notification message via Telegram to alert a human about security events or actions taken.

    Use this to inform humans about important findings or actions the agent performed.
    This is for real-time alerts, not a substitute for create_incident (which is for formal tracking).
    Examples: alerting about blocked IPs, quarantined files, or critical security findings.

    CRITICAL: When notifying about blocking/threat actions, provide evidence_token from check_ip_reputation
    to validate the claim is backed by actual findings.
    """
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")

    if not bot_token or bot_token == "your_telegram_bot_token_here":
        return "Error: TELEGRAM_BOT_TOKEN not configured. Please set it in .env file."
    if not chat_id or chat_id == "your_telegram_chat_id_here":
        return "Error: TELEGRAM_CHAT_ID not configured. Please set it in .env file."

    action_keywords = ["blocked", "malicious", "threat", "attack", "quarantine", "suspicious", "compromise", "breach"]
    evidence = None
    if any(keyword in message.lower() for keyword in action_keywords):
        if not evidence_token:
            _log_rejection("notify_telegram", "missing_evidence_token")
            return json.dumps({
                "error": "REJECTED: Notifications about security threats/actions require evidence_token from check_ip_reputation",
                "message": message,
                "reason": "Cannot send threat notification without validated evidence"
            })

        evidence = REPUTATION_RESULTS.get(evidence_token)
        if not evidence:
            ev = store.get_evidence(evidence_token)
            if ev and ev.get("expires_at", 0) > time.time():
                evidence = ev

        if not evidence:
            _log_rejection("notify_telegram", "unknown_evidence_token")
            return json.dumps({
                "error": "REJECTED: Invalid evidence_token (not found or expired)",
                "provided_token": evidence_token,
                "reason": "evidence_token must come from a recent check_ip_reputation call in the same MCP process"
            })

        evidence = REPUTATION_RESULTS[evidence_token]
        if not evidence.get("is_malicious", False):
            _log_rejection("notify_telegram", "non_malicious_evidence")
            return json.dumps({
                "error": "REJECTED: Evidence does not support threat claim",
                "evidence_token": evidence_token,
                "ip": evidence.get("ip"),
                "abuse_score": evidence.get("abuse_score"),
                "is_malicious": evidence.get("is_malicious"),
                "reason": f"Cannot notify about threat: IP {evidence.get('ip')} has abuse_score {evidence.get('abuse_score')} (not malicious)"
            })

        try:
            ip_match = validate_ip(evidence.get("ip"))
        except ValueError:
            _log_rejection("notify_telegram", "invalid_evidence_ip")
            return json.dumps({
                "error": "REJECTED: Invalid evidence IP",
                "reason": "The evidence token contains an invalid IP"
            })
        if ip_match not in message:
            _log_rejection("notify_telegram", "evidence_ip_not_in_message")
            return json.dumps({
                "error": "REJECTED: Evidence IP not mentioned in message",
                "evidence_token": evidence_token,
                "ip": evidence.get("ip"),
                "reason": "The threat message must mention the IP address from the evidence_token"
            })

    entry = {"action": "notify_telegram", "status": "pending"}

    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": f"SentinelOps Alert\n\n{message}",
            "parse_mode": "HTML"
        }
        response = requests.post(url, json=payload, timeout=10)

        if response.status_code == 200:
            entry["status"] = "sent"
            log_action(entry)
            return f"Telegram notification sent successfully. Message: {message}"

        entry["status"] = "failed"
        entry["reason"] = "telegram_http_failure"
        entry["http_status"] = response.status_code
        log_action(entry)
        return f"Error sending Telegram notification (HTTP {response.status_code})"

    except requests.exceptions.Timeout:
        entry["status"] = "failed"
        entry["reason"] = "telegram_timeout"
        log_action(entry)
        return "Error: Telegram API request timed out"
    except requests.exceptions.RequestException as e:
        entry["status"] = "failed"
        entry["reason"] = "telegram_request_failed"
        log_action(entry)
        return "Error: Failed to send Telegram notification"

if __name__ == "__main__":
    import sys
    
    # CRITICAL FIX: Force UTF-8 encoding for stdout/stderr on Windows
    # This prevents UnicodeEncodeError when MCP responses contain Unicode characters
    # Use reconfigure() instead of detach() to avoid closing the streams
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    
    sys.stderr.write("="*60 + "\n")
    sys.stderr.write("SentinelOps MCP Server Starting\n")
    sys.stderr.write("="*60 + "\n")
    sys.stderr.write(f"USE_REAL_APIS: {USE_REAL_APIS}\n")
    sys.stderr.write(f"Mode: {'REAL INTEGRATIONS' if USE_REAL_APIS else 'STUBBED DATA (safe for testing)'}\n")
    sys.stderr.write("="*60 + "\n\n")
    sys.stderr.flush()
    mcp.run()
