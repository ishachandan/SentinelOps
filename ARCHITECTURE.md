# SentinelOps Architecture

## Design Principles

SentinelOps uses two safety layers for LLM agents that interact with destructive operations:

1. **Evidence Integrity** - Bind high/critical incident claims to validated reputation evidence
2. **Human-in-the-Loop Execution Gate** - Separate proposals from execution and enforce confirmation in Flask and MCP

---

## Pattern 1: Evidence Chain Integrity

### Problem
LLMs can fabricate threats. Early versions would write incident reports claiming "this IP is malicious with 100% abuse score" without actually calling `check_ip_reputation`.

### Solution: Result Tokens

When an agent calls `check_ip_reputation(ip)`:
```python
result = check_ip_reputation("185.220.101.1")
# Returns:
{
    "ip": "185.220.101.1",
    "abuse_score": 100,
    "is_malicious": true,
    "result_token": "f5bce9c4"  # Server-generated, stored in REPUTATION_RESULTS
}
```

If the agent then creates a high-severity incident about this IP, it **must** provide the token:
```python
create_incident(
    summary="Malicious IP detected: 185.220.101.1",
    severity="high",
    related_ip="185.220.101.1",
    evidence_token="f5bce9c4"  # REQUIRED
)
```

Server validation:
```python
# 1. Token must exist in this MCP process's reputation results
if evidence_token not in REPUTATION_RESULTS:
    return {"error": "Invalid evidence_token"}

# 2. Token's IP must match claim
evidence = REPUTATION_RESULTS[evidence_token]
if evidence["ip"] != "185.220.101.1":
    return {"error": "Evidence doesn't match claim"}

# 3. Token's data must support severity
if not evidence["is_malicious"]:
    return {"error": "Evidence shows IP is not malicious"}
```

**Result:** Agent cannot fabricate high-severity incidents. It must provide proof it actually checked.

The token is bound to the normalized IP and stored in MCP process memory. It is valid only in that process; each new MCP subprocess starts with no evidence tokens.

## IP Address Validation

SentinelOps parses IPv4 and IPv6 addresses with `ipaddress.ip_address` and uses their normalized form. `propose_block_ip` rejects loopback, unspecified, and multicast addresses; private, link-local, and documentation/test ranges remain valid targets. `check_ip_reputation` and `create_incident` validate syntax only. Firewall rule filenames use the normalized address with periods and colons replaced by underscores.

---

## Pattern 2: Propose/Execute Split

### Why `confirmed=true` Parameters Don't Work

**Rejected approach:**
```python
@mcp.tool()
def block_ip(ip: str, confirmed: bool = False) -> str:
    if not confirmed:
        return "Please confirm this action"
    execute_block(ip)  # Actually blocks
```

**Problem:** Model learns this pattern and calls `block_ip("1.2.3.4", confirmed=True)` directly. Even sophisticated prompting like "never set confirmed=True yourself" can be bypassed by adversarial prompts.

### Solution: Execution is Not a Tool Parameter

**Instead:**
```python
# Phase 1: Propose (agent HAS access)
@mcp.tool()
def propose_block_ip(ip: str, reason: str) -> str:
    token = generate_token()
    PENDING_ACTIONS[token] = {
        "action_type": "block_ip",
        "ip": ip,
        "reason": reason,
        "status": "pending"
    }
    save_pending_actions(PENDING_ACTIONS)  # Write to file
    return f"PREVIEW: Would block {ip}. Token: {token}\nAwaiting confirmation."

# Phase 2: Execute (human-triggered by Flask after confirmation)
def execute_pending_action(token: str) -> str:
    actions = load_pending_actions()
    action = actions[token]
    if action["status"] != "confirmed":
        return "Error: action is not confirmed"
    if action["action_type"] == "block_ip":
        create_firewall_rule(action["ip"])
    action["status"] = "executed"
    save_pending_actions(actions)
    return "SUCCESS: Action executed"
```

**Key insight:** Human-only tool schemas are filtered out before the model sees them. `run_agent_turn()` rejects tool names outside its exposed set without calling MCP. MCP then re-reads the action file and executes only `status == "confirmed"`.

Execution happens via a separate HTTP route:
```python
@app.route('/confirm/<token>', methods=['POST'])
def confirm_action(token):
    # Validate token, session, status
    # Then spawn NEW MCP subprocess and call execute_pending_action
```

**Why this works:**
- The model does not receive human-only tool schemas; agent-loop and CLI guards reject unexposed names.
- Agent cannot POST to /confirm (different process, requires session cookie)
- Flask checks token existence, session ownership, and pending status, then writes `confirmed` before starting an MCP subprocess.

### Flask and MCP confirmation gates (within layer 2)

Even with human confirmation, Flask validates three separate gates:

```python
@app.route('/confirm/<token>', methods=['POST'])
def confirm_action(token):
    # Gate 1: Token exists in pending_actions.json
    pending = get_pending_action(token)
    if not pending:
        return jsonify({"error": "Invalid token"}), 404
    
    # Gate 2: Token belongs to your session
    if pending['session_id'] != get_session_id():
        return jsonify({"error": "Not your token"}), 403
    
    # Gate 3: Token hasn't been used
    if pending['status'] != 'pending':
        return jsonify({"error": "Already resolved"}), 400
    
    # All Flask gates passed: mark confirmed, then call MCP.
    execute_pending_action(token)
```

The MCP server reads the shared SQLite action and atomically claims it by changing `confirmed` to `executing`. Execution errors move it to `failed`; stale executing actions are marked failed during recovery.

**Flask route responses:**
- **404:** Prevents brute-force token guessing
- **403:** Prevents cross-session hijacking
- **400:** Prevents replay attacks

---

## File-Based Single Source of Truth

### Problem
Flask (web UI) and MCP (agent) run in **separate processes**. Early versions used in-memory dictionaries:

```python
# server.py (MCP process)
PENDING_ACTIONS = {}

# web_ui.py (Flask process)
PENDING_CONFIRMATIONS = {}
```

**Result:** Desynch bugs. Agent writes to `PENDING_ACTIONS`, Flask reads from empty `PENDING_CONFIRMATIONS` → 404.

### Solution
Both processes read and write the **same file**:

```python
# server.py
PENDING_ACTIONS_FILE = "data/pending_actions.json"

def load_pending_actions():
    with open(PENDING_ACTIONS_FILE, 'r') as f:
        return json.load(f)

def save_pending_actions(actions):
    with open(PENDING_ACTIONS_FILE, 'w') as f:
        json.dump(actions, f)

# web_ui.py (same functions)
PENDING_ACTIONS_FILE = "data/pending_actions.json"
# Uses identical load/save functions
```

**Current implementation:** Flask and MCP share a SQLite database. Status changes use compare-and-set updates, so competing confirmations and execution claims cannot both win.

---

## System Diagram

```
┌─────────────┐
│   Browser   │ User sends query
└──────┬──────┘
       │ POST /send {"message": "block 1.2.3.4"}
       ↓
┌─────────────────────────────────────────────────────┐
│ Flask (web_ui.py)                                    │
│                                                       │
│ Step 1: Propose Phase                                │
│ • Spawns MCP subprocess                              │
│ • Human-only schemas filtered before model call     │
│ • Agent loop rejects unexposed tool names           │
└──────┬────────────────────────────────────────────┘
       │
       ↓
┌─────────────────────────────────────────────────────┐
│ MCP Server (server.py)                               │
│                                                       │
│ propose_block_ip(ip="1.2.3.4", reason="..."):       │
│   token = "a3f7c491"                                 │
│   pending_actions.json ← write                       │
│   return "Token: a3f7c491"                           │
└──────┬────────────────────────────────────────────┘
       │
       ↓
┌─────────────────────────────────────────────────────┐
│ Flask (web_ui.py)                                    │
│                                                       │
│ Returns to browser:                                  │
│ {                                                     │
│   "transcript": [                                     │
│     {"type": "pending_confirmation",                 │
│      "token": "a3f7c491",                            │
│      "content": "PREVIEW: Would block 1.2.3.4"}     │
│   ]                                                   │
│ }                                                     │
└──────┬────────────────────────────────────────────┘
       │
┌──────▼──────┐
│   Browser   │ User clicks [Confirm]
└──────┬──────┘
       │ POST /confirm/a3f7c491
       ↓
┌─────────────────────────────────────────────────────┐
│ Flask (web_ui.py)                                    │
│                                                       │
│ Step 2: Execute Phase (Human-Triggered)              │
│ • Validates 3 gates                                  │
│ • Spawns NEW MCP subprocess                          │
│ • THIS time, calls execute_pending_action            │
└──────┬────────────────────────────────────────────┘
       │
       ↓
┌─────────────────────────────────────────────────────┐
│ MCP Server (server.py)                               │
│                                                       │
│ execute_pending_action(token="a3f7c491"):           │
│   action = pending_actions.json[token]               │
│   create_firewall_rule(action["ip"])                 │
│   action["status"] = "executed"                      │
│   pending_actions.json ← write                       │
│   return "SUCCESS"                                    │
└─────────────────────────────────────────────────────┘
```

**Critical separation:** Flask calls `execute_pending_action` only after a human POST passes the route checks. MCP independently reloads the state file and requires `status == "confirmed"` before execution.

---

## Security Properties

**What's protected:**
✅ Agent cannot execute destructive actions directly  
✅ Agent cannot fabricate high-severity incidents without evidence  
✅ Flask UI proposals are session-bound and checked against the current browser session
✅ Tokens are single-use (no replay attacks)  
✅ Execution requires human POST request (no LLM manipulation)  

**What's not protected (intentionally out of scope):**
❌ Malicious human confirming bad actions (human is accountable)  
❌ Physical access to the server (file-based storage is not encrypted)  
❌ Production firewall integration (sandbox only)  

---

## File Structure

```
data/
├── pending_actions.json     # Single source of truth
├── firewall_sandbox/        # Sandbox for "blocked" IPs
├── sentinelops_sandbox/     # Sandbox for "quarantined" files
├── chromadb_sentinelops/    # Semantic log-search index when enabled
└── action_log.jsonl         # Action audit events, including rejections

server.py                    # MCP server, tool definitions
web_ui.py                    # Flask web UI, confirmation routes
agent_shared.py              # Shared agent logic (CLI & web)
cli.py                       # Terminal interface
```

---

## Testing Strategy

Run the offline suite from the project root:

```powershell
venv\Scripts\python.exe -m pytest -q
```

On POSIX, use `venv/bin/python -m pytest -q`. `pytest.ini` excludes `integration` tests by default, and `tests/conftest.py` keeps live-service/manual scripts out of collection. The offline suite includes unit/policy tests, hardening tests, and Flask `test_client()` confirmation-gate tests. The exact collected/passed/skipped counts are determined by the pytest output for the current checkout.

Verified in this checkout: **55 passed, 1 skipped, 2 deselected**. The two deselected tests are marked `integration`. The single skip is the combined symlink-containment test: even after Developer Mode was enabled, Windows returned `WinError 1314` when Python attempted to create a symlink.

`tests/test_integration.py` is marked `integration`; it starts MCP subprocesses, and its LLM-chain test requires Groq credentials. Run it explicitly only when those dependencies are intended:

```powershell
venv\Scripts\python.exe -m pytest tests/test_integration.py -v -m integration
```

Live Flask wrappers (including `test_security_gates.py`, `test_security_direct.py`, and `test_web_ui.py`) and Docker smoke scripts are manual checks, not part of plain pytest collection. The five security-gate cases are covered offline by `tests/test_security_gate_routes.py`.

---

## Audit log and quarantine boundary

`data/action_log.jsonl` stores one sanitized JSON object per line for action outcomes, including rejected evidence and blocked execution attempts. It is read from disk by `get_action_log`, which skips malformed lines; credential/token fields are omitted, configured secret values are redacted, and full message/file contents are not logged.

Quarantine proposal and execution use `realpath` and `commonpath` containment checks against `data/sentinelops_sandbox/`. The sandbox root, quarantine subfolder, traversal paths, sibling-prefix paths, and symlinks resolving outside are rejected.

## Known limitations (by design for this demo)

- Action state is stored in SQLite and transitions use atomic compare-and-set updates.
- Flask starts a new MCP subprocess per request, so evidence tokens and other MCP in-memory state do not survive across requests.
- Conversation history is stored in the Flask cookie session.
- `/confirm` and `/decline` do not have CSRF protection.
- Generated action and evidence tokens are 8 hexadecimal characters.
- The Flask secret key is random per restart unless `FLASK_SECRET_KEY` is configured.
- Execution is sandbox-only; no real firewall or out-of-sandbox quarantine operation occurs.
- Prompt injection through log content is bounded by the confirmation gate but can still influence the preview shown to a human.

---

## Production Considerations

This is a **demonstration platform**. For production:

**Replace sandboxes with real integrations:**
- `data/firewall_sandbox/` → Actual firewall API (iptables, pfSense, cloud provider)
- `data/sentinelops_sandbox/` → Real quarantine system

**Add authentication:**
- OAuth 2.0 or JWT tokens
- Role-based access control

**Add monitoring:**
- Prometheus metrics (action counts, latencies)
- Grafana dashboards
- Alert on repeated declines (possible attack)

**Harden security:**
- HTTPS (nginx reverse proxy)
- Rate limiting
- Secrets management (Vault, AWS Secrets Manager)
- Immutable audit logs

**The confirmation flow remains the same.** The architectural patterns (evidence chains, propose/execute split, multi-gate validation) scale to production.

---

## References

**Design inspiration:**
- [Anthropic's Constitutional AI](https://www.anthropic.com/index/constitutional-ai-harmlessness-from-ai-feedback) - Human feedback in training
- [OpenAI's Function Calling](https://platform.openai.com/docs/guides/function-calling) - Tool interfaces for LLMs
- [Model Context Protocol](https://modelcontextprotocol.io/) - Standardized agent-tool communication

**Security principles:**
- Defense in depth - Multiple independent gates
- Separation of concerns - Proposal ≠ execution
- Principle of least privilege - Agent gets only necessary tools
- Auditability - All actions logged with tokens

---

**Last Updated:** 2026-08-02  
**Version:** 1.0
Groq calls tool: propose_block_ip
         ↓
MCP server creates pending action in pending_actions.json
         ↓
Returns token: "abc123" with PREVIEW message
         ↓
Flask detects "Token:" in result → renders Confirm/Decline buttons
         ↓
Browser shows: [Confirm] [Decline]
```

### Step 4a: User clicks Confirm
```
Browser → POST /confirm/abc123
         ↓
Flask validates:
  ✓ Token exists in pending_actions.json
  ✓ Token belongs to user's session
  ✓ Status is "pending" (not already resolved)
         ↓
Flask updates status to "confirmed" in file
         ↓
Flask spawns MCP subprocess
         ↓
Flask calls execute_pending_action tool with token
         ↓
MCP server reads pending_actions.json
         ↓
MCP server executes action (creates firewall rule)
         ↓
MCP server updates status to "executed" in file
         ↓
Returns success message to Flask
         ↓
Flask returns success JSON to browser
         ↓
Browser shows: ✓ Action executed
```

### Step 4b: User clicks Decline
```
Browser → POST /decline/abc123
         ↓
Flask validates (same checks as confirm)
         ↓
Flask updates status to "declined" in file
         ↓
NO execution - just status update
         ↓
Returns success message to browser
         ↓
Browser shows: Action declined
```

## Security Architecture

### 1. Token Lifecycle
```
Created      → Pending    → Confirmed  → Executed
(MCP)           (Flask)      (Flask)      (MCP)
                    ↓
                Declined
                (Flask)
```

### 2. Validation Gates

**Gate 1: Token Existence**
```python
pending = get_pending_action(token)
if not pending:
    return 404  # Token doesn't exist
```

**Gate 2: Session Ownership**
```python
if pending.get('session_id') != current_session:
    return 403  # Not your token
```

**Gate 3: Status Check**
```python
if pending.get('status') != 'pending':
    return 400  # Already resolved
```

**Gate 4: Execution**
```python
# ONLY /confirm route can call execute_pending_action
# LLM gets callback=None → auto-declined
if confirmation_callback is None:
    return "Human user declined to execute this action."
```

### 3. Single Source of Truth

```
┌────────────┐                    ┌────────────┐
│   Flask    │                    │    MCP     │
│  (web_ui)  │                    │ (server.py)│
└─────┬──────┘                    └─────┬──────┘
      │                                 │
      └────────┐         ┌──────────────┘
               ↓         ↓
        ┌──────────────────────┐
        │ pending_actions.json │
        │  (single file)       │
        └──────────────────────┘

Both components read/write the SAME file
→ No synchronization issues
→ No race conditions
→ Consistent state
```

## Component Responsibilities

### Flask (web_ui.py)
- ✓ Serve web UI
- ✓ Manage user sessions
- ✓ Spawn MCP subprocesses
- ✓ Enforce security gates (/confirm, /decline)
- ✓ Maintain conversation history
- ✓ Build transcript for UI

### MCP Server (server.py)
- ✓ Provide tools to LLM
- ✓ Execute read-only tools immediately
- ✓ Create pending actions for write tools
- ✓ Execute confirmed actions
- ✓ Update pending_actions.json

### Agent Shared (agent_shared.py)
- ✓ Convert MCP tools to Groq format
- ✓ Run agent turn loop
- ✓ Handle tool calls
- ✓ Manage confirmation callback

### Browser (index.html)
- ✓ Display conversation
- ✓ Send user messages
- ✓ Render Confirm/Decline buttons
- ✓ Handle button clicks

## Error Handling Flow

```
Error occurs anywhere in stack
         ↓
Flask catches ExceptionGroup (Python 3.14+)
         ↓
Unwraps nested ExceptionGroups recursively
         ↓
Extracts real exception
         ↓
Formats as error message
         ↓
Adds to conversation as assistant message
         ↓
Renders in UI transcript
         ↓
User sees error (not silent failure)
```

## Deployment Architecture

### Development
```
┌─────────────────────┐
│   Local Machine     │
│                     │
│  python web_ui.py   │
│  → Flask dev server │
│  → Port 5000        │
└─────────────────────┘
```

### Production (Docker)
```
┌──────────────────────────────┐
│      Docker Container        │
│                              │
│  Gunicorn WSGI server        │
│  → 2 workers                 │
│  → 4 threads each            │
│  → Handles Flask app         │
│  → Port 5000                 │
│                              │
│  Health check:               │
│  → Every 30s                 │
│  → GET /                     │
└──────────────────────────────┘
         ↑
         │ Port 5000
         ↓
┌──────────────────────────────┐
│   Reverse Proxy (optional)   │
│   nginx / Traefik            │
│   → HTTPS termination        │
│   → Load balancing           │
│   → Rate limiting            │
└──────────────────────────────┘
```

## File System Layout

```
sentinelops/
├── Application
│   ├── web_ui.py           # Flask server
│   ├── server.py           # MCP server
│   ├── agent_shared.py     # Shared logic
│   └── templates/
│       └── index.html      # Web UI
│
├── Data (persistent volume)
│   └── data/
│   ├── pending_actions.json      # Single source of truth
│   ├── action_log.jsonl          # Append-only JSON Lines audit events
│   ├── firewall_sandbox/         # Executed firewall rules
│   ├── sentinelops_sandbox/      # Input files and quarantine subfolder
│   └── chromadb_sentinelops/     # Semantic log-search index when enabled
│
├── Docker
│   ├── Dockerfile          # Container definition
│   ├── docker-compose.yml  # Orchestration
│   ├── .dockerignore       # Build exclusions
│   └── requirements.txt    # Dependencies
│
├── Configuration
│   ├── .env                # Secrets (not in Git)
│   └── .env.example        # Template
│
└── Documentation
    ├── README.md
    ├── DOCKER_DEPLOYMENT.md
    ├── ARCHITECTURE.md
    └── DOCKER_COMPLETION_REPORT.md
```

## State Management

Action state and reputation evidence are stored in the shared SQLite database. The audit log remains JSONL, and conversation history remains in the Flask cookie session.

### Session State (in-memory)
```python
flask_session['session_id'] = uuid.uuid4()
flask_session['conversations'][session_id] = [
    {"role": "user", "content": "..."},
    {"role": "assistant", "content": "..."}
]
```

### Persistent State (SQLite)
```python
pending -> confirmed -> executing -> executed | failed
pending -> declined | expired
```

Each transition checks the current status in the same `UPDATE`. Pending actions expire after 15 minutes; an executing action older than five minutes is recovered as failed with an unknown outcome.

## Scaling Considerations

### Single Instance (Current)
- Session storage: In-memory (Flask session)
- Storage: Shared SQLite database on a local named volume
- Limitation: Only one container

### Multi-Host Deployment
- Session storage: Redis / Memcached
- Database: Networked database such as PostgreSQL; SQLite WAL is single-host and unsuitable for shared network filesystems
- Load balancer: nginx / Traefik / HAProxy

## Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Frontend | HTML/CSS/JS | Web UI |
| Backend | Flask 3.1.0 | Web framework |
| WSGI | Gunicorn 23.0.0 | Production server |
| LLM | Groq (LLaMA 3.3 70B) | AI reasoning |
| Protocol | MCP 1.3.2 | Tool integration |
| Threat Intel | AbuseIPDB | IP reputation |
| Notifications | Telegram | Alerts |
| Vector DB | ChromaDB 0.6.2 | Semantic log search with `USE_REAL_APIS=true`; stub fallback otherwise |
| Container | Docker | Deployment |
| Orchestration | Docker Compose | Multi-service |

## Conclusion

SentinelOps uses a clean, layered architecture with:
- **Separation of concerns** - Flask handles HTTP, MCP handles tools
- **Single source of truth** - One file for pending actions
- **Security by design** - Multiple validation gates
- **Error resilience** - Comprehensive error handling
- **Scalability** - Docker-ready, multi-instance capable

The architecture prioritizes security and reliability over complexity, making it easy to understand, test, and deploy.
