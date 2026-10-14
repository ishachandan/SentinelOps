# SentinelOps

**AI-Powered Security Operations with Human-in-the-Loop Safety**

An intelligent security operations platform demonstrating safe LLM agent design through two safety layers. Built with the Model Context Protocol (MCP), SentinelOps gives AI agents investigation and proposal tools while maintaining human control of destructive actions.

---

## What It Does

SentinelOps is a conversational security copilot that can investigate threats, recommend actions, and execute security responses—but only after explicit human approval for any destructive operation.

**Core workflow:**
1. User describes a security concern in natural language
2. Agent retrieves context (IP reputation, incident history, logs)
3. Agent proposes actions (block IP, quarantine file, create alert)
4. Human reviews preview and explicitly confirms or declines
5. Confirmed actions execute with full audit trail

**Example session:**
```
You: check if 185.220.101.1 is malicious

Agent: [calls check_ip_reputation(185.220.101.1)]
       AbuseIPDB reports this IP has a 100% abuse confidence score
       with 172 reports. It's associated with malware distribution.
       
       Would you like me to block it?

You: yes, block that IP

Agent: [calls propose_block_ip(185.220.101.1, reason="malware distribution")]
       
       PREVIEW: Would block IP 185.220.101.1
       Reason: Malware distribution, 100% abuse score
       Token: a3f7c491
       
       [Confirm] [Decline]

[You click Confirm]

Agent: [execute_pending_action(a3f7c491) called by Flask /confirm route]
       SUCCESS: Blocked IP 185.220.101.1
       Firewall rule created: data/firewall_sandbox/block_185_220_101_1.rule
```

### IP validation policy

IPv4 and IPv6 inputs are parsed and stored in their normalized form. Block proposals reject only loopback, unspecified, and multicast addresses. Private, link-local, and documentation/test ranges are valid investigation and block targets. Reputation checks and incident IPs require valid IP syntax but do not apply those block-target restrictions.

---

## Architecture

### The Challenge: Safe Tool Access for LLMs

LLMs are powerful but unreliable. Giving an agent tools like "block this IP" or "quarantine this file" creates real risk:
- The model might hallucinate threats that don't exist
- Parameter injection could trick the model into dangerous actions
- A simple `confirmed=true` parameter can be bypassed by a clever adversarial prompt

SentinelOps addresses this through **layered guardrails** rather than trusting the model to make safe choices.

### Layer 1: Evidence Chain Integrity

**Problem:** Model says "this IP is malicious" — how do you know it actually checked?

**Solution:** Chain-integrity tokens.

When the agent calls `check_ip_reputation(ip)`, the server returns:
```json
{
  "ip": "185.220.101.1",
  "abuse_score": 100,
  "is_malicious": true,
  "result_token": "f5bce9c4"
}
```

If the agent then tries to create a high-severity incident about that IP, it **must** provide the `result_token`:

```python
create_incident(
    summary="Malicious IP detected: 185.220.101.1",
    severity="high",
    related_ip="185.220.101.1",
    evidence_token="f5bce9c4"  # REQUIRED for high/critical severity
)
```

The server validates:
1. Token exists in the current MCP process's reputation results
2. Token's IP matches the incident claim
3. Token's data actually shows `is_malicious: true`

**Result:** The model cannot fabricate high-severity incidents. It must provide evidence it actually retrieved.

Evidence tokens are bound to the normalized IP and exist only in the MCP process's memory. A token is valid only while the same MCP process is alive; a new MCP subprocess does not inherit it.

### Layer 2: Human-in-the-Loop Execution Gate

**Problem:** Even with evidence, we don't want the LLM to execute destructive actions directly. A `confirmed=true` parameter is too easy for the model to add on its own.

**Solution:** A propose/execute split guarded in the model schema, agent loop, Flask route, and MCP server.

**Propose phase** (agent has access):
```python
result = propose_block_ip(
    ip="185.220.101.1",
    reason="Malware distribution"
)
# Returns: "PREVIEW: Would block IP... Token: a3f7c491"
# NO actual execution happens here
```

**Execute phase** (human-triggered through Flask):
```python
# Flask calls this only after validating the human's confirmation request.
execute_pending_action(token="a3f7c491")
```

The Flask web UI provides `/confirm/<token>` and `/decline/<token>` routes that **humans** trigger by clicking buttons. Human-only tools are filtered out of schemas sent to the model, and the agent loop rejects any tool call whose name is not in the exposed set before calling MCP. Flask checks token existence, session ownership, and pending status, then marks the action confirmed before starting an MCP process. The MCP server reloads `pending_actions.json` and executes only an action whose status is exactly `confirmed`.

**Why this works:**
- Human-only tool schemas are filtered from model requests; the agent loop and CLI also reject unexposed names without calling MCP.
- In CLI mode, a proposal is shown to the operator; `y` marks it confirmed and executes through MCP, while any other response records it as declined.
- Flask validates token existence, session ownership, and pending status before marking an action confirmed.
- MCP independently reloads the action and refuses unknown, pending, declined, executed, or otherwise unconfirmed actions.

Flask's route gates are:

```python
# Gate 1: Token exists
if token not in pending_actions:
    return 404

# Gate 2: Token belongs to your session
if action['session_id'] != current_session:
    return 403

# Gate 3: Token is still pending
if action['status'] != 'pending':
    return 400
```

After Flask changes the status to `confirmed`, the MCP-side check is a separate final execution gate.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────┐
│ User (Browser)                                      │
│  │                                                   │
│  ├─ Sends query: "block 1.2.3.4"                   │
│  ├─ Views proposal preview                          │
│  └─ Clicks [Confirm] → POST /confirm/a3f7c491      │
└─────────────┬───────────────────────────────────────┘
              │
        ┌─────▼──────┐
        │  Flask     │ Step 2: Propose phase
        │  (web_ui)  │ - Spawns MCP subprocess
        │            │ - Human-only schemas filtered; agent checks exposed names
        └─────┬──────┘ - Returns proposal with token
              │
        ┌─────▼──────┐
        │ Groq LLM   │ Step 3: Agent reasoning
        │ (LLaMA 3.3)│ - Calls check_ip_reputation (evidence)
        │            │ - Calls propose_block_ip (preview)
        └─────┬──────┘ - Returns "Token: a3f7c491"
              │
        ┌─────▼──────┐
        │ MCP Server │ Step 4: Tool execution
        │ (server.py)│ - propose_block_ip: writes pending_actions.json
        │            │ - Reloads state; executes only status == "confirmed"
        └─────┬──────┘
              │
        ┌─────▼────────────────┐
        │ File-Based Storage   │ Step 5: Single source of truth
        │ pending_actions.json │ - Both Flask and MCP read/write this file
        └──────────────────────┘ - Prevents desynch bugs
              │
        ┌─────▼──────┐
        │  Flask     │ Step 6: Execute phase (human-triggered)
        │  /confirm  │ - Validates 3 gates
        │            │ - Spawns NEW MCP subprocess
        └─────┬──────┘ - Calls execute_pending_action(token)
              │
        ┌─────▼──────┐
        │ MCP Server │ Step 7: Actual execution
        │ (server.py)│ - Creates firewall rule in sandbox
        │            │ - Marks action as 'executed'
        └────────────┘ - Returns success
```

**Key insight:** The agent process that *proposes* actions and the Flask process that *executes* them are separate. The agent cannot execute. Flask will not execute without human confirmation. This separation is enforced at the process level, not by trusting the model.

---

## Setup

### Prerequisites
- Python 3.11+
- Docker (optional, for containerized deployment)
- API keys (all free tiers available):
  - [Groq](https://console.groq.com) - LLM inference
  - [AbuseIPDB](https://www.abuseipdb.com/) - IP reputation
  - [Telegram](https://t.me/botfather) - Alerts (optional)

### Quick Start (Docker)

1. **Clone and configure:**
```bash
git clone <your-repo-url>
cd sentinelops
cp .env.example .env
# Edit .env with your API keys
```

2. **Start:**
```bash
docker compose up -d
```

3. **Access:**  
   Open http://localhost:5000

### Local Development

The canonical project virtual environment is named `venv/` on Windows and POSIX.

1. **Install dependencies:**
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

2. **Configure environment:**
```bash
cp .env.example .env
# Edit .env with your API keys
```

3. **Initialize sandbox (first-time setup):**
```bash
python setup_sandbox.py
python ingest_sample_logs.py  # Optional: seed ChromaDB
```

4. **Run:**
```bash
python web_ui.py  # Web interface at http://localhost:5000
# OR
python cli.py     # Terminal interface
```

### Configuration

Required in `.env`:
```bash
GROQ_API_KEY=gsk_...                    # Get from console.groq.com
ABUSEIPDB_API_KEY=...                   # Get from abuseipdb.com/api
TELEGRAM_BOT_TOKEN=...                  # From @BotFather (optional)
TELEGRAM_CHAT_ID=...                    # Your chat ID (optional)

# Production settings
USE_REAL_APIS=true                      # Enables real APIs and ChromaDB; false uses stubs
ENABLE_DEBUG_ENDPOINTS=false            # NEVER true in production
FLASK_DEBUG=false                       # Flask debug mode is off unless explicitly enabled
```

---

## Design Decisions

### Why Not Just a `confirmed` Parameter?

**Rejected approach:**
```python
@mcp.tool()
def block_ip(ip: str, confirmed: bool = False) -> str:
    if not confirmed:
        return "Please confirm this action"
    # Execute block
```

**Problem:** The model can trivially set `confirmed=True` itself:
```
Agent: [calls block_ip("1.2.3.4", confirmed=True)]
```

Even if you try to hide it:
```python
def block_ip(ip: str) -> str:
    """Block an IP. Returns a confirmation token."""
    # Show preview, return token
```

The model learns from examples and documentation that `confirmed=True` is the pattern, and will attempt it. Adversarial prompts can manipulate this further.

**The fix:** Execution is not a tool parameter. It's a separate HTTP endpoint in a different process that the agent cannot access.

### Why Evidence Tokens?

**Problem observed:** In early versions, the agent would write incident reports claiming "this IP is malicious" without actually calling `check_ip_reputation` first. The model "knew" certain IP ranges were bad and fabricated justifications.

**The fix:** High-severity incidents require an `evidence_token` from a prior API call. The server validates the chain:
1. Was `check_ip_reputation` called?
2. Did it return a token?
3. Does that token's data support the severity claim?

Now the agent must actually retrieve evidence, not fabricate it.

### Why File-Based Storage?

**Problem:** Flask (web UI) and MCP (agent tools) run in separate processes. Early versions used in-memory dicts, causing desynch:
- Agent proposes action → writes to MCP's in-memory dict
- User clicks Confirm → Flask reads from its own empty in-memory dict → 404

**The fix:** `pending_actions.json` is the shared source of truth, avoiding separate in-memory copies. The JSON file has no locking, so concurrent writers can still race.

### Why Sandbox-Only Execution?

All destructive operations target sandboxed directories:
- Firewall rules → `data/firewall_sandbox/` (not actual iptables)
- Quarantined files → `data/sentinelops_sandbox/quarantine/` (path-validated)

**Rationale:** This is a demonstration/development platform. In production, you'd replace the sandbox with real integrations (actual firewall API, real quarantine system), but the confirmation flow remains the same.

---

## Testing

### Offline pytest suite
```bash
venv\Scripts\python.exe -m pytest -q
```

Run from the project root on Windows (use `venv/bin/python -m pytest -q` on POSIX). The suite runs without a live Flask server or external API. `pytest.ini` excludes tests marked `integration`; `tests/conftest.py` excludes manual/live-service scripts from collection. Flask confirmation-gate checks use `app.test_client()` and cover valid confirmation, fake and reused tokens, cross-session attempts, and declined actions.

Verified in this checkout: **55 passed, 1 skipped, 2 deselected**. The two deselected tests are marked `integration`. The single skip is the combined symlink-containment test: even after Developer Mode was enabled, Windows returned `WinError 1314` when Python attempted to create a symlink.

### Optional integration tests (not part of the offline suite)
```bash
venv\Scripts\python.exe -m pytest tests/test_integration.py -v -m integration
```
These start MCP subprocesses; the LLM-chain test requires `GROQ_API_KEY` and uses whatever API mode is configured in the environment.

### Manual Live-Server Security-Gate Script
```bash
# Start Flask on localhost:5000 with ENABLE_DEBUG_ENDPOINTS=true, then run:
python tests/test_security_gates.py
```
This is a manual live-server script and is deliberately not collected by pytest. Automated coverage for its five confirmation checks is in `tests/test_security_gate_routes.py`.

### Docker Validation
```bash
# Before building
python validate_docker.py

# After docker compose up
python tests/test_docker_deployment.py
```

---

## Tech Stack

- **LLM:** Groq (LLaMA 3.3 70B) - Fast inference, function calling
- **MCP:** Model Context Protocol - Standardized tool interface
- **Web:** Flask - Lightweight web framework
- **Vector DB:** ChromaDB - Semantic log search when `USE_REAL_APIS=true`; stub search otherwise
- **APIs:** AbuseIPDB (IP reputation), Telegram (alerts)
- **Deployment:** Docker + docker-compose

---

## Project Structure

```
sentinelops/
├── server.py              # MCP server - defines tools
├── agent_shared.py        # Agent loop logic (reused by CLI and web)
├── cli.py                 # Terminal interface
├── web_ui.py              # Flask web interface + confirmation routes
├── templates/
│   └── index.html         # Web UI
├── tests/
│   ├── test_unit.py       # Fast unit tests
│   ├── test_integration.py # Full stack tests
│   ├── test_security_gate_routes.py # Offline Flask test_client() gates
│   ├── test_hardening.py   # Sandbox, audit, evidence, and tool-filter tests
│   └── ...                 # Manual/live-service scripts are excluded from pytest
├── data/                  # Runtime (gitignored)
│   ├── pending_actions.json
│   ├── action_log.jsonl
│   ├── firewall_sandbox/
│   ├── sentinelops_sandbox/
│   └── chromadb_sentinelops/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## Audit log and quarantine boundary

`data/action_log.jsonl` stores one JSON object per line for action outcomes, including rejected evidence and blocked execution attempts. Credential/token fields are omitted, configured secret values are redacted, and full message/file contents are not logged. The `get_action_log` tool reads the file and skips malformed lines.

Quarantine proposals and execution both resolve the candidate and sandbox paths with `realpath` and compare them using `commonpath`. Only paths inside `data/sentinelops_sandbox/` are eligible; the sandbox root and its quarantine subdirectory are excluded.

## Known limitations (by design for this demo)

- State uses JSON files without file locking; concurrent writers can race.
- Flask starts a new MCP subprocess per request. Evidence tokens and other MCP in-memory state do not survive across requests.
- Conversation history is stored in the Flask cookie session.
- `/confirm` and `/decline` have no CSRF protection.
- Generated action and evidence tokens are 8 hexadecimal characters.
- Flask uses a random secret key per restart unless `FLASK_SECRET_KEY` is set.
- Execution is sandbox-only; the demo does not change a real firewall or quarantine files outside its sandbox.
- Prompt injection through log content is bounded by the confirmation gate but can still influence the preview a human sees.

---

## Production Considerations

This is a demonstration platform. For production:

**Security:**
- [ ] Add HTTPS (nginx reverse proxy)
- [ ] Use secrets management (Docker secrets, Vault)
- [ ] Enable rate limiting
- [ ] Add authentication (OAuth, JWT)
- [ ] Audit logging to immutable storage

**Reliability:**
- [ ] Replace sandbox with real integrations
- [ ] Add monitoring (Prometheus + Grafana)
- [ ] Set up log aggregation
- [ ] Configure resource limits
- [ ] Implement health checks

**Compliance:**
- [ ] SOC 2 controls for change management
- [ ] Audit trail for all executed actions
- [ ] Role-based access control

See `ARCHITECTURE.md` for detailed design rationale and `Makefile` for common operations.

---

## Troubleshooting

**Port 5000 in use:**
```bash
# Use different port in docker-compose.yml
ports:
  - "8080:5000"
```

**Groq rate limit (free tier: 100k tokens/day):**
- Wait for reset (error shows time)
- Upgrade tier at console.groq.com
- Use `USE_REAL_APIS=false` for testing without API calls

**ChromaDB slow first request (~30s):**
- This is normal (model loading)
- Subsequent requests are fast
- Happens once per container start

**Docker build fails:**
```bash
docker system prune -a  # Clear cache
docker compose build --no-cache
```

---

## License

MIT License - see LICENSE file

---

## Acknowledgments

Built to demonstrate safe agent design patterns:
- **Evidence chains** - Prevent AI hallucination in critical decisions
- **Propose/execute split** - Separate planning from execution
- **Multi-gate validation** - Defense in depth
- **Process isolation** - Agent cannot bypass human confirmation

Inspired by real security operations workflows where humans remain accountable for destructive actions, even when AI suggests them.
