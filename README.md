# SentinelOps

**AI-Powered Security Operations with Human-in-the-Loop Safety**

An intelligent security operations platform demonstrating safe LLM agent design through multi-layered guardrails. Built with the Model Context Protocol (MCP), SentinelOps shows how to give AI agents access to destructive operations while maintaining rigorous human control.

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
    evidence_token="f5bce9c4"  # REQUIRED for high/critical severity
)
```

The server validates:
1. Token exists in recent reputation checks
2. Token's IP matches the incident claim
3. Token's data actually shows `is_malicious: true`

**Result:** The model cannot fabricate high-severity incidents. It must provide evidence it actually retrieved.

### Layer 2: Human-in-the-Loop Execution Gate

**Problem:** Even with evidence, we don't want the LLM to execute destructive actions directly. A `confirmed=true` parameter is too easy for the model to add on its own.

**Solution:** Propose/execute split enforced by separate processes.

**Propose phase** (agent has access):
```python
result = propose_block_ip(
    ip="185.220.101.1",
    reason="Malware distribution"
)
# Returns: "PREVIEW: Would block IP... Token: a3f7c491"
# NO actual execution happens here
```

**Execute phase** (agent does NOT have access):
```python
# This tool exists, but agent is never given access to it
execute_pending_action(token="a3f7c491")
```

Instead, the Flask web UI provides `/confirm/<token>` and `/decline/<token>` routes that **humans** trigger by clicking buttons. The agent sees the proposal result but cannot proceed without the human's explicit POST request to Flask.

**Why this works:**
- The agent cannot call `execute_pending_action` because it's never in its tool list
- Even if the agent tries to manipulate its own context, the execution happens in a separate process (Flask) that only responds to HTTP requests from the user's browser session
- Tokens are session-scoped—even if the agent somehow got a valid token, it couldn't forge the session cookie

### Layer 3: Multi-Gate Validation

Even with human confirmation, Flask validates three gates before executing:

```python
# Gate 1: Token exists
if token not in pending_actions:
    return 404

# Gate 2: Token belongs to your session
if action['session_id'] != current_session:
    return 403

# Gate 3: Token hasn't been used already
if action['status'] != 'pending':
    return 400
```

**Result:** No replay attacks, no cross-session hijacking, no double-execution.

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
        │            │ - Agent gets tool list (NO execute_pending_action)
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
        │            │ - execute_pending_action: NOT in agent's tool list
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
git clone https://github.com/yourusername/sentinelops.git
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
USE_REAL_APIS=true                      # false = stub mode for testing
ENABLE_DEBUG_ENDPOINTS=false            # NEVER true in production
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

**The fix:** `pending_actions.json` is the single source of truth. Both processes read and write to the same file. No desynch possible.

### Why Sandbox-Only Execution?

All destructive operations target sandboxed directories:
- Firewall rules → `data/firewall_sandbox/` (not actual iptables)
- Quarantined files → `data/sentinelops_sandbox/quarantine/` (path-validated)

**Rationale:** This is a demonstration/development platform. In production, you'd replace the sandbox with real integrations (actual firewall API, real quarantine system), but the confirmation flow remains the same.

---

## Testing

### Unit Tests (Fast)
```bash
python -m pytest tests/test_unit.py -v
# 7 tests, <5 seconds
```

### Integration Tests (Requires APIs)
```bash
python -m pytest tests/test_integration.py -v -m integration
# Full MCP stack, ~30 seconds
```

### Security Gate Tests
```bash
# Flask must be running on localhost:5000
python tests/test_security_gates.py
```

Validates:
- ✅ Valid token + correct session → executes
- ✅ Fake token → 404
- ✅ Reused token → 400
- ✅ Cross-session token → 403
- ✅ Declined action → no execution

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
- **Vector DB:** ChromaDB - Semantic log search (future feature)
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
│   ├── test_security_gates.py # Security validation
│   └── ...                # Additional test files
├── data/                  # Runtime (gitignored)
│   ├── pending_actions.json
│   ├── firewall_sandbox/
│   └── chromadb_sentinelops/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

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

