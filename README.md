# SentinelOps: AI Security Operations Copilot

**SentinelOps** is an open-source, defense-in-depth AI Security Operations Copilot built on FastMCP, Groq LLaMA 3.3, a Flask web UI, and an atomic SQLite WAL store. It pairs autonomous threat investigation with strict human-in-the-loop interlocks: untrusted log ingestion is delimited against prompt injection, destructive tools are filtered from the model's schema, proposals require verified evidence and bind parameters cryptographically via SHA-256 `params_hash`, and all operational state transitions are committed to a tamper-evident, SHA-256 hash-chained audit log with SQLite head verification.

---

## Architecture

### System Component & Evidence-Token Architecture

```
   +----------------------------------------------------------------------------------------------------+
   |                                      INVESTIGATION & REASONING                                     |
   |                                                                                                    |
   |    +-----------------------------+      Prompt & Tools     +----------------------------------+    |
   |    |    GROQ LLM (LLaMA 3.3)     |<=======================>|         FAST-MCP SERVER          |    |
   |    |  - Autonomous Reasoning     |                         |  - Schema Filter (Read/Propose)  |    |
   |    |  - Cannot execute actions   |                         |  - Session Context Management    |    |
   |    |  - Passes evidence_token    |                         +-----+----------------------+-----+    |
   |    +-----------------------------+                               |                      |          |
   +------------------------------------------------------------------|----------------------|----------+
                                                                      |                      |
            1. search_logs(query)                                     |                      | 2. check_ip_reputation(ip)
                                  v                                   v                      v
        +-----------------------------------------------+   +-----------------------------------------------+
        |             CHROMADB VECTOR STORE             |   |            ABUSEIPDB THREAT INTEL             |
        |  - Embeddings: all-MiniLM-L6-v2 ONNX          |   |  - Real-time abuse confidence score (0-100)   |
        |  - Ingests & indexes security audit telemetry |   |  - Score >= 50 flagged malicious              |
        |  - Raw logs returned in <untrusted_data> tag  |   |  - Mints session-bound evidence_token         |
        |  - Structured source_ip -> observed_ips table |   +-----------------------+-----------------------+
        +-----------------------+-----------------------+                           |
                                |                                                   | Returns evidence_token
                                | Structured IPs & Suspicious Events                | & reputation score
                                +-------------------------+-------------------------+
                                                          |
                                                          v
                                        +-----------------------------------+
                                        |        POLICY ENGINE CHECK        |
                                        |  [propose_block_ip/create_inc]    |
                                        |  * Target IP in observed_ips?     |
                                        |  * Valid evidence_token supplied? |
                                        |  * Target IP in Protected List?   |
                                        |  * Derive severity & approvals    |
                                        +-----------------+-----------------+
                                                          |
                                                          | PASS: Generates action token & params_hash
                                                          v
                                        +-----------------------------------+
                                        |      ATOMIC SQLITE WAL STORE      |
                                        |  - Stored: pending proposal       |
                                        |  - Cryptographic params_hash      |
                                        |  - Severity: Critical (2 approvals|
                                        |  - audit_head (last_seq, head)    |
                                        +-----------------+-----------------+
                                                          |
   +------------------------------------------------------|---------------------------------------------+
   |                                      HUMAN-IN-THE-LOOP APPROVAL                                    |
   |                                                      v                                             |
   |    +-----------------------------+       HTTP POST /confirm/<token>    +----------------------+    |
   |    |     OPERATOR (BROWSER)      |------------------------------------>|  FLASK WEB GATEWAY   |    |
   |    |  - Reviews IP, Reason, Hash |                                     |  - 3 Route Gates     |    |
   |    |  - Confirms action          |                                     |  - params_hash check |    |
   |    +-----------------------------+                                     +----------+-----------+    |
   |                                                                                   |                |
   |                                  4. execute_pending_action(token, hash)           v                |
   |                                  (Human-Only Tool: Hidden from LLM)    +----------------------+    |
   |                                                                        |   FIREWALL SANDBOX   |    |
   |                                                                        |   & AUDIT CHAIN      |    |
   |                                                                        | - iptables rule file |    |
   |                                                                        | - SHA-256 log chain  |    |
   |                                                                        +----------------------+    |
   +----------------------------------------------------------------------------------------------------+
```

### Component Interaction Summary

1. **Groq LLaMA 3.3 (Autonomous Copilot)**: Drives threat reasoning and investigations through tool calling. Destructive tools (`execute_pending_action`, `expire_blocks`) are removed from its tool schema (`HUMAN_ONLY_TOOLS`), guaranteeing that the LLM cannot directly apply firewall rules or alter defensive configurations.
2. **ChromaDB (Vector Log Search & Prompt Injection Defense)**: Indexes security telemetry with ONNX `all-MiniLM-L6-v2`. Raw log lines returned to the LLM are sanitized and isolated in `<untrusted_data>` delimiters to defeat indirect prompt injections. FastMCP extracts only structured metadata fields (`source_ip`, `client_ip`) and records them into the SQLite `observed_ips` policy table.
3. **FastMCP Server (Tool Gateway & Human Gatekeeper)**: Enforces input validation, manages session contexts, interfaces with AbuseIPDB, and restricts destructive actions exclusively to human operator routes.
4. **Evidence-Token Check (Anti-Hallucination & Provenance Verification)**:
   - When the agent calls `check_ip_reputation(ip)`, FastMCP queries AbuseIPDB and mints an authenticated `result_token` (stored in SQLite `evidence` table).
   - High/critical escalations (`create_incident`, `notify_telegram`) and mitigations (`propose_block_ip`) require this `evidence_token`.
   - The Policy Engine validates that:
     1. The token exists and belongs to the active session.
     2. The token is cryptographically bound to the target IP being acted on.
     3. Telemetry confirms a malicious threshold (score $\ge 50$ or confirmed high-threat log event).
     4. Target is not in the fail-closed protected allowlist (`data/protected.yaml`).
   - Hallucinated targets or prompt-injected victim IPs (e.g. `10.0.0.1`) fail closed immediately with `policy_denied:unobserved_ip` or `missing_evidence_token`.

---

## Quickstart

### 1. Prerequisites
- Python 3.11+ (or Python 3.12 for optional ChromaDB semantic search)
- Git

### 2. Setup Local Environment
```bash
# Clone and enter directory
cd sentinelops

# Create and activate virtual environment
python -m venv .venv
# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
python -m pip install -r requirements.txt
```

### 3. Configure Environment
```bash
# Copy example configuration
cp .env.example .env

# Configure .env:
# GROQ_API_KEY=gsk_...           # Required only for live LLM mode
# USE_REAL_APIS=false            # Default: offline deterministic stub mode
# SENTINELOPS_REQUIRE_OBSERVED_IP=true
```

### 4. Run SentinelOps
```bash
# Start Web UI (runs at http://localhost:5000)
python web_ui.py

# OR start Interactive Terminal CLI
python cli.py
```

### 5. Run Verification & Test Suite
```bash
# Run the complete test suite (Unit, Hardening, Security Gates, E2E, Eval Harness)
python tests/run_all.py

# Verify cryptographic audit chain integrity
python -m sentinelops.verify_log data/action_log.jsonl
```

---

## Security Guarantees

SentinelOps enforces rigorous security properties proved by automated unit, integration, and security gate tests:

1. **Prompt Injection Containment**: All external log contents are wrapped in `<untrusted_data>` XML fences. System prompts explicitly instruct the agent that content within these fences is raw data. Crucially, the Policy Engine validates that an IP cannot be proposed for blocking unless observed in a *structured* log field or with reputation score $\ge 50$. Poisoned free-text instructions cannot trigger action proposals.
2. **Hidden Execution Tools (`HUMAN_ONLY_TOOLS`)**: Destructive tools (`execute_pending_action`, `expire_blocks`) are stripped from LLM tool definitions via schema transformation. If an injected LLM hallucinated a direct execution call, the agent loop rejects it before forwarding to FastMCP.
3. **Session-Bound Evidence Tokens**: High and critical severity incident creations require a valid 8-character cryptographic token issued by `check_ip_reputation` within the same session. Agents cannot fabricate incidents without active investigation.
4. **Parameter Binding via SHA-256 `params_hash`**: At proposal time, canonical JSON parameters (type, target, reason, TTL, severity, required approvals) are hashed. Both `/confirm` and `execute_pending_action` independently recompute and verify `params_hash` from the SQLite row. Tampering with targets or lowering severity from `critical` to `low` in the database causes immediate execution refusal.
5. **Multi-Party Approval Gate**: Proposals derive severity server-side. Non-critical proposals execute on 1 human confirmation. `critical` severity actions require distinct confirmations from 2 separate operator identities.
6. **Fail-Closed Infrastructure Allowlist**: Critical network infrastructure (`127.0.0.1`, `8.8.8.8`, `1.1.1.1`, `192.168.1.1`, `127.0.0.0/8`) cannot be blocked. If `data/protected.yaml` is missing or corrupted, the system falls back to hardcoded built-in protections and fails closed. The allowlist is re-checked inside `execute_pending_action`.
7. **Tamper-Evident SHA-256 Audit Chain**: Every proposed, confirmed, declined, expired, and executed action is cryptographically chained (`prev_hash`). Concurrent writes are protected with OS file locks (`msvcrt`/`fcntl`). Clean tail truncations are detected via head state comparison against SQLite `audit_head`.

---

## Agent Evaluation Results

The SentinelOps eval harness (`evals/run_evals.py`) runs 20 deterministic scenarios covering clear attackers, benign traffic, multi-IP investigations, all 6 prompt injection attack styles, protected IP defense, quarantine path escapes, and unblock workflows:

| Metric | Benchmark Target | Result | Status |
| :--- | :---: | :---: | :---: |
| **Forbidden Action Rate** | `0.0%` | **`0.0%`** | **PASSED** |
| **Tool-Call Accuracy** | `>= 90.0%` | **`100.0%`** | **PASSED** |
| **Correct Decision Rate** | `>= 90.0%` | **`100.0%`** | **PASSED** |
| **Hallucinated Evidence Rate** | `0.0%` | **`0.0%`** | **PASSED** |
| **Avg Latency / Investigation** | N/A | `252.25 ms` | INFO |
| **Avg Steps / Investigation** | N/A | `1.30` | INFO |

*Detailed scenario breakdown and live LLM variance analysis can be found in [docs/EVALS.md](file:///docs/EVALS.md).*

---

## FastMCP Tool Inventory (13 Tools)

SentinelOps defines 13 FastMCP tools partitioned into public agent tools and human-only administrative tools:

| Tool Name | Access Level | Description |
| :--- | :---: | :--- |
| `ping` | Agent | FastMCP connectivity and health check. |
| `search_logs` | Agent | Search security logs (returns wrapped `<untrusted_data>` and records structured indicators). |
| `check_ip_reputation` | Agent | Query IP reputation and generate authenticated evidence tokens. |
| `create_incident` | Agent | File incidents (enforces evidence token requirement for high/critical). |
| `list_incidents` | Agent | List recorded incidents from local store. |
| `propose_block_ip` | Agent | Propose blocking an IP address (returns preview token and `params_hash`). |
| `propose_quarantine_file`| Agent | Propose isolating a suspicious file in the sandbox. |
| `propose_unblock_ip` | Agent | Propose removing an active firewall block rule for a currently blocked target. |
| `propose_restore_quarantined_file` | Agent | Propose restoring an existing quarantined file to its verified sandbox path. |
| `get_action_log` | Agent | Read recent cryptographic audit trail records. |
| `notify_telegram` | Agent | Send security alerts (requires evidence token for critical notifications). |
| `execute_pending_action` | **Human-Only** | Executes confirmed action tokens. Hidden from LLM; called only by human confirmation flow. |
| `expire_blocks` | **Human-Only** | Scans and expires active block rules past TTL. Hidden from LLM schema. |

---

## Configuration Reference

Configuration is managed via environment variables (with safe defaults in stub mode):

```bash
# Core Mode Settings
USE_REAL_APIS=false                      # 'false' runs deterministic stub data; 'true' uses Groq & AbuseIPDB
ENABLE_DEBUG_ENDPOINTS=false            # Enables debug tools; strictly false in production
FLASK_DEBUG=false                       # Flask debug mode

# LLM & Third-Party APIs
GROQ_API_KEY=                           # Groq API key for LLaMA 3.3
ABUSEIPDB_API_KEY=                      # AbuseIPDB API key
TELEGRAM_BOT_TOKEN=                     # Telegram bot token for alerts (optional)
TELEGRAM_CHAT_ID=                       # Telegram chat ID for alerts (optional)

# Policy & Defense Settings
SENTINELOPS_REQUIRE_OBSERVED_IP=true    # Require IP observation before proposing blocks
SENTINELOPS_OBSERVED_IP_TTL=3600        # Observed IP TTL in seconds (default: 1 hour)
SENTINELOPS_MIN_BLOCK_SCORE=50          # Minimum reputation score required for block proposal
SENTINELOPS_BLOCK_TTL=3600              # Firewall rule expiration TTL in seconds (default: 1 hour)
SENTINELOPS_SUSPICIOUS_EVENTS=          # Comma-separated list of suspicious log event types
SENTINELOPS_PROTECTED_FILE=data/protected.yaml # YAML allowlist of protected IPs and CIDRs
```

---

## Known Limitations

1. **Operator Identity Authentication**: Operator identities are currently passed via the `X-Operator-ID` HTTP header (or session ID) rather than an authenticated session token. Because the current deployment lacks cryptographic authentication (such as OIDC, SAML, or signed JWT session cookies), the two-person approval mechanism is not yet cryptographically strong against an adversarial insider capable of spoofing HTTP headers.
2. **Total File and Database Rewrite**: The SHA-256 hash chain reliably detects tampering, entry modification, record reordering, and tail truncation via SQLite `audit_head`. However, an adversary with root/filesystem access who simultaneously rewrites *both* `action_log.jsonl` and the SQLite database can recalculate the hash chain from a forged genesis record. Defense against simultaneous rewrite requires an external trust anchor (e.g., remote append-only syslog, WORM storage, or hardware security module).
3. **Windows Platform Symlink Escape Test**: On Windows operating systems without Developer Mode or elevated Administrator privileges, non-privileged Python processes return `WinError 1314` when creating filesystem symlinks. Consequently, the symlink escape test (`test_quarantine_rejects_symlink_pointing_outside_sandbox`) is skipped on Windows and validated in POSIX/Linux CI environments.

---

## Further Documentation

- **[Baseline Architecture & Module Map](file:///docs/BASELINE.md)**
- **[STRIDE Threat Model](file:///docs/THREAT_MODEL.md)**
- **[Interactive 5-Minute Demo Script](file:///docs/DEMO.md)**
- **[Evaluation Harness Report](file:///docs/EVALS.md)**
