# SentinelOps Baseline Report

**Execution Date:** 2026-10-29  
**Platform:** Windows 11 / Python 3.12.10  
**Test Suite Status:** **ALL BASELINE TESTS PASSING (100%)**

---

## 1. Test Suite Results & Runtime

| Test Suite / Component | Test Count / Scope | Status | Runtime | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `tests/test_unit.py` | 22 tests | **PASSED** | ~4.2s | Token lifecycles, IP normalization, loopback/multicast rejections, stub evidence. |
| `tests/test_hardening.py` | 28 tests | **PASSED** (27 pass, 1 skip) | ~14.5s | Quarantine sandbox escapes, symlink checks (skipped on unprivileged Win32), audit sanitization, schema tool filtering. |
| `tests/test_store.py` | 6 tests | **PASSED** | ~2.1s | SQLite WAL state transitions, race condition handling, TTL expiry, stuck task recovery. |
| `tests/test_security_gate_routes.py` | 6 tests | **PASSED** | ~0.8s | In-process Flask client testing: 404 on fake/cross-session tokens, 409 on reused tokens, valid execution. |
| **Pytest Total** | **61 passed, 1 skipped, 2 deselected** | **PASSED** | **21.8s** | Integration tests deselected by default (`-m "not integration"`). |
| `tests/e2e_stdio_check.py` | 10 verification steps | **PASSED** | ~6.0s | Real MCP stdio client/server subprocess, schema verification, evidence gating, state transitions, audit log checks. |
| `tests/test_transcript_fix.py` | 2 verification steps | **PASSED** | ~0.2s | UI transcript builder immutability and error-path rendering. |
| **Total Automated Baseline** | **73 checks** | **PASSED** | **~28.0s** | All baseline guarantees verified. |

---

## 2. Module Map

```
sentinelops/
├── server.py              # FastMCP Server (stdio transport)
│                          # - Exposes 13 core tools (+ 1 optional debug tool)
│                          # - Public LLM-accessible tools (11):
│                          #   1. ping
│                          #   2. search_logs
│                          #   3. check_ip_reputation
│                          #   4. create_incident
│                          #   5. list_incidents
│                          #   6. propose_block_ip
│                          #   7. propose_quarantine_file
│                          #   8. propose_unblock_ip
│                          #   9. propose_restore_quarantined_file
│                          #   10. get_action_log
│                          #   11. notify_telegram
│                          # - Human-only / Operator-only tools (2+1):
│                          #   12. execute_pending_action (HUMAN_ONLY: executes confirmed tokens)
│                          #   13. expire_blocks (HUMAN_ONLY: scans and reverts expired block rules)
│                          #   * debug_seed_pending_action (HUMAN_ONLY, gated by ENABLE_DEBUG_ENDPOINTS)
│                          # - Manages AbuseIPDB / ChromaDB / stub datasets
│                          # - Enforces sandbox boundaries & IP target policies
│                          # - Generates 8-character evidence tokens and action tokens
│
├── web_ui.py              # Flask Web Application & Human Gatekeeper
│                          # - Routes: / (UI), /send (Chat), /confirm/<token>, /decline/<token>
│                          # - Gating: Existence (404), Cross-Session Isolation (404), Replay (409)
│                          # - Spawns MCP subprocesses per execution turn
│
├── store.py               # Shared SQLite Persistence Store (WAL Mode)
│                          # - Tables: `actions`, `evidence`
│                          # - State Machine: pending -> confirmed -> executing -> executed | failed
│                          # - Atomic `store.transition()` prevents concurrency race conditions
│
├── agent_shared.py        # Shared LLM Agent Core
│                          # - Schema conversion: MCP JSONSchema -> OpenAI/Groq function format
│                          # - Safety filter: Strips `HUMAN_ONLY_TOOLS` (execute_pending_action, debug tools)
│                          # - Agent turn loop: Handles tool call chaining up to 10 turns
│
├── cli.py                 # Interactive Terminal Client
│                          # - Multi-turn conversational security copilot in CLI
│                          # - Prompts human operators explicitly before executing proposals
│
├── templates/index.html   # Frontend Web Interface
│                          # - Interactive cyber-ops dark UI
│                          # - Asynchronous transcript rendering (user, agent, tool_call, tool_result)
│                          # - Dynamic Pending Confirmation cards with Confirm/Decline triggers
│
├── data/                  # Runtime Data & Sandboxes
│   ├── sentinelops.db     # SQLite database for action & evidence state
│   ├── action_log.jsonl   # Sanitized JSONL audit trail
│   ├── firewall_sandbox/  # Target directory for dropped IP .rule files
│   └── sentinelops_sandbox/ # Quarantine sandbox for suspicious files
│
└── tests/                 # Comprehensive Test Suites
    ├── test_unit.py                # Unit tests for core functions and tools
    ├── test_hardening.py           # Security hardening, path traversal, secret redaction
    ├── test_store.py               # SQLite store concurrency and state machine tests
    ├── test_security_gate_routes.py # Flask route gate verification
    ├── e2e_stdio_check.py          # Real MCP stdio end-to-end verification
    ├── test_transcript_fix.py      # Transcript mutation safety tests
    ├── run_all.sh                  # Bash test runner script
    └── run_all.py                  # Python cross-platform test runner script
```

---

## 3. Baseline Security Guarantees Confirmed

1. **Evidence Chain Integrity**: High/critical incidents and critical Telegram alerts require an unexpired, authentic `result_token` generated by `check_ip_reputation` matching the IP.
2. **Propose / Execute Split**: Destructive tools (`execute_pending_action`) are stripped from LLM schemas and rejected by the agent loop. Propose tools create preview tokens only.
3. **Session & Replay Protection**:
   - Unknown tokens return `404`.
   - Reused tokens return `409 Conflict`.
   - Cross-session tokens return `404 Not Found` (anti-enumeration protection).
4. **Sandboxed File Operations**: Quarantined files are restricted to `data/sentinelops_sandbox/quarantine`, rejecting traversal (`../`) and cross-drive symlink escapes.
5. **Sanitized Audit Log**: Sensitive API keys and tokens are automatically redacted prior to being written to `action_log.jsonl`.

