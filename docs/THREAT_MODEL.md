# SentinelOps STRIDE Threat Model

SentinelOps is an AI Security Operations Copilot operating in an untrusted security operations environment. This threat model details the STRIDE threats, affected components, security mitigations, and automated tests proving those mitigations.

---

## 1. Trust Boundaries & Architecture Overview

```
+-------------------------------------------------------------+
|                     UNTRUSTED INTERNET                      |
| (Malicious Log Payloads, Compromised Hosts, Spoofed IPs)    |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                      INGESTION BOUNDARY                     |
|  - Log Sanitization & Delimiting (<untrusted_data>)         |
|  - IP Normalization (RFC 3986, IPv4/IPv6 canonicalization)  |
|  - Structured-Field-Only IP Extraction                      |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                     COPILOT AGENT LOOP                      |
|  - Groq LLM (Prompt-Sandboxed via Delimiters)               |
|  - Strict FastMCP Tool Schema Filtering                     |
|  - Zero Destructive Tools in Agent View (Human-Only)        |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                  POLICY ENGINE BOUNDARY                     |
|  - Session-Scoped Evidence Grounding (Suspicious Log / Rep) |
|  - Server-Derived Severity & Multi-Party Approval Gate      |
|  - Protected Infrastructure Allowlist (Fail-Closed)         |
|  - Cryptographic params_hash Canonicalization (SHA-256)     |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                   HUMAN CONFIRMATION GATE                   |
|  - Web UI & CLI Human-in-the-Loop Interlocks                |
|  - 3 Security Gates (Existence -> Session -> Pending)       |
|  - Cryptographic params_hash Verification at Execution      |
|  - Tamper-Evident SHA-256 Hash Chained Audit Log + SQLite   |
+-------------------------------------------------------------+
```

---

## 2. STRIDE Threat Matrix

| STRIDE Category | Threat Description | Affected Component | Security Mitigation | Proving Test Case |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | **Token Enumeration & Cross-Session Access**: Attacker guesses pending confirmation tokens or accesses actions from other operator sessions. | Web UI (`web_ui.py`), Action Store (`store.py`) | Tokens are 8-character cryptographically random strings. Gate 1 returns 404 for nonexistent tokens. Gate 2 enforces session isolation, returning 404 (not 403) for tokens belonging to other sessions to prevent token enumeration. | [test_security_gate_routes.py::test_nonexistent_token_returns_404_not_revealing_existence](file:///tests/test_security_gate_routes.py#L22)<br>[test_security_gate_routes.py::test_cross_session_token_returns_404](file:///tests/test_security_gate_routes.py#L32) |
| **Spoofing** | **Operator Identity Header Spoofing**: In multi-party approval workflows, an unauthenticated client could attempt to impersonate different operators via the `X-Operator-ID` HTTP header. | Web UI (`web_ui.py`), Action Store (`store.py`) | System requires distinct operator identities for critical tier approvals. Current design isolates operator tracking and records identities in SQLite; documented requirement for authenticated sessions in production. | [test_policy_confirmation.py::test_operator_identity_header_behavior](file:///tests/test_policy_confirmation.py#L250) |
| **Tampering** | **Parameter Tampering via SQLite DB Mutation**: Attacker or compromised agent modifies pending proposal parameters (e.g. changes target IP or lowers severity from `critical` to `low`) between proposal and execution. | FastMCP Server (`server.py`), Web UI (`web_ui.py`) | Every proposal binds its canonical JSON parameters into a SHA-256 `params_hash`. Both `/confirm` and `execute_pending_action` recompute and verify `params_hash`. Execution is refused if parameters or severity are mutated. | [test_policy_confirmation.py::test_params_hash_computation_and_verification](file:///tests/test_policy_confirmation.py#L112)<br>[test_policy_confirmation.py::test_mutated_db_row_target_changed_refused_at_execution](file:///tests/test_policy_confirmation.py#L135)<br>[test_policy_confirmation.py::test_mutated_db_row_severity_lowered_refused_at_execution](file:///tests/test_policy_confirmation.py#L162) |
| **Tampering** | **Audit Log Tampering & Truncation**: Attacker modifies existing entries, injects forged records, or truncates the tail of `action_log.jsonl` to erase evidence. | Audit Chain (`audit_chain.py`), Verification Tool (`verify_log.py`) | Each audit record embeds a SHA-256 cryptographic hash over `(seq, prev_hash, timestamp, payload_hash)`. Sequential head hash and count are simultaneously mirrored in the WAL SQLite `audit_head` table. Any modification, insertion, or tail deletion is immediately flagged. | [test_audit_chain.py::test_tampered_payload_detected](file:///tests/test_audit_chain.py#L38)<br>[test_audit_chain.py::test_tampered_prev_hash_detected](file:///tests/test_audit_chain.py#L52)<br>[test_audit_chain.py::test_tampered_sequence_detected](file:///tests/test_audit_chain.py#L66)<br>[test_audit_chain.py::test_clean_tail_deletion_detected_via_sqlite_audit_head](file:///tests/test_audit_chain.py#L80) |
| **Tampering** | **Quarantine Metadata Tampering**: Malicious modification of `.metadata` file during file restore targeting directories outside sandbox. | FastMCP Server (`server.py`), Reversible Actions | Target restore paths are re-validated against sandbox boundary inside `execute_pending_action`. Tampered destination paths escaping the sandbox are refused (`tampered_metadata_outside_sandbox`). | [test_reversible_actions.py::test_tampered_metadata_pointing_outside_sandbox_refused_at_execution](file:///tests/test_reversible_actions.py#L168) |
| **Repudiation** | **Unaudited or Unattributed Destructive Actions**: Actions taken by operator or agent without permanent cryptographic record. | Audit Chain (`audit_chain.py`), Action Store (`store.py`) | Every proposed, confirmed, declined, expired, and executed action is written synchronously to `action_log.jsonl` with file locking (`msvcrt`/`fcntl`) and hashed to the previous entry. Missing or corrupted entries break the verification chain. | [test_audit_chain.py::test_clean_chain_verifies](file:///tests/test_audit_chain.py#L22)<br>[test_hardening.py::test_audit_log_persists_calls_and_skips_malformed_lines](file:///tests/test_hardening.py#L187) |
| **Information Disclosure** | **Secret & Credential Leakage in Audit Logs**: Passwords, API tokens, Authorization headers, or private keys written to audit records. | FastMCP Server (`server.py`), Audit Chain (`audit_chain.py`) | Comprehensive secret redaction engine sanitizes payloads before hashing and writing to disk. Patterns matching API keys, Bearer tokens, passwords, and private keys are replaced with `[REDACTED]`. | [test_audit_chain.py::test_secrets_never_appear_in_audit_chain](file:///tests/test_audit_chain.py#L96)<br>[test_hardening.py::test_log_action_does_not_persist_secret_fields](file:///tests/test_hardening.py#L210) |
| **Information Disclosure** | **Path Traversal & Arbitrary File Access**: Attacker requests quarantine or restore of critical host files (`../../../../etc/passwd` or `C:\Windows\System32`). | FastMCP Server (`server.py`), Quarantine Subsystem | Absolute path resolution and containment checking against configured sandbox directory (`DATA_DIR/sandbox`). Directory traversal (`..`), root paths, and symlink escapes outside sandbox are rejected at proposal and execution. | [test_hardening.py::test_quarantine_proposal_contains_target_and_rejects_escape_paths](file:///tests/test_hardening.py#L135)<br>[test_reversible_actions.py::test_restore_path_traversal_and_escape_rejected](file:///tests/test_reversible_actions.py#L140) |
| **Denial of Service** | **Indirect Prompt Injection**: Attacker injects instructions into log lines (User-Agent, URL, error message) instructing copilot to block victim or protected IP. | Agent Prompts (`agent_shared.py`), Policy Engine (`policy.py`) | External log records are enclosed in `<untrusted_data>` XML fences with system instructions prohibiting interpretation as directives. Crucially, the Policy Engine enforces IP observation only via structured log fields and suspicious events, rejecting unobserved or benign IPs. | [test_injection.py::test_search_logs_poisoned_free_text_does_not_observe_victim_ip_for_all_six_styles](file:///tests/test_injection.py#L86)<br>[test_injection.py::test_poisoned_log_injection_styles_cannot_force_block_or_execute](file:///tests/test_injection.py#L125) |
| **Denial of Service** | **Blocking Protected Infrastructure & Network DoS**: Agent tricked into proposing blocks against DNS resolvers (`8.8.8.8`, `1.1.1.1`), default gateway (`192.168.1.1`), internal subnets, or loopback. | Policy Engine (`policy.py`), FastMCP Server (`server.py`) | Dual-layer protected allowlist check at proposal time and execution time against `data/protected.yaml`. If configuration file is missing or corrupt, engine fails closed using hardcoded protected defaults (`BUILTIN_PROTECTED_IPS` & `BUILTIN_PROTECTED_CIDRS`). | [test_policy_confirmation.py::test_protected_allowlist_ips_and_cidrs_rejected_at_propose_time](file:///tests/test_policy_confirmation.py#L22)<br>[test_policy_confirmation.py::test_allowlist_recheck_inside_execute_pending_action](file:///tests/test_policy_confirmation.py#L52)<br>[test_policy_confirmation.py::test_fail_closed_on_missing_or_malformed_protected_yaml](file:///tests/test_policy_confirmation.py#L75) |
| **Denial of Service** | **Unblocking Never-Blocked Targets**: Disruption of blocklist state by submitting spurious unblock requests. | FastMCP Server (`server.py`), Policy Engine | `propose_unblock_ip` and `propose_restore_quarantined_file` query active state before issuing proposals; targets not currently blocked or quarantined are rejected immediately. | [test_reversible_actions.py::test_proposing_unblock_for_never_blocked_ip_is_rejected](file:///tests/test_reversible_actions.py#L78)<br>[test_reversible_actions.py::test_proposing_restore_for_non_quarantined_file_is_rejected](file:///tests/test_reversible_actions.py#L96) |
| **Elevation of Privilege** | **Replay & Double-Execution**: Submitting confirmation multiple times to execute duplicate destructive actions or reopen expired actions. | Web UI (`web_ui.py`), Action Store (`store.py`) | Atomic SQLite WAL state transition (`store.transition`). Gate 3 rejects any token not in `pending` state with HTTP 409 Conflict. Replay attacks fail atomically. | [test_security_gate_routes.py::test_reused_token_returns_409](file:///tests/test_security_gate_routes.py#L42)<br>[test_confirm_consistency.py::test_confirm_once_then_409](file:///tests/test_confirm_consistency.py#L18) |
| **Elevation of Privilege** | **Agent-Callable Destructive Execution**: LLM bypasses human gate by directly calling execution tools (`execute_pending_action`, `expire_blocks`). | FastMCP Server (`server.py`), Agent Bridge (`agent_shared.py`) | Destructive and administrative tools are marked in `HUMAN_ONLY_TOOLS` and stripped from the agent schema. If the LLM generates an unexposed tool call, `agent_shared.py` rejects it immediately without forwarding to FastMCP. | [test_hardening.py::test_tool_conversion_filters_human_only_tools](file:///tests/test_hardening.py#L25)<br>[test_reversible_actions.py::test_model_visible_tools_excludes_expire_blocks_and_human_only_tools](file:///tests/test_reversible_actions.py#L25)<br>[test_hardening.py::test_agent_rejects_unexposed_tool_without_calling_mcp](file:///tests/test_hardening.py#L50) |
| **Elevation of Privilege** | **Hallucinated Evidence Incident Escalation**: LLM hallucinates evidence tokens or invents threat indicators to create critical severity incidents or trigger notifications. | FastMCP Server (`server.py`), Action Store (`store.py`) | `create_incident` and `notify_telegram` enforce evidence matrix: high/critical incidents require a valid, session-bound `evidence_token` generated by `check_ip_reputation`. Propose block requires verified log hit or reputation score $\ge 50$. | [test_hardening.py::test_create_incident_evidence_matrix](file:///tests/test_hardening.py#L75)<br>[test_policy_confirmation.py::test_insufficient_evidence_blocks_rejected](file:///tests/test_policy_confirmation.py#L185)<br>[test_policy_confirmation.py::test_benign_event_does_not_justify_block](file:///tests/test_policy_confirmation.py#L215) |

---

## 3. Residual Risks & Security Scope Boundaries

1. **Operator Identity Authentication**: Current multi-party approval relies on the `X-Operator-ID` HTTP header for identifying approving operators. While isolated across sessions and tracked in the SQLite action store, this does not constitute cryptographic mutual authentication. Production deployments must integrate an identity provider (e.g., OIDC/SAML) with cryptographically signed session tokens.
2. **Global Database & Audit Log Rewrite**: The SHA-256 tamper-evident hash chain detects payload tampering, sequence tampering, and tail deletion via SQLite `audit_head`. However, an adversary with full filesystem access who simultaneously rewrites both `action_log.jsonl` and the SQLite database can recalculate the chain from a new genesis point. Protection against simultaneous rewrite requires an external anchor (e.g., remote append-only syslog, WORM storage, or external timestamp authority).
3. **OS-Specific Symlink Traversal Verification**: On Windows platforms without Developer Mode or elevated Administrator privileges, creation of filesystem symlinks is restricted by the operating system. Symlink traversal tests are skipped on Windows and validated on POSIX environments.

