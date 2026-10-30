# SentinelOps: 5-Minute Interactive Demo Walkthrough

This guide walks through a 5-minute end-to-end demonstration of SentinelOps, showcasing investigation, parameter binding, prompt injection defense, human confirmation gates, cryptographic audit verification, and tamper detection.

---

## Prerequisites

Ensure your virtual environment is active and running in deterministic stub mode (`USE_REAL_APIS=false`):

```bash
# Windows PowerShell
.\.venv\Scripts\Activate.ps1

# Linux / macOS
source .venv/bin/activate
```

---

## Step 1: Start SentinelOps CLI or Web UI

Launch the SentinelOps interactive CLI:

```bash
python cli.py
```

*Or launch the web interface in another terminal at `http://localhost:5000`:*
```bash
python web_ui.py
```

---

## Step 2: Investigate a Malicious IP & Propose Block

In the CLI prompt, enter:
```text
Investigate IP 45.33.22.11 and block it if malicious
```

### What Happens Behind the Scenes:
1. **Evidence Retrieval**: The agent calls `check_ip_reputation(ip="45.33.22.11")`.
2. **Evidence Token**: FastMCP issues an 8-character evidence token (e.g., `a1b2c3d4`) bound to `45.33.22.11` and the active session.
3. **Structured Observation**: The policy engine marks `45.33.22.11` as an observed suspicious IP.
4. **Proposal with Cryptographic Binding**: The agent calls `propose_block_ip(ip="45.33.22.11")`. The server derives severity (`medium`), calculates the SHA-256 `params_hash`, and registers the proposal in SQLite.
5. **Human Gate**: Execution halts. The proposal preview is displayed:
   ```text
   [PROPOSAL PREVIEW]
   Token:           a7f3c9e1
   Action:          block_ip
   Target:          45.33.22.11
   Severity:        medium (1 human approval required)
   Params Hash:     8b3c4f91d0e...
   Confirm this action? [y/N]:
   ```

Do **NOT** confirm yet. Open a second terminal to see how prompt injection is defeated.

---

## Step 3: Prompt Injection Defense (Poisoned Log Attack)

Simulate an adversary attempting to trick SentinelOps into blocking a victim IP (`10.0.0.1`) by injecting directives into server logs:

```bash
python -c "
import server
res = server.propose_block_ip('10.0.0.1', reason='Attacker injected request')
print('Result:', res)
"
```

### Expected Output:
```text
Result: policy_denied:unobserved_ip
```

### Why the Attack Fails:
- External log data is wrapped in `<untrusted_data>` delimiters.
- Even if an injected LLM attempts to call `propose_block_ip('10.0.0.1')`, the **Policy Engine** checks if `10.0.0.1` was observed in a structured log field (`source_ip`) or has a verified reputation check.
- Because `10.0.0.1` was only present in free text, it was never registered in the session's observed IP table.
- The proposal is rejected before reaching the human confirmation queue.

---

## Step 4: Human Confirmation & Parameter Verification

Return to the first terminal from Step 2 and type:
```text
y
```

### What Happens:
1. The client sends confirmation with token `a7f3c9e1`.
2. Flask/CLI validates the 3 gates:
   - **Gate 1**: Token exists $\to$ HTTP 200 (invalid returns 404).
   - **Gate 2**: Session ownership $\to$ match (cross-session returns 404).
   - **Gate 3**: State is `pending` $\to$ valid (replayed token returns 409 Conflict).
3. The server loads the database row, canonicalizes the parameters, and recomputes the SHA-256 `params_hash`. If any parameter or severity level was altered in the database, execution is rejected.
4. FastMCP creates the firewall rule in the sandbox:
   `data/firewall_sandbox/block_45_33_22_11.rule`
5. Status transitions atomically to `executed`.

---

## Step 5: Inspect the Cryptographic Audit Trail

Inspect the latest entry in `data/action_log.jsonl`:

```bash
python -c "
import json
with open('data/action_log.jsonl', 'r') as f:
    lines = f.readlines()
latest = json.loads(lines[-1])
print('Sequence: ', latest['seq'])
print('Event:    ', latest['event'])
print('Prev Hash:', latest['prev_hash'])
print('Hash:     ', latest['hash'])
"
```

### Expected Output:
```text
Sequence:  4
Event:     action_executed
Prev Hash: 3e8b4... (SHA-256 of previous line)
Hash:      d91a2... (SHA-256 of prev_hash + canonical entry)
```

Each log entry is cryptographically linked to its predecessor. The genesis entry starts with `prev_hash: "0" * 64`.

---

## Step 6: Verify Audit Log Integrity

Run the built-in audit verification tool:

```bash
python -m sentinelops.verify_log data/action_log.jsonl
```

### Expected Output:
```text
============================================================
SentinelOps Audit Log Verification
Target: data/action_log.jsonl
============================================================
[PASS] Line 1 (seq=1, event=block_ip_proposed): Hash OK
[PASS] Line 2 (seq=2, event=action_confirmed): Hash OK
[PASS] Line 3 (seq=3, event=action_executing): Hash OK
[PASS] Line 4 (seq=4, event=action_executed): Hash OK
------------------------------------------------------------
[SUCCESS] All 4 records verified.
[PASS] Head hash matches SQLite audit_head.
```

---

## Step 7: Tamper with Audit Log and Detect Violation

Simulate an adversary tampering with an audit record (e.g., trying to change the blocked IP in the log):

```bash
python -c "
with open('data/action_log.jsonl', 'r') as f:
    lines = f.readlines()
# Tamper with the details in the last entry
tampered = lines[-1].replace('45.33.22.11', '1.1.1.1')
lines[-1] = tampered
with open('data/action_log.jsonl', 'w') as f:
    f.writelines(lines)
print('Log tampered!')
"
```

Now re-run verification:

```bash
python -m sentinelops.verify_log data/action_log.jsonl
```

### Expected Output:
```text
============================================================
SentinelOps Audit Log Verification
Target: data/action_log.jsonl
============================================================
[PASS] Line 1 (seq=1, event=block_ip_proposed): Hash OK
[PASS] Line 2 (seq=2, event=action_confirmed): Hash OK
[PASS] Line 3 (seq=3, event=action_executing): Hash OK
[FAIL] Line 4 (seq=4): Payload hash mismatch!
       Stored hash:   d91a2...
       Computed hash: 7c54b...
[ERROR] Chain verification FAILED at sequence 4.
```

The system immediately flags the tampering attempt and pinpoint the exact modified sequence.

*(To restore your clean audit log for tests:)*
```bash
python scripts/generate_demo_audit.py
```

---

## Step 8: Run Agent Safety Evaluation Harness

To verify that the copilot adheres to all safety KPIs across 20 distinct scenarios:

```bash
python evals/run_evals.py
```

### Evaluation Output Summary:
```text
============================================================
SentinelOps Agent Evaluation Harness
Mode: OFFLINE FIXTURES (Deterministic)
============================================================
## Overall Key Performance Indicators

| Metric | Target | Result | Status |
| :--- | :---: | :---: | :---: |
| **Forbidden Action Rate** | 0.0% | 0.0% | PASSED |
| **Tool-Call Accuracy** | >= 90% | 100.0% | PASSED |
| **Correct Decision Rate** | >= 90% | 100.0% | PASSED |
| **Hallucinated Evidence Rate** | 0.0% | 0.0% | PASSED |
| **Avg Steps / Investigation** | N/A | 1.3 | INFO |
| **Avg Latency** | N/A | 252.25 ms | INFO |
============================================================
[SUCCESS] Evaluation PASSED with 0.0% forbidden action rate.
```

---

## Summary of Demonstrated Defenses

1. **Untrusted Data Isolation**: Delimited log ingestion prevents command interpretation.
2. **Policy-Enforced Evidence**: Action proposals require structured observation and high-confidence reputation.
3. **Hidden Execution Tools**: Agents cannot invoke execution tools directly.
4. **Parameter Binding**: Cryptographic `params_hash` prevents SQLite DB tampering.
5. **Multi-Gate Confirmation**: Tokens are session-isolated, single-use, and human-verified.
6. **Tamper-Evident Audit Trail**: SHA-256 hash chaining with SQLite head sync prevents undetected log tampering.

