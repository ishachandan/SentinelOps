"""
Tests for Step 3: Policy Engine and Parameter-Bound Confirmation.
Validates:
3a. Protected allowlist (data/protected.yaml + env) prevents blocking protected IPs/CIDRs.
3b. Severity-based approval tiers: low/medium need 1 confirmation; critical needs 2 distinct confirmations.
3c. Parameter binding: proposal computes params_hash; /confirm refuses mismatching hash;
    execute_pending_action re-verifies immediately before acting and refuses mutated DB rows.
3d. All existing gate constraints remain intact.
"""
import json
import os
import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import store
import policy
import server
import web_ui
import audit_chain


@pytest.fixture(autouse=True)
def setup_policy_confirmation_env(tmp_path, monkeypatch):
    """Set up isolated DB, audit log, and sandbox environment."""
    test_db = str(tmp_path / "test_policy.db")
    test_audit = str(tmp_path / "action_log.jsonl")
    sandbox = tmp_path / "data" / "sentinelops_sandbox"
    quarantine = sandbox / "quarantine"
    firewall = tmp_path / "data" / "firewall_sandbox"
    sandbox.mkdir(parents=True)
    quarantine.mkdir()
    firewall.mkdir(parents=True)

    monkeypatch.setenv("SENTINELOPS_DB_PATH", test_db)
    monkeypatch.setenv("SENTINELOPS_REQUIRE_OBSERVED_IP", "true")
    monkeypatch.setenv("USE_REAL_APIS", "false")
    monkeypatch.setattr(server, "ACTION_LOG_FILE", test_audit)
    monkeypatch.setattr(server, "FIREWALL_SANDBOX_DIR", str(firewall))
    monkeypatch.setattr(server, "QUARANTINE_SANDBOX_DIR", str(sandbox))
    monkeypatch.setattr(server, "QUARANTINE_DIR", str(quarantine))
    monkeypatch.setattr(store, "DB_PATH", test_db)

    store.init_db(test_db)
    store.clear_store(test_db)
    return {"db": test_db, "audit": test_audit, "sandbox": sandbox}


# ==============================================================================
# 3a. Protected Allowlist Tests
# ==============================================================================

@pytest.mark.parametrize("protected_ip", [
    "127.0.0.1",
    "::1",
    "8.8.8.8",
    "1.1.1.1",
    "192.168.1.1",
    "127.0.0.2",  # Inside 127.0.0.0/8
])
def test_protected_allowlist_ips_and_cidrs_rejected_at_propose_time(monkeypatch, protected_ip):
    """Protected IPs from data/protected.yaml and CIDRs can never be proposed for blocking."""
    session_id = "protected_test_sess"
    monkeypatch.setenv("SENTINELOPS_SESSION_ID", session_id)
    monkeypatch.setattr(server, "SESSION_ID", session_id)

    # Even if observed and reported with high score
    store.record_observed_ip(session_id, protected_ip, source="search_logs_match")
    store.save_evidence(token="test_tok", session_id=session_id, ip=protected_ip, is_malicious=True, abuse_score=100)

    # Proposing a block on a protected target must be rejected
    res = server.propose_block_ip(protected_ip, "attempt to block protected target")
    assert "policy_denied:protected_target" in res or "cannot be blocked" in res.lower()

    # Verify no action created
    actions = store.list_actions(session_id=session_id)
    assert len(actions) == 0


def test_environment_variable_protected_allowlist(monkeypatch):
    """IPs and CIDRs configured via SENTINELOPS_PROTECTED_IPS/CIDRS are rejected."""
    session_id = "env_protected_sess"
    custom_protected = "10.99.99.99"
    monkeypatch.setenv("SENTINELOPS_PROTECTED_IPS", custom_protected)
    monkeypatch.setenv("SENTINELOPS_SESSION_ID", session_id)
    monkeypatch.setattr(server, "SESSION_ID", session_id)

    store.record_observed_ip(session_id, custom_protected, source="search_logs_match")
    store.save_evidence(token="test_tok", session_id=session_id, ip=custom_protected, is_malicious=True, abuse_score=100)

    res = server.propose_block_ip(custom_protected, "attempt to block env-protected IP")
    assert "policy_denied:protected_target" in res


# ==============================================================================
# 3b. Severity-Based Approval Tiers Tests
# ==============================================================================

def test_critical_severity_requires_two_distinct_approvers():
    """Critical action requires two distinct approvers; same approver twice fails."""
    session_id = "sess_crit"
    token = "crit0001"
    store.create_action(
        token=token,
        session_id=session_id,
        action_type="block_ip",
        params={"ip": "45.33.22.11", "reason": "Severe APT breach", "severity": "critical"}
    )

    action = store.get_action(token)
    assert action["status"] == "pending"

    # Approver 1 approves
    success_1, msg_1, updated_1 = store.record_approval(token, session_id, approver_id="operator_alice")
    assert success_1 is True
    assert updated_1["status"] == "partially_approved"
    assert updated_1["approvals"] == ["operator_alice"]

    # Approver 1 attempts to approve AGAIN (same operator twice) -> must FAIL
    success_same, msg_same, _ = store.record_approval(token, session_id, approver_id="operator_alice")
    assert success_same is False
    assert "distinct operator" in msg_same.lower()

    # Distinct Approver 2 approves -> transitions to confirmed
    success_2, msg_2, updated_2 = store.record_approval(token, session_id, approver_id="operator_bob")
    assert success_2 is True
    assert updated_2["status"] == "confirmed"
    assert updated_2["approvals"] == ["operator_alice", "operator_bob"]


def test_non_critical_action_confirms_with_single_approver():
    """Non-critical (low/medium/high) actions transition directly to confirmed on single approval."""
    session_id = "sess_med"
    token = "med00001"
    store.create_action(
        token=token,
        session_id=session_id,
        action_type="block_ip",
        params={"ip": "45.33.22.11", "reason": "Routine block", "severity": "medium"}
    )

    success, msg, updated = store.record_approval(token, session_id, approver_id="operator_alice")
    assert success is True
    assert updated["status"] == "confirmed"
    assert updated["approvals"] == ["operator_alice"]


# ==============================================================================
# 3c. Parameter Binding & Mutation Defense Tests
# ==============================================================================

def test_mutated_db_row_target_changed_refused_at_execution(monkeypatch):
    """
    If an attacker or rogue process modifies the target IP in SQLite after proposal,
    execute_pending_action re-computes params_hash, detects the mismatch, refuses execution,
    marks action failed, and logs an audit refusal entry.
    """
    session_id = "tamper_test_sess"
    monkeypatch.setenv("SENTINELOPS_SESSION_ID", session_id)
    monkeypatch.setattr(server, "SESSION_ID", session_id)

    # 1. Propose valid block on 45.33.22.11
    store.record_observed_ip(session_id, "45.33.22.11", source="search_logs_match")
    store.save_evidence("ev_tok", session_id, "45.33.22.11", is_malicious=True, abuse_score=85)
    proposal = server.propose_block_ip("45.33.22.11", "malicious C2")
    assert "PREVIEW" in proposal

    # Extract token
    import re
    token = re.search(r'Token:\s*([a-f0-9]+)', proposal).group(1)
    action = store.get_action(token)
    original_hash = action["params_hash"]

    # 2. Confirm the action legitimately
    assert store.transition(token, session_id, frm="pending", to="confirmed")

    # 3. Malicious DB mutation: attacker alters target IP in SQLite to 10.0.0.1!
    tampered_params = dict(action["params"])
    tampered_params["ip"] = "10.0.0.1"  # Victim IP!
    with store.tx() as c:
        c.execute("UPDATE actions SET params_json=? WHERE token=?", (json.dumps(tampered_params), token))

    # 4. Attempt to execute
    res = server.execute_pending_action(token)
    assert "Error: Parameter binding verification failed" in res

    # 5. Assert action was transitioned to failed
    updated_action = store.get_action(token)
    assert updated_action["status"] == "failed"

    # 6. Assert audit log records refusal:params_hash_mismatch
    entries = server.load_action_log()
    assert any(e.get("reason") == "refusal:params_hash_mismatch" for e in entries)


def test_flask_confirm_route_verifies_params_hash(monkeypatch):
    """Flask /confirm/<token> rejects mismatching params_hash and accepts correct hash."""
    session_id = "flask_hash_sess"
    token = "hash0001"
    created = store.create_action(
        token=token,
        session_id=session_id,
        action_type="block_ip",
        params={"ip": "45.33.22.11", "reason": "Hash check"}
    )
    correct_hash = created["params_hash"]
    correct_short_hash = correct_hash[:8]

    client = web_ui.app.test_client()
    with client.session_transaction() as sess:
        sess["session_id"] = session_id
        sess["conversations"] = {session_id: []}

    # Case 1: Wrong params_hash sent to /confirm -> refused with 400
    res_wrong = client.post(f"/confirm/{token}?hash=badhash123")
    assert res_wrong.status_code == 400
    assert "params_hash mismatch" in res_wrong.get_json()["error"]

    # Action remains pending
    assert store.get_action(token)["status"] == "pending"

    # Case 2: Correct params_hash (or short form) -> succeeds
    with patch("web_ui.stdio_client") as mock_stdio:
        # Mock MCP subprocess execution
        mock_mcp = AsyncMock()
        mock_mcp.initialize = AsyncMock()
        async def mock_call(tool_name, args):
            store.transition(token, session_id, frm="confirmed", to="executing")
            store.transition(token, session_id, frm="executing", to="executed")
            return SimpleNamespace(content=[SimpleNamespace(text="SUCCESS: Blocked")])
        mock_mcp.call_tool = mock_call

        from contextlib import asynccontextmanager
        @asynccontextmanager
        async def mock_cm(*args, **kwargs):
            yield (None, None)

        mock_stdio.side_effect = mock_cm

        with patch("web_ui.ClientSession") as mock_cs:
            @asynccontextmanager
            async def mock_cs_cm(*args, **kwargs):
                yield mock_mcp
            mock_cs.side_effect = mock_cs_cm

            res_ok = client.post(f"/confirm/{token}?hash={correct_short_hash}")
            assert res_ok.status_code == 200
            assert res_ok.get_json()["success"] is True


# ==============================================================================
# Step 3 Hardening Pass Tests
# ==============================================================================

def test_mutated_db_row_severity_lowered_refused_at_execution(monkeypatch):
    """
    Test: DB row mutated critical -> low is refused at execute; an attacker or injected
    agent cannot lower severity in DB to bypass the critical approval tier.
    """
    session_id = "severity_tamper_sess"
    monkeypatch.setenv("SENTINELOPS_SESSION_ID", session_id)
    monkeypatch.setattr(server, "SESSION_ID", session_id)

    # 1. Propose critical block (abuse score 95)
    store.record_observed_ip(session_id, "45.33.22.11", source="search_logs_match:exploit_attempt")
    store.save_evidence("ev_tok", session_id, "45.33.22.11", is_malicious=True, abuse_score=95)
    proposal = server.propose_block_ip("45.33.22.11", "Critical exploit attempt")
    assert "PREVIEW" in proposal

    import re
    token = re.search(r'Token:\s*([a-f0-9]+)', proposal).group(1)
    action = store.get_action(token)
    assert action["severity"] == "critical"
    assert action["required_approvals"] == 2

    # Two distinct approvals to get to confirmed
    store.record_approval(token, session_id, "op_1")
    store.record_approval(token, session_id, "op_2")
    assert store.get_action(token)["status"] == "confirmed"

    # Rogue mutation: mutate params_json severity to "low" and required_approvals to 1
    tampered_params = dict(action["params"])
    tampered_params["severity"] = "low"
    tampered_params["required_approvals"] = 1
    with store.tx() as c:
        c.execute("UPDATE actions SET params_json=? WHERE token=?", (json.dumps(tampered_params), token))

    # Attempt to execute: params_hash verification must fail!
    res = server.execute_pending_action(token)
    assert "Error: Parameter binding verification failed" in res

    # Action transitioned to failed
    updated = store.get_action(token)
    assert updated["status"] == "failed"

    # Audit log recorded refusal
    entries = server.load_action_log()
    assert any(e.get("reason") == "refusal:params_hash_mismatch" for e in entries)


def test_benign_login_record_does_not_justify_block(monkeypatch):
    """
    Test: Benign login record for an IP does not justify a block (policy_denied:insufficient_evidence).
    Only suspicious events (failed_login, port_scan, exploit_attempt, etc.) justify a block.
    """
    session_id = "benign_log_sess"
    monkeypatch.setenv("SENTINELOPS_SESSION_ID", session_id)
    monkeypatch.setattr(server, "SESSION_ID", session_id)

    benign_ip = "198.51.100.99"
    benign_log = json.dumps([{"ip": benign_ip, "event": "successful_login", "user": "admin"}])

    # Mock search_logs to return benign log
    with patch("server.search_logs_stub", return_value=benign_log):
        res = server.search_logs(benign_ip)
        assert "successful_login" in res

    # IP was observed in session
    assert store.is_ip_observed(session_id, benign_ip)

    # But calling propose_block_ip must fail with insufficient_evidence because the log event was benign
    proposal_res = server.propose_block_ip(benign_ip, "Block after login")
    assert "policy_denied:insufficient_evidence" in proposal_res

    # Now if a suspicious log arrives for the same IP (failed_login)
    suspicious_log = json.dumps([{"ip": benign_ip, "event": "failed_login", "count": 20}])
    with patch("server.search_logs_stub", return_value=suspicious_log):
        server.search_logs(benign_ip)

    # Propose block now succeeds because suspicious evidence exists
    proposal_ok = server.propose_block_ip(benign_ip, "Repeated brute force failures")
    assert "PREVIEW" in proposal_ok


def test_missing_or_malformed_protected_yaml_fails_closed_with_builtins(tmp_path, monkeypatch, capsys):
    """
    Test: Missing or malformed protected.yaml fails closed, falls back to built-in defaults,
    and logs a warning to stderr.
    """
    # 1. Missing file
    missing_file = str(tmp_path / "nonexistent_protected.yaml")
    config = policy.load_protected_config(config_path=missing_file)
    err = capsys.readouterr().err
    assert "[WARN]" in err
    assert "127.0.0.1" in config["protected_ips"]
    assert "8.8.8.8" in config["protected_ips"]
    assert "1.1.1.1" in config["protected_ips"]
    assert "192.168.1.1" in config["protected_ips"]
    assert "127.0.0.0/8" in config["protected_cidrs"]

    # 2. Malformed file (invalid YAML)
    bad_yaml = tmp_path / "corrupt_protected.yaml"
    bad_yaml.write_text("protected_ips: [unclosed list", encoding="utf-8")
    config_corrupt = policy.load_protected_config(config_path=str(bad_yaml))
    err2 = capsys.readouterr().err
    assert "[WARN]" in err2
    assert "127.0.0.1" in config_corrupt["protected_ips"]
    assert "8.8.8.8" in config_corrupt["protected_ips"]

    # 3. Both still report is_ip_protected as True for built-in targets (loopback, DNS, gateway)
    is_prot, _ = policy.is_ip_protected("127.0.0.1", config_path=missing_file)
    assert is_prot is True
    is_prot_dns, _ = policy.is_ip_protected("8.8.8.8", config_path=missing_file)
    assert is_prot_dns is True
    is_prot_loopback, _ = policy.is_ip_protected("127.0.0.2", config_path=str(bad_yaml))
    assert is_prot_loopback is True


def test_allowlist_recheck_inside_execute_pending_action(monkeypatch):
    """
    Test: Re-check the allowlist inside execute_pending_action.
    Even if an action was marked confirmed (e.g. by direct DB mutation or prior to policy change),
    execute_pending_action refuses to execute if the target is in the protected allowlist.
    """
    session_id = "exec_allowlist_sess"
    monkeypatch.setenv("SENTINELOPS_SESSION_ID", session_id)
    monkeypatch.setattr(server, "SESSION_ID", session_id)

    token = "execprot1"
    # Seed a confirmed action for protected DNS 8.8.8.8
    store.create_action(
        token=token,
        session_id=session_id,
        action_type="block_ip",
        params={"ip": "8.8.8.8", "reason": "Accidental block attempt"},
        status="confirmed"
    )

    res = server.execute_pending_action(token)
    assert "protected by policy allowlist and cannot be blocked" in res

    action = store.get_action(token)
    assert action["status"] == "failed"

    # Verify audit rejection entry
    entries = server.load_action_log()
    assert any(e.get("reason") == "refusal:protected_target" for e in entries)


def test_operator_identity_header_behavior(monkeypatch):
    """
    Test: Document current behavior where X-Operator-ID header provides operator identity
    for multi-party approval, and defaults to session_id / default_operator if omitted.
    """
    session_id = "sess_op_header"
    token = "ophead01"
    created = store.create_action(
        token=token,
        session_id=session_id,
        action_type="block_ip",
        params={"ip": "45.33.22.11", "reason": "Operator identity test", "severity": "critical"}
    )
    p_hash = created["params_hash"]

    client = web_ui.app.test_client()
    with client.session_transaction() as sess:
        sess["session_id"] = session_id
        sess["conversations"] = {session_id: []}

    # 1. First approval with X-Operator-ID: op_alice
    res1 = client.post(
        f"/confirm/{token}?hash={p_hash[:8]}",
        headers={"X-Operator-ID": "op_alice"}
    )
    assert res1.status_code == 202
    assert res1.get_json()["status"] == "partially_approved"
    action1 = store.get_action(token)
    assert action1["approvals"] == ["op_alice"]

    # 2. Second approval with same X-Operator-ID: op_alice -> rejected 409
    res_same = client.post(
        f"/confirm/{token}?hash={p_hash[:8]}",
        headers={"X-Operator-ID": "op_alice"}
    )
    assert res_same.status_code == 409

    # 3. Second approval with different X-Operator-ID: op_bob -> confirmed
    with patch("web_ui.stdio_client") as mock_stdio:
        mock_mcp = AsyncMock()
        mock_mcp.initialize = AsyncMock()
        async def mock_call(tool_name, args):
            store.transition(token, session_id, frm="confirmed", to="executing")
            store.transition(token, session_id, frm="executing", to="executed")
            return SimpleNamespace(content=[SimpleNamespace(text="SUCCESS: Blocked")])
        mock_mcp.call_tool = mock_call

        from contextlib import asynccontextmanager
        @asynccontextmanager
        async def mock_cm(*args, **kwargs):
            yield (None, None)
        mock_stdio.side_effect = mock_cm

        with patch("web_ui.ClientSession") as mock_cs:
            @asynccontextmanager
            async def mock_cs_cm(*args, **kwargs):
                yield mock_mcp
            mock_cs.side_effect = mock_cs_cm

            res2 = client.post(
                f"/confirm/{token}?hash={p_hash[:8]}",
                headers={"X-Operator-ID": "op_bob"}
            )
            assert res2.status_code == 200
            action2 = store.get_action(token)
            assert action2["approvals"] == ["op_alice", "op_bob"]

