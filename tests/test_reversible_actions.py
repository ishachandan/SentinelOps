"""
Tests for Step 4: Reversible Actions.
Validates:
4a. propose_unblock_ip -> confirm -> execute round trip.
4b. propose_restore_quarantined_file -> confirm -> execute round trip.
4c. Path traversal / escape attempts on restore are strictly rejected.
4d. Block TTL expiry reverts blocks and records to audit chain.
"""
import json
import os
import re
import time
import pytest

import store
import server
import audit_chain


@pytest.fixture(autouse=True)
def setup_reversible_env(tmp_path, monkeypatch):
    """Set up isolated DB, audit log, and sandboxes."""
    test_db = str(tmp_path / "test_reversible.db")
    test_audit = str(tmp_path / "action_log.jsonl")
    sandbox = tmp_path / "data" / "sentinelops_sandbox"
    quarantine = sandbox / "quarantine"
    firewall = tmp_path / "data" / "firewall_sandbox"
    sandbox.mkdir(parents=True)
    quarantine.mkdir()
    firewall.mkdir(parents=True)

    monkeypatch.setenv("SENTINELOPS_DB_PATH", test_db)
    monkeypatch.setenv("SENTINELOPS_REQUIRE_OBSERVED_IP", "true")
    monkeypatch.setenv("USE_REAL_APIS", "true")  # Test filesystem operations in real sandbox
    monkeypatch.setattr(server, "USE_REAL_APIS", True)
    monkeypatch.setattr(server, "ACTION_LOG_FILE", test_audit)
    monkeypatch.setattr(server, "FIREWALL_SANDBOX_DIR", str(firewall))
    monkeypatch.setattr(server, "QUARANTINE_SANDBOX_DIR", str(sandbox))
    monkeypatch.setattr(server, "QUARANTINE_DIR", str(quarantine))
    monkeypatch.setattr(store, "DB_PATH", test_db)

    store.init_db(test_db)
    store.clear_store(test_db)
    return {
        "db": test_db,
        "audit": test_audit,
        "sandbox": sandbox,
        "quarantine": quarantine,
        "firewall": firewall
    }


def test_block_then_unblock_roundtrip(monkeypatch, setup_reversible_env):
    """Propose block -> execute block -> propose unblock -> execute unblock."""
    session_id = "roundtrip_block_sess"
    monkeypatch.setenv("SENTINELOPS_SESSION_ID", session_id)
    monkeypatch.setattr(server, "SESSION_ID", session_id)
    firewall = setup_reversible_env["firewall"]

    ip = "198.51.100.42"
    # Observe IP with evidence
    store.record_observed_ip(session_id, ip, source="search_logs_match:exploit_attempt")
    store.save_evidence("ev_tok", session_id, ip, is_malicious=True, abuse_score=95)

    # 1. Propose block
    block_prop = server.propose_block_ip(ip, "APT Command and Control")
    assert "PREVIEW: Would block IP" in block_prop
    block_token = re.search(r'Token:\s*([a-f0-9]+)', block_prop).group(1)

    # 2. Confirm block (requires 2 approvers because abuse_score=95 is critical)
    store.record_approval(block_token, session_id, "op_alice")
    store.record_approval(block_token, session_id, "op_bob")

    # 3. Execute block
    exec_res = server.execute_pending_action(block_token)
    assert "SUCCESS [SANDBOX]: Blocked IP" in exec_res

    rule_file = firewall / server.safe_ip_rule_filename(ip)
    assert rule_file.exists()

    # 4. Propose unblock
    unblock_prop = server.propose_unblock_ip(ip, "False positive confirmed by analyst")
    assert "PREVIEW: Would unblock IP" in unblock_prop
    unblock_token = re.search(r'Token:\s*([a-f0-9]+)', unblock_prop).group(1)

    # 5. Confirm unblock
    assert store.transition(unblock_token, session_id, frm="pending", to="confirmed")

    # 6. Execute unblock
    unblock_res = server.execute_pending_action(unblock_token)
    assert "SUCCESS [SANDBOX]: Unblocked IP" in unblock_res
    assert not rule_file.exists()

    # Verify audit log chain
    entries = server.load_action_log()
    actions = [e.get("action") for e in entries]
    assert "block_ip" in actions
    assert "unblock_ip" in actions


def test_quarantine_then_restore_roundtrip(monkeypatch, setup_reversible_env):
    """Propose quarantine -> execute -> propose restore -> execute."""
    session_id = "roundtrip_quarantine_sess"
    monkeypatch.setenv("SENTINELOPS_SESSION_ID", session_id)
    monkeypatch.setattr(server, "SESSION_ID", session_id)
    sandbox = setup_reversible_env["sandbox"]
    quarantine = setup_reversible_env["quarantine"]

    # Create dummy malicious file in sandbox
    target_file = sandbox / "malicious_script.sh"
    target_file.write_text("#!/bin/bash\necho bad", encoding="utf-8")
    assert target_file.exists()

    # 1. Propose quarantine
    q_prop = server.propose_quarantine_file(str(target_file), "Detected malicious shell script")
    assert "PREVIEW: Would quarantine file" in q_prop
    q_token = re.search(r'Token:\s*([a-f0-9]+)', q_prop).group(1)

    # 2. Confirm quarantine
    assert store.transition(q_token, session_id, frm="pending", to="confirmed")

    # 3. Execute quarantine
    q_res = server.execute_pending_action(q_token)
    assert "SUCCESS [SANDBOX]: Quarantined file" in q_res
    assert not target_file.exists()

    # Quarantined file exists in quarantine dir
    q_files = list(quarantine.glob(f"{q_token}_*"))
    assert len(q_files) >= 1

    # 4. Propose restore
    r_prop = server.propose_restore_quarantined_file(str(target_file), "Benign admin utility")
    assert "PREVIEW: Would restore file" in r_prop
    r_token = re.search(r'Token:\s*([a-f0-9]+)', r_prop).group(1)

    # 5. Confirm restore
    assert store.transition(r_token, session_id, frm="pending", to="confirmed")

    # 6. Execute restore
    r_res = server.execute_pending_action(r_token)
    assert "SUCCESS [SANDBOX]: Restored file" in r_res
    assert target_file.exists()
    assert target_file.read_text(encoding="utf-8") == "#!/bin/bash\necho bad"

    # Verify audit log
    entries = server.load_action_log()
    actions = [e.get("action") for e in entries]
    assert "quarantine_file" in actions
    assert "restore_quarantined_file" in actions


def test_restore_path_traversal_and_escape_rejected(monkeypatch, setup_reversible_env):
    """Restore requests attempting directory traversal or pointing outside sandbox fail."""
    session_id = "restore_escape_sess"
    monkeypatch.setenv("SENTINELOPS_SESSION_ID", session_id)
    monkeypatch.setattr(server, "SESSION_ID", session_id)

    # 1. Propose restore for path outside sandbox
    escape_path = "../../etc/shadow"
    prop_res = server.propose_restore_quarantined_file(escape_path, "Attempted escape")
    assert "outside the quarantine sandbox" in prop_res

    # 2. Tampered execution attempt
    token = "restoresc1"
    store.create_action(
        token=token,
        session_id=session_id,
        action_type="restore_quarantined_file",
        params={"path": escape_path, "reason": "Bypassed proposal"},
        status="confirmed"
    )

    exec_res = server.execute_pending_action(token)
    assert "outside the quarantine sandbox" in exec_res

    action = store.get_action(token)
    assert action["status"] == "failed"


def test_block_ttl_expiry_reverts_rules_and_logs_audit(monkeypatch, setup_reversible_env):
    """Block rules expire when their TTL has elapsed, removing firewall rules and logging to audit."""
    firewall = setup_reversible_env["firewall"]
    ip = "198.51.100.77"

    # Write a rule that was created 100 seconds ago with TTL 10 seconds
    past_time = time.time() - 100
    rule_file = firewall / server.safe_ip_rule_filename(ip)
    rule_data = {
        "ip": ip,
        "reason": "Temporary block",
        "action": "DROP",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(past_time)),
        "ttl": 10.0,
        "status": "active"
    }
    rule_file.write_text(json.dumps(rule_data), encoding="utf-8")
    assert rule_file.exists()

    # Expire active blocks
    expired = server.expire_active_blocks(ttl=10.0)
    assert ip in expired
    assert not rule_file.exists()

    # Check audit log contains block_expired
    entries = server.load_action_log()
    assert any(e.get("action") == "block_expired" and e.get("ip") == ip for e in entries)

    # Expire blocks MCP tool
    tool_out = server.expire_blocks()
    assert "No active block rules have expired" in tool_out or "SUCCESS" in tool_out


def test_model_visible_tools_excludes_expire_blocks_and_human_only_tools():
    """Verify that agent_shared filters out expire_blocks and all human-only tools from LLM schemas."""
    import agent_shared
    from types import SimpleNamespace

    mcp_tools = [
        SimpleNamespace(name="ping", description="Ping", input_schema={}),
        SimpleNamespace(name="propose_block_ip", description="Block", input_schema={}),
        SimpleNamespace(name="propose_unblock_ip", description="Unblock", input_schema={}),
        SimpleNamespace(name="propose_quarantine_file", description="Quarantine", input_schema={}),
        SimpleNamespace(name="propose_restore_quarantined_file", description="Restore", input_schema={}),
        SimpleNamespace(name="execute_pending_action", description="Execute", input_schema={}),
        SimpleNamespace(name="debug_seed_pending_action", description="Debug", input_schema={}),
        SimpleNamespace(name="expire_blocks", description="Expire blocks", input_schema={}),
    ]
    groq_tools = agent_shared.convert_mcp_tools_to_groq_format(
        SimpleNamespace(tools=mcp_tools),
        exclude=agent_shared.HUMAN_ONLY_TOOLS
    )
    exposed_names = {t["function"]["name"] for t in groq_tools}

    assert "expire_blocks" not in exposed_names
    assert "execute_pending_action" not in exposed_names
    assert "debug_seed_pending_action" not in exposed_names
    assert agent_shared.HUMAN_ONLY_TOOLS.isdisjoint(exposed_names)
    assert "propose_unblock_ip" in exposed_names
    assert "propose_restore_quarantined_file" in exposed_names


def test_proposing_unblock_for_never_blocked_ip_is_rejected(monkeypatch):
    """propose_unblock_ip must only accept targets that currently exist as an active block rule."""
    session_id = "never_blocked_sess"
    monkeypatch.setenv("SENTINELOPS_SESSION_ID", session_id)
    monkeypatch.setattr(server, "SESSION_ID", session_id)

    never_blocked = "198.51.100.99"
    res = server.propose_unblock_ip(never_blocked, "Attempt to unblock never-blocked IP")
    assert "No active block rule found" in res
    assert "policy_denied:not_blocked" in res or "Cannot propose unblock" in res

    # Verify audit log contains policy_denied:not_blocked
    entries = server.load_action_log()
    assert any(e.get("reason") == "policy_denied:not_blocked" and e.get("target") == never_blocked for e in entries)


def test_proposing_restore_for_never_quarantined_file_is_rejected(monkeypatch, setup_reversible_env):
    """propose_restore_quarantined_file must only accept targets that currently exist in quarantine."""
    session_id = "never_quarantined_sess"
    monkeypatch.setenv("SENTINELOPS_SESSION_ID", session_id)
    monkeypatch.setattr(server, "SESSION_ID", session_id)
    sandbox = setup_reversible_env["sandbox"]

    never_quarantined = str(sandbox / "nonexistent_file.txt")
    res = server.propose_restore_quarantined_file(never_quarantined, "Restore non-quarantined file")
    assert "No matching quarantined file found" in res

    entries = server.load_action_log()
    assert any(e.get("reason") == "policy_denied:not_quarantined" for e in entries)


def test_tampered_metadata_pointing_outside_sandbox_refused_at_execution(monkeypatch, setup_reversible_env):
    """
    If a .metadata file in the quarantine store is tampered to point outside the sandbox,
    execute_pending_action detects it upon destination re-validation, refuses execution,
    marks action failed, and logs refusal.
    """
    session_id = "tamper_meta_sess"
    monkeypatch.setenv("SENTINELOPS_SESSION_ID", session_id)
    monkeypatch.setattr(server, "SESSION_ID", session_id)
    sandbox = setup_reversible_env["sandbox"]
    quarantine = setup_reversible_env["quarantine"]

    # 1. Create and quarantine a file legitimately
    target_file = sandbox / "legit_script.sh"
    target_file.write_text("#!/bin/bash\necho ok", encoding="utf-8")

    q_prop = server.propose_quarantine_file(str(target_file), "Suspicious activity")
    q_tok = re.search(r'Token:\s*([a-f0-9]+)', q_prop).group(1)
    store.transition(q_tok, session_id, frm="pending", to="confirmed")
    q_res = server.execute_pending_action(q_tok)
    assert "SUCCESS [SANDBOX]: Quarantined file" in q_res

    # 2. Tamper with the .metadata file in QUARANTINE_DIR to point outside the sandbox
    meta_files = list(quarantine.glob(f"{q_tok}_*.metadata"))
    assert len(meta_files) >= 1
    meta_path = meta_files[0]
    with open(meta_path, "r", encoding="utf-8") as f:
        meta_data = json.load(f)
    meta_data["original_path"] = "../../etc/shadow"  # Tampered escape path!
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta_data, f, indent=2)

    # 3. Propose restore for target_file (proposal passes because target_file was quarantined)
    r_prop = server.propose_restore_quarantined_file(str(target_file), "Attempt restore with tampered metadata")
    r_tok = re.search(r'Token:\s*([a-f0-9]+)', r_prop).group(1)
    store.transition(r_tok, session_id, frm="pending", to="confirmed")

    # 4. Execute restore: execution must detect tampered metadata and refuse!
    exec_res = server.execute_pending_action(r_tok)
    assert "outside quarantine sandbox" in exec_res.lower()

    # Action transitioned to failed
    assert store.get_action(r_tok)["status"] == "failed"

    # Audit log recorded refusal
    entries = server.load_action_log()
    assert any(e.get("reason") == "tampered_metadata_outside_sandbox" for e in entries)


