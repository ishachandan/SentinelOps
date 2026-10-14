"""Fast unit tests - direct function calls, no MCP subprocess, no ChromaDB"""
import pytest
import json
import re
import os
from types import SimpleNamespace

# Force stub mode for fast unit tests - no real API calls, no ChromaDB
os.environ["USE_REAL_APIS"] = "false"

# Import functions directly from server AFTER setting env var
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import server
from server import (
    create_incident,
    notify_telegram,
    propose_block_ip,
    propose_quarantine_file,
    execute_pending_action,
    get_action_log,
    PENDING_ACTIONS,
    REPUTATION_RESULTS
)


@pytest.fixture(autouse=True)
def clear_state(tmp_path, monkeypatch):
    """Clear global state before each test"""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setattr(server, "PENDING_ACTIONS_FILE", str(data_dir / "pending_actions.json"))
    monkeypatch.setattr(server, "ACTION_LOG_FILE", str(data_dir / "action_log.jsonl"))
    monkeypatch.setattr(server, "INCIDENTS_FILE", str(data_dir / "incidents.json"))
    monkeypatch.setattr(server, "FIREWALL_SANDBOX_DIR", str(data_dir / "firewall_sandbox"))
    PENDING_ACTIONS.clear()
    REPUTATION_RESULTS.clear()
    yield
    PENDING_ACTIONS.clear()
    REPUTATION_RESULTS.clear()


def test_check_ip_reputation_returns_token():
    """Test check_ip_reputation returns result_token - stub mode"""
    # Use known IP from FAKE_IP_REPUTATION in server.py
    result = server.check_ip_reputation("45.33.22.11")
    data = json.loads(result)
    
    assert "result_token" in data
    assert "ip" in data
    assert "abuse_score" in data
    assert "is_malicious" in data


def test_check_ip_malicious_vs_clean():
    """Test reputation check distinguishes malicious from clean IPs - stub mode"""
    # Malicious IP from FAKE_IP_REPUTATION: "45.33.22.11"
    result = server.check_ip_reputation("45.33.22.11")
    malicious_data = json.loads(result)
    assert malicious_data["is_malicious"] == True
    assert malicious_data["abuse_score"] > 50
    
    # Clean IP from FAKE_IP_REPUTATION: "8.8.8.8"
    result = server.check_ip_reputation("8.8.8.8")
    clean_data = json.loads(result)
    assert clean_data["is_malicious"] == False
    assert clean_data["abuse_score"] == 0


def test_evidence_token_validation():
    """Test evidence token validation logic - no subprocess needed"""
    # Get clean and malicious evidence tokens from stub data
    clean_result = server.check_ip_reputation("8.8.8.8")
    clean_data = json.loads(clean_result)
    clean_token = clean_data["result_token"]
    
    malicious_result = server.check_ip_reputation("45.33.22.11")
    malicious_data = json.loads(malicious_result)
    malicious_token = malicious_data["result_token"]
    
    # Test: create_incident rejects without evidence_token for high/critical
    result = create_incident(
        summary="Malicious IP detected",
        severity="high"
    )
    assert "REJECTED" in result
    
    # Test: create_incident rejects clean evidence for malicious claim
    result = create_incident(
        summary="Blocked malicious IP",
        severity="high",
        related_ip="8.8.8.8",
        evidence_token=clean_token
    )
    assert "REJECTED" in result
    assert "does not support malicious claim" in result
    
    # Test: create_incident accepts malicious evidence
    result = create_incident(
        summary="Malicious IP blocked",
        severity="high",
        related_ip="45.33.22.11",
        evidence_token=malicious_token
    )
    assert "successfully" in result.lower()


def test_telegram_evidence_validation(monkeypatch):
    """Test Telegram notification evidence validation"""
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "unit-test-bot-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "unit-test-chat-id")
    monkeypatch.setattr(
        server.requests,
        "post",
        lambda *_args, **_kwargs: SimpleNamespace(status_code=200),
    )

    # Get clean and malicious evidence tokens from stub data
    clean_result = server.check_ip_reputation("8.8.8.8")
    clean_data = json.loads(clean_result)
    clean_token = clean_data["result_token"]
    
    malicious_result = server.check_ip_reputation("45.33.22.11")
    malicious_data = json.loads(malicious_result)
    malicious_token = malicious_data["result_token"]
    
    # Test: notify_telegram rejects without evidence_token
    result = notify_telegram(message="Blocked malicious IP 1.2.3.4")
    assert "REJECTED" in result
    
    # Test: notify_telegram rejects clean evidence for threat claim
    result = notify_telegram(
        message="Blocked malicious IP 8.8.8.8",
        evidence_token=clean_token
    )
    assert "REJECTED" in result
    assert "does not support threat claim" in result
    
    # Test: notify_telegram accepts malicious evidence
    result = notify_telegram(
        message="Blocked malicious IP 45.33.22.11",
        evidence_token=malicious_token
    )
    assert "successfully" in result.lower()


def test_pending_action_token_lifecycle():
    """Test token generation, confirmation gate, execution, and reuse rejection."""
    result = propose_block_ip(ip="1.2.3.4", reason="test")
    assert "PREVIEW" in result
    match = re.search(r'[Tt]oken:\s*([a-f0-9]+)', result)
    assert match
    token = match.group(1)

    result = execute_pending_action(token="fakefake")
    assert "not found" in result.lower() or "invalid" in result.lower()

    result = execute_pending_action(token=token)
    assert "pending and not confirmed" in result.lower()

    PENDING_ACTIONS[token]["status"] = "confirmed"
    server.save_pending_actions(PENDING_ACTIONS)
    result = execute_pending_action(token=token)
    assert "Blocked IP" in result or "SANDBOX" in result

    result = execute_pending_action(token=token)
    assert "not found" in result.lower() or "already" in result.lower() or "executed" in result.lower()


@pytest.mark.parametrize(
    "ip",
    [
        "192.168.1.5",
        "10.0.0.100",
        "169.254.1.2",
        "203.0.113.10",
        "fe80::1",
        "2001:db8::1",
    ],
)
def test_propose_block_ip_accepts_nonpublic_addresses(ip):
    result = propose_block_ip(ip=ip, reason="internal investigation")

    assert "PREVIEW" in result
    assert f"Would block IP {ip}" in result


@pytest.mark.parametrize(
    ("ip", "reason"),
    [
        ("127.0.0.1", "Loopback"),
        ("0.0.0.0", "Unspecified"),
        ("::", "Unspecified"),
        ("::1", "Loopback"),
        ("224.0.0.1", "Multicast"),
        ("not-an-ip", "Invalid IP address"),
    ],
)
def test_propose_block_ip_rejects_non_targets(ip, reason):
    result = propose_block_ip(ip=ip, reason="invalid target")

    assert result.startswith("Error:")
    assert reason in result


def test_ip_validation_normalizes_addresses_and_rule_filenames():
    normalized = server.validate_ip("2001:0db8:0:0::1")

    assert normalized == "2001:db8::1"
    filename = server.safe_ip_rule_filename("2001:0db8:0:0::1")
    assert filename == "block_2001_db8__1.rule"
    assert ":" not in filename


def test_reputation_and_incident_accept_private_ips(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "INCIDENTS_FILE", str(tmp_path / "incidents.json"))

    reputation = json.loads(server.check_ip_reputation("192.168.1.5"))
    loopback_reputation = json.loads(server.check_ip_reputation("127.0.0.1"))
    incident_result = create_incident(
        summary="Investigate an internal host",
        severity="low",
        related_ip="10.0.0.100",
    )
    multicast_incident_result = create_incident(
        summary="Investigate multicast traffic",
        severity="low",
        related_ip="224.0.0.1",
    )

    assert reputation["ip"] == "192.168.1.5"
    assert "result_token" in reputation
    assert loopback_reputation["ip"] == "127.0.0.1"
    assert "result_token" in loopback_reputation
    assert "successfully" in incident_result.lower()
    assert "successfully" in multicast_incident_result.lower()
    with open(server.INCIDENTS_FILE, encoding="utf-8") as incidents_file:
        incident_ips = [incident["related_ip"] for incident in json.load(incidents_file)]
    assert incident_ips == ["10.0.0.100", "224.0.0.1"]


def test_incident_evidence_ip_comparison_uses_normalized_addresses(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "INCIDENTS_FILE", str(tmp_path / "incidents.json"))
    REPUTATION_RESULTS["normalized-ip-token"] = {
        "ip": "2001:0db8:0:0::1",
        "abuse_score": 90,
        "is_malicious": True,
    }

    result = create_incident(
        summary="Malicious IPv6 address detected",
        severity="high",
        related_ip="2001:db8::1",
        evidence_token="normalized-ip-token",
    )

    assert "successfully" in result.lower()
    with open(server.INCIDENTS_FILE, encoding="utf-8") as incidents_file:
        assert json.load(incidents_file)[0]["related_ip"] == "2001:db8::1"


def test_propose_has_no_side_effects(tmp_path, monkeypatch):
    """Test that propose tools don't execute anything."""
    sandbox_dir = tmp_path / "sentinelops_sandbox"
    sandbox_dir.mkdir()
    quarantine_dir = sandbox_dir / "quarantine"
    quarantine_dir.mkdir()
    monkeypatch.setattr(server, "QUARANTINE_SANDBOX_DIR", str(sandbox_dir))
    monkeypatch.setattr(server, "QUARANTINE_DIR", str(quarantine_dir))

    log_before = get_action_log()
    before_data = json.loads(log_before)
    before_executed = [a for a in before_data if a.get("status") == "executed"]

    result = propose_block_ip(ip="203.0.113.10", reason="test")
    assert "PREVIEW" in result

    sandbox_file = sandbox_dir / "proposal_target.txt"
    with sandbox_file.open("w", encoding="utf-8") as f:
        f.write("test")

    result = propose_quarantine_file(path=str(sandbox_file), reason="test")
    assert "PREVIEW" in result

    log_after = get_action_log()
    after_data = json.loads(log_after)
    after_executed = [a for a in after_data if a.get("status") == "executed"]

    assert len(after_executed) == len(before_executed), "propose should not execute"


def test_chain_integrity_enforcement():
    """Test full chain-integrity enforcement - all scenarios"""
    # Get clean evidence token from stub data
    clean_result = server.check_ip_reputation("8.8.8.8")
    clean_data = json.loads(clean_result)
    clean_token = clean_data["result_token"]
    assert clean_data["is_malicious"] == False
    
    # Server MUST reject malicious claim with clean evidence
    incident_result = create_incident(
        summary="Blocked malicious IP",
        severity="high",
        related_ip="8.8.8.8",
        evidence_token=clean_token
    )
    assert "REJECTED" in incident_result
    
    telegram_result = notify_telegram(
        message="Blocked malicious IP 8.8.8.8",
        evidence_token=clean_token
    )
    assert "REJECTED" in telegram_result
