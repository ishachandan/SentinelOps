"""Fast unit tests - direct function calls, no MCP subprocess, no ChromaDB"""
import pytest
import json
import re
import os

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
def clear_state():
    """Clear global state before each test"""
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


def test_telegram_evidence_validation():
    """Test Telegram notification evidence validation"""
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
    """Test token generation, execution, and reuse rejection"""
    # Test: propose generates token
    result = propose_block_ip(ip="1.2.3.4", reason="test")
    assert "PREVIEW" in result
    match = re.search(r'[Tt]oken:\s*([a-f0-9]+)', result)
    assert match
    token = match.group(1)
    
    # Test: unknown token rejected
    result = execute_pending_action(token="fakefake")
    assert "not found" in result.lower() or "invalid" in result.lower()
    
    # Test: valid token executes once
    result = execute_pending_action(token=token)
    assert "Blocked IP" in result or "SANDBOX" in result
    
    # Test: reused token rejected
    result = execute_pending_action(token=token)
    assert "not found" in result.lower() or "already" in result.lower()


def test_propose_has_no_side_effects():
    """Test that propose tools don't execute anything"""
    # Get log before
    log_before = get_action_log()
    before_data = json.loads(log_before)
    before_executed = [a for a in before_data if a.get("status") == "executed"]
    
    # Propose should only create preview
    result = propose_block_ip(ip="10.0.0.1", reason="test")
    assert "PREVIEW" in result
    
    result = propose_quarantine_file(path="data/test.txt", reason="test")
    assert "PREVIEW" in result
    
    # Log should show no new executed actions
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
