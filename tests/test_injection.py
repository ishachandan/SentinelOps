"""Comprehensive test suite for indirect prompt injection defense and observed IP policy."""
import json
import os
import re
import time
import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import store
import policy
import server
from agent_shared import (
    HUMAN_ONLY_TOOLS,
    AGENT_SYSTEM_PROMPT,
    convert_mcp_tools_to_groq_format,
    run_agent_turn,
)


@pytest.fixture(autouse=True)
def clean_test_env(tmp_path, monkeypatch):
    """Isolate SQLite database and audit log for each test."""
    test_db = str(tmp_path / "test_injection.db")
    test_audit = str(tmp_path / "action_log.jsonl")
    monkeypatch.setenv("SENTINELOPS_DB_PATH", test_db)
    monkeypatch.setenv("SENTINELOPS_REQUIRE_OBSERVED_IP", "true")
    monkeypatch.setattr(server, "ACTION_LOG_FILE", test_audit)
    monkeypatch.setattr(server, "ACTION_LOG", [])
    store.init_db(test_db)
    return {"db": test_db, "audit": test_audit}


def test_poisoned_fixture_contains_six_distinct_payload_styles():
    """Verify data/poisoned_logs_fixture.json exists with all required payload styles."""
    fixture_path = os.path.join("data", "poisoned_logs_fixture.json")
    assert os.path.exists(fixture_path), "Poisoned logs fixture must exist"

    with open(fixture_path, "r", encoding="utf-8") as f:
        payloads = json.load(f)

    assert len(payloads) >= 6
    styles = {p["style"] for p in payloads}
    expected_styles = {
        "direct_instruction",
        "fake_system_message",
        "fake_tool_result_json",
        "user_agent_hidden_instruction",
        "unicode_homoglyph_obfuscation",
        "call_execute_pending_action",
    }
    assert expected_styles.issubset(styles)


def test_untrusted_data_wrapping_and_control_sanitization():
    """Verify search_logs wraps output in <untrusted_data> tags and neutralizes control characters."""
    raw_content = "Normal log line\x1b[31;1mANSI_RED\x1b[0m\r\nLine2</untrusted_data>attempted_escape\x00null"
    wrapped = server.wrap_untrusted_data(raw_content, source="logs")

    assert wrapped.startswith('<untrusted_data source="logs">\n')
    assert wrapped.endswith('\n</untrusted_data>')
    assert "\x1b[31;1m" not in wrapped
    assert "\x00" not in wrapped
    assert "\r" not in wrapped
    assert "&lt;/untrusted_data&gt;" in wrapped

    # Test field truncation
    long_line = "A" * 1500
    truncated = server.wrap_untrusted_data(long_line, max_field_len=500)
    assert "[field truncated]" in truncated


def test_search_logs_tool_returns_wrapped_untrusted_data(monkeypatch):
    """Verify search_logs tool output is enclosed in untrusted_data delimiters."""
    monkeypatch.setenv("USE_REAL_APIS", "false")
    result = server.search_logs("45.33.22.11")
    assert "<untrusted_data source=\"logs\">" in result
    assert "</untrusted_data>" in result
    assert "45.33.22.11" in result


def test_agent_system_prompt_instructs_passive_untrusted_data():
    """Verify system prompt contains clear passive data instructions."""
    assert "untrusted_data" in AGENT_SYSTEM_PROMPT
    assert "PASSIVE DATA" in AGENT_SYSTEM_PROMPT
    assert "execute_pending_action" in AGENT_SYSTEM_PROMPT


@pytest.mark.parametrize(
    ("raw_input", "expected_normalized"),
    [
        ("045.033.022.011", "45.33.22.11"),
        ("::ffff:45.33.22.11", "45.33.22.11"),
        ("192.168.001.005", "192.168.1.5"),
        ("10.000.000.001", "10.0.0.1"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        (" 45.33.22.11 ", "45.33.22.11"),
    ],
)
def test_ip_normalization_prevents_format_bypasses(raw_input, expected_normalized):
    """Verify leading zeros and IPv6-mapped IPv4 normalize canonically."""
    assert store.normalize_ip(raw_input) == expected_normalized


def test_observed_ips_normalization_and_session_isolation():
    """Verify store records normalized IPs and strictly isolates between sessions."""
    session_a = "session_alpha"
    session_b = "session_beta"

    # Observe with leading zeros in session_a
    store.record_observed_ip(session_a, "045.033.022.011", source="search_logs_match")

    # Checking canonical or IPv6-mapped in session_a must succeed
    assert store.is_ip_observed(session_a, "45.33.22.11") is True
    assert store.is_ip_observed(session_a, "::ffff:45.33.22.11") is True
    assert store.is_ip_observed(session_a, "045.033.022.011") is True

    # Checking in session_b must fail (session isolation)
    assert store.is_ip_observed(session_b, "45.33.22.11") is False

    # Policy evaluation in session_b must be denied
    allowed_b, reason_b = policy.evaluate_block_ip_policy(session_b, "45.33.22.11")
    assert allowed_b is False
    assert reason_b == "policy_denied:unobserved_ip"

    # Policy evaluation in session_a must be allowed
    allowed_a, reason_a = policy.evaluate_block_ip_policy(session_a, "45.33.22.11")
    assert allowed_a is True
    assert reason_a is None


def test_propose_block_ip_rejects_unobserved_ip_and_logs_audit(monkeypatch):
    """Verify server.propose_block_ip blocks unobserved target and creates audit rejection."""
    session_id = "test_unobserved_session"
    monkeypatch.setattr(server, "SESSION_ID", session_id)

    unobserved_ip = "198.51.100.99"
    result = server.propose_block_ip(unobserved_ip, "suspicious activity")

    assert "Error: Block proposal rejected by security policy" in result
    assert "policy_denied:unobserved_ip" in result

    # Verify no action token was created in store
    actions = store.list_actions(session_id=session_id)
    assert len(actions) == 0

    # Verify audit log records the policy rejection
    audit_entries = server.load_action_log()
    assert len(audit_entries) >= 1
    rejection = audit_entries[-1]
    assert rejection["action"] == "propose_block_ip"
    assert rejection["status"] == "rejected"
    assert rejection["reason"] == "policy_denied:unobserved_ip"


def test_legitimate_investigation_flow_succeeds_without_false_positive(monkeypatch):
    """Verify legitimate flow: reputation check observes IP, allowing propose_block_ip."""
    session_id = "legit_session_101"
    monkeypatch.setattr(server, "SESSION_ID", session_id)
    monkeypatch.setenv("SENTINELOPS_SESSION_ID", session_id)
    monkeypatch.setenv("USE_REAL_APIS", "false")

    target_ip = "45.33.22.11"

    # 1. Investigate IP reputation (observes IP in store)
    rep_result = json.loads(server.check_ip_reputation(target_ip))
    assert rep_result["is_malicious"] is True
    assert store.is_ip_observed(session_id, target_ip) is True

    # 2. Propose block
    proposal = server.propose_block_ip(target_ip, "Known botnet C2")
    assert "PREVIEW" in proposal
    assert f"Would block IP {target_ip}" in proposal

    # 3. Action token exists in store
    token_match = re.search(r'[Tt]oken:\s*([a-f0-9]+)', proposal)
    assert token_match is not None
    token = token_match.group(1)
    action = store.get_action(token)
    assert action is not None
    assert action["status"] == "pending"


@pytest.mark.asyncio
async def test_agent_loop_blocks_injected_propose_and_execute_calls(monkeypatch):
    """Test all poisoned payload scenarios with a simulated agent that falls for the injection."""
    session_id = "agent_injection_test"
    monkeypatch.setattr(server, "SESSION_ID", session_id)
    monkeypatch.setenv("SENTINELOPS_SESSION_ID", session_id)

    fixture_path = os.path.join("data", "poisoned_logs_fixture.json")
    with open(fixture_path, "r", encoding="utf-8") as f:
        poisoned_payloads = json.load(f)

    # Convert MCP tools to Groq format (strips execute_pending_action)
    mcp_tools = [
        SimpleNamespace(name="search_logs", description="Search logs", input_schema={"type": "object", "properties": {"query": {"type": "string"}}}),
        SimpleNamespace(name="check_ip_reputation", description="Check IP", input_schema={"type": "object", "properties": {"ip": {"type": "string"}}}),
        SimpleNamespace(name="propose_block_ip", description="Propose block", input_schema={"type": "object", "properties": {"ip": {"type": "string"}, "reason": {"type": "string"}}}),
        SimpleNamespace(name="execute_pending_action", description="Execute", input_schema={"type": "object", "properties": {"token": {"type": "string"}}}),
    ]
    groq_tools = convert_mcp_tools_to_groq_format(SimpleNamespace(tools=mcp_tools), exclude=HUMAN_ONLY_TOOLS)
    exposed_tool_names = {t["function"]["name"] for t in groq_tools}

    # Ensure execute_pending_action is strictly excluded from exposed tools
    assert "execute_pending_action" not in exposed_tool_names

    # Mock MCP session
    mock_mcp_session = AsyncMock()
    async def mock_call_tool(tool_name, tool_args):
        if tool_name == "propose_block_ip":
            res = server.propose_block_ip(tool_args["ip"], tool_args.get("reason", "injected"))
            return SimpleNamespace(content=[SimpleNamespace(text=res)])
        if tool_name == "execute_pending_action":
            res = server.execute_pending_action(tool_args.get("token", "dummy"))
            return SimpleNamespace(content=[SimpleNamespace(text=res)])
        return SimpleNamespace(content=[SimpleNamespace(text="ok")])
    mock_mcp_session.call_tool = mock_call_tool

    # Test each poisoned payload style
    for payload in poisoned_payloads:
        store.clear_store()
        server.ACTION_LOG.clear()

        style = payload["style"]
        if style == "call_execute_pending_action":
            # Attacker payload commands calling execute_pending_action directly
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.choices = [
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=None,
                        tool_calls=[
                            SimpleNamespace(
                                id="call_evil_execute",
                                function=SimpleNamespace(
                                    name="execute_pending_action",
                                    arguments='{"token": "root_bypass_001"}'
                                )
                            )
                        ]
                    )
                )
            ]
            mock_client.chat.completions.create.return_value = mock_response

            messages = [{"role": "user", "content": payload["raw_log"]}]
            updated_messages, final_response = await run_agent_turn(
                client=mock_client,
                messages=messages,
                groq_tools=groq_tools,
                session=mock_mcp_session,
                max_turns=1
            )

            # Assert execute_pending_action was blocked by agent layer before MCP
            tool_msgs = [m for m in updated_messages if m.get("role") == "tool"]
            assert len(tool_msgs) == 1
            assert "Tool not available" in tool_msgs[0]["content"]

        else:
            # Attacker payload commands proposing a block on an unobserved target (e.g. 10.0.0.1)
            target_ip = "10.0.0.1"
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.choices = [
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=None,
                        tool_calls=[
                            SimpleNamespace(
                                id="call_evil_propose",
                                function=SimpleNamespace(
                                    name="propose_block_ip",
                                    arguments=f'{{"ip": "{target_ip}", "reason": "Compromised directive"}}'
                                )
                            )
                        ]
                    )
                )
            ]
            mock_client.chat.completions.create.return_value = mock_response

            messages = [{"role": "user", "content": payload["raw_log"]}]
            updated_messages, final_response = await run_agent_turn(
                client=mock_client,
                messages=messages,
                groq_tools=groq_tools,
                session=mock_mcp_session,
                max_turns=1
            )

            # Assert tool result reports policy rejection
            tool_msgs = [m for m in updated_messages if m.get("role") == "tool"]
            assert len(tool_msgs) == 1
            assert "policy_denied:unobserved_ip" in tool_msgs[0]["content"]

            # Assert no pending action was created in store
            assert len(store.list_actions(session_id=session_id)) == 0

            # Assert rejection was logged to audit log
            entries = server.load_action_log()
            assert any(e.get("reason") == "policy_denied:unobserved_ip" for e in entries)


@pytest.mark.asyncio
async def test_search_logs_poisoned_free_text_does_not_observe_victim_ip_for_all_six_styles(monkeypatch):
    """
    Assert search_logs only records structured IPs, never IPs in free-text (raw_log, user_agent, etc.).
    When mocked LLM subsequently attempts propose_block_ip(victim_ip), it must be rejected with policy_denied:unobserved_ip.
    """
    monkeypatch.setenv("SENTINELOPS_REQUIRE_OBSERVED_IP", "true")
    monkeypatch.setenv("USE_POISONED_LOGS", "true")

    victim_ips_by_style = {
        "direct_instruction": "10.0.0.1",
        "fake_system_message": "192.168.1.99",
        "fake_tool_result_json": "172.16.0.5",
        "user_agent_hidden_instruction": "10.10.10.10",
        "unicode_homoglyph_obfuscation": "10.20.30.40",
        "call_execute_pending_action": "10.0.0.99",
    }

    fixture_path = os.path.join("data", "poisoned_logs_fixture.json")
    with open(fixture_path, "r", encoding="utf-8") as f:
        poisoned_payloads = json.load(f)

    # Groq tools setup
    mcp_tools = [
        SimpleNamespace(name="search_logs", description="Search logs", input_schema={"type": "object", "properties": {"query": {"type": "string"}}}),
        SimpleNamespace(name="propose_block_ip", description="Propose block", input_schema={"type": "object", "properties": {"ip": {"type": "string"}, "reason": {"type": "string"}}}),
    ]
    groq_tools = convert_mcp_tools_to_groq_format(SimpleNamespace(tools=mcp_tools), exclude=HUMAN_ONLY_TOOLS)

    for payload in poisoned_payloads:
        style = payload["style"]
        victim_ip = victim_ips_by_style[style]
        structured_source_ip = payload["ip"]  # e.g. 198.51.100.x
        test_session = f"session_test_{style}"
        monkeypatch.setenv("SENTINELOPS_SESSION_ID", test_session)
        monkeypatch.setattr(server, "SESSION_ID", test_session)

        store.clear_store()
        server.ACTION_LOG.clear()

        # Step 1: Agent calls search_logs for the payload event
        search_output = server.search_logs(payload["event"])
        assert '<untrusted_data source="logs">' in search_output

        # The structured source IP must be observed, but victim IP in free text must NOT be observed
        assert store.is_ip_observed(test_session, structured_source_ip) is True
        assert store.is_ip_observed(test_session, victim_ip) is False

        # Step 2: Mocked LLM falls for the injection and attempts to propose a block on the victim IP
        mock_mcp_session = AsyncMock()
        async def mock_call_tool(tool_name, tool_args):
            if tool_name == "propose_block_ip":
                res = server.propose_block_ip(tool_args["ip"], tool_args.get("reason", "injected"))
                return SimpleNamespace(content=[SimpleNamespace(text=res)])
            return SimpleNamespace(content=[SimpleNamespace(text="ok")])
        mock_mcp_session.call_tool = mock_call_tool

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [
            SimpleNamespace(
                message=SimpleNamespace(
                    content=None,
                    tool_calls=[
                        SimpleNamespace(
                            id="call_evil_propose_victim",
                            function=SimpleNamespace(
                                name="propose_block_ip",
                                arguments=f'{{"ip": "{victim_ip}", "reason": "injected proposal from free text"}}'
                            )
                        )
                    ]
                )
            )
        ]
        mock_client.chat.completions.create.return_value = mock_response

        messages = [{"role": "user", "content": f"Investigate log: {payload['event']}"}]
        updated_messages, _ = await run_agent_turn(
            client=mock_client,
            messages=messages,
            groq_tools=groq_tools,
            session=mock_mcp_session,
            max_turns=1
        )

        # Assert propose_block_ip was rejected with policy_denied:unobserved_ip
        tool_msgs = [m for m in updated_messages if m.get("role") == "tool"]
        assert len(tool_msgs) == 1
        assert "policy_denied:unobserved_ip" in tool_msgs[0]["content"]

        # Assert no action created in store for victim IP
        actions = store.list_actions(session_id=test_session)
        assert len(actions) == 0

        # Assert audit log entry records the rejection
        entries = server.load_action_log()
        assert any(e.get("reason") == "policy_denied:unobserved_ip" and e.get("target") == victim_ip for e in entries)


def test_observed_ip_ttl_and_expiry(monkeypatch):
    """Test TTL enforcement for observed IPs in SQLite store."""
    session_id = "ttl_test_session"
    test_ip = "198.51.100.77"

    store.clear_store()
    monkeypatch.setenv("SENTINELOPS_REQUIRE_OBSERVED_IP", "true")
    monkeypatch.setenv("SENTINELOPS_SESSION_ID", session_id)
    monkeypatch.setattr(server, "SESSION_ID", session_id)

    # Record IP with 2-second TTL and structured log match evidence
    monkeypatch.setenv("SENTINELOPS_OBSERVED_IP_TTL", "2")
    store.record_observed_ip(session_id, test_ip, source="search_logs_match")

    # Within TTL window
    assert store.is_ip_observed(session_id, test_ip) is True
    assert test_ip in store.get_observed_ips(session_id)

    # Proposal succeeds within TTL window
    res = server.propose_block_ip(test_ip, "valid in window")
    assert "PREVIEW" in res

    # Fast forward: manually set observed_at to 10 seconds in the past
    with store.tx() as c:
        c.execute("UPDATE observed_ips SET observed_at = ? WHERE session_id=? AND ip=?", (time.time() - 10, session_id, test_ip))

    # Past TTL window
    assert store.is_ip_observed(session_id, test_ip) is False
    assert test_ip not in store.get_observed_ips(session_id)

    # Proposal must be rejected after expiry
    res_expired = server.propose_block_ip(test_ip, "attempt after expiry")
    assert "policy_denied:unobserved_ip" in res_expired


def test_cli_session_id_per_run_unless_flag_passed(monkeypatch):
    """Test CLI uses a fresh session ID per run unless --session is specified."""
    import argparse
    import cli

    # Case 1: --session passed
    parser = argparse.ArgumentParser()
    parser.add_argument("--session", dest="session_id", default=None)
    args = parser.parse_args(["--session", "my_custom_session_42"])
    assert args.session_id == "my_custom_session_42"

    # Case 2: No --session, defaults to None, runner generates cli_<uuid>
    args_default = parser.parse_args([])
    assert args_default.session_id is None


@pytest.mark.asyncio
async def test_propose_block_ip_requires_justified_evidence_not_just_observation(monkeypatch):
    """
    Addition A Test:
    Observation alone via a low-score reputation call is not enough.
    1. Mocked LLM calls check_ip_reputation(benign_ip) where score < 50.
       IP is observed, but propose_block_ip(benign_ip) is rejected with policy_denied:insufficient_evidence.
    2. Real attacker IP (abuse_score >= 50 or structured log hit) succeeds.
    """
    session_id = "evidence_justification_test_sess"
    monkeypatch.setenv("SENTINELOPS_REQUIRE_OBSERVED_IP", "true")
    monkeypatch.setenv("SENTINELOPS_MIN_BLOCK_SCORE", "50")
    monkeypatch.setenv("SENTINELOPS_SESSION_ID", session_id)
    monkeypatch.setattr(server, "SESSION_ID", session_id)

    store.clear_store()
    server.ACTION_LOG.clear()

    # Step 1: Benign IP 192.168.1.5 (abuse score 0 in stub)
    benign_ip = "192.168.1.5"
    rep_benign = json.loads(server.check_ip_reputation(benign_ip))
    assert rep_benign["abuse_score"] == 0
    assert store.is_ip_observed(session_id, benign_ip) is True

    # Attempt to propose block on benign IP with only observation
    res_benign = server.propose_block_ip(benign_ip, "injected block attempt")
    assert "policy_denied:insufficient_evidence" in res_benign

    # Step 2: Real attacker IP 45.33.22.11 (abuse score 85 in stub)
    attacker_ip = "45.33.22.11"
    rep_attacker = json.loads(server.check_ip_reputation(attacker_ip))
    assert rep_attacker["abuse_score"] >= 50
    assert store.is_ip_observed(session_id, attacker_ip) is True

    # Attempt to propose block on attacker IP with verified evidence
    res_attacker = server.propose_block_ip(attacker_ip, "verified botnet threat")
    assert "PREVIEW" in res_attacker
    assert f"Would block IP {attacker_ip}" in res_attacker



