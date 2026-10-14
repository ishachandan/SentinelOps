"""Focused tests for SentinelOps security hardening contracts."""
import asyncio
import json
import os
from types import SimpleNamespace

import pytest

os.environ["USE_REAL_APIS"] = "false"

import agent_shared
import cli
import server
import web_ui


@pytest.fixture
def isolated_server(tmp_path, monkeypatch):
    sandbox = tmp_path / "data" / "sentinelops_sandbox"
    quarantine = sandbox / "quarantine"
    sandbox.mkdir(parents=True)
    quarantine.mkdir()
    pending_file = tmp_path / "data" / "pending_actions.json"
    audit_file = tmp_path / "data" / "action_log.jsonl"
    incidents_file = tmp_path / "incidents.json"

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(server, "QUARANTINE_SANDBOX_DIR", str(sandbox))
    monkeypatch.setattr(server, "QUARANTINE_DIR", str(quarantine))
    monkeypatch.setattr(server, "PENDING_ACTIONS_FILE", str(pending_file))
    monkeypatch.setattr(server, "ACTION_LOG_FILE", str(audit_file))
    monkeypatch.setattr(server, "INCIDENTS_FILE", str(incidents_file))
    monkeypatch.setattr(server, "ACTION_LOG", [])
    monkeypatch.setattr(server, "USE_REAL_APIS", False)
    server.PENDING_ACTIONS.clear()
    server.REPUTATION_RESULTS.clear()
    return sandbox, pending_file, audit_file, incidents_file


def read_audit(path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ] if path.exists() else []


def test_quarantine_proposal_contains_target_and_rejects_escape_paths(isolated_server, tmp_path):
    sandbox, _, _, _ = isolated_server
    in_sandbox_file = sandbox / "payload.txt"
    in_sandbox_file.write_text("sample", encoding="utf-8")
    assert "PREVIEW" in server.propose_quarantine_file(str(in_sandbox_file), "test")

    sibling = tmp_path / "data" / "sentinelops_sandbox_evil"
    sibling.mkdir()
    existing_outside = sibling / "x"
    existing_outside.write_text("outside", encoding="utf-8")
    absent_outside = sibling / "missing"
    messages = [
        server.propose_quarantine_file(str(existing_outside), "test"),
        server.propose_quarantine_file(str(absent_outside), "test"),
        server.propose_quarantine_file("../outside.txt", "test"),
        server.propose_quarantine_file(str(tmp_path / "outside.txt"), "test"),
        server.propose_quarantine_file(str(sandbox), "test"),
        server.propose_quarantine_file(str(sandbox / "quarantine"), "test"),
    ]

    assert len(set(messages)) == 1
    assert messages[0] == "Error: File is outside the quarantine sandbox."
    rejection_entries = read_audit(tmp_path / "data" / "action_log.jsonl")
    assert len(rejection_entries) == 6
    assert all(entry["status"] == "rejected" for entry in rejection_entries)


def test_sandbox_resolver_rejects_different_drive_paths(isolated_server, monkeypatch):
    monkeypatch.setattr(server.os.path, "realpath", lambda path: path)
    monkeypatch.setattr(server.os.path, "commonpath", lambda _paths: (_ for _ in ()).throw(ValueError()))

    assert server._resolve_in_sandbox("C:\\outside.txt") is None


def test_quarantine_symlink_escape_rejected_at_proposal_and_execution(
    isolated_server, tmp_path
):
    sandbox, pending_file, _, _ = isolated_server
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = sandbox / "payload.txt"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Operating system refused to create a symlink: {exc}")

    assert server.propose_quarantine_file(str(link), "test") == (
        "Error: File is outside the quarantine sandbox."
    )
    link.unlink()

    candidate = sandbox / "payload.txt"
    candidate.write_text("sample", encoding="utf-8")
    result = server.propose_quarantine_file(str(candidate), "test")
    token = result.split("Token: ", 1)[1].splitlines()[0]
    actions = server.load_pending_actions()
    actions[token]["status"] = "confirmed"
    server.save_pending_actions(actions)
    candidate.unlink()
    try:
        os.symlink(outside, candidate)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Operating system refused to create a symlink: {exc}")

    result = server.execute_pending_action(token)

    assert result == "Error: File is outside the quarantine sandbox."
    with pending_file.open(encoding="utf-8") as actions_file:
        assert json.load(actions_file)[token]["status"] == "confirmed"


def test_audit_log_persists_calls_and_skips_malformed_lines(isolated_server):
    _, _, audit_file, _ = isolated_server
    server.log_action({"action": "one", "status": "recorded"})
    server.log_action({"action": "two", "status": "recorded"})
    with audit_file.open("a", encoding="utf-8") as audit:
        audit.write("not-json\n")

    assert [entry["action"] for entry in server.load_action_log()] == ["one", "two"]
    assert len(server.ACTION_LOG) == 2


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("pending", "not confirmed"),
        ("declined", "declined"),
        ("executed", "already executed"),
    ],
)
def test_execute_pending_action_refusals_are_logged(isolated_server, status, expected):
    _, _, audit_file, _ = isolated_server
    actions = {"test-token": {"action_type": "block_ip", "ip": "8.8.8.8", "status": status}}
    server.save_pending_actions(actions)

    result = server.execute_pending_action("test-token")

    assert expected in result
    assert read_audit(audit_file)[0]["status"] == "rejected"


def test_rejected_block_ip_is_logged(isolated_server):
    _, _, audit_file, _ = isolated_server

    assert server.propose_block_ip("127.0.0.1", "test") == (
        "Error: Loopback IP addresses cannot be blocked: 127.0.0.1"
    )
    entry = read_audit(audit_file)[0]
    assert entry["action"] == "propose_block_ip"
    assert entry["status"] == "rejected"
    assert entry["reason"] == "invalid_block_ip"


def test_unknown_execution_token_is_logged_without_token_value(isolated_server):
    _, _, audit_file, _ = isolated_server

    result = server.execute_pending_action("sensitive-token-value")

    assert "not found" in result
    contents = audit_file.read_text(encoding="utf-8")
    assert "sensitive-token-value" not in contents
    assert read_audit(audit_file)[0]["reason"] == "unknown_token"


def test_failed_execution_keeps_confirmed_state(isolated_server, monkeypatch):
    _, pending_file, audit_file, _ = isolated_server
    server.save_pending_actions({
        "failed-token": {"action_type": "block_ip", "ip": "8.8.8.8", "status": "confirmed"}
    })
    monkeypatch.setattr(server, "execute_block_ip_stub", lambda _action, _token: "Error: simulated")

    assert "Error:" in server.execute_pending_action("failed-token")
    with pending_file.open(encoding="utf-8") as actions_file:
        assert json.load(actions_file)["failed-token"]["status"] == "confirmed"
    assert read_audit(audit_file)[0]["reason"] == "execution_failed"


@pytest.mark.parametrize(
    ("related_ip", "evidence_token", "evidence", "severity", "summary", "succeeds"),
    [
        ("8.8.8.8", None, None, "high", "routine incident", False),
        (None, "malicious", {"ip": "8.8.8.8", "is_malicious": True}, "high", "routine incident", False),
        ("8.8.8.8", "unknown", None, "high", "routine incident", False),
        ("8.8.8.8", "clean", {"ip": "8.8.8.8", "is_malicious": False}, "high", "routine incident", False),
        ("1.1.1.1", "other", {"ip": "8.8.8.8", "is_malicious": True}, "high", "routine incident", False),
        ("8.8.8.8", "malicious", {"ip": "8.8.8.8", "is_malicious": True}, "high", "routine incident", True),
        (None, None, None, "low", "routine incident", True),
        (None, None, None, "medium", "routine incident", True),
    ],
)
def test_create_incident_evidence_matrix(
    isolated_server, related_ip, evidence_token, evidence, severity, summary, succeeds
):
    if evidence_token and evidence is not None:
        server.REPUTATION_RESULTS[evidence_token] = evidence

    result = server.create_incident(
        summary=summary,
        severity=severity,
        related_ip=related_ip,
        evidence_token=evidence_token,
    )

    assert ("successfully" in result.lower()) is succeeds


def test_create_incident_rejection_audit_covers_required_evidence_failures(isolated_server):
    _, _, audit_file, _ = isolated_server
    server.REPUTATION_RESULTS["clean"] = {"ip": "8.8.8.8", "is_malicious": False}
    server.REPUTATION_RESULTS["other"] = {"ip": "1.1.1.1", "is_malicious": True}

    server.create_incident("no ip", "high")
    server.create_incident("no token", "high", related_ip="8.8.8.8")
    server.create_incident("unknown", "high", related_ip="8.8.8.8", evidence_token="secret-unknown")
    server.create_incident("clean", "high", related_ip="8.8.8.8", evidence_token="clean")
    server.create_incident("mismatch", "high", related_ip="8.8.8.8", evidence_token="other")

    entries = read_audit(audit_file)
    assert len(entries) == 5
    assert all(entry["status"] == "rejected" for entry in entries)
    assert "secret-unknown" not in audit_file.read_text(encoding="utf-8")


def test_notify_telegram_evidence_matrix_and_audit(isolated_server, monkeypatch):
    _, _, audit_file, _ = isolated_server
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "fake-bot-secret")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "fake-chat-secret")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake-api-secret")
    server.REPUTATION_RESULTS.update({
        "clean": {"ip": "8.8.8.8", "is_malicious": False},
        "different": {"ip": "1.1.1.1", "is_malicious": True},
        "fake-evidence-secret": {"ip": "45.33.22.11", "is_malicious": True},
    })
    calls = []

    def send_success(*_args, **_kwargs):
        calls.append("sent")
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(server.requests, "post", send_success)
    assert "REJECTED" in server.notify_telegram("Threat from 45.33.22.11")
    assert "REJECTED" in server.notify_telegram("Threat from 45.33.22.11", "unknown-secret-token")
    assert "REJECTED" in server.notify_telegram("Threat from 8.8.8.8", "clean")
    assert "REJECTED" in server.notify_telegram("Threat from 8.8.8.8", "different")
    assert "successfully" in server.notify_telegram(
        "Threat from 45.33.22.11", "fake-evidence-secret"
    ).lower()
    assert calls == ["sent"]

    def send_failure(*_args, **_kwargs):
        calls.append("failed")
        return SimpleNamespace(status_code=503)

    monkeypatch.setattr(server.requests, "post", send_failure)
    assert "HTTP 503" in server.notify_telegram(
        "Threat from 45.33.22.11", "fake-evidence-secret"
    )

    entries = read_audit(audit_file)
    assert [entry["status"] for entry in entries].count("rejected") == 4
    assert "sent" in [entry["status"] for entry in entries]
    assert "failed" in [entry["status"] for entry in entries]
    audit_contents = audit_file.read_text(encoding="utf-8")
    for secret in (
        "fake-bot-secret", "fake-chat-secret", "fake-api-secret",
        "fake-evidence-secret", "unknown-secret-token"
    ):
        assert secret not in audit_contents


def test_log_action_does_not_persist_secret_fields(isolated_server):
    _, _, audit_file, _ = isolated_server

    server.log_action({
        "action": "test",
        "api_key": "fake-api-secret",
        "bot_token": "fake-bot-secret",
        "evidence_token": "fake-evidence-secret",
    })

    contents = audit_file.read_text(encoding="utf-8")
    assert all(secret not in contents for secret in ("fake-api-secret", "fake-bot-secret", "fake-evidence-secret"))


def test_flask_debug_env_parser(monkeypatch):
    monkeypatch.delenv("FLASK_DEBUG", raising=False)
    assert web_ui.is_flask_debug_enabled() is False
    for value in ("1", "true", "YES", "TrUe"):
        monkeypatch.setenv("FLASK_DEBUG", value)
        assert web_ui.is_flask_debug_enabled() is True
    for value in ("0", "false", "no", ""):
        monkeypatch.setenv("FLASK_DEBUG", value)
        assert web_ui.is_flask_debug_enabled() is False


def test_web_ui_passes_mcp_feature_flags_without_copying_secrets(monkeypatch):
    monkeypatch.setenv("USE_REAL_APIS", "false")
    monkeypatch.setenv("ENABLE_DEBUG_ENDPOINTS", "true")
    monkeypatch.setenv("GROQ_API_KEY", "fake-groq-secret")

    params = web_ui.mcp_server_parameters()

    assert params.env == {
        "USE_REAL_APIS": "false",
        "ENABLE_DEBUG_ENDPOINTS": "true",
    }


def make_tool(name):
    return {
        "type": "function",
        "function": {"name": name, "parameters": {"type": "object"}},
    }


def make_mcp_tool(name):
    return SimpleNamespace(
        name=name,
        description=name,
        inputSchema={"type": "object", "properties": {}},
    )


def fake_groq_client(*tool_names):
    responses = []
    for index, name in enumerate(tool_names):
        tool_call = SimpleNamespace(
            id=f"call-{index}",
            function=SimpleNamespace(name=name, arguments="{}"),
        )
        message = SimpleNamespace(content=None, tool_calls=[tool_call])
        responses.append(SimpleNamespace(choices=[SimpleNamespace(message=message)]))
    final_message = SimpleNamespace(content="done", tool_calls=None)
    responses.append(SimpleNamespace(choices=[SimpleNamespace(message=final_message)]))

    class Completions:
        def create(self, **_kwargs):
            return responses.pop(0)

    return SimpleNamespace(chat=SimpleNamespace(completions=Completions()))


def test_tool_conversion_filters_human_only_tools():
    response = SimpleNamespace(tools=[
        make_mcp_tool("execute_pending_action"),
        make_mcp_tool("debug_seed_pending_action"),
        make_mcp_tool("ping"),
    ])

    tools = agent_shared.convert_mcp_tools_to_groq_format(
        response,
        exclude=agent_shared.HUMAN_ONLY_TOOLS,
    )

    assert [tool["function"]["name"] for tool in tools] == ["ping"]


@pytest.mark.asyncio
async def test_agent_rejects_unexposed_tool_without_calling_mcp():
    calls = []

    class Session:
        async def call_tool(self, name, args):
            calls.append((name, args))
            return SimpleNamespace(content=[SimpleNamespace(text="called")])

    messages, _ = await agent_shared.run_agent_turn(
        fake_groq_client("not_exposed"),
        [],
        [make_tool("ping")],
        Session(),
    )

    assert any(
        message.get("role") == "tool" and message.get("content") == "Tool not available"
        for message in messages
    )
    assert calls == []


@pytest.mark.asyncio
async def test_agent_executes_normal_exposed_tool():
    calls = []

    class Session:
        async def call_tool(self, name, args):
            calls.append((name, args))
            return SimpleNamespace(content=[SimpleNamespace(text="pong")])

    messages, final_response = await agent_shared.run_agent_turn(
        fake_groq_client("ping"),
        [],
        [make_tool("ping")],
        Session(),
    )

    assert calls == [("ping", {})]
    assert any(message.get("content") == "pong" for message in messages)
    assert final_response == "done"


@pytest.mark.parametrize(
    ("confirmation", "expected_status", "expected_executions"),
    [("n", "declined", 0), ("y", "executed", 1)],
)
def test_cli_human_confirmation_controls_proposal_execution(
    tmp_path, monkeypatch, confirmation, expected_status, expected_executions
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GROQ_API_KEY", "fake-groq-key")
    inputs = iter(["block 45.33.22.11", confirmation, "exit"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))
    pending_file = tmp_path / "data" / "pending_actions.json"
    pending_file.parent.mkdir()
    calls = []
    status_observed_at_execution = []

    class FakeSession:
        async def initialize(self):
            return None

        async def list_tools(self):
            return SimpleNamespace(tools=[
                make_mcp_tool("propose_block_ip"),
                make_mcp_tool("execute_pending_action"),
                make_mcp_tool("debug_seed_pending_action"),
            ])

        async def call_tool(self, name, args):
            calls.append(name)
            if name == "propose_block_ip":
                pending_file.write_text(json.dumps({
                    "c11a1234": {"status": "pending", "action_type": "block_ip"}
                }), encoding="utf-8")
                return SimpleNamespace(content=[SimpleNamespace(
                    text="PREVIEW: Would block IP 45.33.22.11\nToken: c11a1234"
                )])
            assert name == "execute_pending_action"
            actions = json.loads(pending_file.read_text(encoding="utf-8"))
            status_observed_at_execution.append(actions["c11a1234"]["status"])
            actions["c11a1234"]["status"] = "executed"
            pending_file.write_text(json.dumps(actions), encoding="utf-8")
            return SimpleNamespace(content=[SimpleNamespace(text="SUCCESS: blocked")])

    session = FakeSession()

    class FakeClient:
        api_key = "fake-groq-key"

        def __init__(self):
            tool_call = SimpleNamespace(
                id="proposal-call",
                function=SimpleNamespace(
                    name="propose_block_ip",
                    arguments='{"ip":"45.33.22.11","reason":"test"}',
                ),
            )
            self.responses = [
                SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(
                    content=None, tool_calls=[tool_call]
                ))]),
                SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(
                    content="finished", tool_calls=None
                ))]),
            ]
            self.chat = SimpleNamespace(completions=self)

        def create(self, **_kwargs):
            return self.responses.pop(0)

    class FakeGroq:
        def __init__(self, api_key):
            self.client = FakeClient()
            self.api_key = api_key

        @property
        def chat(self):
            return self.client.chat

    class FakeSessionContext:
        async def __aenter__(self):
            return session

        async def __aexit__(self, *_args):
            return False

    class FakeStdioContext:
        async def __aenter__(self):
            return None, None

        async def __aexit__(self, *_args):
            return False

    monkeypatch.setattr(cli, "Groq", FakeGroq)
    monkeypatch.setattr(cli, "ClientSession", lambda *_args: FakeSessionContext())
    monkeypatch.setattr(cli, "stdio_client", lambda *_args: FakeStdioContext())

    asyncio.run(cli.run_cli())

    saved_action = json.loads(pending_file.read_text(encoding="utf-8"))["c11a1234"]
    assert saved_action["status"] == expected_status
    assert calls.count("execute_pending_action") == expected_executions
    if confirmation == "y":
        assert status_observed_at_execution == ["confirmed"]
    else:
        assert status_observed_at_execution == []
