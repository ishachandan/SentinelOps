"""Offline Flask test-client coverage for the server-side confirmation gate."""
import asyncio
import json
import os
import sys
from pathlib import Path

os.environ["USE_REAL_APIS"] = "false"

import pytest

import web_ui


@pytest.fixture
def gate_client(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    pending_actions_file = data_dir / "pending_actions.json"
    action_log_file = data_dir / "action_log.jsonl"
    server_path = Path(__file__).resolve().parents[1] / "server.py"
    server_parameters = web_ui.StdioServerParameters

    monkeypatch.setattr(web_ui, "PENDING_ACTIONS_FILE", str(pending_actions_file))
    monkeypatch.setattr(web_ui, "ENABLE_DEBUG_ENDPOINTS", True)

    def local_server_parameters(command, args, env=None):
        child_env = os.environ.copy()
        child_env.update(env or {})
        child_env["USE_REAL_APIS"] = "false"
        child_env["ENABLE_DEBUG_ENDPOINTS"] = "false"
        return server_parameters(
            command=sys.executable if command == "python" else command,
            args=[str(server_path), *args[1:]],
            env=child_env,
            cwd=str(tmp_path),
        )

    monkeypatch.setattr(web_ui, "StdioServerParameters", local_server_parameters)

    monkeypatch.setitem(web_ui.app.config, "TESTING", True)
    client = web_ui.app.test_client()
    with client.session_transaction() as flask_session:
        flask_session["session_id"] = "session-a"

    return client, pending_actions_file, action_log_file


def seed_action(client, token):
    response = client.post(
        "/debug/seed_token",
        json={
            "token": token,
            "action_type": "block_ip",
            "ip": "192.168.1.5",
            "reason": "test-client security gate test",
        },
    )
    assert response.status_code == 200


def test_debug_seed_endpoint_is_disabled_when_flag_is_false(gate_client, monkeypatch):
    client, _, _ = gate_client
    monkeypatch.setattr(web_ui, "ENABLE_DEBUG_ENDPOINTS", False)

    response = client.post(
        "/debug/seed_token",
        json={"token": "disabled1", "action_type": "block_ip", "ip": "192.168.1.5"},
    )

    assert response.status_code == 404
    assert "Debug endpoints are disabled" in response.json["error"]


def confirm(client, token):
    try:
        return client.post(f"/confirm/{token}")
    finally:
        asyncio.set_event_loop(None)


def test_valid_token_for_correct_session_executes(gate_client):
    client, pending_actions_file, action_log_file = gate_client
    seed_action(client, "valid-token")

    response = confirm(client, "valid-token")

    assert response.status_code == 200
    assert response.json["success"] is True
    assert "Blocked IP 192.168.1.5" in response.json["result"]
    with pending_actions_file.open(encoding="utf-8") as actions_file:
        assert json.load(actions_file)["valid-token"]["status"] == "executed"
    with action_log_file.open(encoding="utf-8") as action_log:
        entries = [json.loads(line) for line in action_log if line.strip()]
    assert len(entries) == 1
    assert entries[0]["ip"] == "192.168.1.5"


def test_fake_token_returns_404(gate_client):
    client, _, _ = gate_client

    response = client.post("/confirm/fake-token")

    assert response.status_code == 404


def test_reused_token_returns_400(gate_client):
    client, _, action_log_file = gate_client
    seed_action(client, "reused-token")

    first_response = confirm(client, "reused-token")
    second_response = client.post("/confirm/reused-token")

    assert first_response.status_code == 200
    assert second_response.status_code == 400
    with action_log_file.open(encoding="utf-8") as action_log:
        entries = [json.loads(line) for line in action_log if line.strip()]
    assert len(entries) == 1


def test_cross_session_token_returns_403(gate_client):
    client, _, _ = gate_client
    seed_action(client, "cross-session-token")
    other_client = web_ui.app.test_client()
    with other_client.session_transaction() as flask_session:
        flask_session["session_id"] = "session-b"

    response = other_client.post("/confirm/cross-session-token")

    assert response.status_code == 403


def test_declined_token_never_executes(gate_client):
    client, pending_actions_file, action_log_file = gate_client
    seed_action(client, "declined-token")

    response = client.post("/decline/declined-token")
    assert response.status_code == 200
    assert response.json["success"] is True
    with pending_actions_file.open(encoding="utf-8") as actions_file:
        assert json.load(actions_file)["declined-token"]["status"] == "declined"
    assert not action_log_file.exists()
