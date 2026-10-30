"""Pytest configuration"""
import pytest

# These files are manual/live-service scripts, not offline pytest modules.
collect_ignore = [
    "e2e_stdio_check.py",
    "test_adversarial_gates.py",
    "test_confirm_consistency.py",
    "test_debug_gate.py",
    "test_decline_consistency.py",
    "test_docker_deployment.py",
    "test_error_rendering.py",
    "test_flask_debug_gate_simple.py",
    "test_flask_mcp_consistency.py",
    "test_mcp_persistence.py",
    "test_mcp_sees_declined.py",
    "test_security_direct.py",
    "test_security_gates.py",
    "test_transcript_fix.py",
    "test_web_ui.py",
]


@pytest.fixture(autouse=True)
def configure_unit_test_policy(request, monkeypatch):
    """Allow legacy unit tests to test address-target format validation directly."""
    if "test_unit" in request.node.nodeid:
        monkeypatch.setenv("SENTINELOPS_REQUIRE_OBSERVED_IP", "false")
