import multiprocessing
import time

import pytest

import store


@pytest.fixture(autouse=True)
def use_temporary_store(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELOPS_DB", str(tmp_path / "sentinelops.db"))


def _confirm_in_process(token):
    return store.transition(token, "s1", "pending", "confirmed")


def new_action(ttl=900):
    return store.create_action("store-test-token", "s1", "block_ip", {"ip": "1.2.3.4"}, ttl=ttl)


def test_state_machine_happy_path():
    new_action()
    assert store.transition("store-test-token", "s1", "pending", "confirmed")
    assert store.transition("store-test-token", "s1", "confirmed", "executing")
    assert store.transition("store-test-token", "s1", "executing", "executed")
    assert store.get_action("store-test-token")["status"] == "executed"


def test_wrong_session_and_replay_are_rejected():
    new_action()
    assert not store.transition("store-test-token", "other", "pending", "confirmed")
    assert store.transition("store-test-token", "s1", "pending", "confirmed")
    assert not store.transition("store-test-token", "s1", "pending", "confirmed")


def test_illegal_transition_raises():
    with pytest.raises(ValueError):
        store.transition("missing", "s1", "pending", "executed")


def test_pending_expiry_and_confirmed_execution_after_expiry():
    new_action(ttl=-1)
    assert not store.transition("store-test-token", "s1", "pending", "confirmed")
    assert store.expire_stale() == 1

    store.create_action("confirmed-token", "s1", "block_ip", {}, ttl=1)
    assert store.transition("confirmed-token", "s1", "pending", "confirmed")
    time.sleep(1.1)
    assert store.transition("confirmed-token", "s1", "confirmed", "executing")


def test_stuck_execution_is_recovered():
    new_action()
    store.transition("store-test-token", "s1", "pending", "confirmed")
    store.transition("store-test-token", "s1", "confirmed", "executing")
    store.STUCK_AFTER = -1
    try:
        assert store.expire_stale() == 1
        action = store.get_action("store-test-token")
        assert action["status"] == "failed"
        assert action["error"] == "interrupted: outcome unknown"
    finally:
        store.STUCK_AFTER = 5 * 60


def test_multiprocess_confirms_have_exactly_one_winner():
    new_action()
    with multiprocessing.get_context("spawn").Pool(8) as pool:
        results = pool.map(_confirm_in_process, ["store-test-token"] * 8)
    assert results.count(True) == 1
