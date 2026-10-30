"""
Tests for Step 2: Tamper-evident audit log with cryptographic hash chain.
Verifies integrity guarantees:
- Clean chain verifies successfully
- Editing any field is detected
- Deleting a middle line is detected
- Swapping two lines is detected
- Truncating the tail (mid-line or removed records) is detected
- Concurrent writers from 4 separate processes produce a valid hash chain
- Secrets never appear in the audit log
- Migration archives un-chained legacy logs to action_log.legacy.jsonl
- CLI verify_log tool exits with 0 on valid and non-zero on failure
"""
import json
import multiprocessing
import os
import subprocess
import sys
import pytest

import audit_chain
from audit_chain import (
    GENESIS_PREV_HASH,
    append_audit_entry,
    read_audit_log,
    verify_log_chain,
    migrate_legacy_log_if_needed,
)


def test_genesis_entry_has_64_zeros_prev_hash(tmp_path):
    """The first entry in a fresh audit log must have prev_hash equal to 64 zeros and seq=0."""
    log_path = str(tmp_path / "action_log.jsonl")
    entry = append_audit_entry({"event": "system_boot", "details": {"env": "test"}}, log_path=log_path)

    assert entry["seq"] == 0
    assert entry["prev_hash"] == GENESIS_PREV_HASH
    assert "hash" in entry
    assert len(entry["hash"]) == 64

    # Verify chain passes
    is_valid, msg, broken_seq = verify_log_chain(log_path)
    assert is_valid is True
    assert broken_seq is None


def test_clean_chain_verifies(tmp_path):
    """A sequentially appended chain of entries verifies cleanly."""
    log_path = str(tmp_path / "action_log.jsonl")

    for i in range(10):
        entry = append_audit_entry(
            {"action": f"test_action_{i}", "details": {"counter": i, "status": "ok"}},
            log_path=log_path
        )
        assert entry["seq"] == i

    is_valid, msg, broken_seq = verify_log_chain(log_path)
    assert is_valid is True
    assert "Verified 10 entries" in msg
    assert broken_seq is None


def test_editing_a_field_is_detected(tmp_path):
    """Modifying any field (even whitespace or timestamp) in an entry breaks the hash and is detected."""
    log_path = str(tmp_path / "action_log.jsonl")

    for i in range(5):
        append_audit_entry({"event": f"action_{i}", "details": {"val": i}}, log_path=log_path)

    # Tamper with seq 2
    entries = read_audit_log(log_path)
    entries[2]["details"]["val"] = 999  # Tampered field!

    with open(log_path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")

    is_valid, msg, broken_seq = verify_log_chain(log_path)
    assert is_valid is False
    assert broken_seq == 2
    assert "Modified entry at seq 2" in msg


def test_deleting_a_middle_line_is_detected(tmp_path):
    """Deleting a line causes a sequence gap and broken prev_hash, which is detected."""
    log_path = str(tmp_path / "action_log.jsonl")

    for i in range(6):
        append_audit_entry({"event": f"event_{i}"}, log_path=log_path)

    # Delete entry seq 2
    entries = read_audit_log(log_path)
    del entries[2]

    with open(log_path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")

    is_valid, msg, broken_seq = verify_log_chain(log_path)
    assert is_valid is False
    # Next entry had seq 3, expected seq 2
    assert broken_seq == 3
    assert "Deleted entry or gap in sequence" in msg


def test_swapping_two_lines_is_detected(tmp_path):
    """Swapping adjacent entries disrupts sequence and prev_hash links, which is detected."""
    log_path = str(tmp_path / "action_log.jsonl")

    for i in range(5):
        append_audit_entry({"event": f"event_{i}"}, log_path=log_path)

    # Swap entries 2 and 3
    entries = read_audit_log(log_path)
    entries[2], entries[3] = entries[3], entries[2]

    with open(log_path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")

    is_valid, msg, broken_seq = verify_log_chain(log_path)
    assert is_valid is False
    assert broken_seq in (2, 3)


def test_truncating_the_tail_is_detected(tmp_path):
    """Truncating the file mid-line or removing entries against expected count is detected."""
    log_path = str(tmp_path / "action_log.jsonl")

    for i in range(5):
        append_audit_entry({"event": f"event_{i}"}, log_path=log_path)

    # Case A: Partial line cut-off at tail
    with open(log_path, "rb") as f:
        content = f.read()
    with open(log_path, "wb") as f:
        f.write(content[:-25])  # Cut off trailing bytes mid-JSON

    is_valid, msg, _ = verify_log_chain(log_path)
    assert is_valid is False
    assert "Malformed or truncated JSON" in msg

    # Case B: Complete entries removed from tail when checked against expected count
    log_path_b = str(tmp_path / "action_log_b.jsonl")
    for i in range(5):
        append_audit_entry({"event": f"event_{i}"}, log_path=log_path_b)

    entries = read_audit_log(log_path_b)
    del entries[-1]  # Remove 5th entry
    with open(log_path_b, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")

    is_valid_b, msg_b, _ = verify_log_chain(log_path_b, expected_count=5)
    assert is_valid_b is False
    assert "Tail truncated" in msg_b


def _worker_write_entries(log_path, worker_id, count):
    """Worker process for concurrency testing."""
    for i in range(count):
        append_audit_entry(
            {"event": f"worker_{worker_id}_event_{i}", "details": {"worker": worker_id, "i": i}},
            log_path=log_path,
        )


def test_concurrent_writers_from_four_processes_produce_valid_chain(tmp_path):
    """4 concurrent processes writing simultaneously produce an unbroken, monotonically ordered chain."""
    log_path = str(tmp_path / "concurrent_action_log.jsonl")
    num_processes = 4
    entries_per_process = 25
    total_expected = num_processes * entries_per_process

    processes = []
    for wid in range(num_processes):
        p = multiprocessing.Process(
            target=_worker_write_entries,
            args=(log_path, wid, entries_per_process)
        )
        processes.append(p)
        p.start()

    for p in processes:
        p.join(timeout=30)
        assert p.exitcode == 0, f"Worker process failed with exit code {p.exitcode}"

    entries = read_audit_log(log_path)
    assert len(entries) == total_expected

    # Verify that sequences are strictly 0..total_expected-1 without gaps or duplicates
    seqs = [e["seq"] for e in entries]
    assert seqs == list(range(total_expected))

    # Cryptographic hash chain verification
    is_valid, msg, broken_seq = verify_log_chain(log_path)
    assert is_valid is True, f"Chain failed verification: {msg}"
    assert broken_seq is None


def test_secrets_never_appear_in_audit_chain(tmp_path, monkeypatch):
    """Configured API keys, bot tokens, evidence tokens, and passwords must never appear in the chained log."""
    log_path = str(tmp_path / "secrets_action_log.jsonl")

    fake_groq = "gsk_test_secret_key_1234567890"
    fake_abuse = "abuse_secret_key_abcdef12345"
    fake_tg = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
    monkeypatch.setenv("GROQ_API_KEY", fake_groq)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", fake_abuse)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", fake_tg)

    append_audit_entry(
        {
            "event": "suspicious_request",
            "api_key": fake_groq,
            "bot_token": fake_tg,
            "evidence_token": "secret_evidence_token_xyz",
            "details": {
                "url": f"https://api.test/?key={fake_abuse}",
                "password": "SuperSecretPassword123",
            }
        },
        log_path=log_path
    )

    with open(log_path, "r", encoding="utf-8") as f:
        content = f.read()

    for secret in (fake_groq, fake_abuse, fake_tg, "SuperSecretPassword123", "secret_evidence_token_xyz"):
        assert secret not in content

    # The chain itself remains valid
    is_valid, msg, broken_seq = verify_log_chain(log_path)
    assert is_valid is True
    assert broken_seq is None


def test_legacy_log_migration_archives_to_legacy_file(tmp_path):
    """Existing un-chained legacy logs are moved to action_log.legacy.jsonl, starting a fresh chain."""
    log_path = str(tmp_path / "action_log.jsonl")
    legacy_archive = str(tmp_path / "action_log.legacy.jsonl")

    # Seed an old legacy log without hash/seq
    legacy_record = {"action": "old_action", "timestamp": "2026-01-01 00:00:00"}
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(legacy_record) + "\n")

    # Writing an audit entry should trigger migration
    entry = append_audit_entry({"event": "new_action"}, log_path=log_path)

    # Legacy file was created and contains the old line
    assert os.path.exists(legacy_archive)
    with open(legacy_archive, "r", encoding="utf-8") as f:
        legacy_lines = f.readlines()
    assert len(legacy_lines) == 1
    assert "old_action" in legacy_lines[0]

    # New log starts cleanly from seq 0
    assert entry["seq"] == 0
    assert entry["prev_hash"] == GENESIS_PREV_HASH

    is_valid, msg, _ = verify_log_chain(log_path)
    assert is_valid is True


def test_verify_log_cli_tool(tmp_path):
    """Test CLI verification commands via python -m sentinelops.verify_log and scripts/verify_log.py."""
    log_path = str(tmp_path / "cli_test_log.jsonl")

    # Create 3 valid entries
    for i in range(3):
        append_audit_entry({"event": f"event_{i}"}, log_path=log_path)

    # Case 1: Valid log exits 0
    res_module = subprocess.run(
        [sys.executable, "-m", "sentinelops.verify_log", "--path", log_path],
        capture_output=True,
        text=True,
    )
    assert res_module.returncode == 0
    assert "OK: Verified 3 entries" in res_module.stdout

    res_script = subprocess.run(
        [sys.executable, os.path.join("scripts", "verify_log.py"), "--path", log_path],
        capture_output=True,
        text=True,
    )
    assert res_script.returncode == 0
    assert "OK: Verified 3 entries" in res_script.stdout

    # Case 2: Tamper with log -> exits non-zero (1)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write('{"seq": 99, "prev_hash": "bad", "hash": "bad"}\n')

    res_bad = subprocess.run(
        [sys.executable, "-m", "sentinelops.verify_log", "--path", log_path],
        capture_output=True,
        text=True,
    )
    assert res_bad.returncode != 0
    assert "FAIL" in res_bad.stderr


def test_clean_tail_deletion_detected_via_sqlite_audit_head(tmp_path, monkeypatch):
    """
    Addition B Test:
    Writes entries to log and SQLite store.
    Deleting the last 3 lines cleanly leaves a valid cryptographic sub-chain in the file,
    but verify_log detects head mismatch with the SQLite store without needing --expected-count.
    """
    import store
    log_path = str(tmp_path / "action_log.jsonl")
    db_path = str(tmp_path / "test.db")
    monkeypatch.setenv("SENTINELOPS_DB_PATH", db_path)
    store.init_db(db_path)

    # Write 6 entries
    for i in range(6):
        append_audit_entry({"event": f"event_{i}"}, log_path=log_path, db_path=db_path)

    # Clean file verifies with SQLite audit head
    is_valid, msg, _ = verify_log_chain(log_path, db_path=db_path)
    assert is_valid is True

    # Check store has recorded head
    head = store.get_audit_head(db_path=db_path)
    assert head is not None
    assert head["last_seq"] == 5

    # Delete the last 3 lines cleanly
    entries = read_audit_log(log_path)
    del entries[-3:]  # Now only has seq 0, 1, 2
    assert len(entries) == 3

    with open(log_path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")

    # verify_log_chain fails WITHOUT --expected-count because SQLite store head has seq 5
    is_valid_after, msg_after, broken_seq = verify_log_chain(log_path, db_path=db_path)
    assert is_valid_after is False
    assert "Audit head mismatch or tail truncation" in msg_after
    assert broken_seq == 2


