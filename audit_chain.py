"""
Tamper-evident audit log with cryptographic hash chaining and secret redaction.
Each record contains: seq, ts, event, details, prev_hash, hash.
Genesis entry has prev_hash = '0' * 64.
hash = SHA256(prev_hash + canonical_json(entry without hash)).
"""
import datetime
import hashlib
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

GENESIS_PREV_HASH = "0" * 64
DEFAULT_ACTION_LOG_FILE = os.path.join("data", "action_log.jsonl")
SENSITIVE_KEYS = {"api_key", "bot_token", "chat_id", "secret", "password", "evidence_token", "token"}
SECRET_ENV_VARS = (
    "ABUSEIPDB_API_KEY",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
    "GROQ_API_KEY",
    "FLASK_SECRET_KEY",
)


class FileLock:
    """Cross-platform inter-process file lock (msvcrt on Windows, fcntl on Unix)."""

    def __init__(self, lock_file_path: str, timeout: float = 15.0, retry_interval: float = 0.05):
        self.lock_file_path = lock_file_path
        self.timeout = timeout
        self.retry_interval = retry_interval
        self._fd = None

    def __enter__(self):
        start = time.time()
        os.makedirs(os.path.dirname(os.path.abspath(self.lock_file_path)), exist_ok=True)
        while True:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    self._fd = open(self.lock_file_path, "w")
                    msvcrt.locking(self._fd.fileno(), msvcrt.LK_NBLCK, 1)
                    return self
                else:
                    import fcntl
                    self._fd = open(self.lock_file_path, "w")
                    fcntl.flock(self._fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return self
            except (IOError, OSError):
                if self._fd is not None:
                    try:
                        self._fd.close()
                    except Exception:
                        pass
                    self._fd = None
                if time.time() - start > self.timeout:
                    raise TimeoutError(f"Could not acquire file lock on {self.lock_file_path} within {self.timeout}s")
                time.sleep(self.retry_interval)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._fd is not None:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    self._fd.seek(0)
                    msvcrt.locking(self._fd.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._fd.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            finally:
                try:
                    self._fd.close()
                except Exception:
                    pass
                self._fd = None


def canonical_json(obj: Any) -> str:
    """Deterministic, whitespace-normalized JSON encoding for cryptographic hashing."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def compute_entry_hash(prev_hash: str, entry_without_hash: Dict[str, Any]) -> str:
    """Compute SHA256(prev_hash + canonical_json(entry without hash))."""
    filtered = {k: v for k, v in entry_without_hash.items() if k != "hash"}
    payload = prev_hash + canonical_json(filtered)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def sanitize_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize entry by stripping sensitive keys and redacting environment secrets."""
    secrets = [os.getenv(name) for name in SECRET_ENV_VARS if os.getenv(name)]

    def _sanitize(val: Any) -> Any:
        if isinstance(val, str):
            for secret in secrets:
                val = val.replace(secret, "[REDACTED]")
            return val
        if isinstance(val, list):
            return [_sanitize(item) for item in val]
        if isinstance(val, dict):
            return {
                k: _sanitize(v) for k, v in val.items()
                if k.lower() not in SENSITIVE_KEYS
                and not any(s in k.lower() for s in ("api_key", "bot_token", "secret", "password"))
            }
        return val

    return _sanitize(entry)


def migrate_legacy_log_if_needed(log_path: str) -> bool:
    """
    If log_path contains un-chained legacy records (missing 'hash' or 'seq'),
    archive it to action_log.legacy.jsonl and start a fresh log.
    Returns True if migration was performed.
    """
    if not os.path.exists(log_path) or os.path.getsize(log_path) == 0:
        return False

    is_legacy = False
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                if not isinstance(record, dict) or "hash" not in record or "seq" not in record:
                    is_legacy = True
                break
    except Exception:
        is_legacy = True

    if not is_legacy:
        return False

    # Perform migration
    base_dir = os.path.dirname(os.path.abspath(log_path))
    legacy_path = os.path.join(base_dir, "action_log.legacy.jsonl")

    # If legacy archive already exists, append old contents; otherwise rename
    try:
        if os.path.exists(legacy_path):
            with open(log_path, "r", encoding="utf-8") as src, open(legacy_path, "a", encoding="utf-8") as dst:
                dst.write(src.read())
            os.remove(log_path)
        else:
            os.rename(log_path, legacy_path)
        return True
    except Exception as exc:
        sys.stderr.write(f"[WARN] Failed to archive legacy audit log: {exc}\n")
        return False


def append_audit_entry(
    entry: Dict[str, Any],
    log_path: Optional[str] = None,
    db_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Atomically append a sanitized, chained audit record to action_log.jsonl.
    Safely acquires process lock to read last hash, assign seq, compute hash, and write.
    Also updates (last_seq, head_hash) in SQLite store for tamper/truncation detection.
    """
    path = os.path.abspath(log_path or DEFAULT_ACTION_LOG_FILE)
    lock_path = f"{path}.lock"

    with FileLock(lock_path):
        migrate_legacy_log_if_needed(path)

        # Read last entry to determine seq and prev_hash
        seq = 0
        prev_hash = GENESIS_PREV_HASH

        if os.path.exists(path) and os.path.getsize(path) > 0:
            with open(path, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip()]
                if lines:
                    try:
                        last_rec = json.loads(lines[-1])
                        seq = int(last_rec.get("seq", -1)) + 1
                        prev_hash = last_rec.get("hash", GENESIS_PREV_HASH)
                    except Exception:
                        seq = len(lines)
                        prev_hash = GENESIS_PREV_HASH

        # Sanitize input
        safe = sanitize_entry(entry)

        # Build standardized record with backward-compatible top-level fields
        event_name = safe.get("event") or safe.get("action") or "unknown"
        ts_val = safe.get("ts") or safe.get("timestamp") or datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Build details dictionary
        details = safe.get("details")
        if not isinstance(details, dict):
            details = {
                k: v for k, v in safe.items()
                if k not in ("seq", "ts", "event", "prev_hash", "hash", "timestamp", "action")
            }

        record = {
            "seq": seq,
            "ts": ts_val,
            "event": event_name,
            "details": details,
            "prev_hash": prev_hash,
            # Backward compatibility fields for existing tests
            **{k: v for k, v in safe.items() if k not in ("seq", "ts", "event", "details", "prev_hash", "hash")}
        }
        # Compute SHA256 over prev_hash + canonical_json(record without hash)
        record["hash"] = compute_entry_hash(prev_hash, record)

        # Atomic append
        os.makedirs(os.path.dirname(path), exist_ok=True)
        line = json.dumps(record, ensure_ascii=True) + "\n"
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()

        # Update SQLite store head state
        try:
            import store
            store.update_audit_head(seq, record["hash"], db_path=db_path)
        except Exception:
            pass

        return record


def read_audit_log(log_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Read all valid JSONL records from the audit log, skipping malformed lines."""
    path = os.path.abspath(log_path or DEFAULT_ACTION_LOG_FILE)
    if not os.path.exists(path):
        return []

    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                if isinstance(record, dict):
                    entries.append(record)
            except json.JSONDecodeError:
                continue
    return entries


def verify_log_chain(
    log_path: Optional[str] = None,
    expected_count: Optional[int] = None,
    expected_tail_hash: Optional[str] = None,
    db_path: Optional[str] = None,
    check_db_head: bool = True,
) -> Tuple[bool, str, Optional[int]]:
    """
    Verify the cryptographic hash chain of the audit log.
    Returns (is_valid: bool, reason: str, broken_seq: Optional[int]).
    Checks:
    - JSON validity
    - Genesis prev_hash == 64 zeros
    - Monotonic seq == prev_seq + 1 (detects deletion, reordering, duplicate)
    - prev_hash matches previous entry's hash (detects tampering/swapping)
    - Recomputed hash matches entry's hash (detects field modification)
    - SQLite head check (detects tail truncation without needing external count)
    - Optional expected_count / expected_tail_hash
    """
    path = os.path.abspath(log_path or DEFAULT_ACTION_LOG_FILE)
    if not os.path.exists(path):
        if expected_count is not None and expected_count > 0:
            return False, f"Log file does not exist: {path}", None
        return True, "OK: Log file is empty or does not exist", None

    lines = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                rec = json.loads(stripped)
            except json.JSONDecodeError as err:
                return False, f"Malformed or truncated JSON on line {line_no}: {err}", None
            if not isinstance(rec, dict):
                return False, f"Line {line_no} is not a valid JSON object", None
            lines.append(rec)

    if not lines:
        if expected_count is not None and expected_count > 0:
            return False, f"Log file is empty, expected {expected_count} entries", None
        return True, "OK: Log file contains 0 entries", None

    # Check chain integrity
    prev_hash = GENESIS_PREV_HASH
    prev_seq = -1

    for idx, entry in enumerate(lines):
        # Validate required fields
        for req in ("seq", "ts", "event", "prev_hash", "hash"):
            if req not in entry:
                return False, f"Missing required field '{req}' at index {idx}", entry.get("seq")

        curr_seq = entry["seq"]
        curr_prev_hash = entry["prev_hash"]
        curr_hash = entry["hash"]

        # 1. Sequence check
        if idx == 0:
            if curr_seq != 0:
                return False, f"Genesis entry seq must be 0, found {curr_seq}", curr_seq
            if curr_prev_hash != GENESIS_PREV_HASH:
                return False, f"Genesis entry bad prev_hash: expected {GENESIS_PREV_HASH}, got {curr_prev_hash}", curr_seq
        else:
            expected_seq = prev_seq + 1
            if curr_seq > expected_seq:
                return False, f"Deleted entry or gap in sequence: expected seq {expected_seq}, found {curr_seq}", curr_seq
            elif curr_seq < expected_seq:
                return False, f"Reordered or duplicate entry: expected seq {expected_seq}, found {curr_seq}", curr_seq

            if curr_prev_hash != prev_hash:
                return False, f"Broken hash chain at seq {curr_seq}: prev_hash does not match previous entry hash", curr_seq

        # 2. Hash integrity check (detects modification of any field in the entry)
        expected_hash = compute_entry_hash(curr_prev_hash, entry)
        if curr_hash != expected_hash:
            return False, f"Modified entry at seq {curr_seq}: hash mismatch (stored={curr_hash}, computed={expected_hash})", curr_seq

        prev_hash = curr_hash
        prev_seq = curr_seq

    # Optional expected count check (tail truncation detection)
    if expected_count is not None and len(lines) != expected_count:
        return False, f"Tail truncated: expected {expected_count} entries, but found {len(lines)}", len(lines)

    # Optional tail hash check
    if expected_tail_hash is not None and lines[-1]["hash"] != expected_tail_hash:
        return False, f"Tail hash mismatch: expected {expected_tail_hash}, found {lines[-1]['hash']}", lines[-1]["seq"]

    # Compare against SQLite audit_head to detect clean tail truncation without requiring expected_count
    if check_db_head:
        try:
            import store
            head = store.get_audit_head(db_path=db_path)
            if head is not None:
                db_last_seq = head["last_seq"]
                db_head_hash = head["head_hash"]
                file_last_seq = lines[-1]["seq"]
                file_last_hash = lines[-1]["hash"]

                if file_last_seq != db_last_seq or file_last_hash != db_head_hash:
                    return False, (
                        f"Audit head mismatch or tail truncation: log file ends at seq {file_last_seq} "
                        f"(hash={file_last_hash}), but SQLite records head at seq {db_last_seq} (hash={db_head_hash})"
                    ), file_last_seq
        except Exception:
            pass

    return True, f"OK: Verified {len(lines)} entries", None

