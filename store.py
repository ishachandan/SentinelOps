"""Shared SQLite store for SentinelOps actions and evidence."""
import hashlib
import ipaddress
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Tuple

ACTION_TTL = 15 * 60
STUCK_AFTER = 5 * 60
_ALLOWED = {
    ("pending", "confirmed"), ("pending", "partially_approved"), ("pending", "declined"), ("pending", "expired"),
    ("partially_approved", "confirmed"), ("partially_approved", "declined"), ("partially_approved", "expired"),
    ("confirmed", "executing"), ("confirmed", "failed"),
    ("executing", "executed"), ("executing", "failed"),
    ("executing", "pending"),
}


def db_path() -> str:
    """Read the DB override on every call so processes and tests can select it."""
    return os.environ.get("SENTINELOPS_DB", os.environ.get("SENTINELOPS_DB_PATH", DB_PATH))


DB_PATH = os.path.join(os.path.dirname(__file__), "data", "sentinelops.db")
DEFAULT_TTL = float(os.getenv("SENTINELOPS_ACTION_TTL", str(ACTION_TTL)))


def normalize_ip(value: Any) -> str:
    """Parse and normalize an IPv4/IPv6 address, handling leading zeros and IPv6-mapped IPv4."""
    if value is None:
        raise ValueError("Missing IP address")
    text = str(value).strip()
    if not text:
        raise ValueError("Empty IP address")

    # Handle decimal IPv4 with potential leading zeros in octets (e.g. 045.033.022.011)
    parts = text.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        try:
            octets = [int(p) for p in parts]
            if all(0 <= o <= 255 for o in octets):
                text = ".".join(str(o) for o in octets)
        except ValueError:
            pass

    try:
        addr = ipaddress.ip_address(text)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(addr)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address '{value}'") from exc


def init_db(db_path: Optional[str] = None):
    """Ensure database tables exist with proper schema."""
    path = db_path or globals()["db_path"]()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path, timeout=5, isolation_level=None)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        
        # Check existing actions table schema
        cur = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='actions'")
        row = cur.fetchone()
        if row and "partially_approved" not in row[0]:
            conn.execute("ALTER TABLE actions RENAME TO actions_legacy_schema")
            conn.execute("""
            CREATE TABLE actions (
              token TEXT PRIMARY KEY, session_id TEXT NOT NULL,
              action_type TEXT NOT NULL, params_json TEXT NOT NULL, params_hash TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN
                ('pending','partially_approved','confirmed','executing','executed','failed','declined','expired')),
              created_at REAL, expires_at REAL, resolved_at REAL,
              updated_at REAL, error TEXT, approvals_json TEXT DEFAULT '[]');
            """)
            conn.execute("""
            INSERT INTO actions (token, session_id, action_type, params_json, params_hash, status, created_at, expires_at, resolved_at, updated_at, error)
            SELECT token, session_id, action_type, params_json, params_hash, status, created_at, expires_at, resolved_at, updated_at, error
            FROM actions_legacy_schema;
            """)
            conn.execute("DROP TABLE actions_legacy_schema;")
        else:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS actions (
              token TEXT PRIMARY KEY, session_id TEXT NOT NULL,
              action_type TEXT NOT NULL, params_json TEXT NOT NULL, params_hash TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN
                ('pending','partially_approved','confirmed','executing','executed','failed','declined','expired')),
              created_at REAL, expires_at REAL, resolved_at REAL,
              updated_at REAL, error TEXT, approvals_json TEXT DEFAULT '[]');
            """)

        columns = {col[1] for col in conn.execute("PRAGMA table_info(actions)")}
        if "updated_at" not in columns:
            conn.execute("ALTER TABLE actions ADD COLUMN updated_at REAL")
            conn.execute("UPDATE actions SET updated_at=COALESCE(resolved_at, created_at)")
        if "error" not in columns:
            conn.execute("ALTER TABLE actions ADD COLUMN error TEXT")
        if "approvals_json" not in columns:
            conn.execute("ALTER TABLE actions ADD COLUMN approvals_json TEXT DEFAULT '[]'")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
          token TEXT PRIMARY KEY, session_id TEXT NOT NULL, ip TEXT NOT NULL,
          is_malicious INTEGER, abuse_score INTEGER, created_at REAL, expires_at REAL);
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS observed_ips (
          session_id TEXT NOT NULL, ip TEXT NOT NULL,
          source TEXT NOT NULL, observed_at REAL NOT NULL,
          PRIMARY KEY (session_id, ip));
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_head (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          last_seq INTEGER NOT NULL,
          head_hash TEXT NOT NULL,
          updated_at REAL NOT NULL);
        """)
    finally:
        conn.close()


@contextmanager
def tx(db_path: Optional[str] = None):
    path = db_path or globals()["db_path"]()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path, timeout=5, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def transition(token: str, session_id: str, frm: str, to: str, *, enforce_expiry=None, error=None) -> bool:
    """Transition an action atomically from one status to another.

    State machine:
      pending -> confirmed -> executing -> executed | failed
      pending -> declined | expired
    """
    if (frm, to) not in _ALLOWED:
        raise ValueError(f"illegal transition {frm} -> {to}")
    now = time.time()
    if enforce_expiry is None:
        enforce_expiry = frm == "pending"
    sql = "UPDATE actions SET status=?, error=?, resolved_at=?, updated_at=? WHERE token=? AND session_id=? AND status=?"
    args = [to, error, now, now, token, session_id, frm]
    if enforce_expiry:
        sql += " AND expires_at>?"
        args.append(now)
    with tx() as c:
        cur = c.execute(sql, args)
        return cur.rowcount == 1


def expire_stale() -> int:
    now = time.time()
    with tx() as c:
        count = c.execute(
            "UPDATE actions SET status='expired', resolved_at=?, updated_at=? WHERE status IN ('pending', 'partially_approved') AND expires_at<=?",
            (now, now, now)
        ).rowcount
        count += c.execute(
            "UPDATE actions SET status='failed', error='interrupted: outcome unknown', resolved_at=?, updated_at=? WHERE status='executing' AND updated_at<=?",
            (now, now, now - STUCK_AFTER)
        ).rowcount
    return count


def compute_action_params_hash(
    action_type: str,
    target: str,
    reason: str,
    expires_at: float,
    severity: str = "medium",
    required_approvals: int = 1
) -> str:
    """Compute parameter binding hash SHA256(canonical_json({action_type, target, reason, expires_at, severity, required_approvals}))."""
    payload = {
        "action_type": str(action_type),
        "expires_at": float(expires_at),
        "reason": str(reason),
        "required_approvals": int(required_approvals),
        "severity": str(severity).lower(),
        "target": str(target),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_params_hash(params: Any) -> str:
    """Compute sha256 hash of parameters."""
    if isinstance(params, str):
        payload = params.encode("utf-8")
    else:
        payload = json.dumps(params, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _row_to_action_dict(row: sqlite3.Row) -> Dict[str, Any]:
    try:
        params = json.loads(row["params_json"])
    except (TypeError, json.JSONDecodeError):
        params = {}

    approvals = []
    if "approvals_json" in row.keys() and row["approvals_json"]:
        try:
            approvals = json.loads(row["approvals_json"])
        except Exception:
            approvals = []

    severity = params.get("severity", "medium").lower() if isinstance(params, dict) else "medium"
    required_approvals = params.get("required_approvals", 2 if severity == "critical" else 1) if isinstance(params, dict) else 1

    d: Dict[str, Any] = {
        "token": row["token"],
        "session_id": row["session_id"],
        "action_type": row["action_type"],
        "params": params,
        "params_json": row["params_json"],
        "params_hash": row["params_hash"],
        "status": row["status"],
        "severity": severity,
        "required_approvals": required_approvals,
        "approvals": approvals,
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "resolved_at": row["resolved_at"],
        "updated_at": row["updated_at"],
        "error": row["error"],
    }
    # Unpack inner params for backward-compatible attribute access (e.g., action['ip'], action['reason'])
    if isinstance(params, dict):
        for k, v in params.items():
            if k not in d:
                d[k] = v
    return d


def create_action(
    token: str,
    session_id: str,
    action_type: str,
    params: Dict[str, Any],
    ttl: float = DEFAULT_TTL,
    status: str = "pending",
    severity: Optional[str] = None,
    required_approvals: Optional[int] = None
) -> Dict[str, Any]:
    """Create a new action in the store."""
    init_db()
    now = time.time()
    expires_at = now + ttl
    target = params.get("ip") or params.get("path") or params.get("target") or ""
    reason = params.get("reason", "")
    
    effective_severity = severity or params.get("severity", "medium").lower()
    if required_approvals is None:
        required_approvals = 2 if effective_severity == "critical" else 1

    params_copy = dict(params)
    params_copy["severity"] = effective_severity
    params_copy["required_approvals"] = required_approvals
    params_json = json.dumps(params_copy, sort_keys=True)
    params_hash = compute_action_params_hash(
        action_type, target, reason, expires_at, effective_severity, required_approvals
    )
    approvals_json = "[]"

    with tx() as c:
        c.execute(
            """INSERT INTO actions
               (token, session_id, action_type, params_json, params_hash, status, created_at, expires_at, resolved_at, updated_at, approvals_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)""",
            (token, session_id, action_type, params_json, params_hash, status, now, expires_at, now, approvals_json)
        )

    return {
        "token": token,
        "session_id": session_id,
        "action_type": action_type,
        "params": params_copy,
        "params_json": params_json,
        "params_hash": params_hash,
        "status": status,
        "severity": effective_severity,
        "required_approvals": required_approvals,
        "approvals": [],
        "created_at": now,
        "expires_at": expires_at,
        "resolved_at": None,
        "updated_at": now,
        "error": None,
        **params_copy
    }


def record_approval(
    token: str,
    session_id: str,
    approver_id: str,
    db_path: Optional[str] = None
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Record an approval for an action.
    - Low/Medium/High actions: 1 approval needed. Transitions pending -> confirmed.
    - Critical actions: 2 distinct approvals needed from different approvers.
      First approval: transitions pending -> partially_approved.
      Second approval from same approver: REJECTED (cannot self-approve twice).
      Second approval from different approver: transitions partially_approved -> confirmed.
    Returns (success, message, action_dict).
    """
    init_db(db_path)
    now = time.time()
    with tx(db_path) as c:
        cur = c.execute("SELECT * FROM actions WHERE token=?", (token,))
        row = cur.fetchone()
        if not row:
            return False, "Token not found", None
        action = _row_to_action_dict(row)
        if action["session_id"] != session_id:
            return False, "Cross-session approval rejected", action
        if action["expires_at"] <= now:
            return False, "Action expired", action

        severity = str(action.get("severity", "medium")).lower()
        approvals = list(action.get("approvals", []))
        curr_status = action["status"]

        if severity == "critical":
            if curr_status == "pending":
                approvals.append(approver_id)
                new_status = "partially_approved"
                c.execute(
                    "UPDATE actions SET status=?, approvals_json=?, updated_at=? WHERE token=? AND status='pending'",
                    (new_status, json.dumps(approvals), now, token)
                )
                action["status"] = new_status
                action["approvals"] = approvals
                return True, "First approval recorded; critical actions require a second approval", action

            elif curr_status == "partially_approved":
                if approver_id in approvals:
                    return False, "Second approval must come from a distinct operator", action
                approvals.append(approver_id)
                new_status = "confirmed"
                c.execute(
                    "UPDATE actions SET status=?, approvals_json=?, updated_at=? WHERE token=? AND status='partially_approved'",
                    (new_status, json.dumps(approvals), now, token)
                )
                action["status"] = new_status
                action["approvals"] = approvals
                return True, "Second approval recorded; action confirmed", action

            else:
                return False, f"Action in status '{curr_status}' cannot be approved", action

        else:
            if curr_status != "pending":
                return False, f"Action in status '{curr_status}' cannot be approved", action
            approvals.append(approver_id)
            new_status = "confirmed"
            c.execute(
                "UPDATE actions SET status=?, approvals_json=?, updated_at=? WHERE token=? AND status='pending'",
                (new_status, json.dumps(approvals), now, token)
            )
            action["status"] = new_status
            action["approvals"] = approvals
            return True, "Action confirmed", action


def get_action(token: str) -> Optional[Dict[str, Any]]:
    """Retrieve an action by token."""
    init_db()
    with tx() as c:
        cur = c.execute(
            "SELECT token, session_id, action_type, params_json, params_hash, status, created_at, expires_at, resolved_at, updated_at, error, approvals_json "
            "FROM actions WHERE token=?",
            (token,)
        )
        row = cur.fetchone()
        if not row:
            return None
        return _row_to_action_dict(row)


def list_actions(session_id: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
    """List actions filtered optionally by session_id and status."""
    init_db()
    query = "SELECT token, session_id, action_type, params_json, params_hash, status, created_at, expires_at, resolved_at, updated_at, error, approvals_json FROM actions WHERE 1=1"
    params = []
    if session_id:
        query += " AND session_id=?"
        params.append(session_id)
    if status:
        query += " AND status=?"
        params.append(status)
    query += " ORDER BY created_at DESC"
    with tx() as c:
        cur = c.execute(query, tuple(params))
        return [_row_to_action_dict(r) for r in cur.fetchall()]


def save_evidence(
    token: str,
    session_id: str,
    ip: str,
    is_malicious: bool,
    abuse_score: int,
    ttl: float = DEFAULT_TTL
) -> Dict[str, Any]:
    """Store reputation check evidence."""
    init_db()
    canonical_ip = normalize_ip(ip)
    now = time.time()
    expires_at = now + ttl
    with tx() as c:
        c.execute(
            """INSERT OR REPLACE INTO evidence
               (token, session_id, ip, is_malicious, abuse_score, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (token, session_id, canonical_ip, 1 if is_malicious else 0, abuse_score, now, expires_at)
        )
    return {
        "token": token,
        "session_id": session_id,
        "ip": canonical_ip,
        "is_malicious": bool(is_malicious),
        "abuse_score": abuse_score,
        "created_at": now,
        "expires_at": expires_at
    }


def get_evidence(token: str) -> Optional[Dict[str, Any]]:
    """Retrieve evidence by token."""
    init_db()
    with tx() as c:
        cur = c.execute(
            "SELECT token, session_id, ip, is_malicious, abuse_score, created_at, expires_at "
            "FROM evidence WHERE token=?",
            (token,)
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "token": row["token"],
            "session_id": row["session_id"],
            "ip": row["ip"],
            "is_malicious": bool(row["is_malicious"]),
            "abuse_score": row["abuse_score"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"]
        }


def record_observed_ip(session_id: str, ip: str, source: str = "unknown", db_path: Optional[str] = None) -> str:
    """Normalize and record an observed IP for a session."""
    canonical_ip = normalize_ip(ip)
    init_db(db_path)
    now = time.time()
    with tx(db_path) as c:
        c.execute(
            """INSERT INTO observed_ips (session_id, ip, source, observed_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(session_id, ip) DO UPDATE SET
                   source = CASE 
                       WHEN excluded.source LIKE 'search_logs_match%' THEN excluded.source
                       WHEN observed_ips.source LIKE 'search_logs_match%' THEN observed_ips.source
                       ELSE excluded.source
                   END,
                   observed_at = excluded.observed_at""",
            (session_id, canonical_ip, source, now)
        )
    return canonical_ip


def is_ip_observed(session_id: str, ip: str, ttl: Optional[float] = None, db_path: Optional[str] = None) -> bool:
    """Check if a normalized IP was observed in this session within the TTL window (default: 3600s)."""
    try:
        canonical_ip = normalize_ip(ip)
    except ValueError:
        return False
    if ttl is None:
        try:
            ttl = float(os.getenv("SENTINELOPS_OBSERVED_IP_TTL", 3600))
        except ValueError:
            ttl = 3600.0
    init_db(db_path)
    now = time.time()
    cutoff = now - ttl if ttl > 0 else 0
    with tx(db_path) as c:
        cur = c.execute(
            "SELECT 1 FROM observed_ips WHERE session_id=? AND ip=? AND observed_at >= ?",
            (session_id, canonical_ip, cutoff)
        )
        return cur.fetchone() is not None


def get_observed_ips(session_id: str, ttl: Optional[float] = None, db_path: Optional[str] = None) -> List[str]:
    """Return all normalized observed IPs for a session within the TTL window."""
    if ttl is None:
        try:
            ttl = float(os.getenv("SENTINELOPS_OBSERVED_IP_TTL", 3600))
        except ValueError:
            ttl = 3600.0
    now = time.time()
    cutoff = now - ttl if ttl > 0 else 0
    init_db(db_path)
    with tx(db_path) as c:
        cur = c.execute(
            "SELECT ip FROM observed_ips WHERE session_id=? AND observed_at >= ? ORDER BY observed_at ASC",
            (session_id, cutoff)
        )
        return [row["ip"] for row in cur.fetchall()]


def has_justified_block_evidence(
    session_id: str,
    ip: str,
    min_score: int = 50,
    ttl: Optional[float] = None,
    db_path: Optional[str] = None
) -> bool:
    """Check whether a block proposal is justified by evidence in this session.
    Requires:
      - A structured log hit in this session (source in ('search_logs_match', 'search_logs'))
      OR
      - A reputation check with abuse score >= min_score (default: 50)
    """
    try:
        canonical_ip = normalize_ip(ip)
    except ValueError:
        return False

    if ttl is None:
        try:
            ttl = float(os.getenv("SENTINELOPS_OBSERVED_IP_TTL", 3600))
        except ValueError:
            ttl = 3600.0

    now = time.time()
    cutoff = now - ttl if ttl > 0 else 0
    init_db(db_path)

    with tx(db_path) as c:
        # Check structured log hit
        cur = c.execute(
            """SELECT 1 FROM observed_ips
               WHERE session_id=? AND ip=? AND (source IN ('search_logs_match', 'search_logs') OR source LIKE 'search_logs_match%') AND observed_at >= ?""",
            (session_id, canonical_ip, cutoff)
        )
        if cur.fetchone() is not None:
            return True

        # Check reputation score >= min_score
        cur2 = c.execute(
            """SELECT 1 FROM evidence
               WHERE session_id=? AND ip=? AND abuse_score >= ? AND expires_at >= ?""",
            (session_id, canonical_ip, min_score, now)
        )
        if cur2.fetchone() is not None:
            return True

    return False


def update_audit_head(last_seq: int, head_hash: str, db_path: Optional[str] = None):
    """Store the latest audit log sequence and head hash in SQLite for tamper detection."""
    init_db(db_path)
    now = time.time()
    with tx(db_path) as c:
        c.execute(
            """INSERT INTO audit_head (id, last_seq, head_hash, updated_at)
               VALUES (1, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                   last_seq=excluded.last_seq,
                   head_hash=excluded.head_hash,
                   updated_at=excluded.updated_at""",
            (last_seq, head_hash, now)
        )


def get_audit_head(db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve the latest audit log head state from SQLite."""
    init_db(db_path)
    with tx(db_path) as c:
        cur = c.execute("SELECT last_seq, head_hash, updated_at FROM audit_head WHERE id=1")
        row = cur.fetchone()
        if row:
            return {
                "last_seq": row["last_seq"],
                "head_hash": row["head_hash"],
                "updated_at": row["updated_at"]
            }
        return None


def clear_store(db_path: Optional[str] = None):
    """Delete all records from actions, evidence, observed_ips, and audit_head tables."""
    init_db(db_path)
    with tx(db_path) as c:
        c.execute("DELETE FROM actions")
        c.execute("DELETE FROM evidence")
        c.execute("DELETE FROM observed_ips")
        c.execute("DELETE FROM audit_head")


# Initialize tables on import
init_db()
