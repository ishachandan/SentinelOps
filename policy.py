"""Evidence-grounded policy engine for SentinelOps actions."""
import ipaddress
import os
from typing import Any, Dict, Optional, Tuple
import store


def is_observed_ip_required() -> bool:
    """Return whether the observed IP policy is actively enforced."""
    return os.getenv("SENTINELOPS_REQUIRE_OBSERVED_IP", "true").lower() in ("true", "1", "yes")


DEFAULT_SUSPICIOUS_EVENTS = {
    "failed_login", "port_scan", "exploit_attempt", "auth_failure",
    "waf_block", "botnet", "malware", "c2", "brute_force",
    "unauthorized_access", "sql_injection", "ddos"
}


def is_suspicious_event(event_name: Optional[str]) -> bool:
    """Check if a log event type qualifies as suspicious evidence for mitigation."""
    if not event_name or not isinstance(event_name, str):
        return False
    custom = os.getenv("SENTINELOPS_SUSPICIOUS_EVENTS")
    if custom:
        suspicious_set = {e.strip().lower().replace(" ", "_").replace("-", "_") for e in custom.split(",") if e.strip()}
    else:
        suspicious_set = {e.lower().replace(" ", "_").replace("-", "_") for e in DEFAULT_SUSPICIOUS_EVENTS}
    normalized = event_name.strip().lower().replace(" ", "_").replace("-", "_")
    return normalized in suspicious_set


BUILTIN_PROTECTED_IPS = ["127.0.0.1", "::1", "8.8.8.8", "1.1.1.1", "192.168.1.1"]
BUILTIN_PROTECTED_CIDRS = ["127.0.0.0/8"]


def load_protected_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load protected allowlist configuration. Fails closed with built-in defaults if missing or malformed."""
    import sys
    path = config_path or os.getenv("SENTINELOPS_PROTECTED_FILE", os.path.join("data", "protected.yaml"))
    defaults = {"protected_ips": list(BUILTIN_PROTECTED_IPS), "protected_cidrs": list(BUILTIN_PROTECTED_CIDRS)}

    if not os.path.exists(path):
        sys.stderr.write(f"[WARN] Protected allowlist file '{path}' not found. Failing closed with built-in defaults.\n")
        sys.stderr.flush()
        return defaults

    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if not isinstance(data, dict):
                sys.stderr.write(f"[WARN] Protected allowlist file '{path}' is not a valid YAML dictionary. Failing closed with built-in defaults.\n")
                sys.stderr.flush()
                return defaults
            # Merge with built-in defaults to guarantee fail-closed behavior
            p_ips = list(set(defaults["protected_ips"] + list(data.get("protected_ips", []))))
            p_cidrs = list(set(defaults["protected_cidrs"] + list(data.get("protected_cidrs", []))))
            return {"protected_ips": p_ips, "protected_cidrs": p_cidrs}
    except Exception as exc:
        sys.stderr.write(f"[WARN] Failed to parse protected allowlist file '{path}': {exc}. Failing closed with built-in defaults.\n")
        sys.stderr.flush()
        return defaults


def derive_block_severity(
    session_id: str,
    ip: str,
    db_path: Optional[str] = None
) -> Tuple[str, int]:
    """Derive severity and required_approvals server-side from evidence.
    Returns:
        (severity: str, required_approvals: int)
        - Critical (2 approvals): abuse_score >= 90 or high-threat matched event (exploit_attempt, brute_force, c2, botnet)
        - Medium (1 approval): abuse_score >= 50 or standard suspicious log match
        - Low (1 approval): default
    """
    try:
        canonical_ip = store.normalize_ip(ip)
    except ValueError:
        return "medium", 1

    # Check evidence table for reputation score
    score = 0
    init_path = db_path or store.db_path()
    store.init_db(init_path)
    with store.tx(init_path) as c:
        cur = c.execute(
            "SELECT abuse_score FROM evidence WHERE session_id=? AND ip=? ORDER BY abuse_score DESC LIMIT 1",
            (session_id, canonical_ip)
        )
        row = cur.fetchone()
        if row and row["abuse_score"] is not None:
            score = row["abuse_score"]

    if score >= 90:
        return "critical", 2

    # Check observed_ips for high-threat event types
    with store.tx(init_path) as c:
        cur = c.execute(
            "SELECT source FROM observed_ips WHERE session_id=? AND ip=?",
            (session_id, canonical_ip)
        )
        sources = [r["source"] for r in cur.fetchall()]
        if any(term in s for term in ("exploit_attempt", "brute_force", "c2", "botnet") for s in sources):
            return "critical", 2

    if score >= 50:
        return "medium", 1

    return "medium", 1


def is_ip_protected(ip: str, config_path: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """Check if an IP address is in the protected allowlist (can NEVER be blocked).
    Checks:
    - Environment variables: SENTINELOPS_PROTECTED_IPS, SENTINELOPS_PROTECTED_CIDRS
    - Config file: data/protected.yaml
    """
    try:
        addr = ipaddress.ip_address(store.normalize_ip(ip))
    except ValueError:
        return False, None

    # Check environment variable allowlist
    env_ips = os.getenv("SENTINELOPS_PROTECTED_IPS", "").split(",")
    for env_ip in env_ips:
        item = env_ip.strip()
        if item:
            try:
                if addr == ipaddress.ip_address(store.normalize_ip(item)):
                    return True, f"IP {item} is protected by environment allowlist"
            except ValueError:
                pass

    env_cidrs = os.getenv("SENTINELOPS_PROTECTED_CIDRS", "").split(",")
    for env_cidr in env_cidrs:
        item = env_cidr.strip()
        if item:
            try:
                if addr in ipaddress.ip_network(item, strict=False):
                    return True, f"IP belongs to protected network {item} (env)"
            except ValueError:
                pass

    # Check config file allowlist
    config = load_protected_config(config_path)
    for p_ip in config.get("protected_ips", []):
        try:
            if addr == ipaddress.ip_address(store.normalize_ip(str(p_ip).strip())):
                return True, f"IP {p_ip} is protected by configuration allowlist"
        except ValueError:
            pass

    for p_cidr in config.get("protected_cidrs", []):
        try:
            if addr in ipaddress.ip_network(str(p_cidr).strip(), strict=False):
                return True, f"IP belongs to protected network {p_cidr}"
        except ValueError:
            pass

    return False, None


def evaluate_block_ip_policy(
    session_id: str,
    ip: str,
    db_path: Optional[str] = None,
    config_path: Optional[str] = None
) -> Tuple[bool, Optional[str]]:
    """Decide whether propose_block_ip(ip) is allowed under current policy.

    Rules:
    1. The IP must not be in the protected allowlist (data/protected.yaml or env).
    2. The IP must have been observed in THIS session via check_ip_reputation or search_logs.
    3. The IP must have justified evidence: either a structured log hit in this session OR
       a reputation check with abuse score >= SENTINELOPS_MIN_BLOCK_SCORE (default 50).

    Returns:
        (allowed, reason_code) where reason_code is None if allowed, or
        a machine-readable reason like 'policy_denied:protected_target',
        'policy_denied:unobserved_ip', or 'policy_denied:insufficient_evidence'.
    """
    try:
        canonical_ip = store.normalize_ip(ip)
    except ValueError:
        return False, "policy_denied:invalid_ip"

    # Step 1: Protected allowlist check
    protected, _ = is_ip_protected(canonical_ip, config_path=config_path)
    if protected:
        return False, "policy_denied:protected_target"

    if not is_observed_ip_required():
        return True, None

    # Step 2: Observation check
    if not store.is_ip_observed(session_id, canonical_ip, db_path=db_path):
        return False, "policy_denied:unobserved_ip"

    # Step 3: Justified evidence check (structured log hit OR reputation score >= SENTINELOPS_MIN_BLOCK_SCORE)
    try:
        min_score = int(os.getenv("SENTINELOPS_MIN_BLOCK_SCORE", "50"))
    except ValueError:
        min_score = 50

    if not store.has_justified_block_evidence(session_id, canonical_ip, min_score=min_score, db_path=db_path):
        return False, "policy_denied:insufficient_evidence"

    return True, None

