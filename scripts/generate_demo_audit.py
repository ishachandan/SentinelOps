#!/usr/bin/env python3
"""Generate a clean, fresh 9-entry cryptographic audit log for live demo."""
import json
import os
import re
import sys
import dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

dotenv.load_dotenv()
os.environ["USE_REAL_APIS"] = "true"

import server
import store
import audit_chain

log_path = os.path.join("data", "action_log.jsonl")
if os.path.exists(log_path):
    os.remove(log_path)

with store.tx() as c:
    c.execute("DELETE FROM actions")
    c.execute("DELETE FROM audit_head")
    c.execute("DELETE FROM observed_ips")

session_id = "live_audit_demo_session"
os.environ["SENTINELOPS_SESSION_ID"] = session_id

print("[*] Generating live audit trail entries...")

# 1. Search logs (real ChromaDB)
server.search_logs("185.220.101.1")
# 2. Check reputation (real AbuseIPDB)
rep = json.loads(server.check_ip_reputation("185.220.101.1"))

# 3. Propose block
p1 = server.propose_block_ip("185.220.101.1", reason="Malicious brute-force attack from known attacker")
t1 = re.search(r"Token: ([a-f0-9]+)", p1).group(1)

# 4. Confirm proposal
store.transition(t1, session_id, "pending", "confirmed")

# 5. Execute proposal (logs entry 0)
server.execute_pending_action(t1)

# 6. Rejection: protected loopback IP (entry 1)
server.propose_block_ip("127.0.0.1", reason="Attacker tried to block localhost")

# 7. Rejection: protected DNS IP (entry 2)
server.propose_block_ip("8.8.8.8", reason="Attacker tried to block DNS server")

# 8. Rejection: unobserved IP prompt injection (entry 3)
server.propose_block_ip("10.0.0.1", reason="Prompt injected victim IP")

# 9. Rejection: path traversal in quarantine (entry 4)
server.propose_quarantine_file("../../etc/shadow", reason="Directory escape attempt")

# 10. Rejection: invalid token execution (entry 5)
server.execute_pending_action("00000000")

# 11. Rejection: create critical incident without evidence (entry 6)
server.create_incident("Critical breach attempt", "critical")

# 12. Rejection: notify telegram without evidence (entry 7)
server.notify_telegram("Critical alert without token", "critical")

# 13. Create legitimate incident with real evidence token (entry 8)
server.create_incident("Confirmed 100% abuse score brute force attack", "critical", evidence_token=rep["result_token"])

with open(log_path, "r", encoding="utf-8") as f:
    lines = f.readlines()

print(f"[+] Total audit records written: {len(lines)}")
for line in lines:
    d = json.loads(line)
    print(f"  Seq {d.get('seq')}: {d.get('action')} -> {d.get('status')} ({d.get('reason','')})")
