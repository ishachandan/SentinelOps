#!/usr/bin/env python3
"""Simulate an adversary tampering with the audit log."""
import os
import sys

log_path = os.path.join("data", "action_log.jsonl")

if not os.path.exists(log_path):
    print(f"Error: {log_path} not found.")
    sys.exit(1)

with open(log_path, "r", encoding="utf-8") as f:
    lines = f.readlines()

if len(lines) < 4:
    print(f"Error: Log file only has {len(lines)} lines, need at least 4 lines to tamper sequence 3.")
    sys.exit(1)

# Tamper with the IP in sequence 3
lines[3] = lines[3].replace("10.0.0.1", "1.1.1.1")
# If 10.0.0.1 wasn't in line 3, replace another field to ensure hash break
if "1.1.1.1" not in lines[3]:
    lines[3] = lines[3].replace('"reason":', '"reason":"tampered", "orig":')

with open(log_path, "w", encoding="utf-8") as f:
    f.writelines(lines)

print("Log tampered at sequence 3!")

