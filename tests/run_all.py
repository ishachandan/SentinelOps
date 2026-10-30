#!/usr/bin/env python3
"""Cross-platform test runner for SentinelOps."""
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

def run():
    env = dict(os.environ)
    env["USE_REAL_APIS"] = "false"
    env["ENABLE_DEBUG_ENDPOINTS"] = "false"
    env["PYTHONPATH"] = "."
    
    print("=" * 60)
    print("SentinelOps Comprehensive Test Runner")
    print("=" * 60)

    # 1. Pytest
    print("\n[1/4] Running Pytest Suite (Unit, Hardening, Store, Gate Routes, Evals)...")
    res1 = subprocess.run([sys.executable, "-m", "pytest", "-v"], cwd=str(PROJECT_ROOT), env=env)
    if res1.returncode != 0:
        print("FAIL: Pytest failed")
        sys.exit(res1.returncode)

    # 2. E2E Stdio
    print("\n[2/4] Running End-to-End Stdio Subprocess Verification...")
    res2 = subprocess.run([sys.executable, "tests/e2e_stdio_check.py"], cwd=str(PROJECT_ROOT), env=env)
    if res2.returncode != 0:
        print("FAIL: E2E Stdio verification failed")
        sys.exit(res2.returncode)

    # 3. Transcript fix
    print("\n[3/4] Running Transcript Logic Verification...")
    res3 = subprocess.run([sys.executable, "tests/test_transcript_fix.py"], cwd=str(PROJECT_ROOT), env=env)
    if res3.returncode != 0:
        print("FAIL: Transcript fix verification failed")
        sys.exit(res3.returncode)

    # 4. Evaluation Harness
    print("\n[4/4] Running Agent Evaluation Harness (evals/run_evals.py)...")
    res4 = subprocess.run([sys.executable, "evals/run_evals.py"], cwd=str(PROJECT_ROOT), env=env)
    if res4.returncode != 0:
        print("FAIL: Evaluation harness failed")
        sys.exit(res4.returncode)

    print("\n" + "=" * 60)
    print("SUCCESS: All SentinelOps test suites passed!")
    print("=" * 60)

if __name__ == "__main__":
    run()

