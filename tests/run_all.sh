#!/usr/bin/env bash
set -eo pipefail

# SentinelOps Complete Test Runner
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

export USE_REAL_APIS="false"
export ENABLE_DEBUG_ENDPOINTS="false"
export PYTHONPATH="."

echo "=========================================================="
echo "SentinelOps Test Suite Execution"
echo "=========================================================="

echo ""
echo "[Step 1/3] Running Pytest Suite (Unit, Hardening, Store, Gate Routes)..."
pytest -v

echo ""
echo "[Step 2/3] Running End-to-End Stdio Subprocess Verification..."
python tests/e2e_stdio_check.py

echo ""
echo "[Step 3/3] Running UI Transcript Logic Verification..."
python tests/test_transcript_fix.py

echo ""
echo "=========================================================="
echo "SUCCESS: All SentinelOps baseline test suites passed!"
echo "=========================================================="

