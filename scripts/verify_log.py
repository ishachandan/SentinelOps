#!/usr/bin/env python3
"""Wrapper script to verify SentinelOps tamper-evident audit log chain."""
import os
import sys

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinelops.verify_log import main

if __name__ == "__main__":
    main()

