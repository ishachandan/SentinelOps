"""CLI tool to verify the tamper-evident audit log chain."""
import argparse
import sys
import os

# Add root directory to sys.path so audit_chain can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_chain import verify_log_chain, DEFAULT_ACTION_LOG_FILE


def main():
    parser = argparse.ArgumentParser(description="Verify SentinelOps tamper-evident audit log chain.")
    parser.add_argument(
        "positional_path",
        nargs="?",
        default=None,
        help="Optional positional path to action_log.jsonl"
    )
    parser.add_argument(
        "--path",
        default=None,
        help=f"Path to action_log.jsonl (default: {DEFAULT_ACTION_LOG_FILE})"
    )
    parser.add_argument(
        "--expected-count",
        type=int,
        default=None,
        help="Optional expected total entry count (detects tail truncation)"
    )
    parser.add_argument(
        "--expected-tail-hash",
        default=None,
        help="Optional expected hash of the final entry"
    )
    parser.add_argument(
        "--db-path",
        default=None,
        help="Optional SQLite DB path to verify audit head (defaults to store DB)"
    )
    parser.add_argument(
        "--no-db-check",
        action="store_true",
        help="Skip comparison against SQLite audit_head"
    )

    args = parser.parse_args()

    chosen_path = args.path or args.positional_path or DEFAULT_ACTION_LOG_FILE
    is_valid, message, broken_seq = verify_log_chain(
        log_path=chosen_path,
        expected_count=args.expected_count,
        expected_tail_hash=args.expected_tail_hash,
        db_path=args.db_path,
        check_db_head=not args.no_db_check
    )

    if is_valid:
        print(f"OK: {message}")
        sys.exit(0)
    else:
        seq_str = f" [seq={broken_seq}]" if broken_seq is not None else ""
        print(f"FAIL{seq_str}: {message}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

