#!/usr/bin/env python3
"""Ingest realistic security logs into SentinelOps ChromaDB store.

Ensures every document has:
- Structured source IP metadata field ('source_ip' and 'ip')
- Event type matching policy's suspicious set ('failed_login', 'brute_force', etc.)
- Timestamp, severity, and log text
"""
import argparse
import os
import re
import sys
import uuid

CHROMA_PERSIST_DIR = "data/chromadb_sentinelops"
CHROMA_COLLECTION = "security_logs"

IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def parse_log_line(line: str) -> dict:
    """Parse a single raw log line into text and structured metadata."""
    line_clean = line.strip()
    if not line_clean or line_clean.startswith("#"):
        return None

    # Detect IPv4 address
    ip_match = IPV4_REGEX.search(line_clean)
    source_ip = ip_match.group(0) if ip_match else "unknown"

    # Detect timestamp
    ts_match = re.match(r'^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})', line_clean)
    timestamp = ts_match.group(1) if ts_match else "unknown"

    # Classify event type matching policy suspicious set
    lower = line_clean.lower()
    if "failed password" in lower or "authentication failure" in lower:
        event_type = "failed_login"
        severity = "high"
    elif "too many authentication failures" in lower:
        event_type = "brute_force"
        severity = "high"
    elif "etc/passwd" in lower or "sqlmap" in lower or "exploit" in lower:
        event_type = "exploit_attempt"
        severity = "high"
    elif "wp-login" in lower:
        event_type = "failed_login"
        severity = "medium"
    elif "port scan" in lower:
        event_type = "port_scan"
        severity = "medium"
    elif "accepted publickey" in lower or "accepted password" in lower:
        event_type = "successful_login"
        severity = "low"
    else:
        event_type = "auth_event"
        severity = "low"

    metadata = {
        "source_ip": source_ip,
        "ip": source_ip,
        "event_type": event_type,
        "severity": severity,
        "timestamp": timestamp,
        "log_type": "security"
    }

    return {
        "id": f"log_{uuid.uuid4().hex[:12]}",
        "document": line_clean,
        "metadata": metadata
    }


def ingest(log_file: str, persist_dir: str = CHROMA_PERSIST_DIR):
    """Load logs from file and store into ChromaDB collection."""
    if not os.path.exists(log_file):
        print(f"[ERROR] Log file not found: {log_file}")
        sys.exit(1)

    print(f"[*] Reading logs from {log_file}...")
    entries = []
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                entries.append(parsed)

    if not entries:
        print("[!] No log entries found to ingest.")
        return

    print(f"[*] Parsed {len(entries)} valid log records.")

    print(f"[*] Initializing ChromaDB at {persist_dir}...")
    import chromadb
    from chromadb.config import Settings
    from chromadb.utils import embedding_functions

    client = chromadb.PersistentClient(
        path=persist_dir,
        settings=Settings(anonymized_telemetry=False, allow_reset=False)
    )

    ef = embedding_functions.DefaultEmbeddingFunction()
    collection = client.get_or_create_collection(
        name=CHROMA_COLLECTION,
        embedding_function=ef,
        metadata={"description": "Security log embeddings for SentinelOps"}
    )

    ids = [e["id"] for e in entries]
    documents = [e["document"] for e in entries]
    metadatas = [e["metadata"] for e in entries]

    collection.add(
        ids=ids,
        documents=documents,
        metadatas=metadatas
    )

    total_count = collection.count()
    print(f"[+] Successfully ingested {len(entries)} logs into collection '{CHROMA_COLLECTION}'.")
    print(f"[+] Total records now in ChromaDB: {total_count}")


def main():
    parser = argparse.ArgumentParser(description="Ingest security logs into SentinelOps ChromaDB.")
    parser.add_argument(
        "--file",
        default=os.path.join("data", "sample_auth.log"),
        help="Path to raw log file (default: data/sample_auth.log)"
    )
    parser.add_argument(
        "--persist-dir",
        default=CHROMA_PERSIST_DIR,
        help="Path to ChromaDB persist dir"
    )
    args = parser.parse_args()
    ingest(args.file, args.persist_dir)


if __name__ == "__main__":
    main()

