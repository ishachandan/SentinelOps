"""Ingest sample security logs into ChromaDB for semantic search testing."""
import os
import json
from datetime import datetime, timedelta

# Sample security logs dataset (SSH auth attacks and suspicious activity)
SAMPLE_LOGS = [
    # Failed login attempts
    "2024-01-15 10:23:45 Failed password for root from 45.33.22.11 port 22 ssh2",
    "2024-01-15 10:23:50 Failed password for admin from 45.33.22.11 port 22 ssh2",
    "2024-01-15 10:24:01 Failed password for ubuntu from 45.33.22.11 port 22 ssh2",
    "2024-01-15 10:30:12 Failed password for root from 185.220.101.1 port 22 ssh2",
    
    # Successful suspicious logins
    "2024-01-15 11:05:23 Accepted password for root from 45.33.22.11 port 22 ssh2",
    "2024-01-15 11:05:30 pam_unix(sshd:session): session opened for user root by (uid=0)",
    
    # Port scanning activity
    "2024-01-15 12:15:01 Connection attempt from 192.168.1.5 to multiple ports: 22,80,443,3389,8080",
    "2024-01-15 12:15:15 Port scan detected from 192.168.1.5: 100 ports scanned in 30 seconds",
    "2024-01-15 12:16:20 Firewall blocked connection from 192.168.1.5 to port 3389",
    
    # Malware/exploit attempts
    "2024-01-15 13:20:45 Suspicious file upload detected: malicious_payload.exe from 103.21.163.81",
    "2024-01-15 13:21:10 SQL injection attempt detected in HTTP request from 198.108.67.16",
    "2024-01-15 13:22:30 Buffer overflow attempt in application server from 45.33.22.11",
    
    # DDoS patterns
    "2024-01-15 14:30:00 High request rate detected from 185.220.101.1: 5000 requests/minute",
    "2024-01-15 14:30:30 Distributed attack pattern: 50 IPs targeting web server simultaneously",
    "2024-01-15 14:31:00 Rate limiting activated for 185.220.101.1",
    
    # Data exfiltration
    "2024-01-15 15:45:12 Large data transfer detected: 500MB uploaded to external IP 45.33.22.11",
    "2024-01-15 15:46:00 Suspicious database query from user 'admin': SELECT * FROM users WHERE 1=1",
    "2024-01-15 15:47:20 Unauthorized access to /etc/passwd from 45.33.22.11",
    
    # Privilege escalation
    "2024-01-15 16:10:45 Sudo privilege escalation attempt by user 'guest'",
    "2024-01-15 16:11:10 Unauthorized root shell spawned from web application",
    "2024-01-15 16:12:00 Kernel exploit attempt detected: privilege escalation via CVE-2024-1234",
    
    # Network anomalies
    "2024-01-15 17:20:30 Unusual outbound connection to tor exit node 185.220.101.1",
    "2024-01-15 17:21:00 DNS tunneling detected: excessive DNS queries to suspicious domain",
    "2024-01-15 17:22:15 Encrypted traffic to known C2 server at 45.33.22.11:4444",
    
    # Clean/normal activity (for contrast)
    "2024-01-15 18:00:00 Successful login for user john from 192.168.1.100",
    "2024-01-15 18:05:30 System backup completed successfully",
    "2024-01-15 18:10:15 Regular database maintenance job started",
    "2024-01-15 18:30:00 Automated security scan completed: no issues found",
    "2024-01-15 19:00:00 System health check: all services running normally",
]

def ingest_logs():
    """Ingest sample logs into ChromaDB."""
    try:
        from sentence_transformers import SentenceTransformer
        import chromadb
        from chromadb.config import Settings
        import uuid
        
        print("="*70)
        print("Ingesting Sample Security Logs into ChromaDB")
        print("="*70)
        
        # Initialize embedding model
        print("\nProcessing Loading embedding model (all-MiniLM-L6-v2)...")
        embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
        print("SUCCESS: Model loaded")
        
        # Initialize ChromaDB
        persist_dir = "data/chromadb_sentinelops"
        os.makedirs(persist_dir, exist_ok=True)
        
        print(f"\nProcessing Initializing ChromaDB: {persist_dir}...")
        client = chromadb.PersistentClient(
            path=persist_dir,
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )
        
        # Get or create collection
        collection = client.get_or_create_collection(
            name="security_logs",
            metadata={"description": "Security log embeddings for SentinelOps"}
        )
        
        print(f"SUCCESS: ChromaDB initialized (existing: {collection.count()} logs)")
        
        # Generate embeddings
        print(f"\nProcessing Generating embeddings for {len(SAMPLE_LOGS)} logs...")
        embeddings = embedding_model.encode(SAMPLE_LOGS, convert_to_numpy=True, show_progress_bar=True)
        print("SUCCESS: Embeddings generated")
        
        # Prepare data
        ids = [str(uuid.uuid4()) for _ in SAMPLE_LOGS]
        documents = SAMPLE_LOGS
        metadatas = []
        
        for i, log in enumerate(SAMPLE_LOGS):
            # Extract metadata from log
            metadata = {
                "index": i,
                "timestamp": log.split()[0] + " " + log.split()[1] if len(log.split()) >= 2 else "unknown",
                "log_type": "security"
            }
            
            # Classify log type
            if "failed password" in log.lower() or "failed login" in log.lower():
                metadata["event_type"] = "failed_auth"
                metadata["severity"] = "medium"
            elif "port scan" in log.lower():
                metadata["event_type"] = "port_scan"
                metadata["severity"] = "high"
            elif "malware" in log.lower() or "exploit" in log.lower() or "injection" in log.lower():
                metadata["event_type"] = "exploit_attempt"
                metadata["severity"] = "critical"
            elif "ddos" in log.lower() or "high request rate" in log.lower():
                metadata["event_type"] = "ddos"
                metadata["severity"] = "critical"
            elif "exfiltration" in log.lower() or "unauthorized access" in log.lower():
                metadata["event_type"] = "data_breach"
                metadata["severity"] = "critical"
            elif "privilege escalation" in log.lower():
                metadata["event_type"] = "privilege_escalation"
                metadata["severity"] = "critical"
            elif "successful" in log.lower() or "completed" in log.lower() or "health check" in log.lower():
                metadata["event_type"] = "normal"
                metadata["severity"] = "low"
            else:
                metadata["event_type"] = "suspicious"
                metadata["severity"] = "medium"
            
            metadatas.append(metadata)
        
        # Add to collection
        print(f"\nProcessing Adding {len(SAMPLE_LOGS)} logs to ChromaDB...")
        collection.add(
            ids=ids,
            embeddings=embeddings.tolist(),
            documents=documents,
            metadatas=metadatas
        )
        
        print(f"SUCCESS: Ingestion complete! Total logs in collection: {collection.count()}")
        
        # Test semantic search
        print("\n" + "="*70)
        print("Testing Semantic Search")
        print("="*70)
        
        test_queries = [
            "brute force attack",  # Should match failed login attempts
            "unauthorized database access",  # Should match data exfiltration
            "network scanning activity",  # Should match port scans
        ]
        
        for query in test_queries:
            print(f"\nQuery: \"{query}\"")
            print("-"*70)
            
            query_embedding = embedding_model.encode(query, convert_to_numpy=True).tolist()
            results = collection.query(
                query_embeddings=[query_embedding],
                n_results=3
            )
            
            for i, doc in enumerate(results['documents'][0], 1):
                distance = results['distances'][0][i-1]
                metadata = results['metadatas'][0][i-1]
                print(f"{i}. [{metadata.get('event_type', 'unknown')}] {doc[:80]}... (distance: {distance:.3f})")
        
        print("\n" + "="*70)
        print("SUCCESS: Integration 2 Setup Complete")
        print("="*70)
        print("\nTo enable real semantic search in SentinelOps:")
        print("  1. Ensure USE_REAL_APIS=true in .env")
        print("  2. Run: python server.py")
        print("  3. Test with: python test_integration2_chromadb.py")
        
    except ImportError as e:
        print(f"ERROR: Error: Missing dependencies: {e}")
        print("\nInstall with:")
        print("  pip install chromadb sentence-transformers")
    except Exception as e:
        print(f"ERROR: Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    ingest_logs()

