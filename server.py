from mcp.server.fastmcp import FastMCP
import json
import datetime
import os
import uuid
from dotenv import load_dotenv
import requests

load_dotenv()

# Feature flag for real API integrations
USE_REAL_APIS = os.getenv("USE_REAL_APIS", "false").lower() in ("true", "1", "yes")

# Feature flag for debug endpoints (MUST be explicitly enabled)
ENABLE_DEBUG_ENDPOINTS = os.getenv("ENABLE_DEBUG_ENDPOINTS", "false").lower() in ("true", "1", "yes")

mcp = FastMCP("SentinelOps")

# Phase 1: Dummy tool
@mcp.tool()
def ping() -> str:
    """Health check tool. Returns 'pong' if the server is alive."""
    return "pong"

# Phase 2: First real retrieval tool with fake data
FAKE_LOGS = [
    {"ip": "45.33.22.11", "event": "failed login", "count": 12},
    {"ip": "192.168.1.5", "event": "port scan", "count": 3},
]

# Real ChromaDB setup for semantic search
CHROMA_PERSIST_DIR = "data/chromadb_sentinelops"
CHROMA_COLLECTION = "security_logs"

# Global variables for ChromaDB (initialized at module load if USE_REAL_APIS=true)
_chroma_store = None
_embedding_generator = None

# Initialize immediately if real APIs are enabled (not lazily)
if USE_REAL_APIS:
    try:
        import sys
        sys.stderr.write("[STARTUP] USE_REAL_APIS=true, initializing ChromaDB...\n")
        sys.stderr.flush()
        
        from sentence_transformers import SentenceTransformer
        import chromadb
        from chromadb.config import Settings
        
        sys.stderr.write("[STARTUP] Loading embedding model (this may take ~30s on first run)...\n")
        sys.stderr.flush()
        _embedding_generator = SentenceTransformer("all-MiniLM-L6-v2")
        sys.stderr.write("[STARTUP] Embedding model loaded\n")
        sys.stderr.flush()
        
        sys.stderr.write("[STARTUP] Initializing ChromaDB client...\n")
        sys.stderr.flush()
        client = chromadb.PersistentClient(
            path=CHROMA_PERSIST_DIR,
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=False
            )
        )
        
        _chroma_store = client.get_or_create_collection(
            name=CHROMA_COLLECTION,
            metadata={"description": "Security log embeddings for SentinelOps"}
        )
        
        count = _chroma_store.count()
        sys.stderr.write(f"[STARTUP] ChromaDB initialized: {count} logs indexed\n")
        sys.stderr.flush()
        
    except ImportError as e:
        import sys
        sys.stderr.write(f"[STARTUP] WARNING: ChromaDB/sentence-transformers not available: {e}\n")
        sys.stderr.write("[STARTUP]    search_logs will fall back to stub mode\n")
        sys.stderr.flush()
        USE_REAL_APIS = False  # Force fallback
    except Exception as e:
        import sys
        sys.stderr.write(f"[STARTUP] WARNING: Error initializing ChromaDB: {e}\n")
        sys.stderr.flush()
        import traceback
        traceback.print_exc()
        USE_REAL_APIS = False  # Force fallback

def init_chromadb_store():
    """Check if ChromaDB store is initialized (no longer does lazy init)"""
    if _chroma_store is None or _embedding_generator is None:
        return False
    return True

def search_logs_real(query: str) -> str:
    """Search logs using real ChromaDB semantic search."""
    import sys
    
    # Check if ChromaDB is initialized
    if not init_chromadb_store():
        return json.dumps({"error": "ChromaDB not available. Install: pip install chromadb sentence-transformers"})
    
    try:
        import signal
        
        # Timeout handler
        def timeout_handler(signum, frame):
            raise TimeoutError("Query timed out after 30 seconds")
        
        # Set 30-second timeout for the entire operation
        # Note: signal.alarm only works on Unix; on Windows this is a no-op safety measure
        try:
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(30)
        except AttributeError:
            # Windows doesn't support SIGALRM, skip timeout mechanism
            pass
        
        # Generate query embedding (should take ~0.3s)
        query_embedding = _embedding_generator.encode(query, convert_to_numpy=True).tolist()
        
        # Search ChromaDB (should take <0.01s)
        results = _chroma_store.query(
            query_embeddings=[query_embedding],
            n_results=5
        )
        
        # Cancel timeout
        try:
            signal.alarm(0)
        except AttributeError:
            pass
        
        # Format results
        if not results['documents'] or not results['documents'][0]:
            return json.dumps([])
        
        formatted_results = []
        for i in range(len(results['documents'][0])):
            result = {
                "text": results['documents'][0][i],
                "metadata": results['metadatas'][0][i] if results['metadatas'] else {},
                "distance": results['distances'][0][i] if results['distances'] else 0.0
            }
            formatted_results.append(result)
        
        return json.dumps(formatted_results)
        
    except TimeoutError as e:
        sys.stderr.write(f"[ERROR] search_logs_real timeout: {e}\n")
        sys.stderr.flush()
        return json.dumps({"error": "Search timed out after 30 seconds. Check ChromaDB performance."})
    except Exception as e:
        sys.stderr.write(f"[ERROR] search_logs_real exception: {e}\n")
        sys.stderr.flush()
        import traceback
        traceback.print_exc(file=sys.stderr)
        return json.dumps({"error": f"Search failed: {str(e)}"})

def search_logs_stub(query: str) -> str:
    """Search logs using stubbed data (substring match)."""
    results = [l for l in FAKE_LOGS if query in json.dumps(l)]
    return json.dumps(results) if results else "No matches found."

@mcp.tool()
def search_logs(query: str) -> str:
    """Search recent security logs for a keyword (ip or event type)."""
    
    if USE_REAL_APIS:
        return search_logs_real(query)
    else:
        return search_logs_stub(query)

# Phase 3: First action tool (dry-run only)
ACTION_LOG = []

# File-based storage for PENDING_ACTIONS to persist between MCP connections
PENDING_ACTIONS_FILE = "data/pending_actions.json"

def load_pending_actions():
    """Load pending actions from file"""
    try:
        with open(PENDING_ACTIONS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_pending_actions(actions):
    """Save pending actions to file"""
    os.makedirs(os.path.dirname(PENDING_ACTIONS_FILE), exist_ok=True)
    with open(PENDING_ACTIONS_FILE, 'w') as f:
        json.dump(actions, f, indent=2)

# Load pending actions at module initialization
PENDING_ACTIONS = load_pending_actions()

# Fake file paths for testing
FAKE_FILES = [
    "/tmp/suspicious_payload.exe",
    "/home/user/downloads/ransomware.bin",
    "/var/log/system.log",
    "/etc/nginx/nginx.conf"
]

def generate_action_token():
    """Generate a unique token for pending actions."""
    import uuid
    return str(uuid.uuid4())[:8]

@mcp.tool()
def propose_block_ip(ip: str, reason: str) -> str:
    """Propose blocking an IP address. This ONLY creates a preview - it does NOT execute the block.
    Returns a unique action token that must be confirmed by a human before execution.
    Use this when you want to block an IP but need human approval first."""
    
    token = generate_action_token()
    PENDING_ACTIONS[token] = {
        "action_type": "block_ip",
        "ip": ip,
        "reason": reason,
        "status": "pending",
        "created_at": str(datetime.datetime.now())
    }
    save_pending_actions(PENDING_ACTIONS)  # Persist to file
    
    return f"PREVIEW: Would block IP {ip}. Reason: {reason}\nToken: {token}\nAwaiting human confirmation."

@mcp.tool()
def propose_quarantine_file(path: str, reason: str) -> str:
    """Propose quarantining a suspicious file. This ONLY creates a preview - it does NOT execute the quarantine.
    Returns a unique action token that must be confirmed by a human before execution.
    Use this when you want to quarantine a file but need human approval first.
    Only propose this for files that are confirmed or highly suspected to be malicious."""
    
    token = generate_action_token()
    PENDING_ACTIONS[token] = {
        "action_type": "quarantine_file",
        "path": path,
        "reason": reason,
        "status": "pending",
        "created_at": str(datetime.datetime.now())
    }
    save_pending_actions(PENDING_ACTIONS)  # Persist to file
    
    return f"PREVIEW: Would quarantine file: {path}. Reason: {reason}\nToken: {token}\nAwaiting human confirmation."

@mcp.tool()
def execute_pending_action(token: str) -> str:
    """Execute a previously proposed action using its token.
    This is a DESTRUCTIVE operation - only call this after explicit human approval.
    The action can only be executed once per token."""
    
    if token not in PENDING_ACTIONS:
        return f"Error: Token '{token}' not found. It may be invalid or already executed."
    
    action = PENDING_ACTIONS[token]
    
    if action["status"] == "executed":
        return f"Error: Action with token '{token}' was already executed."
    
    # Execute the action based on type
    if action["action_type"] == "block_ip":
        if USE_REAL_APIS:
            result = execute_block_ip_real(action, token)
        else:
            result = execute_block_ip_stub(action, token)
        action["status"] = "executed"
        action["executed_at"] = str(datetime.datetime.now())
        save_pending_actions(PENDING_ACTIONS)  # Persist status change
        return result
        
    elif action["action_type"] == "quarantine_file":
        if USE_REAL_APIS:
            result = execute_quarantine_file_real(action, token)
        else:
            result = execute_quarantine_file_stub(action, token)
        action["status"] = "executed"
        action["executed_at"] = str(datetime.datetime.now())
        save_pending_actions(PENDING_ACTIONS)  # Persist status change
        return result
    
    else:
        return f"Error: Unknown action type '{action['action_type']}'"

# Sandbox directory for real firewall rule simulation
FIREWALL_SANDBOX_DIR = "data/firewall_sandbox"

def execute_block_ip_real(action: dict, token: str) -> str:
    """Execute real IP block in sandboxed environment."""
    import os
    
    try:
        # Create sandbox directory if it doesn't exist
        os.makedirs(FIREWALL_SANDBOX_DIR, exist_ok=True)
        
        ip = action["ip"]
        reason = action["reason"]
        timestamp = str(datetime.datetime.now())
        
        # Create a "firewall rule" file (simulates iptables rule)
        rule_file = os.path.join(FIREWALL_SANDBOX_DIR, f"block_{ip.replace('.', '_')}.rule")
        
        rule_content = {
            "ip": ip,
            "reason": reason,
            "action": "DROP",
            "chain": "INPUT",
            "created_at": timestamp,
            "token": token,
            "status": "active"
        }
        
        with open(rule_file, 'w') as f:
            json.dump(rule_content, f, indent=2)
        
        # Log to ACTION_LOG
        entry = {
            "action": "block_ip",
            "ip": ip,
            "reason": reason,
            "time": timestamp,
            "sandbox_file": rule_file,
            "status": "executed",
            "token": token
        }
        ACTION_LOG.append(entry)
        
        return f"SUCCESS [SANDBOX]: Blocked IP {ip}. Rule file created: {rule_file}\nReason: {reason}"
        
    except Exception as e:
        return f"Error executing block_ip: {str(e)}"

def execute_block_ip_stub(action: dict, token: str) -> str:
    """Execute stub IP block (dry-run mode)."""
    entry = {
        "action": "block_ip",
        "ip": action["ip"],
        "reason": action["reason"],
        "time": str(datetime.datetime.now()),
        "dry_run": True,
        "status": "executed",
        "token": token
    }
    ACTION_LOG.append(entry)
    return f"SUCCESS [DRY RUN]: Blocked IP {action['ip']}. Reason: {action['reason']}"

# Quarantine sandbox directory
QUARANTINE_SANDBOX_DIR = "data/sentinelops_sandbox"
QUARANTINE_DIR = os.path.join(QUARANTINE_SANDBOX_DIR, "quarantine")

def execute_quarantine_file_real(action: dict, token: str) -> str:
    """Execute real file quarantine in sandboxed environment."""
    import os
    import shutil
    
    try:
        # Create directories if they don't exist
        os.makedirs(QUARANTINE_SANDBOX_DIR, exist_ok=True)
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        
        path = action["path"]
        reason = action["reason"]
        timestamp = str(datetime.datetime.now())
        
        # Check if file exists in sandbox
        if not os.path.exists(path):
            return f"Error: File not found in sandbox: {path}\nNote: Only files in {QUARANTINE_SANDBOX_DIR} can be quarantined"
        
        # Check if file is actually in our sandbox
        abs_path = os.path.abspath(path)
        sandbox_abs = os.path.abspath(QUARANTINE_SANDBOX_DIR)
        
        if not abs_path.startswith(sandbox_abs):
            return f"Error: File is outside sandbox directory. Only files in {QUARANTINE_SANDBOX_DIR} can be quarantined for safety."
        
        # Move file to quarantine
        filename = os.path.basename(path)
        quarantine_path = os.path.join(QUARANTINE_DIR, f"{token}_{filename}")
        
        shutil.move(path, quarantine_path)
        
        # Create metadata file
        metadata_file = quarantine_path + ".metadata"
        metadata = {
            "original_path": path,
            "quarantined_path": quarantine_path,
            "reason": reason,
            "timestamp": timestamp,
            "token": token,
            "status": "quarantined"
        }
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Log to ACTION_LOG
        entry = {
            "action": "quarantine_file",
            "path": path,
            "quarantine_path": quarantine_path,
            "reason": reason,
            "time": timestamp,
            "status": "executed",
            "token": token
        }
        ACTION_LOG.append(entry)
        
        return f"SUCCESS [SANDBOX]: Quarantined file: {path}\nMoved to: {quarantine_path}\nReason: {reason}"
        
    except Exception as e:
        import traceback
        import sys
        traceback.print_exc(file=sys.stderr)
        return f"Error executing quarantine_file: {str(e)}"

def execute_quarantine_file_stub(action: dict, token: str) -> str:
    """Execute stub file quarantine (dry-run mode)."""
    entry = {
        "action": "quarantine_file",
        "path": action["path"],
        "reason": action["reason"],
        "time": str(datetime.datetime.now()),
        "dry_run": True,
        "status": "executed",
        "token": token
    }
    ACTION_LOG.append(entry)
    return f"SUCCESS [DRY RUN]: Quarantined file: {action['path']}. Reason: {action['reason']}"

@mcp.tool()
def get_action_log() -> str:
    """Return all actions taken so far, for audit purposes."""
    return json.dumps(ACTION_LOG, indent=2)

# Phase 5: IP reputation checking tool
FAKE_IP_REPUTATION = {
    "45.33.22.11": {"ip": "45.33.22.11", "abuse_score": 85, "is_malicious": True, "reason": "Known botnet C2 server"},
    "192.168.1.5": {"ip": "192.168.1.5", "abuse_score": 0, "is_malicious": False, "reason": "Private network IP"},
    "8.8.8.8": {"ip": "8.8.8.8", "abuse_score": 0, "is_malicious": False, "reason": "Google DNS - legitimate service"},
    "185.220.101.50": {"ip": "185.220.101.50", "abuse_score": 95, "is_malicious": True, "reason": "Tor exit node with abuse reports"},
}

# Chain-integrity tokens: store reputation check results for server-side validation
REPUTATION_RESULTS = {}

def check_ip_reputation_real(ip: str) -> str:
    """Check IP reputation using real AbuseIPDB API."""
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    
    # Validate API key is configured
    if not api_key or api_key == "your_abuseipdb_key_here":
        return json.dumps({
            "ip": ip,
            "abuse_score": -1,
            "is_malicious": False,
            "reason": "Error: ABUSEIPDB_API_KEY not configured in .env file"
        })
    
    try:
        # AbuseIPDB API endpoint
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": ""
        }
        
        # Make API request with timeout
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        # Handle different HTTP status codes
        if response.status_code == 200:
            data = response.json()
            
            if "data" not in data:
                return json.dumps({
                    "ip": ip,
                    "abuse_score": -1,
                    "is_malicious": False,
                    "reason": "Error: Malformed response from AbuseIPDB (missing 'data' field)"
                })
            
            abuse_data = data["data"]
            abuse_score = abuse_data.get("abuseConfidenceScore", 0)
            country_code = abuse_data.get("countryCode", "Unknown")
            total_reports = abuse_data.get("totalReports", 0)
            
            # Generate result_token and store for validation
            result_token = str(uuid.uuid4())[:8]
            REPUTATION_RESULTS[result_token] = {
                "token": result_token,
                "ip": ip,
                "abuse_score": abuse_score,
                "is_malicious": abuse_score > 50,
                "timestamp": str(datetime.datetime.now())
            }
            
            # Construct response in same format as fake data, plus result_token
            return json.dumps({
                "ip": ip,
                "abuse_score": abuse_score,
                "is_malicious": abuse_score > 50,  # Threshold: >50 is considered malicious
                "reason": f"AbuseIPDB: {abuse_score}% confidence, {total_reports} reports, Country: {country_code}",
                "result_token": result_token
            })
            
        elif response.status_code == 401:
            return json.dumps({
                "ip": ip,
                "abuse_score": -1,
                "is_malicious": False,
                "reason": "Error: Invalid ABUSEIPDB_API_KEY (401 Unauthorized)"
            })
            
        elif response.status_code == 429:
            return json.dumps({
                "ip": ip,
                "abuse_score": -1,
                "is_malicious": False,
                "reason": "Error: AbuseIPDB rate limit exceeded (429). Free tier limits apply."
            })
            
        else:
            return json.dumps({
                "ip": ip,
                "abuse_score": -1,
                "is_malicious": False,
                "reason": f"Error: AbuseIPDB API returned status {response.status_code}"
            })
            
    except requests.exceptions.Timeout:
        return json.dumps({
            "ip": ip,
            "abuse_score": -1,
            "is_malicious": False,
            "reason": "Error: AbuseIPDB API request timed out (>10 seconds)"
        })
        
    except requests.exceptions.RequestException as e:
        return json.dumps({
            "ip": ip,
            "abuse_score": -1,
            "is_malicious": False,
            "reason": f"Error: Network error contacting AbuseIPDB: {str(e)}"
        })
        
    except json.JSONDecodeError:
        return json.dumps({
            "ip": ip,
            "abuse_score": -1,
            "is_malicious": False,
            "reason": "Error: Could not parse AbuseIPDB response (invalid JSON)"
        })

def check_ip_reputation_stub(ip: str) -> str:
    """Check IP reputation using stubbed data (safe for testing)."""
    if ip in FAKE_IP_REPUTATION:
        result = FAKE_IP_REPUTATION[ip].copy()
    else:
        result = {
            "ip": ip,
            "abuse_score": -1,
            "is_malicious": False,
            "reason": "No reputation data available (stub mode)"
        }
    
    # Generate result_token and store for validation
    result_token = str(uuid.uuid4())[:8]
    REPUTATION_RESULTS[result_token] = {
        "token": result_token,
        "ip": ip,
        "abuse_score": result.get("abuse_score", -1),
        "is_malicious": result.get("is_malicious", False),
        "timestamp": str(datetime.datetime.now())
    }
    
    result["result_token"] = result_token
    return json.dumps(result)

@mcp.tool()
def check_ip_reputation(ip: str) -> str:
    """Check the reputation of an IP address to determine if it is malicious or trustworthy. 
    Use this tool when you need to verify whether an IP should be blocked or investigate its threat level.
    Returns abuse score (0-100 where higher is more malicious), malicious status, and a result_token.
    IMPORTANT: Pass the result_token to create_incident or notify_telegram when acting on this finding."""
    
    if USE_REAL_APIS:
        return check_ip_reputation_real(ip)
    else:
        return check_ip_reputation_stub(ip)

# Phase 5: Incident tracking system
INCIDENTS_FILE = "incidents.json"
VALID_SEVERITIES = ["low", "medium", "high", "critical"]

def load_incidents():
    """Load incidents from JSON file."""
    try:
        with open(INCIDENTS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_incidents(incidents):
    """Save incidents to JSON file."""
    with open(INCIDENTS_FILE, 'w') as f:
        json.dump(incidents, f, indent=2)

@mcp.tool()
def create_incident(summary: str, severity: str, related_ip: str = None, evidence_token: str = None) -> str:
    """Create a formal security incident ticket that requires follow-up investigation or response.
    Use this to track security events that need human review or coordination, not for routine automated actions.
    Examples: persistent attack patterns, confirmed breaches, policy violations requiring escalation.
    Do NOT create incidents for every blocked IP or quarantined file - those are logged separately.
    
    Severity must be one of: low, medium, high, critical
    
    CRITICAL: For high or critical severity incidents claiming malicious activity, you MUST provide 
    evidence_token from a prior check_ip_reputation call. This ensures incidents are backed by actual findings."""
    
    # Validate severity
    if severity.lower() not in VALID_SEVERITIES:
        return f"Error: Invalid severity '{severity}'. Must be one of: {', '.join(VALID_SEVERITIES)}"
    
    # SERVER-SIDE VALIDATION: High/critical incidents about security threats require evidence
    severity_lower = severity.lower()
    if severity_lower in ("high", "critical"):
        # Check if summary implies a malicious/threat claim
        threat_keywords = ["malicious", "attack", "threat", "blocked", "suspicious", "compromise", "breach", "abuse"]
        if any(keyword in summary.lower() for keyword in threat_keywords):
            # Evidence token is REQUIRED
            if not evidence_token:
                return json.dumps({
                    "error": "REJECTED: High/critical severity incidents about security threats require evidence_token from check_ip_reputation",
                    "severity": severity_lower,
                    "summary": summary,
                    "reason": "Cannot create high-severity incident without validated evidence"
                })
            
            # Validate the evidence token
            if evidence_token not in REPUTATION_RESULTS:
                return json.dumps({
                    "error": "REJECTED: Invalid evidence_token (not found or expired)",
                    "provided_token": evidence_token,
                    "reason": "evidence_token must come from a recent check_ip_reputation call"
                })
            
            # Check if the evidence actually supports a malicious claim
            evidence = REPUTATION_RESULTS[evidence_token]
            if not evidence.get("is_malicious", False):
                return json.dumps({
                    "error": "REJECTED: Evidence does not support malicious claim",
                    "evidence_token": evidence_token,
                    "ip": evidence.get("ip"),
                    "abuse_score": evidence.get("abuse_score"),
                    "is_malicious": evidence.get("is_malicious"),
                    "reason": f"Cannot create high-severity incident: IP {evidence.get('ip')} has abuse_score {evidence.get('abuse_score')} (not malicious)"
                })
    
    # Load existing incidents
    incidents = load_incidents()
    
    # Generate incident ID
    incident_id = len(incidents) + 1
    
    # Create incident entry
    incident = {
        "incident_id": incident_id,
        "summary": summary,
        "severity": severity.lower(),
        "related_ip": related_ip,
        "timestamp": str(datetime.datetime.now()),
        "status": "open"
    }
    
    # Add evidence reference if provided
    if evidence_token:
        incident["evidence_token"] = evidence_token
    
    # Save incident
    incidents.append(incident)
    save_incidents(incidents)
    
    return f"Incident created successfully. ID: {incident_id}, Severity: {severity.lower()}"

@mcp.tool()
def list_incidents() -> str:
    """List all security incidents that have been created."""
    incidents = load_incidents()
    if not incidents:
        return "No incidents found."
    return json.dumps(incidents, indent=2)

# Phase 5: Telegram notification system

@mcp.tool()
def debug_seed_pending_action(token: str, action_type: str, ip: str = None, path: str = None, reason: str = "Test action", status: str = "pending") -> str:
    """
    DEBUG TOOL: Manually seed a pending action for testing.
    This bypasses propose_* tools to directly create test tokens.
    
    SECURITY: Only available when ENABLE_DEBUG_ENDPOINTS=true in environment.
    
    Args:
        token: The token to use
        action_type: "block_ip" or "quarantine_file"
        ip: IP address (required for block_ip)
        path: File path (required for quarantine_file)
        reason: Reason for action
        status: "pending", "executed", or "declined"
    """
    # SECURITY GATE: Check if debug endpoints are enabled
    if not ENABLE_DEBUG_ENDPOINTS:
        return "Error: Debug endpoints are disabled. Set ENABLE_DEBUG_ENDPOINTS=true to enable."
    
    if action_type == "block_ip":
        if not ip:
            return "Error: ip is required for block_ip action_type"
        
        PENDING_ACTIONS[token] = {
            "action_type": "block_ip",
            "ip": ip,
            "reason": reason,
            "status": status,
            "created_at": str(datetime.datetime.now()),
            "debug_seed": True
        }
        save_pending_actions(PENDING_ACTIONS)  # Persist to file
        
        return f"DEBUG: Seeded pending action with token '{token}' (block_ip: {ip}, status: {status})"
        
    elif action_type == "quarantine_file":
        if not path:
            return "Error: path is required for quarantine_file action_type"
        
        PENDING_ACTIONS[token] = {
            "action_type": "quarantine_file",
            "path": path,
            "reason": reason,
            "status": status,
            "created_at": str(datetime.datetime.now()),
            "debug_seed": True
        }
        save_pending_actions(PENDING_ACTIONS)  # Persist to file
        
        return f"DEBUG: Seeded pending action with token '{token}' (quarantine_file: {path}, status: {status})"
        
    else:
        return f"Error: Unknown action_type '{action_type}'. Must be 'block_ip' or 'quarantine_file'"

@mcp.tool()
def notify_telegram(message: str, evidence_token: str = None) -> str:
    """Send a notification message via Telegram to alert a human about security events or actions taken.
    
    Use this to inform humans about important findings or actions the agent performed.
    This is for real-time alerts, not a substitute for create_incident (which is for formal tracking).
    Examples: alerting about blocked IPs, quarantined files, or critical security findings.
    
    CRITICAL: When notifying about blocking/threat actions, provide evidence_token from check_ip_reputation 
    to validate the claim is backed by actual findings."""
    
    # Get credentials from environment
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    
    # Validate credentials
    if not bot_token or bot_token == "your_telegram_bot_token_here":
        return "Error: TELEGRAM_BOT_TOKEN not configured. Please set it in .env file."
    if not chat_id or chat_id == "your_telegram_chat_id_here":
        return "Error: TELEGRAM_CHAT_ID not configured. Please set it in .env file."
    
    # SERVER-SIDE VALIDATION: Messages about threats/blocks require evidence
    action_keywords = ["blocked", "malicious", "threat", "attack", "quarantine", "suspicious", "compromise", "breach"]
    if any(keyword in message.lower() for keyword in action_keywords):
        # Evidence token is REQUIRED for threat notifications
        if not evidence_token:
            return json.dumps({
                "error": "REJECTED: Notifications about security threats/actions require evidence_token from check_ip_reputation",
                "message": message,
                "reason": "Cannot send threat notification without validated evidence"
            })
        
        # Validate the evidence token
        if evidence_token not in REPUTATION_RESULTS:
            return json.dumps({
                "error": "REJECTED: Invalid evidence_token (not found or expired)",
                "provided_token": evidence_token,
                "reason": "evidence_token must come from a recent check_ip_reputation call"
            })
        
        # Check if the evidence actually supports a threat claim
        evidence = REPUTATION_RESULTS[evidence_token]
        if not evidence.get("is_malicious", False):
            return json.dumps({
                "error": "REJECTED: Evidence does not support threat claim",
                "evidence_token": evidence_token,
                "ip": evidence.get("ip"),
                "abuse_score": evidence.get("abuse_score"),
                "is_malicious": evidence.get("is_malicious"),
                "reason": f"Cannot notify about threat: IP {evidence.get('ip')} has abuse_score {evidence.get('abuse_score')} (not malicious)"
            })
    
    # Log the notification attempt
    entry = {
        "action": "notify_telegram",
        "message": message,
        "time": str(datetime.datetime.now()),
        "status": "executed"
    }
    if evidence_token:
        entry["evidence_token"] = evidence_token
    ACTION_LOG.append(entry)
    
    try:
        # Send message via Telegram API
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": f"SentinelOps Alert\n\n{message}",
            "parse_mode": "HTML"
        }
        
        response = requests.post(url, json=payload, timeout=10)
        
        if response.status_code == 200:
            return f"Telegram notification sent successfully. Message: {message}"
        else:
            error_detail = response.json().get("description", "Unknown error")
            return f"Error sending Telegram notification: {error_detail}"
            
    except requests.exceptions.Timeout:
        return "Error: Telegram API request timed out"
    except requests.exceptions.RequestException as e:
        return f"Error: Failed to send Telegram notification: {str(e)}"

if __name__ == "__main__":
    import sys
    sys.stderr.write("="*60 + "\n")
    sys.stderr.write("SentinelOps MCP Server Starting\n")
    sys.stderr.write("="*60 + "\n")
    sys.stderr.write(f"USE_REAL_APIS: {USE_REAL_APIS}\n")
    sys.stderr.write(f"Mode: {'REAL INTEGRATIONS' if USE_REAL_APIS else 'STUBBED DATA (safe for testing)'}\n")
    sys.stderr.write("="*60 + "\n\n")
    sys.stderr.flush()
    mcp.run()
