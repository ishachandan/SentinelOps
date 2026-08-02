"""Set up sandbox environment for testing real actions."""
import os
import json

# Create sandbox directories
os.makedirs("data/firewall_sandbox", exist_ok=True)
os.makedirs("data/sentinelops_sandbox", exist_ok=True)
os.makedirs("data/sentinelops_sandbox/quarantine", exist_ok=True)

print("SUCCESS: Created data/firewall_sandbox/")
print("SUCCESS: Created data/sentinelops_sandbox/")
print("SUCCESS: Created data/sentinelops_sandbox/quarantine/")

# Create test files for quarantine testing
test_files = [
    ("malicious_payload.exe", "This is a simulated malware payload"),
    ("suspicious_script.sh", "#!/bin/bash\nrm -rf / # Dangerous!"),
    ("normal_document.txt", "This is a normal file with legitimate content"),
]

for filename, content in test_files:
    filepath = os.path.join("data/sentinelops_sandbox", filename)
    with open(filepath, 'w') as f:
        f.write(content)
    print(f"SUCCESS: Created test file: {filepath}")

print("\nSUCCESS: Sandbox setup complete!")
print("\nTest files created in data/sentinelops_sandbox/:")
print("  - malicious_payload.exe (for quarantine testing)")
print("  - suspicious_script.sh (for quarantine testing)")
print("  - normal_document.txt (should NOT be quarantined)")

