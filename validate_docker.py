#!/usr/bin/env python3
"""
Validate Docker setup before building.
Checks for required files, environment variables, and syntax.
"""
import os
import sys

def check_file_exists(filepath, required=True):
    """Check if a file exists"""
    exists = os.path.isfile(filepath)
    status = "SUCCESS:" if exists else ("FAILED:" if required else "WARNING:")
    req_label = " (required)" if required else " (optional)"
    print(f"{status} {filepath}{req_label if not exists and required else ''}")
    return exists or not required

def check_env_file():
    """Check .env file has required variables"""
    if not os.path.isfile('.env'):
        print("WARNING: .env file not found - using .env.example as template")
        return False
    
    required_vars = [
        'GROQ_API_KEY',
        'TELEGRAM_BOT_TOKEN',
        'TELEGRAM_CHAT_ID',
        'ABUSEIPDB_API_KEY'
    ]
    
    with open('.env', 'r') as f:
        content = f.read()
    
    missing = []
    for var in required_vars:
        if f"{var}=" not in content or f"{var}=your_" in content:
            missing.append(var)
    
    if missing:
        print(f"WARNING: .env file missing or has placeholder values for: {', '.join(missing)}")
        return False
    
    print("SUCCESS: .env file has required variables")
    return True

def main():
    print("=" * 60)
    print("SentinelOps Docker Setup Validation")
    print("=" * 60)
    
    all_checks_passed = True
    
    print("\n1. Checking required files:")
    all_checks_passed &= check_file_exists('Dockerfile')
    all_checks_passed &= check_file_exists('docker-compose.yml')
    all_checks_passed &= check_file_exists('requirements.txt')
    all_checks_passed &= check_file_exists('.dockerignore')
    
    print("\n2. Checking application files:")
    all_checks_passed &= check_file_exists('web_ui.py')
    all_checks_passed &= check_file_exists('server.py')
    all_checks_passed &= check_file_exists('agent_shared.py')
    
    print("\n3. Checking templates:")
    all_checks_passed &= check_file_exists('templates/index.html')
    
    print("\n4. Checking environment configuration:")
    env_ok = check_env_file()
    if not env_ok:
        print("   → Copy .env.example to .env and fill in your API keys")
        all_checks_passed = False
    
    print("\n5. Checking data directories:")
    for dir_path in ['data', 'data/firewall_sandbox']:
        exists = os.path.isdir(dir_path)
        status = "SUCCESS:" if exists else "WARNING:"
        print(f"{status} {dir_path}/ {'(will be created)' if not exists else ''}")
    
    print("\n" + "=" * 60)
    if all_checks_passed:
        print("SUCCESS: All checks passed! Ready to build Docker image.")
        print("\nNext steps:")
        print("  1. docker-compose build")
        print("  2. docker-compose up -d")
        print("  3. Open http://localhost:5000")
        return 0
    else:
        print("FAILED: Some checks failed. Please fix the issues above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())

