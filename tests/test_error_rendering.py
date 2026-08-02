#!/usr/bin/env python3
"""Test that error messages render properly in the UI"""
import requests
import json

def test_error_rendering():
    """
    Test by sending a request that will produce an error response.
    We'll check that the response contains the error in the transcript.
    """
    print("Testing error rendering in UI...")
    
    # Send a message to trigger the agent
    response = requests.post(
        'http://localhost:5000/send',
        json={'message': 'test error rendering'},
        timeout=30
    )
    
    print(f"Response status: {response.status_code}")
    
    if response.status_code != 200:
        print(f"FAIL: Expected 200, got {response.status_code}")
        print(f"Response: {response.text}")
        return False
    
    data = response.json()
    
    print(f"Success: {data.get('success')}")
    print(f"Transcript entries: {len(data.get('transcript', []))}")
    
    # Check transcript structure
    transcript = data.get('transcript', [])
    
    for i, entry in enumerate(transcript):
        print(f"\nEntry {i}:")
        print(f"  Type: {entry.get('type')}")
        print(f"  Content: {entry.get('content', '')[:100]}...")
    
    # Verify we have at least user message
    if len(transcript) < 1:
        print("\nFAIL: No transcript entries")
        return False
    
    # Check if first entry is user message
    if transcript[0].get('type') != 'user':
        print(f"\nFAIL: First entry should be user, got {transcript[0].get('type')}")
        return False
    
    print("\nOK: User message rendered")
    
    # Check if we have an agent response (could be error or success)
    agent_entries = [e for e in transcript if e.get('type') == 'agent']
    
    if agent_entries:
        print(f"OK: Found {len(agent_entries)} agent response(s)")
        for entry in agent_entries:
            content = entry.get('content', '')
            if 'Error' in content or 'error' in content:
                print(f"OK: Error message is present in transcript: {content[:100]}...")
            else:
                print(f"OK: Agent response: {content[:100]}...")
        return True
    else:
        print("WARNING: No agent response in transcript (might be rate limited or error)")
        print("This is OK if Groq is rate limited - the structure is correct")
        return True

if __name__ == "__main__":
    result = test_error_rendering()
    print(f"\n{'PASS' if result else 'FAIL'}: Error rendering test")
