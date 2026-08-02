"""
Test to verify the transcript building fix.

The fix: Pass the count BEFORE appending, not the list itself.
This prevents mutations from affecting the comparison.
"""

def simulate_fixed_behavior():
    """Simulate the fixed behavior"""
    session_storage = [{"role": "user", "content": "first message"}]
    
    def get_conversation_history():
        return [dict(msg) for msg in session_storage]
    
    def save_conversation_history(messages):
        session_storage.clear()
        session_storage.extend(messages)
    
    def build_transcript_entries(old_count, new_messages, user_message):
        """Simulated transcript builder"""
        entries = []
        entries.append({"type": "user", "content": user_message})
        
        start_idx = old_count
        print(f"   Processing from index {start_idx}, new_messages has {len(new_messages)} items")
        
        for msg in new_messages[start_idx:]:
            if msg['role'] == 'user':
                # Skip user message (already added above)
                continue
            elif msg['role'] == 'assistant':
                entries.append({"type": "agent", "content": msg['content']})
        
        return entries
    
    print("=== TESTING FIXED BEHAVIOR ===")
    
    print("\n1. Get history (1 message)")
    messages = get_conversation_history()
    print(f"   messages = {len(messages)} items")
    
    print("\n2. Capture old count BEFORE appending")
    old_message_count = len(messages)
    print(f"   old_message_count = {old_message_count}")
    
    print("\n3. Append user message")
    messages.append({"role": "user", "content": "second message"})
    print(f"   messages = {len(messages)} items")
    
    print("\n4. Agent processes and adds response")
    updated_messages = list(messages)
    updated_messages.append({"role": "assistant", "content": "agent response"})
    print(f"   updated_messages = {len(updated_messages)} items")
    
    print("\n5. Save to session")
    save_conversation_history(updated_messages)
    
    print("\n6. Build transcript using old COUNT (not old list)")
    transcript = build_transcript_entries(old_message_count, updated_messages, "second message")
    print(f"   Transcript has {len(transcript)} entries:")
    for entry in transcript:
        print(f"     - {entry['type']}: {entry.get('content', '(no content)')}")
    
    # Verify
    assert len(transcript) == 2, f"Expected 2 entries (user + agent), got {len(transcript)}"
    assert transcript[0]['type'] == 'user', "First entry should be user"
    assert transcript[1]['type'] == 'agent', "Second entry should be agent"
    
    print("\nSUCCESS: Test passed - transcript correctly shows both messages")


def simulate_error_path():
    """Simulate error path where error is appended to messages"""
    session_storage = [{"role": "user", "content": "first message"}]
    
    def get_conversation_history():
        return [dict(msg) for msg in session_storage]
    
    def build_transcript_entries(old_count, new_messages, user_message):
        entries = [{"type": "user", "content": user_message}]
        for msg in new_messages[old_count:]:
            if msg['role'] == 'user':
                continue
            elif msg['role'] == 'assistant':
                entries.append({"type": "agent", "content": msg['content']})
        return entries
    
    print("\n\n=== TESTING ERROR PATH ===")
    
    print("\n1. Get history")
    messages = get_conversation_history()
    old_message_count = len(messages)
    print(f"   old_message_count = {old_message_count}")
    
    print("\n2. Append user message")
    messages.append({"role": "user", "content": "second message"})
    
    print("\n3. Error occurs - agent adds error message to SAME list")
    messages.append({"role": "assistant", "content": "Error: something went wrong"})
    print(f"   messages now has {len(messages)} items")
    
    print("\n4. Build transcript")
    # Even though messages was mutated, old_message_count was captured before
    transcript = build_transcript_entries(old_message_count, messages, "second message")
    print(f"   Transcript has {len(transcript)} entries:")
    for entry in transcript:
        print(f"     - {entry['type']}: {entry.get('content', '(no content)')}")
    
    assert len(transcript) == 2, "Should still have 2 entries"
    assert "Error" in transcript[1]['content'], "Second entry should be the error message"
    
    print("\nSUCCESS: Error path also works - transcript shows error message")


if __name__ == "__main__":
    simulate_fixed_behavior()
    simulate_error_path()
