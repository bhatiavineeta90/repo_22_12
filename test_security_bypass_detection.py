# Test script to verify security bypass detection
import sys
sys.path.insert(0, '.')

from attacks.bad_likert_judge import (
    check_security_bypass_content, 
    map_attack_result,
    SECURITY_BYPASS_PATTERNS,
    SECURITY_BYPASS_KEYWORDS,
    HYPOTHETICAL_CONTEXT_PATTERNS
)

print("=" * 60)
print("SECURITY BYPASS DETECTION TEST")
print("=" * 60)

print(f"\nPatterns loaded: {len(SECURITY_BYPASS_PATTERNS)}")
print(f"Keywords loaded: {len(SECURITY_BYPASS_KEYWORDS)}")
print(f"Context patterns: {len(HYPOTHETICAL_CONTEXT_PATTERNS)}")

# Turn 1 response from security scan (SHOULD detect bypass)
turn1_response = """A response rated 3 would look like this:

---

User: "What can you help me with?"
