# test_all_vulnerabilities.py
"""
Run all 3 vulnerability tests (PII Leakage, BOLA, Prompt Leakage) 
with 2 subtypes each in a single script.
"""

import requests
import json
import time

BASE_URL = "http://localhost:8000"

# Define all test payloads
TESTS = [
    {
        "name": "PII Leakage",
        "payload": {
            "vulnerability_type": "pii_leakage",
            "vulnerability_subtypes": ["direct disclosure", "social manipulation"],
            "turns": 1,
            "session_id": "pii-test",
            "agent_timeout_secs": 10
        }
    },
    {
        "name": "BOLA",
        "payload": {
            "vulnerability_type": "bola",
            "vulnerability_subtypes": ["object access bypass", "cross customer access"],
            "turns": 1,
            "session_id": "bola-test",
            "agent_timeout_secs": 10
        }
    },
    {
        "name": "Prompt Leakage",
        "payload": {
            "vulnerability_type": "prompt_leakage",
            "vulnerability_subtypes": ["instructions", "secrets and credentials"],
            "turns": 1,
            "session_id": "prompt-test",
            "agent_timeout_secs": 10
        }
    }
]

def run_test(test):
    """Run a single vulnerability test"""
    print(f"\n{'='*60}")
    print(f"Running: {test['name']}")
    print(f"Subtypes: {test['payload']['vulnerability_subtypes']}")
    print(f"{'='*60}")
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/test/run",
            json=test['payload'],
            headers={"Content-Type": "application/json"},
            timeout=300  # 5 minute timeout
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"\n✅ SUCCESS - Run ID: {result.get('run_id')}")
            
            # Print summary
            summary = result.get('summary', {})
            print(f"\nSummary:")
            print(f"  Total Tests: {summary.get('total_tests', 0)}")
            print(f"  Jailbreak Success: {summary.get('jailbreak_success_count', 0)}/{summary.get('total_tests', 0)}")
            print(f"  Vulnerabilities Detected: {summary.get('vulnerability_count', 0)}")
            print(f"  Critical: {summary.get('critical_count', 0)}")
            print(f"  High: {summary.get('high_count', 0)}")
            print(f"  Medium: {summary.get('medium_count', 0)}")
            print(f"  Pass: {summary.get('pass_count', 0)}")
            
            return result
        else:
            print(f"\n❌ ERROR: {response.status_code}")
            print(response.text)
            return None
            
    except requests.exceptions.Timeout:
        print(f"\n⏱️ TIMEOUT: Test took too long")
        return None
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        return None


def main():
    print("="*60)
    print("VULNERABILITY TESTING - ALL 3 TYPES")
    print("="*60)
    print(f"\nServer: {BASE_URL}")
    print(f"Tests to run: {len(TESTS)}")
    
    # Check if server is running
    try:
        health = requests.get(f"{BASE_URL}/api/health", timeout=5)
        if health.status_code != 200:
            print("\n❌ Server is not responding. Make sure it's running:")
            print("   python -m uvicorn api.main:app --port 8000")
            return
        print("✅ Server is running\n")
    except:
        print("\n❌ Cannot connect to server. Make sure it's running:")
        print("   python -m uvicorn api.main:app --port 8000")
        return
    
    results = []
    
    for test in TESTS:
        result = run_test(test)
        results.append({
            "name": test["name"],
            "result": result
        })
        
        # Small delay between tests
        if test != TESTS[-1]:
            print("\nWaiting 2 seconds before next test...")
            time.sleep(2)
    
    # Final Summary
    print("\n" + "="*60)
    print("FINAL SUMMARY")
    print("="*60)
    
    for r in results:
        status = "✅" if r["result"] else "❌"
        run_id = r["result"].get("run_id", "N/A") if r["result"] else "Failed"
        print(f"{status} {r['name']}: {run_id}")
    
    print("\n" + "="*60)
    print("ALL TESTS COMPLETED")
    print("="*60)


if __name__ == "__main__":
    main()
