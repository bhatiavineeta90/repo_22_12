import sys
import json
from datetime import datetime

# Add project root to path
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import get_db


def print_separator(title=""):
    print(f"\n{'='*60}")
    if title:
        print(f"  {title}")
        print(f"{'='*60}")


def fetch_all_runs(limit=10):
    """Fetch and display recent runs."""
    db = get_db()
    if not db.is_connected():
        print("❌ Not connected to MongoDB")
        return
    
    print_separator("RECENT RUNS")
    runs = db.get_recent_runs(limit)
    
    if not runs:
        print("No runs found in database.")
        return
    
    print(f"Found {len(runs)} run(s):\n")
    
    for i, run in enumerate(runs, 1):
        status_icon = "✅" if run.get("status") == "completed" else "🔄"
        print(f"{i}. {status_icon} {run.get('run_id')}")
        print(f"   Payload: {run.get('payload_name', 'N/A')}")
        print(f"   Status: {run.get('status')}")
        print(f"   Started: {run.get('started_at', 'N/A')}")
        print(f"   Success Rate: {run.get('overall_success_rate', 'N/A')}%")
        print()


def fetch_run_details(run_id: str):
    """Fetch detailed results for a specific run."""
    db = get_db()
    if not db.is_connected():
        print("❌ Not connected to MongoDB")
        return
    
    print_separator(f"RUN DETAILS: {run_id}")
    
    # Get run info
    run = db.get_run(run_id)
    if not run:
        print(f"❌ Run not found: {run_id}")
        return
    
    run_dict = run.to_dict()
    print(f"Payload: {run_dict.get('payload_name')}")
    print(f"Status: {run_dict.get('status')}")
    print(f"LLM Model: {run_dict.get('llm_model')}")
    print(f"Started: {run_dict.get('started_at')}")
    print(f"Completed: {run_dict.get('completed_at')}")
    print(f"Success Rate: {run_dict.get('overall_success_rate')}%")
    print(f"Risk Level: {run_dict.get('overall_risk_level')}")
    
    # Get attack executions
    print_separator("ATTACK EXECUTIONS")
    attack_execs = db.get_all_attack_executions(run_id)
    
    for attack in attack_execs:
        status_icon = "✅" if attack.get("status") == "completed" else "🔄"
        print(f"\n{status_icon} {attack.get('attack_name')}")
        print(f"   Type: {attack.get('attack_type')}")
        print(f"   Turns: {attack.get('turns_completed')}/{attack.get('planned_turns')}")
        print(f"   Success: {attack.get('success_turns')}")
        print(f"   Best Score: {attack.get('best_score')}")
    
    # Get results
    print_separator("TURN RESULTS")
    results = db.get_results_for_run(run_id)
    
    if not results:
        print("No turn results found.")
        return
    
    print(f"Total turns: {len(results)}\n")
    
    for result in results[-10:]:  # Show last 10
        score = result.get("attack_score", 0)
        atk_result = result.get("attack_result", "?")
        vuln = "🔴" if result.get("vulnerability_detected") else "🟢"
        
        print(f"Turn {result.get('turn')}: Score={score:.1f}, Result={atk_result}, Vuln={vuln}")
        print(f"   Attack: {result.get('attack_prompt', '')[:60]}...")
        print(f"   Overall: {result.get('overall_result')}")
        print()


def fetch_collection_stats():
    """Show statistics for all collections."""
    db = get_db()
    if not db.is_connected():
        print("❌ Not connected to MongoDB")
        return
    
    print_separator("DATABASE STATISTICS")
    
    collections = [
        ("rt_runs", db.COLLECTION_RUNS),
        ("rt_results", db.COLLECTION_RESULTS),
        ("rt_attack_execution", db.COLLECTION_ATTACK_EXECUTION),
        ("rt_vulnerability_execution", db.COLLECTION_VULN_EXECUTION),
    ]
    
    for name, collection_name in collections:
        count = db.db[collection_name].count_documents({})
        print(f"  {name}: {count} records")
    
    # Attack type stats
    print_separator("STATS BY ATTACK TYPE")
    stats = db.get_stats_by_attack_type()
    
    if not stats:
        print("No attack statistics available.")
        return
    
    for stat in stats:
        print(f"\n{stat.get('_id')}:")
        print(f"   Total Runs: {stat.get('total_runs')}")
        print(f"   Avg Success Rate: {stat.get('avg_success_rate', 0):.1f}%")
        print(f"   Total Successes: {stat.get('total_successes')}")


def export_run_to_json(run_id: str, output_file: str = None):
    """Export run results to JSON file."""
    db = get_db()
    if not db.is_connected():
        print("❌ Not connected to MongoDB")
        return
    
    summary = db.get_run_summary(run_id)
    if not summary.get("run"):
        print(f"❌ Run not found: {run_id}")
        return
    
    # Get all results
    results = db.get_results_for_run(run_id)
    summary["results"] = results
    
    # Convert ObjectId to string for JSON serialization
    def clean_for_json(obj):
        if isinstance(obj, dict):
            return {k: clean_for_json(v) for k, v in obj.items() if k != "_id"}
        elif isinstance(obj, list):
            return [clean_for_json(item) for item in obj]
        return obj
    
    summary = clean_for_json(summary)
    
    output_file = output_file or f"results/exports/{run_id}.json"
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    
    print(f"✅ Exported to: {output_file}")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("  MongoDB Results Viewer")
    print("="*60)
    
    if len(sys.argv) > 1:
        run_id = sys.argv[1]
        if run_id == "--stats":
            fetch_collection_stats()
        elif run_id.startswith("--export="):
            export_run_id = run_id.split("=")[1]
            export_run_to_json(export_run_id)
        else:
            fetch_run_details(run_id)
    else:
        # Show menu
        fetch_collection_stats()
        print()
        fetch_all_runs(5)
        
        print("\n" + "-"*60)
        print("Usage:")
        print("  python fetch_db_results.py              # Show stats & recent runs")
        print("  python fetch_db_results.py <run_id>     # Show run details")
        print("  python fetch_db_results.py --stats      # Show database stats")
        print("  python fetch_db_results.py --export=<run_id>  # Export to JSON")
        print("-"*60 + "\n")
