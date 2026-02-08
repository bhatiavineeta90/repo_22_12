"""
Test script to fetch and display results from MongoDB.
Run: python test_fetch_db_results.py
"""
import json
from datetime import datetime

from database.mongo_service import get_db, MongoDBService


def print_header(title: str):
    """Print formatted section header."""
    print("\n" + "=" * 70)
    print(f" {title}")
    print("=" * 70)


def print_table(headers: list, rows: list, col_widths: list = None):
    """Print a simple ASCII table."""
    if not col_widths:
        col_widths = [max(len(str(h)), 10) for h in headers]
    
    # Build format string
    fmt = " | ".join(f"{{:<{w}}}" for w in col_widths)
    sep = "-+-".join("-" * w for w in col_widths)
    
    print(fmt.format(*[str(h)[:w] for h, w in zip(headers, col_widths)]))
    print(sep)
    for row in rows:
        print(fmt.format(*[str(c)[:w] for c, w in zip(row, col_widths)]))


def display_recent_runs(db: MongoDBService, limit: int = 5):
    """Display recent test runs."""
    print_header(f"Recent {limit} Runs")
    
    runs = db.get_recent_runs(limit=limit)
    if not runs:
        print("No runs found in database.")
        return None
    
    headers = ["Run ID", "Payload", "Status", "Model", "Attacks", "Started At"]
    col_widths = [22, 25, 12, 18, 8, 20]
    
    rows = []
    for run in runs:
        started = run.get("started_at", "N/A")
        if started and isinstance(started, str):
            started = started[:19]
        rows.append([
            run.get("run_id", "")[:20] + "..",
            run.get("payload_name", "N/A")[:23],
            run.get("status", "N/A"),
            run.get("llm_model", "N/A"),
            run.get("total_attack_profiles", 0),
            started,
        ])
    
    print_table(headers, rows, col_widths)
    return runs[0]["run_id"] if runs else None


def display_run_details(db: MongoDBService, run_id: str):
    """Display detailed information for a specific run."""
    print_header(f"Run Details: {run_id[:40]}...")
    
    run = db.get_run(run_id)
    if not run:
        print(f"Run {run_id} not found.")
        return
    
    run_dict = run.to_dict()
    print(f"\n  Run ID:          {run_dict['run_id']}")
    print(f"  Payload ID:      {run_dict['payload_id']}")
    print(f"  Payload Name:    {run_dict['payload_name']}")
    print(f"  Status:          {run_dict['status']}")
    print(f"  LLM Model:       {run_dict['llm_model']}")
    print(f"  Temperature:     {run_dict['temperature']}")
    print(f"  Attack Profiles: {run_dict['total_attack_profiles']}")
    print(f"  Vuln Profiles:   {run_dict['total_vuln_profiles']}")
    print(f"  Started At:      {run_dict['started_at']}")
    print(f"  Completed At:    {run_dict.get('completed_at', 'N/A')}")
    if run_dict.get('overall_success_rate'):
        print(f"  Success Rate:    {run_dict['overall_success_rate']}%")
    if run_dict.get('overall_risk_level'):
        print(f"  Risk Level:      {run_dict['overall_risk_level']}")


def display_attack_executions(db: MongoDBService, run_id: str):
    """Display attack execution progress for a run."""
    print_header("Attack Executions")
    
    executions = db.get_all_attack_executions(run_id)
    if not executions:
        print("No attack executions found.")
        return
    
    headers = ["Attack Name", "Type", "Status", "Done", "Plan", "Success", "Score"]
    col_widths = [22, 18, 12, 6, 6, 8, 8]
    
    rows = []
    for exec in executions:
        rows.append([
            exec.get("attack_name", "N/A")[:20],
            exec.get("attack_type", "N/A")[:16],
            exec.get("status", "N/A"),
            exec.get("turns_completed", 0),
            exec.get("planned_turns", 0),
            exec.get("success_turns", 0),
            f"{exec.get('best_score', 0):.2f}",
        ])
    
    print_table(headers, rows, col_widths)


def display_results(db: MongoDBService, run_id: str, limit: int = 10):
    """Display individual turn results for a run."""
    print_header(f"Turn Results (Last {limit})")
    
    results = db.get_latest_results(run_id, limit=limit)
    if not results:
        print("No results found.")
        return
    
    headers = ["Turn", "Attack Profile", "Result", "Score", "Overall", "Prompt Preview"]
    col_widths = [6, 20, 10, 8, 10, 30]
    
    rows = []
    for result in results:
        prompt_preview = (result.get("attack_prompt", "") or "")[:28]
        rows.append([
            result.get("turn", 0),
            result.get("attack_profile_name", "N/A")[:18],
            result.get("attack_result", "N/A"),
            f"{result.get('attack_score', 0):.2f}",
            result.get("overall_result", "N/A"),
            prompt_preview + ".." if len(prompt_preview) >= 28 else prompt_preview,
        ])
    
    print_table(headers, rows, col_widths)


def display_detailed_result(db: MongoDBService, run_id: str, result_index: int = 0):
    """Display full details of a specific result."""
    print_header("Detailed Result View")
    
    results = db.get_latest_results(run_id, limit=result_index + 1)
    if not results or len(results) <= result_index:
        print("Result not found.")
        return
    
    result = results[result_index]
    
    print(f"\n  Result ID:      {result.get('result_id', 'N/A')}")
    print(f"  Turn:           {result.get('turn', 0)}")
    print(f"  Attack Profile: {result.get('attack_profile_name', 'N/A')}")
    print(f"  Attack Type:    {result.get('attack_type', 'N/A')}")
    print(f"  Timestamp:      {result.get('timestamp', 'N/A')}")
    print(f"\n  === Attack Results ===")
    print(f"  Attack Score:   {result.get('attack_score', 0)}")
    print(f"  Attack Result:  {result.get('attack_result', 'N/A')}")
    
    if result.get('attack_reasoning'):
        reasoning = result['attack_reasoning']
        print(f"\n  Attack Reasoning:")
        print(f"  {reasoning[:500]}{'...' if len(reasoning) > 500 else ''}")
    
    prompt = result.get('attack_prompt', 'N/A') or 'N/A'
    print(f"\n  === Attack Prompt ===")
    print(f"  {prompt[:800]}{'...' if len(prompt) > 800 else ''}")
    
    response = result.get('agent_response', 'N/A') or 'N/A'
    print(f"\n  === Agent Response ===")
    print(f"  {response[:800]}{'...' if len(response) > 800 else ''}")
    
    if result.get('vulnerability_detected'):
        print(f"\n  === Vulnerability Details ===")
        print(f"  Detected:       {result.get('vulnerability_detected')}")
        print(f"  Severity:       {result.get('vulnerability_severity', 'N/A')}")
        print(f"  Score:          {result.get('vulnerability_score', 'N/A')}")
        if result.get('detected_pii_types'):
            print(f"  PII Types:      {result.get('detected_pii_types')}")
    
    if result.get('attack_mitigation_suggestions'):
        mitigation = result['attack_mitigation_suggestions']
        print(f"\n  === Attack Mitigation ===")
        print(f"  {mitigation[:500]}{'...' if len(mitigation) > 500 else ''}")
    
    if result.get('vulnerability_mitigation_suggestions'):
        mitigation = result['vulnerability_mitigation_suggestions']
        print(f"\n  === Vulnerability Mitigation ===")
        print(f"  {mitigation[:500]}{'...' if len(mitigation) > 500 else ''}")


def display_run_summary(db: MongoDBService, run_id: str):
    """Display aggregated summary for a run."""
    print_header("Run Summary")
    
    summary = db.get_run_summary(run_id)
    if not summary or not summary.get('summary'):
        print("Could not generate summary.")
        return
    
    s = summary.get('summary', {})
    print(f"\n  Total Turns:     {s.get('total_turns', 0)}")
    print(f"  Total Successes: {s.get('total_successes', 0)}")
    print(f"  Success Rate:    {s.get('success_rate_pct', 0)}%")


def display_attack_type_stats(db: MongoDBService):
    """Display statistics grouped by attack type."""
    print_header("Stats by Attack Type")
    
    stats = db.get_stats_by_attack_type()
    if not stats:
        print("No statistics available.")
        return
    
    headers = ["Attack Type", "Total Runs", "Avg Success Rate", "Successes"]
    col_widths = [25, 12, 18, 12]
    
    rows = []
    for stat in stats:
        rows.append([
            stat.get("_id", "Unknown")[:23],
            stat.get("total_runs", 0),
            f"{stat.get('avg_success_rate', 0):.1f}%",
            stat.get("total_successes", 0),
        ])
    
    print_table(headers, rows, col_widths)


def list_all_runs(db: MongoDBService):
    """List all run IDs for reference."""
    print_header("All Run IDs")
    
    try:
        runs = list(db.db[db.COLLECTION_RUNS].find({}, {"run_id": 1, "payload_name": 1, "status": 1}))
        if not runs:
            print("No runs found.")
            return
        
        for i, run in enumerate(runs, 1):
            print(f"  {i}. {run.get('run_id')} - {run.get('payload_name', 'N/A')} ({run.get('status', 'N/A')})")
    except Exception as e:
        print(f"Error listing runs: {e}")


def main():
    print("\n" + "=" * 70)
    print("   MongoDB Results Viewer - Red Team Testing")
    print("=" * 70)
    
    # Connect to database
    db = get_db()
    if not db.is_connected():
        print("\n❌ Failed to connect to MongoDB!")
        print("   Check your config/config.ini settings.")
        return
    
    print(f"\n✅ Connected to MongoDB: {db.db_name}")
    
    # Display recent runs and get the most recent run_id
    latest_run_id = display_recent_runs(db, limit=5)
    
    if latest_run_id:
        print(f"\n📋 Showing details for most recent run...")
        
        # Display details for the most recent run
        display_run_details(db, latest_run_id)
        display_attack_executions(db, latest_run_id)
        display_results(db, latest_run_id, limit=10)
        display_run_summary(db, latest_run_id)
        
        # Show detailed view of the most recent result
        display_detailed_result(db, latest_run_id, result_index=0)
    
    # Display overall stats
    display_attack_type_stats(db)
    
    # List all run IDs for reference
    list_all_runs(db)
    
    print("\n" + "=" * 70)
    print("   Report Complete")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
