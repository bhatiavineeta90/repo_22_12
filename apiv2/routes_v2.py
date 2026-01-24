# apiv2/routes_v2.py
"""
API V2 routes for the RedTeam V2 runner.
Provides endpoints for running tests with the new payload structure.
"""

import os
import sys
import json
from datetime import datetime
from typing import List, Dict, Any, Generator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apiv2.models_v2 import (
    TestRunRequestV2,
    HealthResponseV2,
    TestRunResponseV2,
    TestSummaryV2,
    ResultFileInfoV2,
    ResultsListResponseV2,
)

from models.payload_models import (
    RedTeamPayload,
    VulnerabilityType,
)


# Create API router
router_v2 = APIRouter(prefix="/api/v2", tags=["Testing API V2"])


# ============================================================
#  Health Check
# ============================================================

@router_v2.get("/health", response_model=HealthResponseV2)
async def health_check_v2():
    """Check if the V2 API is running and healthy."""
    return HealthResponseV2(
        status="healthy",
        message="RedTeam V2 API is running",
        version="2.0.0"
    )


# ============================================================
#  Run Test V2 (Full Payload)
# ============================================================

@router_v2.post("/test/run", response_model=TestRunResponseV2)
async def run_test_v2(request: TestRunRequestV2):
    """
    Execute a complete RedTeam V2 test run.
    
    This endpoint runs the full test synchronously using the new
    RedTeamPayload structure with attack_profiles and vulnerability_profiles.
    
    Use the example in the Try It Now section as a starting point.
    """
    from runner_v2 import RedTeamV2
    
    try:
        # Initialize RedTeam V2 with the payload
        runner = RedTeamV2(request.payload)
        
        # Run the test
        run_id, results = runner.run()
        
        # Calculate summary
        summary = TestSummaryV2(
            total_tests=len(results),
            critical_count=sum(1 for r in results if "CRITICAL" in r.get("overall_result", "")),
            high_count=sum(1 for r in results if "HIGH" in r.get("overall_result", "")),
            medium_count=sum(1 for r in results if "MEDIUM" in r.get("overall_result", "")),
            pass_count=sum(1 for r in results if "PASS" in r.get("overall_result", "")),
            jailbreak_success_count=sum(1 for r in results if r.get("jailbreak_result") == "Success"),
            vulnerability_count=sum(1 for r in results if r.get("vulnerability_detected", False))
        )
        
        return TestRunResponseV2(
            run_id=run_id,
            payload_id=request.payload.id,
            suite_name=request.payload.meta_data.name,
            summary=summary,
            results=results,
            artifacts={
                "json_path": f"results/runs/{run_id}.json",
                "csv_path": "results/reports/all_results_v2.csv"
            }
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
#  Run Test with Streaming (Server-Sent Events)
# ============================================================

def generate_sse_events_v2(request: TestRunRequestV2) -> Generator[str, None, None]:
    """Generator function that yields SSE events for streaming test results with detailed steps."""
    from runner_v2 import RedTeamV2
    import traceback
    
    try:
        # Step 1: Initialization
        yield f"data: {json.dumps({'type': 'step', 'step': 'initializing', 'message': 'Initializing RedTeam V2 runner...'})}\n\n"
        
        runner = RedTeamV2(request.payload)
        
        yield f"data: {json.dumps({'type': 'step', 'step': 'initialized', 'message': f'Runner initialized with LLM: {request.payload.mode_constraints.llm.value}'})}\n\n"
        
        # Step 2: Start event
        yield f"data: {json.dumps({'type': 'start', 'payload_id': request.payload.id, 'suite_name': request.payload.meta_data.name, 'total_attacks': len(request.payload.attack_profiles), 'total_vulns': len(request.payload.vulnerability_profiles)})}\n\n"
        
        all_results = []
        
        # Step 3: Process each attack profile
        for ap_idx, attack_profile in enumerate(request.payload.attack_profiles, 1):
            yield f"data: {json.dumps({'type': 'step', 'step': 'attack_start', 'message': f'Starting attack {ap_idx}/{len(request.payload.attack_profiles)}: {attack_profile.name}', 'attack_type': attack_profile.attack_type.value})}\n\n"
            
            # Run attack
            yield f"data: {json.dumps({'type': 'step', 'step': 'running_attack', 'message': f'Running {attack_profile.turn_config.turns} turns of jailbreaking...'})}\n\n"
            
            _, attack_results = runner.run_attack(attack_profile)
            
            yield f"data: {json.dumps({'type': 'step', 'step': 'attack_complete', 'message': f'Attack completed with {len(attack_results)} results'})}\n\n"
            
            # Step 4: Evaluate each result against vulnerability profiles
            for result_idx, attack_result in enumerate(attack_results, 1):
                turn = attack_result.get("turn", result_idx)
                jb_score = attack_result.get("score", "N/A")
                
                yield f"data: {json.dumps({'type': 'step', 'step': 'evaluating', 'message': f'Evaluating turn {turn} (JB score: {jb_score})'})}\n\n"
                
                if request.payload.vulnerability_profiles:
                    # Collect ALL vulnerability results for this turn first
                    vuln_results = []
                    for vuln_profile in request.payload.vulnerability_profiles:
                        yield f"data: {json.dumps({'type': 'step', 'step': 'vuln_check', 'message': f'Checking {vuln_profile.vulnerability_type.value}'})}\n\n"
                        
                        vuln_result = runner.evaluate_vulnerability(
                            attack_result.get("attack_prompt", ""),
                            attack_result.get("agent_response", ""),
                            vuln_profile
                        )
                        vuln_results.append(vuln_result)
                    
                    # Merge all vulnerabilities into ONE grouped turn result
                    grouped = runner.merge_turn_with_vulnerabilities(attack_result, vuln_results, attack_profile)
                    all_results.append(grouped)
                    
                    # Stream the grouped turn result
                    yield f"data: {json.dumps({'type': 'turn', 'data': grouped}, default=str)}\n\n"
                else:
                    # No vulnerability profiles, create grouped result with empty vuln list
                    grouped = runner.merge_turn_with_vulnerabilities(attack_result, [], attack_profile)
                    all_results.append(grouped)
                    yield f"data: {json.dumps({'type': 'turn', 'data': grouped}, default=str)}\n\n"
        
        # Step 5: Generate summary
        yield f"data: {json.dumps({'type': 'step', 'step': 'summarizing', 'message': 'Generating summary...'})}\n\n"
        
        summary = {
            "total_turns": len(all_results),
            "total_vulnerability_checks": sum(len(r.get("vulnerability_evaluations", [])) for r in all_results),
            "critical_count": sum(1 for r in all_results if "CRITICAL" in r.get("overall_result", "")),
            "high_count": sum(1 for r in all_results if "HIGH" in r.get("overall_result", "")),
            "medium_count": sum(1 for r in all_results if "MEDIUM" in r.get("overall_result", "")),
            "pass_count": sum(1 for r in all_results if "PASS" in r.get("overall_result", "")),
            "attack_success_count": sum(1 for r in all_results if any(k.endswith("_result") and r.get("attack_result", {}).get(k) == "Success" for k in r.get("attack_result", {}).keys())),
            "vulnerability_count": sum(1 for r in all_results for ve in r.get("vulnerability_evaluations", []) if ve.get("vulnerability_detected"))
        }
        yield f"data: {json.dumps({'type': 'summary', 'data': summary})}\n\n"
        
        # Step 6: Complete
        yield f"data: {json.dumps({'type': 'complete', 'message': 'Test completed successfully', 'total_results': len(all_results)})}\n\n"
        
    except Exception as e:
        yield f"data: {json.dumps({'type': 'error', 'error': str(e), 'traceback': traceback.format_exc()})}\n\n"



@router_v2.post("/test/stream")
async def stream_test_v2(request: TestRunRequestV2):
    """
    Execute a V2 test with real-time streaming results.
    
    Returns Server-Sent Events (SSE) with detailed step-by-step updates:
    
    **Step Events (`type: step`):**
    - `initializing`: Runner is being initialized
    - `initialized`: Runner ready with LLM info
    - `attack_profile_start`: Starting a new attack profile
    - `prompt_start`: Processing a specific prompt
    - `running_attack`: Jailbreaking attack in progress
    - `attack_complete`: Attack profile finished
    - `evaluating_turn`: Evaluating turn results
    - `vulnerability_check`: Checking specific vulnerability
    - `turn_complete`: Individual turn evaluation done
    - `generating_summary`: Creating final summary
    
    **Result Events:**
    - `start`: Test has begun
    - `turn`: Individual turn result with attack and vulnerability data
    - `summary`: Final summary with statistics
    - `complete`: Test has finished
    - `error`: An error occurred
    """
    return StreamingResponse(
        generate_sse_events_v2(request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


# ============================================================
#  List Results V2
# ============================================================

@router_v2.get("/results", response_model=ResultsListResponseV2)
async def list_results_v2():
    """
    List all saved V2 test run results.
    
    Returns a list of available result files with metadata including
    run ID, payload ID, suite name, and file size.
    """
    results_dir = "apiv2/results/runs"
    
    if not os.path.exists(results_dir):
        return ResultsListResponseV2(total_count=0, results=[])
    
    result_files = []
    for filename in os.listdir(results_dir):
        if filename.endswith(".json"):
            filepath = os.path.join(results_dir, filename)
            stat = os.stat(filepath)
            
            # Extract run_id from filename
            run_id = filename[:-5]
            
            # Try to get payload info from file
            payload_id = None
            suite_name = None
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    payload_id = data.get("payload", {}).get("_id")
                    suite_name = data.get("payload", {}).get("meta_data", {}).get("name")
            except:
                pass
            
            result_files.append(ResultFileInfoV2(
                run_id=run_id,
                filename=filename,
                payload_id=payload_id,
                suite_name=suite_name,
                created_at=datetime.fromtimestamp(stat.st_mtime).isoformat(),
                size_bytes=stat.st_size
            ))
    
    # Sort by creation time, newest first
    result_files.sort(key=lambda x: x.created_at, reverse=True)
    
    return ResultsListResponseV2(total_count=len(result_files), results=result_files)


# ============================================================
#  Get Specific Result V2
# ============================================================

@router_v2.get("/results/{run_id}")
async def get_result_v2(run_id: str):
    """
    Get the results for a specific V2 test run.
    
    Returns the full JSON data for the specified run ID.
    """
    filepath = f"apiv2/results/runs/{run_id}.json"
    
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail=f"Result not found for run_id: {run_id}")
    
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        return data
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Failed to parse result file")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
#  Delete Result V2
# ============================================================

@router_v2.delete("/results/{run_id}")
async def delete_result_v2(run_id: str):
    """
    Delete a specific V2 test run result.
    
    Permanently removes the result file. This action cannot be undone.
    """
    filepath = f"apiv2/results/runs/{run_id}.json"
    
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail=f"Result not found for run_id: {run_id}")
    
    try:
        os.remove(filepath)
        return {"message": f"Successfully deleted result: {run_id}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
