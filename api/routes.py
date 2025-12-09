# api/routes.py
"""
API routes for the vulnerability testing system.
Provides endpoints for running tests, streaming results, and retrieving test history.
"""

import os
import sys
import json
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Generator

from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.models import (
    TestRunRequest,
    AttackOnlyRequest,
    HealthResponse,
    VulnerabilityInfo,
    VulnerabilitySubtype,
    VulnerabilitiesResponse,
    AttackInfo,
    AttacksResponse,
    TestRunResponse,
    TestSummaryStats,
    ResultFileInfo,
    ResultsListResponse,
    ErrorResponse,
    VulnerabilityType
)

# Create API router
router = APIRouter(prefix="/api", tags=["Testing API"])


# ============================================================
#  Health Check
# ============================================================

@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Check if the API is running and healthy."""
    return HealthResponse(status="healthy", message="Vulnerability Testing API is running")


# ============================================================
#  List Available Vulnerabilities
# ============================================================

@router.get("/vulnerabilities", response_model=VulnerabilitiesResponse)
async def list_vulnerabilities():
    """
    List all available vulnerability types.
    
    Note: Prompts are now provided via payload (custom_prompts field).
    No default hardcoded prompts are used.
    """
    vulnerabilities = [
        VulnerabilityInfo(
            name="PII Leakage",
            type_key="pii_leakage",
            description="Tests for exposure of personally identifiable information (PII). Prompts provided via custom_prompts in payload.",
            subtypes=[]
        ),
        VulnerabilityInfo(
            name="BOLA (Broken Object Level Authorization)",
            type_key="bola",
            description="Tests for unauthorized access to objects/resources. Prompts provided via custom_prompts in payload.",
            subtypes=[]
        ),
        VulnerabilityInfo(
            name="Prompt Leakage",
            type_key="prompt_leakage",
            description="Tests for exposure of system prompts and internal configurations. Prompts provided via custom_prompts in payload.",
            subtypes=[]
        )
    ]
    
    return VulnerabilitiesResponse(vulnerabilities=vulnerabilities)


# ============================================================
#  List Available Attacks
# ============================================================

@router.get("/attacks", response_model=AttacksResponse)
async def list_attacks():
    """
    List all available attack methods.
    
    Currently supports:
    - Linear Jailbreaking: Iterative prompt refinement to bypass AI safeguards
    """
    attacks = [
        AttackInfo(
            name="Linear Jailbreaking",
            description="Iterative attack that refines prompts turn-by-turn to bypass AI safety measures. Uses LLM-based improvement and scoring.",
            parameters={
                "turns": "Number of attack iterations (1-10)",
                "penalized_phrases": "List of phrases that reduce scores if detected",
                "mitigation_threshold": "Score threshold for generating mitigations (0.0-1.0)"
            }
        )
    ]
    
    return AttacksResponse(attacks=attacks)


# ============================================================
#  Run Attack Only (No Vulnerability Evaluation)
# ============================================================

@router.post("/attack/run")
async def run_attack_only(request: AttackOnlyRequest):
    """
    Execute a jailbreaking attack WITHOUT vulnerability evaluation.
    
    This endpoint runs only the jailbreaking attack, which is faster than
    the full test. Use this when you want to test prompt injection/jailbreaking
    without checking for specific vulnerabilities like PII or BOLA.
    
    **Example Request:**
    ```json
    {
        "initial_prompt": "What is John Smith's email address?",
        "turns": 3,
        "agent_timeout_secs": 10
    }
    ```
    
    **Response includes:**
    - Attack prompts generated for each turn
    - Agent responses
    - Jailbreak success scores
    - Reasoning for each turn
    """
    from attacks.linear_jailbreaking import LinearJailbreakingRunner
    
    try:
        # Initialize attack runner
        runner = LinearJailbreakingRunner()
        
        # Build payload
        payload = {
            "agent": {
                "timeout_secs": request.agent_timeout_secs
            },
            "turns": request.turns,
            "session_id": request.session_id,
            "penalized_phrases": request.penalized_phrases,
            "initial_attack_prompt": request.initial_prompt
        }
        
        # Run the attack
        run_id, results = runner.run(payload)
        
        # Calculate summary
        success_count = sum(1 for r in results if r.get("attack_result") == "Success")
        valid_scores = [r.get("score") for r in results if r.get("score") is not None]
        
        return {
            "run_id": run_id,
            "attack_type": "linear_jailbreaking",
            "initial_prompt": request.initial_prompt,
            "turns_completed": len(results),
            "summary": {
                "success_count": success_count,
                "success_rate": f"{success_count/len(results)*100:.1f}%" if results else "0%",
                "avg_score": round(sum(valid_scores)/len(valid_scores), 2) if valid_scores else 0,
                "max_score": round(max(valid_scores), 2) if valid_scores else 0
            },
            "results": results
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
#  Run Test (Synchronous)
# ============================================================

@router.post("/test/run", response_model=TestRunResponse)
async def run_test(request: TestRunRequest):
    """
    Execute a complete vulnerability test run.
    
    This endpoint runs the full test synchronously and returns all results
    once complete. For real-time updates, use the `/test/stream` endpoint.
    
    The test combines jailbreaking attacks with vulnerability evaluation to
    assess the security of your AI agent.
    """
    from vulnerabilities.pii_leakage import PIILeakage
    from vulnerabilities.bola import BOLA
    from vulnerabilities.prompt_leakage import PromptLeakage
    from attacks.linear_jailbreaking import LinearJailbreakingRunner
    from runner import RedTeam
    
    try:
        # Initialize vulnerability based on type
        if request.vulnerability_type == VulnerabilityType.PII_LEAKAGE:
            vulnerability = PIILeakage(
                types=request.vulnerability_subtypes if request.vulnerability_subtypes else None
            )
        elif request.vulnerability_type == VulnerabilityType.BOLA:
            vulnerability = BOLA(
                types=request.vulnerability_subtypes if request.vulnerability_subtypes else None
            )
        elif request.vulnerability_type == VulnerabilityType.PROMPT_LEAKAGE:
            vulnerability = PromptLeakage(
                types=request.vulnerability_subtypes if request.vulnerability_subtypes else None
            )
        else:
            raise HTTPException(status_code=400, detail=f"Unknown vulnerability type: {request.vulnerability_type}")
        
        # Initialize attack
        attack = LinearJailbreakingRunner()
        
        # Initialize RedTeam runner
        red_team = RedTeam(vulnerability=vulnerability, attack=attack)
        
        # Build payload
        payload = {
            "agent": {
                "timeout_secs": request.agent_timeout_secs
            },
            "turns": request.turns,
            "session_id": request.session_id,
            "penalized_phrases": request.penalized_phrases,
            "mitigation_threshold": request.mitigation_threshold,
            # Custom prompts from payload (REQUIRED)
            "custom_prompts": request.custom_prompts
        }
        
        # Run the test (this blocks until complete)
        run_id, results = red_team.run(payload)
        
        # Calculate summary statistics
        vuln_key = request.vulnerability_type.value
        
        jailbreak_success = sum(1 for r in results if r.get("jailbreak_result") == "Success")
        vuln_detected = sum(1 for r in results if r.get(f"{vuln_key}_vulnerable", False))
        
        valid_jb_scores = [r.get("jailbreak_score") for r in results if r.get("jailbreak_score") is not None]
        valid_vuln_scores = [r.get(f"{vuln_key}_score") for r in results if r.get(f"{vuln_key}_score") is not None]
        
        critical_count = sum(1 for r in results if "CRITICAL" in r.get("overall_result", ""))
        high_count = sum(1 for r in results if "HIGH" in r.get("overall_result", ""))
        medium_count = sum(1 for r in results if "MEDIUM" in r.get("overall_result", ""))
        pass_count = sum(1 for r in results if "PASS" in r.get("overall_result", ""))
        
        summary = TestSummaryStats(
            total_tests=len(results),
            jailbreak_success_count=jailbreak_success,
            jailbreak_success_rate=f"{jailbreak_success/len(results)*100:.1f}%" if results else "0%",
            avg_jailbreak_score=round(sum(valid_jb_scores)/len(valid_jb_scores), 2) if valid_jb_scores else 0,
            max_jailbreak_score=round(max(valid_jb_scores), 2) if valid_jb_scores else 0,
            vulnerability_count=vuln_detected,
            vulnerability_rate=f"{vuln_detected/len(results)*100:.1f}%" if results else "0%",
            avg_vulnerability_score=round(sum(valid_vuln_scores)/len(valid_vuln_scores), 2) if valid_vuln_scores else 0,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            pass_count=pass_count
        )
        
        return TestRunResponse(
            run_id=run_id,
            vulnerability_type=request.vulnerability_type.value,
            summary=summary,
            results=results,
            artifacts={
                "json_path": f"results/runs/{run_id}.json",
                "csv_path": "results/reports/all_results.csv"
            }
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
#  Run Test with Streaming (Server-Sent Events)
# ============================================================

def generate_sse_events(request: TestRunRequest) -> Generator[str, None, None]:
    """Generator function that yields SSE events for streaming test results."""
    from vulnerabilities.pii_leakage import PIILeakage
    from vulnerabilities.bola import BOLA
    from vulnerabilities.prompt_leakage import PromptLeakage
    from attacks.linear_jailbreaking import LinearJailbreakingRunner
    from runner import RedTeam
    
    try:
        # Initialize vulnerability based on type
        if request.vulnerability_type == VulnerabilityType.PII_LEAKAGE:
            vulnerability = PIILeakage(
                types=request.vulnerability_subtypes if request.vulnerability_subtypes else None
            )
        elif request.vulnerability_type == VulnerabilityType.BOLA:
            vulnerability = BOLA(
                types=request.vulnerability_subtypes if request.vulnerability_subtypes else None
            )
        elif request.vulnerability_type == VulnerabilityType.PROMPT_LEAKAGE:
            vulnerability = PromptLeakage(
                types=request.vulnerability_subtypes if request.vulnerability_subtypes else None
            )
        else:
            yield f"data: {json.dumps({'type': 'error', 'data': {'error': f'Unknown vulnerability type: {request.vulnerability_type}'}})}\n\n"
            return
        
        # Initialize attack
        attack = LinearJailbreakingRunner()
        
        # Initialize RedTeam runner
        red_team = RedTeam(vulnerability=vulnerability, attack=attack)
        
        # Build payload
        payload = {
            "agent": {
                "timeout_secs": request.agent_timeout_secs
            },
            "turns": request.turns,
            "session_id": request.session_id,
            "penalized_phrases": request.penalized_phrases,
            "mitigation_threshold": request.mitigation_threshold,
            # Custom prompts from payload (REQUIRED)
            "custom_prompts": request.custom_prompts
        }
        
        # Send start event
        yield f"data: {json.dumps({'type': 'start', 'data': {'message': 'Test started', 'vulnerability_type': request.vulnerability_type.value}})}\n\n"
        
        # Stream results using iter_run
        for event in red_team.iter_run(payload):
            # Convert to SSE format
            yield f"data: {json.dumps(event, default=str)}\n\n"
        
        # Send completion event
        yield f"data: {json.dumps({'type': 'complete', 'data': {'message': 'Test completed'}})}\n\n"
        
    except Exception as e:
        yield f"data: {json.dumps({'type': 'error', 'data': {'error': str(e)}})}\n\n"


@router.post("/test/stream")
async def stream_test(request: TestRunRequest):
    """
    Execute a vulnerability test with real-time streaming results.
    
    Returns Server-Sent Events (SSE) with the following event types:
    - `start`: Test has begun
    - `turn`: Individual turn result with attack and vulnerability data
    - `prompt_complete`: A base prompt's turns have all completed
    - `summary`: Final summary with statistics
    - `complete`: Test has finished
    - `error`: An error occurred
    
    Use EventSource in JavaScript to consume this endpoint:
    ```javascript
    const eventSource = new EventSource('/api/test/stream');
    eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data);
        console.log(data);
    };
    ```
    """
    return StreamingResponse(
        generate_sse_events(request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


# ============================================================
#  List Results
# ============================================================

@router.get("/results", response_model=ResultsListResponse)
async def list_results():
    """
    List all saved test run results.
    
    Returns a list of available result files with metadata including
    run ID, filename, creation time, and file size.
    """
    results_dir = "results/runs"
    
    if not os.path.exists(results_dir):
        return ResultsListResponse(total_count=0, results=[])
    
    result_files = []
    for filename in os.listdir(results_dir):
        if filename.endswith(".json"):
            filepath = os.path.join(results_dir, filename)
            stat = os.stat(filepath)
            
            # Extract run_id from filename (remove .json extension)
            run_id = filename[:-5]
            
            result_files.append(ResultFileInfo(
                run_id=run_id,
                filename=filename,
                created_at=datetime.fromtimestamp(stat.st_mtime).isoformat(),
                size_bytes=stat.st_size
            ))
    
    # Sort by creation time, newest first
    result_files.sort(key=lambda x: x.created_at, reverse=True)
    
    return ResultsListResponse(total_count=len(result_files), results=result_files)


# ============================================================
#  Get Specific Result
# ============================================================

@router.get("/results/{run_id}")
async def get_result(run_id: str):
    """
    Get the results for a specific test run.
    
    Returns the full JSON data for the specified run ID.
    """
    filepath = f"results/runs/{run_id}.json"
    
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
#  Delete Result
# ============================================================

@router.delete("/results/{run_id}")
async def delete_result(run_id: str):
    """
    Delete a specific test run result.
    
    Permanently removes the result file. This action cannot be undone.
    """
    filepath = f"results/runs/{run_id}.json"
    
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail=f"Result not found for run_id: {run_id}")
    
    try:
        os.remove(filepath)
        return {"message": f"Successfully deleted result: {run_id}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
