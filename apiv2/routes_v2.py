import os
import sys
import json
import traceback
from datetime import datetime
from typing import Generator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import RESULTS_DIR, validate_run_id, get_result_filepath
from apiv2.models_v2 import (
    TestRunRequestV2, HealthResponseV2, TestRunResponseV2,
    TestSummaryV2, ResultFileInfoV2, ResultsListResponseV2,
)
from models.payload_models import RedTeamPayload, VulnerabilityType

router_v2 = APIRouter(prefix="/api/v2", tags=["Testing API V2"])


# Health check
@router_v2.get("/health", response_model=HealthResponseV2)
async def health_check_v2():
    return HealthResponseV2(status="healthy", message="RedTeam V2 API is running", version="2.0.0")


# Sync test execution
@router_v2.post("/test/run", response_model=TestRunResponseV2)
async def run_test_v2(request: TestRunRequestV2):
    from runner_v2 import RedTeamV2
    try:
        runner = RedTeamV2(request.payload)
        run_id, results = runner.run()
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
            artifacts={"json_path": f"results/runs/{run_id}.json", "csv_path": "results/reports/all_results_v2.csv"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# SSE generator for streaming test results
def generate_sse_events_v2(request: TestRunRequestV2) -> Generator[str, None, None]:
    from runner_v2 import RedTeamV2
    try:
        yield f"data: {json.dumps({'type': 'step', 'step': 'initializing', 'message': 'Initializing RedTeam V2 runner...'})}\n\n"
        runner = RedTeamV2(request.payload)
        yield f"data: {json.dumps({'type': 'step', 'step': 'initialized', 'message': f'Runner initialized with LLM: {request.payload.mode_constraints.llm.value}'})}\n\n"
        yield f"data: {json.dumps({'type': 'start', 'payload_id': request.payload.id, 'suite_name': request.payload.meta_data.name, 'total_attacks': len(request.payload.attack_profiles), 'total_vulns': len(request.payload.vulnerability_profiles)})}\n\n"

        all_results = []
        for ap_idx, attack_profile in enumerate(request.payload.attack_profiles, 1):
            yield f"data: {json.dumps({'type': 'step', 'step': 'attack_start', 'message': f'Starting attack {ap_idx}/{len(request.payload.attack_profiles)}: {attack_profile.name}', 'attack_type': attack_profile.attack_type.value})}\n\n"
            yield f"data: {json.dumps({'type': 'step', 'step': 'running_attack', 'message': f'Running {attack_profile.turn_config.turns} turns of jailbreaking...'})}\n\n"
            _, attack_results = runner.run_attack(attack_profile)
            yield f"data: {json.dumps({'type': 'step', 'step': 'attack_complete', 'message': f'Attack completed with {len(attack_results)} results'})}\n\n"

            # evaluate each turn against vuln profiles
            for result_idx, attack_result in enumerate(attack_results, 1):
                turn = attack_result.get("turn", result_idx)
                jb_score = attack_result.get("score", "N/A")
                yield f"data: {json.dumps({'type': 'step', 'step': 'evaluating', 'message': f'Evaluating turn {turn} (JB score: {jb_score})'})}\n\n"

                if request.payload.vulnerability_profiles:
                    vuln_results = []
                    for vuln_profile in request.payload.vulnerability_profiles:
                        yield f"data: {json.dumps({'type': 'step', 'step': 'vuln_check', 'message': f'Checking {vuln_profile.vulnerability_type.value}'})}\n\n"
                        vuln_result = runner.evaluate_vulnerability(
                            attack_result.get("attack_prompt", ""),
                            attack_result.get("agent_response", ""),
                            vuln_profile
                        )
                        vuln_results.append(vuln_result)
                    grouped = runner.merge_turn_with_vulnerabilities(attack_result, vuln_results, attack_profile)
                else:
                    grouped = runner.merge_turn_with_vulnerabilities(attack_result, [], attack_profile)
                all_results.append(grouped)
                yield f"data: {json.dumps({'type': 'turn', 'data': grouped}, default=str)}\n\n"

        # summary
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
        yield f"data: {json.dumps({'type': 'complete', 'message': 'Test completed successfully', 'total_results': len(all_results)})}\n\n"
    except Exception as e:
        yield f"data: {json.dumps({'type': 'error', 'error': str(e), 'traceback': traceback.format_exc()})}\n\n"


# Streaming test execution
@router_v2.post("/test/stream")
async def stream_test_v2(request: TestRunRequestV2):
    return StreamingResponse(
        generate_sse_events_v2(request),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"}
    )


# List all results
@router_v2.get("/results", response_model=ResultsListResponseV2)
async def list_results_v2():
    if not RESULTS_DIR.exists():
        return ResultsListResponseV2(total_count=0, results=[])
    result_files = []
    for filepath in RESULTS_DIR.glob("*.json"):
        stat = filepath.stat()
        run_id = filepath.stem
        payload_id, suite_name = None, None
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                payload_id = data.get("payload", {}).get("_id")
                suite_name = data.get("payload", {}).get("meta_data", {}).get("name")
        except (json.JSONDecodeError, IOError):
            pass
        result_files.append(ResultFileInfoV2(
            run_id=run_id, filename=filepath.name, payload_id=payload_id,
            suite_name=suite_name, created_at=datetime.fromtimestamp(stat.st_mtime).isoformat(),
            size_bytes=stat.st_size
        ))
    result_files.sort(key=lambda x: x.created_at, reverse=True)
    return ResultsListResponseV2(total_count=len(result_files), results=result_files)


# Get specific result (validates run_id to prevent path traversal)
@router_v2.get("/results/{run_id}")
async def get_result_v2(run_id: str):
    if not validate_run_id(run_id):
        raise HTTPException(status_code=400, detail="Invalid run_id format")
    try:
        filepath = get_result_filepath(run_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not filepath.exists():
        raise HTTPException(status_code=404, detail=f"Result not found: {run_id}")
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Failed to parse result file")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Delete result
@router_v2.delete("/results/{run_id}")
async def delete_result_v2(run_id: str):
    if not validate_run_id(run_id):
        raise HTTPException(status_code=400, detail="Invalid run_id format")
    try:
        filepath = get_result_filepath(run_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not filepath.exists():
        raise HTTPException(status_code=404, detail=f"Result not found: {run_id}")
    try:
        filepath.unlink()
        return {"message": f"Deleted: {run_id}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
