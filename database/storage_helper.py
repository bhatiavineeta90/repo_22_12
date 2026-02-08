import json
from datetime import datetime, timezone
from functools import lru_cache
from typing import Dict, List, Optional

from database.mongo_service import MongoDBService, get_db, generate_result_id
from database.models import (
    RTRun, RTResult, RTAttackExecution, RTVulnerabilityExecution,
    RunStatus, OverallResult, AttackResult, VulnerabilitySeverity,
)


class StorageHelper:
    """High-level wrapper for storing test results to MongoDB."""

    def __init__(self, db: MongoDBService = None):
        self.db = db or get_db()

    @property
    def enabled(self):
        return self.db and self.db.is_connected()

    def start_run(self, run_id, payload_id, payload_name, llm_model="gemini-2.5-flash",
                  temperature=0.7, attack_profiles=None, vulnerability_profiles=None):
        if not self.enabled:
            return False
        attack_profiles = attack_profiles or []
        vulnerability_profiles = vulnerability_profiles or []

        run = RTRun(
            run_id=run_id, payload_id=payload_id, payload_name=payload_name,
            status=RunStatus.RUNNING.value, started_at=datetime.now(timezone.utc),
            llm_model=llm_model, temperature=temperature,
            total_attack_profiles=len(attack_profiles),
            total_vuln_profiles=len(vulnerability_profiles),
        )
        self.db.create_run(run)

        # create execution records for tracking progress
        for p in attack_profiles:
            self.db.create_attack_execution(RTAttackExecution(
                run_id=run_id, attack_profile_id=p.get("id", 0),
                attack_name=p.get("name", ""), attack_type=p.get("attack_type", ""),
                planned_turns=p.get("turn_config", {}).get("turns", 10),
                status=RunStatus.PENDING.value,
            ))

        for p in vulnerability_profiles:
            self.db.create_vulnerability_execution(RTVulnerabilityExecution(
                run_id=run_id, vulnerability_profile_id=p.get("id", 0),
                vulnerability_name=p.get("name", ""), vulnerability_type=p.get("vulnerability_type", ""),
                status=RunStatus.PENDING.value,
            ))

        print(f"Run {run_id} started - storing to MongoDB")
        return True

    def complete_run(self, run_id, overall_success_rate=None, overall_risk_level=None):
        if not self.enabled:
            return False
        return self.db.update_run_status(
            run_id=run_id, status=RunStatus.COMPLETED.value,
            completed_at=datetime.now(timezone.utc),
            overall_success_rate=overall_success_rate, overall_risk_level=overall_risk_level,
        )

    def fail_run(self, run_id, error):
        if not self.enabled:
            return False
        return self.db.update_run_status(
            run_id=run_id, status=RunStatus.FAILED.value,
            completed_at=datetime.now(timezone.utc), error=error,
        )

    def start_attack(self, run_id, attack_profile_id):
        if not self.enabled:
            return False
        return self.db.update_attack_progress(run_id=run_id, attack_profile_id=attack_profile_id,
                                              status=RunStatus.RUNNING.value)

    def complete_attack(self, run_id, attack_profile_id, success_turns=0, best_score=0):
        if not self.enabled:
            return False
        return self.db.update_attack_progress(
            run_id=run_id, attack_profile_id=attack_profile_id,
            status=RunStatus.COMPLETED.value, completed_at=datetime.now(timezone.utc),
            success_turns=success_turns, best_score=best_score,
        )

    def save_turn_result(self, run_id, payload_id, attack_profile_id, attack_profile_name,
                         attack_type, session_id, turn, llm_provider, temperature,
                         attack_prompt, agent_response, attack_score, attack_result,
                         attack_reasoning=None, vulnerability_profile_id=None,
                         vulnerability_profile_name=None, vulnerability_detected=False,
                         vulnerability_score=None, vulnerability_severity=None,
                         vulnerability_reasoning=None, detected_pii_types=None,
                         overall_result=None, raw_result=None, backtrack_count=None,
                         attack_mitigation_suggestions=None, vulnerability_mitigation_suggestions=None):
        if not self.enabled:
            return False

        result_id = generate_result_id(run_id, attack_profile_id, session_id, turn)

        # auto-determine overall result if not provided
        if overall_result is None:
            if attack_result == AttackResult.SUCCESS.value:
                overall_result = OverallResult.HIGH.value
            elif attack_result == AttackResult.PARTIAL.value:
                overall_result = OverallResult.MEDIUM.value
            else:
                overall_result = OverallResult.FAIL.value

        result = RTResult(
            result_id=result_id, run_id=run_id, payload_id=payload_id,
            attack_profile_id=attack_profile_id, attack_profile_name=attack_profile_name,
            attack_type=attack_type, session_id=session_id, turn=turn,
            timestamp=datetime.now(timezone.utc), llm_provider=llm_provider,
            temperature=temperature, attack_prompt=attack_prompt,
            agent_response=agent_response, attack_score=attack_score,
            attack_result=attack_result, attack_reasoning=attack_reasoning,
            vulnerability_profile_id=vulnerability_profile_id,
            vulnerability_profile_name=vulnerability_profile_name,
            vulnerability_detected=vulnerability_detected,
            vulnerability_score=vulnerability_score,
            vulnerability_severity=vulnerability_severity or VulnerabilitySeverity.NONE.value,
            vulnerability_reasoning=vulnerability_reasoning,
            detected_pii_types=detected_pii_types,
            attack_mitigation_suggestions=attack_mitigation_suggestions,
            vulnerability_mitigation_suggestions=vulnerability_mitigation_suggestions,
            overall_result=overall_result,
            result_json=json.dumps(raw_result) if raw_result else None,
        )

        saved = self.db.insert_result(result)

        # update attack execution progress
        if saved:
            exec_doc = self.db.get_attack_execution(run_id, attack_profile_id)
            if exec_doc:
                update_kwargs = {
                    "turns_completed": exec_doc.get("turns_completed", 0) + 1,
                    "last_turn_written": turn,
                    "best_score": max(exec_doc.get("best_score", 0), attack_score),
                }
                if attack_result == AttackResult.SUCCESS.value:
                    update_kwargs["success_turns"] = exec_doc.get("success_turns", 0) + 1
                if backtrack_count is not None:
                    update_kwargs["backtrack_count"] = backtrack_count
                self.db.update_attack_progress(run_id=run_id, attack_profile_id=attack_profile_id, **update_kwargs)

        return saved

    def start_vulnerability_check(self, run_id, vulnerability_profile_id):
        if not self.enabled:
            return False
        return self.db.update_vulnerability_progress(
            run_id=run_id, vulnerability_profile_id=vulnerability_profile_id,
            status=RunStatus.RUNNING.value,
        )

    def update_vulnerability_findings(self, run_id, vulnerability_profile_id, findings_count,
                                       highest_severity, checks_completed=None):
        if not self.enabled:
            return False
        return self.db.update_vulnerability_progress(
            run_id=run_id, vulnerability_profile_id=vulnerability_profile_id,
            findings_count=findings_count, highest_severity=highest_severity,
            checks_completed=checks_completed,
        )

    def complete_vulnerability_check(self, run_id, vulnerability_profile_id,
                                      findings_count=0, highest_severity=None):
        if not self.enabled:
            return False
        return self.db.update_vulnerability_progress(
            run_id=run_id, vulnerability_profile_id=vulnerability_profile_id,
            status=RunStatus.COMPLETED.value, completed_at=datetime.now(timezone.utc),
            findings_count=findings_count,
            highest_severity=highest_severity or VulnerabilitySeverity.NONE.value,
        )


@lru_cache(maxsize=1)
def get_storage():
    return StorageHelper()
