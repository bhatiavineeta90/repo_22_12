import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from database.mongo_service import MongoDBService, get_db, generate_result_id
from database.models import (
    RTRun,
    RTResult,
    RTAttackExecution,
    RTVulnerabilityExecution,
    RunStatus,
    OverallResult,
    JailbreakResult,
    VulnerabilitySeverity,
)


class StorageHelper:
    """
    Helper class for storing attack results during execution.
    Designed to be used by attack runners (LinearJailbreaking, Crescendo, etc.)
    """
    
    def __init__(self, db: MongoDBService = None):
        self.db = db or get_db()
        
    @property
    def enabled(self) -> bool:
        """Check if storage is enabled (MongoDB connected)."""
        return self.db and self.db.is_connected()
    
     
    #  Run Management
     
    
    def start_run(
        self,
        run_id: str,
        payload_id: str,
        payload_name: str,
        llm_model: str = "gemini-2.5-flash",
        temperature: float = 0.7,
        attack_profiles: List[Dict] = None,
        vulnerability_profiles: List[Dict] = None,
    ) -> bool:
        """
        Start a new test run. Call this before executing attacks.
        
        Returns True if successfully saved, False otherwise.
        """
        if not self.enabled:
            return False
        
        # Create main run record
        run = RTRun(
            run_id=run_id,
            payload_id=payload_id,
            payload_name=payload_name,
            status=RunStatus.RUNNING.value,
            started_at=datetime.now(timezone.utc),
            llm_model=llm_model,
            temperature=temperature,
            total_attack_profiles=len(attack_profiles or []),
            total_vuln_profiles=len(vulnerability_profiles or []),
        )
        self.db.create_run(run)
        
        # Create attack execution records
        for profile in (attack_profiles or []):
            attack_exec = RTAttackExecution(
                run_id=run_id,
                attack_profile_id=profile.get("id", 0),
                attack_name=profile.get("name", ""),
                attack_type=profile.get("attack_type", ""),
                planned_turns=profile.get("turn_config", {}).get("turns", 10),
                status=RunStatus.PENDING.value,
            )
            self.db.create_attack_execution(attack_exec)
        
        # Create vulnerability execution records
        for profile in (vulnerability_profiles or []):
            vuln_exec = RTVulnerabilityExecution(
                run_id=run_id,
                vulnerability_profile_id=profile.get("id", 0),
                vulnerability_name=profile.get("name", ""),
                vulnerability_type=profile.get("vulnerability_type", ""),
                status=RunStatus.PENDING.value,
            )
            self.db.create_vulnerability_execution(vuln_exec)
        
        print(f"📊 Run {run_id} started - storing results to MongoDB")
        return True
    
    def complete_run(
        self,
        run_id: str,
        overall_success_rate: float = None,
        overall_risk_level: str = None,
    ) -> bool:
        """Mark run as completed."""
        if not self.enabled:
            return False
            
        return self.db.update_run_status(
            run_id=run_id,
            status=RunStatus.COMPLETED.value,
            completed_at=datetime.now(timezone.utc),
            overall_success_rate=overall_success_rate,
            overall_risk_level=overall_risk_level,
        )
    
    def fail_run(self, run_id: str, error: str) -> bool:
        """Mark run as failed."""
        if not self.enabled:
            return False
            
        return self.db.update_run_status(
            run_id=run_id,
            status=RunStatus.FAILED.value,
            completed_at=datetime.now(timezone.utc),
            error=error,
        )
    
     
    #  Attack Execution Tracking
     
    
    def start_attack(self, run_id: str, attack_profile_id: int) -> bool:
        """Mark attack as started. Call before running attack."""
        if not self.enabled:
            return False
            
        return self.db.update_attack_progress(
            run_id=run_id,
            attack_profile_id=attack_profile_id,
            status=RunStatus.RUNNING.value,
        )
    
    def complete_attack(
        self,
        run_id: str,
        attack_profile_id: int,
        success_turns: int = 0,
        best_score: float = 0,
    ) -> bool:
        """Mark attack as completed."""
        if not self.enabled:
            return False
            
        return self.db.update_attack_progress(
            run_id=run_id,
            attack_profile_id=attack_profile_id,
            status=RunStatus.COMPLETED.value,
            completed_at=datetime.now(timezone.utc),
            success_turns=success_turns,
            best_score=best_score,
        )
    
     
    #  Per-Turn Result Saving
     
    
    def save_turn_result(
        self,
        run_id: str,
        payload_id: str,
        attack_profile_id: int,
        attack_profile_name: str,
        attack_type: str,
        session_id: str,
        turn: int,
        llm_provider: str,
        temperature: float,
        attack_prompt: str,
        agent_response: str,
        jailbreak_score: float,
        jailbreak_result: str,
        jailbreak_reasoning: str = None,
        # Vulnerability fields (optional)
        vulnerability_profile_id: int = None,
        vulnerability_profile_name: str = None,
        vulnerability_detected: bool = False,
        vulnerability_score: float = None,
        vulnerability_severity: str = None,
        vulnerability_reasoning: str = None,
        detected_pii_types: List[str] = None,
        # Overall
        overall_result: str = None,
        raw_result: Dict = None,
        # Crescendo-specific
        backtrack_count: int = None,
    ) -> bool:
        """
        Save a single turn result. Call this after each turn completes.
        Also updates attack execution progress automatically.
        """
        if not self.enabled:
            return False
        
        # Generate deterministic result ID
        result_id = generate_result_id(run_id, attack_profile_id, session_id, turn)
        
        # Determine overall result
        if overall_result is None:
            if jailbreak_result == JailbreakResult.SUCCESS.value:
                overall_result = OverallResult.HIGH.value
            elif jailbreak_result == JailbreakResult.PARTIAL.value:
                overall_result = OverallResult.MEDIUM.value
            else:
                overall_result = OverallResult.FAIL.value
        
        # Create result record
        result = RTResult(
            result_id=result_id,
            run_id=run_id,
            payload_id=payload_id,
            attack_profile_id=attack_profile_id,
            attack_profile_name=attack_profile_name,
            attack_type=attack_type,
            session_id=session_id,
            turn=turn,
            timestamp=datetime.now(timezone.utc),
            llm_provider=llm_provider,
            temperature=temperature,
            attack_prompt=attack_prompt,
            agent_response=agent_response,
            jailbreak_score=jailbreak_score,
            jailbreak_result=jailbreak_result,
            jailbreak_reasoning=jailbreak_reasoning,
            vulnerability_profile_id=vulnerability_profile_id,
            vulnerability_profile_name=vulnerability_profile_name,
            vulnerability_detected=vulnerability_detected,
            vulnerability_score=vulnerability_score,
            vulnerability_severity=vulnerability_severity or VulnerabilitySeverity.NONE.value,
            vulnerability_reasoning=vulnerability_reasoning,
            detected_pii_types=detected_pii_types,
            overall_result=overall_result,
            result_json=json.dumps(raw_result) if raw_result else None,
        )
        
        # Save result
        saved = self.db.insert_result(result)
        
        # Update attack execution progress
        if saved:
            is_success = jailbreak_result == JailbreakResult.SUCCESS.value
            
            # Get current execution to increment counts
            exec_doc = self.db.get_attack_execution(run_id, attack_profile_id)
            if exec_doc:
                current_turns = exec_doc.get("turns_completed", 0)
                current_successes = exec_doc.get("success_turns", 0)
                current_best = exec_doc.get("best_score", 0)
                current_backtracks = exec_doc.get("backtrack_count", 0)
                
                update_kwargs = {
                    "turns_completed": current_turns + 1,
                    "last_turn_written": turn,
                    "best_score": max(current_best, jailbreak_score),
                }
                
                if is_success:
                    update_kwargs["success_turns"] = current_successes + 1
                
                if backtrack_count is not None:
                    update_kwargs["backtrack_count"] = backtrack_count
                
                self.db.update_attack_progress(
                    run_id=run_id,
                    attack_profile_id=attack_profile_id,
                    **update_kwargs
                )
        
        return saved
    
     
    #  Vulnerability Tracking
     
    
    def start_vulnerability_check(self, run_id: str, vulnerability_profile_id: int) -> bool:
        """Mark vulnerability check as started."""
        if not self.enabled:
            return False
            
        return self.db.update_vulnerability_progress(
            run_id=run_id,
            vulnerability_profile_id=vulnerability_profile_id,
            status=RunStatus.RUNNING.value,
        )
    
    def update_vulnerability_findings(
        self,
        run_id: str,
        vulnerability_profile_id: int,
        findings_count: int,
        highest_severity: str,
        checks_completed: int = None,
    ) -> bool:
        """Update vulnerability findings count."""
        if not self.enabled:
            return False
            
        return self.db.update_vulnerability_progress(
            run_id=run_id,
            vulnerability_profile_id=vulnerability_profile_id,
            findings_count=findings_count,
            highest_severity=highest_severity,
            checks_completed=checks_completed,
        )
    
    def complete_vulnerability_check(
        self,
        run_id: str,
        vulnerability_profile_id: int,
        findings_count: int = 0,
        highest_severity: str = None,
    ) -> bool:
        """Mark vulnerability check as completed."""
        if not self.enabled:
            return False
            
        return self.db.update_vulnerability_progress(
            run_id=run_id,
            vulnerability_profile_id=vulnerability_profile_id,
            status=RunStatus.COMPLETED.value,
            completed_at=datetime.now(timezone.utc),
            findings_count=findings_count,
            highest_severity=highest_severity or VulnerabilitySeverity.NONE.value,
        )


_storage_helper: Optional[StorageHelper] = None


def get_storage() -> StorageHelper:
    """Get or create storage helper instance."""
    global _storage_helper
    if _storage_helper is None:
        _storage_helper = StorageHelper()
    return _storage_helper
