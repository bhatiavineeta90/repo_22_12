from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from enum import Enum
import json


class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class OverallResult(str, Enum):
    PASS = "PASS"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    FAIL = "FAIL"


class AttackResult(str, Enum):
    SUCCESS = "Success"
    PARTIAL = "Partial"
    FAIL = "Fail"
    REFUSED = "Refused"


class VulnerabilitySeverity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


 
#  rt_runs - Master Run Record
 

@dataclass
class RTRun:
    """Master run record - tracks overall execution."""
    run_id: str
    payload_id: str
    payload_name: str
    status: str = RunStatus.PENDING.value
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    llm_model: str = ""
    temperature: float = 0.7
    total_attack_profiles: int = 0
    total_vuln_profiles: int = 0
    overall_success_rate: Optional[float] = None
    overall_risk_level: Optional[str] = None
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Convert datetime to ISO format for MongoDB
        if d.get('started_at'):
            d['started_at'] = d['started_at'].isoformat() if isinstance(d['started_at'], datetime) else d['started_at']
        if d.get('completed_at'):
            d['completed_at'] = d['completed_at'].isoformat() if isinstance(d['completed_at'], datetime) else d['completed_at']
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RTRun":
        return cls(**{k: v for k, v in data.items() if k != '_id'})


 
#  rt_results - Per-Turn Results
 

@dataclass
class RTResult:
    """Individual turn result - stores attack and vulnerability data per turn."""
    result_id: str  # Deterministic: {run_id}:{attack_profile_id}:{session_id}:{turn}
    run_id: str
    payload_id: str
    attack_profile_id: int
    attack_profile_name: str
    attack_type: str
    session_id: str
    turn: int
    timestamp: datetime
    llm_provider: str
    temperature: float
    
    # Attack data
    attack_prompt: str
    agent_response: str
    attack_score: float
    attack_result: str  # Success/Fail/Refused
    attack_reasoning: Optional[str] = None
    
    # Vulnerability data
    vulnerability_profile_id: Optional[int] = None
    vulnerability_profile_name: Optional[str] = None
    vulnerability_detected: bool = False
    vulnerability_score: Optional[float] = None
    vulnerability_severity: str = VulnerabilitySeverity.NONE.value
    vulnerability_reasoning: Optional[str] = None
    detected_pii_types: Optional[List[str]] = None
    
    # Overall
    overall_result: str = OverallResult.FAIL.value
    result_json: Optional[str] = None  # Full raw result object
    
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if d.get('timestamp'):
            d['timestamp'] = d['timestamp'].isoformat() if isinstance(d['timestamp'], datetime) else d['timestamp']
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RTResult":
        return cls(**{k: v for k, v in data.items() if k != '_id'})


 
#  rt_attack_execution - Attack Progress Tracking
 

@dataclass
class RTAttackExecution:
    """Attack execution status - for real-time progress tracking."""
    run_id: str
    attack_profile_id: int
    attack_name: str
    attack_type: str
    planned_turns: int
    status: str = RunStatus.PENDING.value
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    turns_completed: int = 0
    success_turns: int = 0
    last_turn_written: Optional[int] = None
    last_error: Optional[str] = None
    
    # Additional stats
    best_score: float = 0.0
    backtrack_count: int = 0  # For Crescendo
    
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if d.get('started_at'):
            d['started_at'] = d['started_at'].isoformat() if isinstance(d['started_at'], datetime) else d['started_at']
        if d.get('completed_at'):
            d['completed_at'] = d['completed_at'].isoformat() if isinstance(d['completed_at'], datetime) else d['completed_at']
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RTAttackExecution":
        return cls(**{k: v for k, v in data.items() if k != '_id'})


 
#  rt_vulnerability_execution - Vulnerability Check Tracking
 

@dataclass
class RTVulnerabilityExecution:
    """Vulnerability execution status - for real-time progress tracking."""
    run_id: str
    vulnerability_profile_id: int
    vulnerability_name: str
    vulnerability_type: str
    status: str = RunStatus.PENDING.value
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    checks_completed: int = 0
    findings_count: int = 0
    highest_severity: str = VulnerabilitySeverity.NONE.value
    last_error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if d.get('started_at'):
            d['started_at'] = d['started_at'].isoformat() if isinstance(d['started_at'], datetime) else d['started_at']
        if d.get('completed_at'):
            d['completed_at'] = d['completed_at'].isoformat() if isinstance(d['completed_at'], datetime) else d['completed_at']
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RTVulnerabilityExecution":
        return cls(**{k: v for k, v in data.items() if k != '_id'})
