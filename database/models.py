from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum


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


class SerializableMixin:
    """Provides to_dict/from_dict for MongoDB serialization."""
    _datetime_fields = ('started_at', 'completed_at', 'timestamp')

    def to_dict(self):
        d = asdict(self)
        # convert datetime to ISO string
        for field in self._datetime_fields:
            if val := d.get(field):
                d[field] = val.isoformat() if isinstance(val, datetime) else val
        return d

    @classmethod
    def from_dict(cls, data):
        # filter out mongodb _id field
        return cls(**{k: v for k, v in data.items() if k != '_id'})


# master run record
@dataclass
class RTRun(SerializableMixin):
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


# per-turn result record
@dataclass
class RTResult(SerializableMixin):
    result_id: str  # format: {run_id}:{attack_profile_id}:{session_id}:{turn}
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
    # attack data
    attack_prompt: str
    agent_response: str
    attack_score: float
    attack_result: str
    attack_reasoning: Optional[str] = None
    # vulnerability data
    vulnerability_profile_id: Optional[int] = None
    vulnerability_profile_name: Optional[str] = None
    vulnerability_detected: bool = False
    vulnerability_score: Optional[float] = None
    vulnerability_severity: str = VulnerabilitySeverity.NONE.value
    vulnerability_reasoning: Optional[str] = None
    detected_pii_types: Optional[List[str]] = None
    # mitigations
    attack_mitigation_suggestions: Optional[str] = None
    vulnerability_mitigation_suggestions: Optional[str] = None
    # overall
    overall_result: str = OverallResult.FAIL.value
    result_json: Optional[str] = None


# attack execution tracking (for real-time progress)
@dataclass
class RTAttackExecution(SerializableMixin):
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
    best_score: float = 0.0
    backtrack_count: int = 0


# vulnerability execution tracking
@dataclass
class RTVulnerabilityExecution(SerializableMixin):
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
