# database/mongo_service.py
"""
MongoDB Service for Red Team Testing.
Handles all database operations with real-time status updates.
"""

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import json

from database.models import (
    RTRun,
    RTResult,
    RTAttackExecution,
    RTVulnerabilityExecution,
    RunStatus,
    OverallResult,
    VulnerabilitySeverity,
)


# Default configuration
DEFAULT_MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
DEFAULT_DB_NAME = os.environ.get("MONGO_DB_NAME", "redteam")


class MongoDBService:
    """
    MongoDB service for storing and retrieving red team test results.
    Supports real-time status updates during attack execution.
    """
    
    # Collection names matching user's schema
    COLLECTION_RUNS = "rt_runs"
    COLLECTION_RESULTS = "rt_results"
    COLLECTION_ATTACK_EXECUTION = "rt_attack_execution"
    COLLECTION_VULN_EXECUTION = "rt_vulnerability_execution"
    
    def __init__(
        self,
        mongo_uri: str = None,
        db_name: str = None,
        auto_connect: bool = True,
    ):
        self.mongo_uri = mongo_uri or DEFAULT_MONGO_URI
        self.db_name = db_name or DEFAULT_DB_NAME
        self.client: Optional[MongoClient] = None
        self.db = None
        self._connected = False
        
        if auto_connect:
            self.connect()
    
    # ============================================================
    #  Connection Management
    # ============================================================
    
    def connect(self) -> bool:
        """Connect to MongoDB server."""
        try:
            self.client = MongoClient(
                self.mongo_uri,
                serverSelectionTimeoutMS=5000,
            )
            # Verify connection
            self.client.admin.command('ping')
            self.db = self.client[self.db_name]
            self._connected = True
            print(f"✅ Connected to MongoDB: {self.db_name}")
            
            # Create indexes for optimal query performance
            self._create_indexes()
            return True
            
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            print(f"❌ MongoDB connection failed: {e}")
            self._connected = False
            return False
        except Exception as e:
            print(f"❌ MongoDB error: {e}")
            self._connected = False
            return False
    
    def disconnect(self):
        """Close MongoDB connection."""
        if self.client:
            self.client.close()
            self._connected = False
            print("🔌 MongoDB connection closed")
    
    def is_connected(self) -> bool:
        """Check if connected to MongoDB."""
        return self._connected
    
    def _create_indexes(self):
        """Create indexes for optimal query performance."""
        try:
            # rt_runs indexes
            self.db[self.COLLECTION_RUNS].create_index("run_id", unique=True)
            self.db[self.COLLECTION_RUNS].create_index([("status", ASCENDING), ("started_at", DESCENDING)])
            
            # rt_results indexes
            self.db[self.COLLECTION_RESULTS].create_index("result_id", unique=True)
            self.db[self.COLLECTION_RESULTS].create_index([("run_id", ASCENDING), ("turn", ASCENDING)])
            self.db[self.COLLECTION_RESULTS].create_index([("run_id", ASCENDING), ("attack_profile_id", ASCENDING)])
            
            # rt_attack_execution indexes
            self.db[self.COLLECTION_ATTACK_EXECUTION].create_index(
                [("run_id", ASCENDING), ("attack_profile_id", ASCENDING)],
                unique=True
            )
            self.db[self.COLLECTION_ATTACK_EXECUTION].create_index("status")
            
            # rt_vulnerability_execution indexes
            self.db[self.COLLECTION_VULN_EXECUTION].create_index(
                [("run_id", ASCENDING), ("vulnerability_profile_id", ASCENDING)],
                unique=True
            )
            
            print("📑 MongoDB indexes created")
        except Exception as e:
            print(f"⚠️ Index creation warning: {e}")
    
    # ============================================================
    #  Run Operations (rt_runs)
    # ============================================================
    
    def create_run(self, run: RTRun) -> str:
        """Create a new run record."""
        if not self._connected:
            return None
            
        try:
            self.db[self.COLLECTION_RUNS].insert_one(run.to_dict())
            return run.run_id
        except Exception as e:
            print(f"❌ Failed to create run: {e}")
            return None
    
    def update_run_status(
        self,
        run_id: str,
        status: str,
        completed_at: datetime = None,
        overall_success_rate: float = None,
        overall_risk_level: str = None,
        error: str = None,
    ) -> bool:
        """Update run status."""
        if not self._connected:
            return False
            
        update_data = {"status": status}
        if completed_at:
            update_data["completed_at"] = completed_at.isoformat()
        if overall_success_rate is not None:
            update_data["overall_success_rate"] = overall_success_rate
        if overall_risk_level:
            update_data["overall_risk_level"] = overall_risk_level
        if error:
            update_data["error"] = error
            
        try:
            result = self.db[self.COLLECTION_RUNS].update_one(
                {"run_id": run_id},
                {"$set": update_data}
            )
            return result.modified_count > 0
        except Exception as e:
            print(f"❌ Failed to update run status: {e}")
            return False
    
    def get_run(self, run_id: str) -> Optional[RTRun]:
        """Get run by ID."""
        if not self._connected:
            return None
            
        try:
            doc = self.db[self.COLLECTION_RUNS].find_one({"run_id": run_id})
            return RTRun.from_dict(doc) if doc else None
        except Exception as e:
            print(f"❌ Failed to get run: {e}")
            return None
    
    def get_recent_runs(self, limit: int = 10) -> List[Dict]:
        """Get recent runs for dashboard."""
        if not self._connected:
            return []
            
        try:
            cursor = self.db[self.COLLECTION_RUNS].find().sort("started_at", DESCENDING).limit(limit)
            return list(cursor)
        except Exception as e:
            print(f"❌ Failed to get recent runs: {e}")
            return []
    
    # ============================================================
    #  Result Operations (rt_results)
    # ============================================================
    
    def insert_result(self, result: RTResult) -> bool:
        """Insert a single turn result."""
        if not self._connected:
            return False
            
        try:
            self.db[self.COLLECTION_RESULTS].insert_one(result.to_dict())
            return True
        except Exception as e:
            print(f"❌ Failed to insert result: {e}")
            return False
    
    def get_results_for_run(self, run_id: str) -> List[Dict]:
        """Get all results for a run."""
        if not self._connected:
            return []
            
        try:
            cursor = self.db[self.COLLECTION_RESULTS].find(
                {"run_id": run_id}
            ).sort("turn", ASCENDING)
            return list(cursor)
        except Exception as e:
            print(f"❌ Failed to get results: {e}")
            return []
    
    def get_latest_results(self, run_id: str, limit: int = 5) -> List[Dict]:
        """Get latest N results for real-time display."""
        if not self._connected:
            return []
            
        try:
            cursor = self.db[self.COLLECTION_RESULTS].find(
                {"run_id": run_id}
            ).sort("turn", DESCENDING).limit(limit)
            return list(cursor)
        except Exception as e:
            print(f"❌ Failed to get latest results: {e}")
            return []
    
    # ============================================================
    #  Attack Execution Operations (rt_attack_execution)
    # ============================================================
    
    def create_attack_execution(self, execution: RTAttackExecution) -> bool:
        """Create attack execution record."""
        if not self._connected:
            return False
            
        try:
            self.db[self.COLLECTION_ATTACK_EXECUTION].insert_one(execution.to_dict())
            return True
        except Exception as e:
            print(f"❌ Failed to create attack execution: {e}")
            return False
    
    def update_attack_progress(
        self,
        run_id: str,
        attack_profile_id: int,
        turns_completed: int = None,
        success_turns: int = None,
        last_turn_written: int = None,
        best_score: float = None,
        backtrack_count: int = None,
        status: str = None,
        completed_at: datetime = None,
        last_error: str = None,
    ) -> bool:
        """Update attack execution progress - called after each turn."""
        if not self._connected:
            return False
            
        update_data = {}
        if turns_completed is not None:
            update_data["turns_completed"] = turns_completed
        if success_turns is not None:
            update_data["success_turns"] = success_turns
        if last_turn_written is not None:
            update_data["last_turn_written"] = last_turn_written
        if best_score is not None:
            update_data["best_score"] = best_score
        if backtrack_count is not None:
            update_data["backtrack_count"] = backtrack_count
        if status:
            update_data["status"] = status
        if completed_at:
            update_data["completed_at"] = completed_at.isoformat()
        if last_error:
            update_data["last_error"] = last_error
            
        if not update_data:
            return True
            
        try:
            result = self.db[self.COLLECTION_ATTACK_EXECUTION].update_one(
                {"run_id": run_id, "attack_profile_id": attack_profile_id},
                {"$set": update_data}
            )
            return result.matched_count > 0
        except Exception as e:
            print(f"❌ Failed to update attack progress: {e}")
            return False
    
    def get_attack_execution(self, run_id: str, attack_profile_id: int) -> Optional[Dict]:
        """Get attack execution status."""
        if not self._connected:
            return None
            
        try:
            doc = self.db[self.COLLECTION_ATTACK_EXECUTION].find_one({
                "run_id": run_id,
                "attack_profile_id": attack_profile_id
            })
            return doc
        except Exception as e:
            print(f"❌ Failed to get attack execution: {e}")
            return None
    
    def get_all_attack_executions(self, run_id: str) -> List[Dict]:
        """Get all attack executions for a run."""
        if not self._connected:
            return []
            
        try:
            cursor = self.db[self.COLLECTION_ATTACK_EXECUTION].find({"run_id": run_id})
            return list(cursor)
        except Exception as e:
            print(f"❌ Failed to get attack executions: {e}")
            return []
    
    # ============================================================
    #  Vulnerability Execution Operations (rt_vulnerability_execution)
    # ============================================================
    
    def create_vulnerability_execution(self, execution: RTVulnerabilityExecution) -> bool:
        """Create vulnerability execution record."""
        if not self._connected:
            return False
            
        try:
            self.db[self.COLLECTION_VULN_EXECUTION].insert_one(execution.to_dict())
            return True
        except Exception as e:
            print(f"❌ Failed to create vulnerability execution: {e}")
            return False
    
    def update_vulnerability_progress(
        self,
        run_id: str,
        vulnerability_profile_id: int,
        checks_completed: int = None,
        findings_count: int = None,
        highest_severity: str = None,
        status: str = None,
        completed_at: datetime = None,
        last_error: str = None,
    ) -> bool:
        """Update vulnerability execution progress."""
        if not self._connected:
            return False
            
        update_data = {}
        if checks_completed is not None:
            update_data["checks_completed"] = checks_completed
        if findings_count is not None:
            update_data["findings_count"] = findings_count
        if highest_severity:
            update_data["highest_severity"] = highest_severity
        if status:
            update_data["status"] = status
        if completed_at:
            update_data["completed_at"] = completed_at.isoformat()
        if last_error:
            update_data["last_error"] = last_error
            
        if not update_data:
            return True
            
        try:
            result = self.db[self.COLLECTION_VULN_EXECUTION].update_one(
                {"run_id": run_id, "vulnerability_profile_id": vulnerability_profile_id},
                {"$set": update_data}
            )
            return result.matched_count > 0
        except Exception as e:
            print(f"❌ Failed to update vulnerability progress: {e}")
            return False
    
    def get_vulnerability_execution(self, run_id: str, vulnerability_profile_id: int) -> Optional[Dict]:
        """Get vulnerability execution status."""
        if not self._connected:
            return None
            
        try:
            doc = self.db[self.COLLECTION_VULN_EXECUTION].find_one({
                "run_id": run_id,
                "vulnerability_profile_id": vulnerability_profile_id
            })
            return doc
        except Exception as e:
            print(f"❌ Failed to get vulnerability execution: {e}")
            return None
    
    # ============================================================
    #  Aggregate Queries for Dashboard
    # ============================================================
    
    def get_run_summary(self, run_id: str) -> Dict[str, Any]:
        """Get complete run summary including all stats."""
        if not self._connected:
            return {}
            
        try:
            run = self.get_run(run_id)
            attack_execs = self.get_all_attack_executions(run_id)
            
            # Calculate totals
            total_turns = sum(e.get("turns_completed", 0) for e in attack_execs)
            total_successes = sum(e.get("success_turns", 0) for e in attack_execs)
            success_rate = (total_successes / total_turns * 100) if total_turns > 0 else 0
            
            return {
                "run": run.to_dict() if run else None,
                "attack_executions": attack_execs,
                "summary": {
                    "total_turns": total_turns,
                    "total_successes": total_successes,
                    "success_rate_pct": round(success_rate, 1),
                }
            }
        except Exception as e:
            print(f"❌ Failed to get run summary: {e}")
            return {}
    
    def get_stats_by_attack_type(self) -> List[Dict]:
        """Get aggregated stats by attack type."""
        if not self._connected:
            return []
            
        try:
            pipeline = [
                {"$group": {
                    "_id": "$attack_type",
                    "total_runs": {"$sum": 1},
                    "avg_success_rate": {"$avg": {
                        "$cond": [
                            {"$gt": ["$turns_completed", 0]},
                            {"$multiply": [
                                {"$divide": ["$success_turns", "$turns_completed"]},
                                100
                            ]},
                            0
                        ]
                    }},
                    "total_successes": {"$sum": "$success_turns"}
                }}
            ]
            result = self.db[self.COLLECTION_ATTACK_EXECUTION].aggregate(pipeline)
            return list(result)
        except Exception as e:
            print(f"❌ Failed to get attack type stats: {e}")
            return []


# ============================================================
#  Helper Functions
# ============================================================

def generate_result_id(run_id: str, attack_profile_id: int, session_id: str, turn: int) -> str:
    """Generate deterministic result ID."""
    return f"{run_id}:{attack_profile_id}:{session_id}:{turn}"


# Singleton instance for global access
_db_instance: Optional[MongoDBService] = None


def get_db() -> MongoDBService:
    """Get or create MongoDB service instance."""
    global _db_instance
    if _db_instance is None:
        _db_instance = MongoDBService()
    return _db_instance


def init_db(mongo_uri: str = None, db_name: str = None) -> MongoDBService:
    """Initialize MongoDB service with custom config."""
    global _db_instance
    _db_instance = MongoDBService(mongo_uri=mongo_uri, db_name=db_name)
    return _db_instance
