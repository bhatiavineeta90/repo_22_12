import os
import configparser
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

from database.models import (
    RTRun, RTResult, RTAttackExecution, RTVulnerabilityExecution,
    RunStatus, OverallResult, VulnerabilitySeverity,
)


# load mongodb config from config.ini or env vars
def _load_config():
    config = configparser.ConfigParser()
    config_paths = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "config.ini"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config", "config.ini"),
        "config/config.ini",
    ]
    for path in config_paths:
        if os.path.exists(path):
            config.read(path)
            break
    return config

_config = _load_config()

MONGO_URI = _config.get("mongodb", "uri")
DB_NAME = _config.get("mongodb", "database_name")


class MongoDBService:
    COLLECTION_RUNS = "rt_runs"
    COLLECTION_RESULTS = "rt_results"
    COLLECTION_ATTACK_EXECUTION = "rt_attack_execution"
    COLLECTION_VULN_EXECUTION = "rt_vulnerability_execution"

    def __init__(self, mongo_uri=None, db_name=None, auto_connect=True):
        self.mongo_uri = mongo_uri or MONGO_URI
        self.db_name = db_name or DB_NAME
        self.client = None
        self.db = None
        self._connected = False
        if auto_connect:
            self.connect()

    def connect(self):
        try:
            self.client = MongoClient(self.mongo_uri, serverSelectionTimeoutMS=5000)
            self.client.admin.command('ping')
            self.db = self.client[self.db_name]
            self._connected = True
            print(f"Connected to MongoDB: {self.db_name}")
            self._create_indexes()
            return True
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            print(f"MongoDB connection failed: {e}")
            self._connected = False
            return False
        except Exception as e:
            print(f"MongoDB error: {e}")
            self._connected = False
            return False

    def disconnect(self):
        if self.client:
            self.client.close()
            self._connected = False

    def is_connected(self):
        return self._connected

    def _create_indexes(self):
        try:
            self.db[self.COLLECTION_RUNS].create_index("run_id", unique=True)
            self.db[self.COLLECTION_RUNS].create_index([("status", ASCENDING), ("started_at", DESCENDING)])
            self.db[self.COLLECTION_RESULTS].create_index("result_id", unique=True)
            self.db[self.COLLECTION_RESULTS].create_index([("run_id", ASCENDING), ("turn", ASCENDING)])
            self.db[self.COLLECTION_RESULTS].create_index([("run_id", ASCENDING), ("attack_profile_id", ASCENDING)])
            self.db[self.COLLECTION_ATTACK_EXECUTION].create_index(
                [("run_id", ASCENDING), ("attack_profile_id", ASCENDING)], unique=True
            )
            self.db[self.COLLECTION_ATTACK_EXECUTION].create_index("status")
            self.db[self.COLLECTION_VULN_EXECUTION].create_index(
                [("run_id", ASCENDING), ("vulnerability_profile_id", ASCENDING)], unique=True
            )
        except Exception as e:
            print(f"Index creation warning: {e}")

    # runs
    def create_run(self, run: RTRun):
        if not self._connected:
            return None
        try:
            self.db[self.COLLECTION_RUNS].insert_one(run.to_dict())
            return run.run_id
        except Exception as e:
            print(f"Failed to create run: {e}")
            return None

    def update_run_status(self, run_id, status, completed_at=None, overall_success_rate=None,
                          overall_risk_level=None, error=None):
        if not self._connected:
            return False
        update = {"status": status}
        if completed_at:
            update["completed_at"] = completed_at.isoformat()
        if overall_success_rate is not None:
            update["overall_success_rate"] = overall_success_rate
        if overall_risk_level:
            update["overall_risk_level"] = overall_risk_level
        if error:
            update["error"] = error
        try:
            result = self.db[self.COLLECTION_RUNS].update_one({"run_id": run_id}, {"$set": update})
            return result.modified_count > 0
        except Exception as e:
            print(f"Failed to update run: {e}")
            return False

    def get_run(self, run_id):
        if not self._connected:
            return None
        try:
            doc = self.db[self.COLLECTION_RUNS].find_one({"run_id": run_id})
            return RTRun.from_dict(doc) if doc else None
        except Exception as e:
            print(f"Failed to get run: {e}")
            return None

    def get_recent_runs(self, limit=10):
        if not self._connected:
            return []
        try:
            return list(self.db[self.COLLECTION_RUNS].find().sort("started_at", DESCENDING).limit(limit))
        except Exception as e:
            print(f"Failed to get recent runs: {e}")
            return []

    # results
    def insert_result(self, result: RTResult):
        if not self._connected:
            return False
        try:
            self.db[self.COLLECTION_RESULTS].insert_one(result.to_dict())
            return True
        except Exception as e:
            print(f"Failed to insert result: {e}")
            return False

    def get_results_for_run(self, run_id):
        if not self._connected:
            return []
        try:
            return list(self.db[self.COLLECTION_RESULTS].find({"run_id": run_id}).sort("turn", ASCENDING))
        except Exception as e:
            print(f"Failed to get results: {e}")
            return []

    def get_latest_results(self, run_id, limit=5):
        if not self._connected:
            return []
        try:
            return list(self.db[self.COLLECTION_RESULTS].find({"run_id": run_id}).sort("turn", DESCENDING).limit(limit))
        except Exception as e:
            print(f"Failed to get latest results: {e}")
            return []

    # attack execution
    def create_attack_execution(self, execution: RTAttackExecution):
        if not self._connected:
            return False
        try:
            self.db[self.COLLECTION_ATTACK_EXECUTION].insert_one(execution.to_dict())
            return True
        except Exception as e:
            print(f"Failed to create attack execution: {e}")
            return False

    def update_attack_progress(self, run_id, attack_profile_id, turns_completed=None, success_turns=None,
                               last_turn_written=None, best_score=None, backtrack_count=None,
                               status=None, completed_at=None, last_error=None):
        if not self._connected:
            return False
        update = {}
        if turns_completed is not None:
            update["turns_completed"] = turns_completed
        if success_turns is not None:
            update["success_turns"] = success_turns
        if last_turn_written is not None:
            update["last_turn_written"] = last_turn_written
        if best_score is not None:
            update["best_score"] = best_score
        if backtrack_count is not None:
            update["backtrack_count"] = backtrack_count
        if status:
            update["status"] = status
        if completed_at:
            update["completed_at"] = completed_at.isoformat()
        if last_error:
            update["last_error"] = last_error
        if not update:
            return True
        try:
            result = self.db[self.COLLECTION_ATTACK_EXECUTION].update_one(
                {"run_id": run_id, "attack_profile_id": attack_profile_id}, {"$set": update}
            )
            return result.matched_count > 0
        except Exception as e:
            print(f"Failed to update attack progress: {e}")
            return False

    def get_attack_execution(self, run_id, attack_profile_id):
        if not self._connected:
            return None
        try:
            return self.db[self.COLLECTION_ATTACK_EXECUTION].find_one({
                "run_id": run_id, "attack_profile_id": attack_profile_id
            })
        except Exception as e:
            print(f"Failed to get attack execution: {e}")
            return None

    def get_all_attack_executions(self, run_id):
        if not self._connected:
            return []
        try:
            return list(self.db[self.COLLECTION_ATTACK_EXECUTION].find({"run_id": run_id}))
        except Exception as e:
            print(f"Failed to get attack executions: {e}")
            return []

    # vulnerability execution
    def create_vulnerability_execution(self, execution: RTVulnerabilityExecution):
        if not self._connected:
            return False
        try:
            self.db[self.COLLECTION_VULN_EXECUTION].insert_one(execution.to_dict())
            return True
        except Exception as e:
            print(f"Failed to create vulnerability execution: {e}")
            return False

    def update_vulnerability_progress(self, run_id, vulnerability_profile_id, checks_completed=None,
                                       findings_count=None, highest_severity=None, status=None,
                                       completed_at=None, last_error=None):
        if not self._connected:
            return False
        update = {}
        if checks_completed is not None:
            update["checks_completed"] = checks_completed
        if findings_count is not None:
            update["findings_count"] = findings_count
        if highest_severity:
            update["highest_severity"] = highest_severity
        if status:
            update["status"] = status
        if completed_at:
            update["completed_at"] = completed_at.isoformat()
        if last_error:
            update["last_error"] = last_error
        if not update:
            return True
        try:
            result = self.db[self.COLLECTION_VULN_EXECUTION].update_one(
                {"run_id": run_id, "vulnerability_profile_id": vulnerability_profile_id}, {"$set": update}
            )
            return result.matched_count > 0
        except Exception as e:
            print(f"Failed to update vulnerability progress: {e}")
            return False

    def get_vulnerability_execution(self, run_id, vulnerability_profile_id):
        if not self._connected:
            return None
        try:
            return self.db[self.COLLECTION_VULN_EXECUTION].find_one({
                "run_id": run_id, "vulnerability_profile_id": vulnerability_profile_id
            })
        except Exception as e:
            print(f"Failed to get vulnerability execution: {e}")
            return None

    # aggregates
    def get_run_summary(self, run_id):
        if not self._connected:
            return {}
        try:
            run = self.get_run(run_id)
            attack_execs = self.get_all_attack_executions(run_id)
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
            print(f"Failed to get run summary: {e}")
            return {}

    def get_stats_by_attack_type(self):
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
                            {"$multiply": [{"$divide": ["$success_turns", "$turns_completed"]}, 100]},
                            0
                        ]
                    }},
                    "total_successes": {"$sum": "$success_turns"}
                }}
            ]
            return list(self.db[self.COLLECTION_ATTACK_EXECUTION].aggregate(pipeline))
        except Exception as e:
            print(f"Failed to get attack type stats: {e}")
            return []


def generate_result_id(run_id, attack_profile_id, session_id, turn):
    return f"{run_id}:{attack_profile_id}:{session_id}:{turn}"


# singleton
_db_instance = None

def get_db():
    global _db_instance
    if _db_instance is None:
        _db_instance = MongoDBService()
    return _db_instance

def init_db(mongo_uri=None, db_name=None):
    global _db_instance
    _db_instance = MongoDBService(mongo_uri=mongo_uri, db_name=db_name)
    return _db_instance
