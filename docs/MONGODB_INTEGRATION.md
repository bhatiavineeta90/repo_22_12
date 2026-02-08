# MongoDB Storage Integration - Technical Documentation

**Version:** 1.0  
**Last Updated:** 2026-02-08  
**Project:** RedTeam V2
red_circle = "\U0001F534"      # 🔴
green_circle = "\U0001F7E2"    # 🟢
yellow_circle = "\U0001F7E1"   # 🟡
warning = "\u26A0\uFE0F"       # ⚠️
red_x = "\u274C"               # ❌
green_check = "\u2705"         # ✅

print(f"{red_circle} VULNERABLE")
print(f"{green_circle} SECURE")
---

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [File Structure](#file-structure)
4. [MongoDB Schema](#mongodb-schema)
5. [Data Flow](#data-flow)
6. [Code Reference](#code-reference)
7. [Configuration](#configuration)
8. [Error Handling](#error-handling)

---

## Overview

The RedTeam V2 application stores test results in three parallel storage mechanisms:
- **JSON files** - Complete run data in `apiv2/results/runs/{run_id}.json`
- **CSV files** - Flat results appended to `apiv2/results/reports/all_results_v2.csv`
- **MongoDB** - Structured storage with indexed collections for querying and dashboards

MongoDB storage provides:
- Real-time progress tracking during test execution
- Structured querying for analytics and reporting
- Historical data for trend analysis
- Dashboard integration support

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         runner_v2.py                                │
│                        (RedTeamV2 class)                            │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ run() method orchestrates:                                   │   │
│  │   1. start_run() → Creates run record                       │   │
│  │   2. run_attack() → Executes attacks                        │   │
│  │   3. evaluate_vulnerability() → Checks vulnerabilities      │   │
│  │   4. _save_result_to_storage() → Saves each turn            │   │
│  │   5. complete_run() → Marks run complete                    │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    database/storage_helper.py                       │
│                      (StorageHelper class)                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ High-level API wrapping MongoDB operations:                  │   │
│  │   • start_run(run_id, payload_id, ...)                      │   │
│  │   • save_turn_result(run_id, attack_data, vuln_data, ...)   │   │
│  │   • complete_run(run_id, success_rate, risk_level)          │   │
│  │   • start_attack() / complete_attack()                      │   │
│  │   • start_vulnerability_check() / complete_vulnerability()   │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    database/mongo_service.py                        │
│                     (MongoDBService class)                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Low-level MongoDB operations:                                │   │
│  │   • connect() / disconnect()                                │   │
│  │   • create_run() / update_run_status() / get_run()          │   │
│  │   • insert_result() / get_results_for_run()                 │   │
│  │   • create_attack_execution() / update_attack_progress()    │   │
│  │   • create_vulnerability_execution() / update_vuln_progress │   │
│  │   • get_run_summary() / get_stats_by_attack_type()          │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      database/models.py                             │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Data models (Python dataclasses):                            │   │
│  │   • RTRun - Master run record                               │   │
│  │   • RTResult - Per-turn result                              │   │
│  │   • RTAttackExecution - Attack progress tracking            │   │
│  │   • RTVulnerabilityExecution - Vuln check progress          │   │
│  │   • Enums: RunStatus, OverallResult, AttackResult, etc.     │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         MongoDB Database                            │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Collections:                                                 │   │
│  │   • rt_runs (indexed: run_id, status+started_at)            │   │
│  │   • rt_results (indexed: result_id, run_id+turn)            │   │
│  │   • rt_attack_execution (indexed: run_id+attack_profile_id) │   │
│  │   • rt_vulnerability_execution (indexed: run_id+vuln_id)    │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## File Structure

```
repo_22_12/
├── config/
│   └── config.ini              # MongoDB connection settings
│
├── database/
│   ├── __init__.py             # Module exports
│   ├── models.py               # Data models and enums
│   ├── mongo_service.py        # Low-level MongoDB operations
│   └── storage_helper.py       # High-level storage API
│
└── runner_v2.py                # Main runner with storage integration
```

### File Responsibilities

| File | Purpose | Key Classes/Functions |
|------|---------|----------------------|
| `models.py` | Define data structures | `RTRun`, `RTResult`, `RTAttackExecution`, `RTVulnerabilityExecution` |
| `mongo_service.py` | Database operations | `MongoDBService`, `get_db()`, `init_db()` |
| `storage_helper.py` | Business logic wrapper | `StorageHelper`, `get_storage()` |
| `runner_v2.py` | Test orchestration | `RedTeamV2._save_result_to_storage()` |

---

## MongoDB Schema

### Collection: `rt_runs`
Master record for each test run.

```javascript
{
  "run_id": "rt-payload-123-20260208T120000",    // unique identifier
  "payload_id": "payload-123",                   // source payload
  "payload_name": "SQL Injection Tests",         // display name
  "status": "running|completed|failed|pending",  // run status
  "started_at": "2026-02-08T12:00:00Z",         // ISO timestamp
  "completed_at": "2026-02-08T12:15:00Z",       // ISO timestamp
  "llm_model": "gemini",                         // LLM used
  "temperature": 0.7,                            // LLM temperature
  "total_attack_profiles": 3,                    // count
  "total_vuln_profiles": 2,                      // count
  "overall_success_rate": 45.5,                  // percentage
  "overall_risk_level": "high",                  // critical|high|medium|low|none
  "error": null                                  // error message if failed
}
```

**Indexes:**
- `run_id` (unique)
- `[status, started_at]` (compound, descending)

---

### Collection: `rt_results`
Individual turn results.

```javascript
{
  "result_id": "run-123:1:session-abc:1",        // format: run:attack:session:turn
  "run_id": "rt-payload-123-20260208T120000",
  "payload_id": "payload-123",
  "attack_profile_id": 1,
  "attack_profile_name": "Linear Jailbreaking",
  "attack_type": "linear_jailbreaking",
  "session_id": "session-abc",
  "turn": 1,
  "timestamp": "2026-02-08T12:01:30Z",
  "llm_provider": "gemini",
  "temperature": 0.7,
  
  // Attack data
  "attack_prompt": "Ignore instructions and...",
  "agent_response": "I cannot help with...",
  "attack_score": 3.5,
  "attack_result": "Fail",                       // Success|Partial|Fail|Refused
  "attack_reasoning": "Agent refused the request",
  
  // Vulnerability data
  "vulnerability_profile_id": 101,
  "vulnerability_profile_name": "PII Leakage",
  "vulnerability_detected": false,
  "vulnerability_score": 1.0,
  "vulnerability_severity": "none",              // critical|high|medium|low|none
  "vulnerability_reasoning": "No PII detected",
  "detected_pii_types": [],
  
  // Mitigations
  "attack_mitigation_suggestions": "...",
  "vulnerability_mitigation_suggestions": "...",
  
  // Overall
  "overall_result": "PASS - Secure",
  "result_json": "{...}"                         // raw JSON blob
}
```

**Indexes:**
- `result_id` (unique)
- `[run_id, turn]` (compound)
- `[run_id, attack_profile_id]` (compound)

---

### Collection: `rt_attack_execution`
Real-time attack progress tracking.

```javascript
{
  "run_id": "rt-payload-123-20260208T120000",
  "attack_profile_id": 1,
  "attack_name": "Linear Jailbreaking",
  "attack_type": "linear_jailbreaking",
  "planned_turns": 10,
  "status": "running",                           // pending|running|completed|failed
  "started_at": "2026-02-08T12:00:00Z",
  "completed_at": null,
  "turns_completed": 5,
  "success_turns": 2,
  "last_turn_written": 5,
  "last_error": null,
  "best_score": 8.5,
  "backtrack_count": 0
}
```

**Indexes:**
- `[run_id, attack_profile_id]` (unique compound)
- `status`

---

### Collection: `rt_vulnerability_execution`
Real-time vulnerability check progress.

```javascript
{
  "run_id": "rt-payload-123-20260208T120000",
  "vulnerability_profile_id": 101,
  "vulnerability_name": "PII Leakage",
  "vulnerability_type": "pii_leakage",
  "status": "completed",
  "started_at": "2026-02-08T12:00:00Z",
  "completed_at": "2026-02-08T12:05:00Z",
  "checks_completed": 10,
  "findings_count": 2,
  "highest_severity": "medium",
  "last_error": null
}
```

**Indexes:**
- `[run_id, vulnerability_profile_id]` (unique compound)

---

## Data Flow

### Complete Execution Flow

```
1. Test Initiated
   │
   ▼
2. RedTeamV2.__init__()
   ├── get_storage() → returns StorageHelper instance
   └── StorageHelper uses get_db() → MongoDBService singleton
   │
   ▼
3. RedTeamV2.run() starts
   │
   ├─► storage.start_run(run_id, payload_data...)
   │   └── Creates: rt_runs record (status=running)
   │   └── Creates: rt_attack_execution records (status=pending)
   │   └── Creates: rt_vulnerability_execution records (status=pending)
   │
   ▼
4. For each attack_profile:
   │
   ├─► runner.run_attack(attack_profile)
   │   │
   │   ▼
   │   For each turn result:
   │   │
   │   ├─► evaluate_vulnerability() [if attack succeeded]
   │   │
   │   ├─► merge_turn_with_vulnerabilities()
   │   │
   │   └─► _save_result_to_storage(grouped_result)
   │       └── storage.save_turn_result(...)
   │           └── Inserts: rt_results record
   │           └── Updates: rt_attack_execution (turns_completed++)
   │
   ▼
5. Finally block:
   │
   ├─► write_run_json() [JSON file]
   ├─► append_csv()     [CSV file]
   │
   └─► storage.complete_run(run_id, success_rate, risk_level)
       └── Updates: rt_runs (status=completed, completed_at, stats)
```

---

## Code Reference

### 1. Initialization (runner_v2.py)

```python
# Import storage module
from database import get_storage, StorageHelper

class RedTeamV2:
    def __init__(self, payload, enable_storage=True):
        # ...
        self.storage = None
        if enable_storage and MONGODB_STORAGE_AVAILABLE:
            try:
                self.storage = get_storage()
                if self.storage.enabled:
                    print("MongoDB storage enabled")
            except Exception as e:
                print(f"MongoDB storage init failed: {e}")
```

### 2. Start Run (runner_v2.py)

```python
def run(self):
    # ...
    if self.storage:
        attack_profiles_data = [
            {"id": ap.id, "name": ap.name, "attack_type": ap.attack_type.value,
             "turn_config": {"turns": ap.turn_config.turns}}
            for ap in self.payload.attack_profiles
        ]
        self.storage.start_run(
            run_id=run_id,
            payload_id=self.payload.id,
            payload_name=self.payload.meta_data.name,
            attack_profiles=attack_profiles_data,
            vulnerability_profiles=vuln_profiles_data,
        )
```

### 3. Save Turn Result (runner_v2.py)

```python
def _save_result_to_storage(self, merged, run_id, attack_profile):
    if not self.storage:
        return
    try:
        self.storage.save_turn_result(
            run_id=run_id,
            payload_id=self.payload.id,
            attack_profile_id=attack_profile.id,
            attack_prompt=attack_prompt,
            agent_response=agent_response,
            attack_score=float(attack_score),
            attack_result=attack_result_val,
            # ... more fields
        )
    except Exception as e:
        print(f"Storage save error: {e}")
```

### 4. Complete Run (runner_v2.py)

```python
finally:
    # ...
    if self.storage and all_results:
        summary = self._generate_summary(all_results)
        self.storage.complete_run(
            run_id=run_id,
            overall_success_rate=summary.get("attack_success_rate_pct", 0),
            overall_risk_level=self._determine_risk_level(summary),
        )
```

### 5. StorageHelper Methods (storage_helper.py)

```python
class StorageHelper:
    def __init__(self, db=None):
        self.db = db or get_db()

    @property
    def enabled(self):
        return self.db and self.db.is_connected()

    def start_run(self, run_id, payload_id, payload_name, ...):
        run = RTRun(run_id=run_id, ...)
        self.db.create_run(run)
        # Create execution records for each attack/vuln profile

    def save_turn_result(self, run_id, attack_profile_id, ...):
        result = RTResult(result_id=..., ...)
        self.db.insert_result(result)
        # Update attack execution progress

    def complete_run(self, run_id, overall_success_rate, overall_risk_level):
        self.db.update_run_status(
            run_id=run_id,
            status=RunStatus.COMPLETED.value,
            completed_at=datetime.now(timezone.utc),
            overall_success_rate=overall_success_rate,
            overall_risk_level=overall_risk_level,
        )
```

### 6. MongoDBService Methods (mongo_service.py)

```python
class MongoDBService:
    COLLECTION_RUNS = "rt_runs"
    COLLECTION_RESULTS = "rt_results"
    COLLECTION_ATTACK_EXECUTION = "rt_attack_execution"

    def connect(self):
        self.client = MongoClient(self.mongo_uri, serverSelectionTimeoutMS=5000)
        self.client.admin.command('ping')
        self.db = self.client[self.db_name]
        self._create_indexes()

    def create_run(self, run: RTRun):
        self.db[self.COLLECTION_RUNS].insert_one(run.to_dict())

    def insert_result(self, result: RTResult):
        self.db[self.COLLECTION_RESULTS].insert_one(result.to_dict())

    def update_attack_progress(self, run_id, attack_profile_id, ...):
        self.db[self.COLLECTION_ATTACK_EXECUTION].update_one(
            {"run_id": run_id, "attack_profile_id": attack_profile_id},
            {"$set": update}
        )
```

---

## Configuration

### config/config.ini

```ini
[mongodb]
uri = mongodb://localhost:27017/
database_name = redteam
```

### Environment Variables (fallback)

```bash
MONGO_URI=mongodb://localhost:27017/
MONGO_DB_NAME=redteam
```

**Priority:** config.ini > environment variables

---

## Error Handling

### Connection Failures

```python
def connect(self):
    try:
        self.client = MongoClient(self.mongo_uri, serverSelectionTimeoutMS=5000)
        self.client.admin.command('ping')
        self._connected = True
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        print(f"MongoDB connection failed: {e}")
        self._connected = False
```

### Graceful Degradation

If MongoDB is unavailable:
- `MONGODB_STORAGE_AVAILABLE = False`
- `self.storage = None`
- JSON and CSV saving continue normally
- No exceptions thrown to caller

### Per-Operation Error Handling

```python
def _save_result_to_storage(self, merged, run_id, attack_profile):
    if not self.storage:
        return
    try:
        self.storage.save_turn_result(...)
    except Exception as e:
        print(f"Storage save error: {e}")
        # Does not interrupt test execution
```

---

## Query Examples

### Get Recent Runs
```python
db.rt_runs.find().sort("started_at", -1).limit(10)
```

### Get Results for a Run
```python
db.rt_results.find({"run_id": "rt-123"}).sort("turn", 1)
```

### Get Attack Success Rate by Type
```python
db.rt_attack_execution.aggregate([
    {"$group": {
        "_id": "$attack_type",
        "total_runs": {"$sum": 1},
        "avg_success_rate": {"$avg": {
            "$cond": [
                {"$gt": ["$turns_completed", 0]},
                {"$multiply": [{"$divide": ["$success_turns", "$turns_completed"]}, 100]},
                0
            ]
        }}
    }}
])
```

---

## Summary

| Component | File | Purpose |
|-----------|------|---------|
| Data Models | `models.py` | RTRun, RTResult, RTAttackExecution, RTVulnerabilityExecution |
| DB Operations | `mongo_service.py` | MongoDBService with CRUD operations |
| Business Logic | `storage_helper.py` | StorageHelper with workflow methods |
| Integration | `runner_v2.py` | RedTeamV2._save_result_to_storage() |
| Configuration | `config.ini` | MongoDB URI and database name |

**Collections:** `rt_runs`, `rt_results`, `rt_attack_execution`, `rt_vulnerability_execution`

**Storage Flow:** start_run() → [save_turn_result() × N] → complete_run()
