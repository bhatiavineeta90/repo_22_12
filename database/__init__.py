# database/__init__.py
"""
Database module for Red Team testing results storage.
Provides MongoDB integration for real-time result tracking.
"""

from database.mongo_service import (
    MongoDBService,
    get_db,
    init_db,
    generate_result_id,
)
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
from database.storage_helper import (
    StorageHelper,
    get_storage,
)

__all__ = [
    # Service
    'MongoDBService',
    'get_db',
    'init_db',
    'generate_result_id',
    # Models
    'RTRun',
    'RTResult',
    'RTAttackExecution',
    'RTVulnerabilityExecution',
    'RunStatus',
    'OverallResult',
    'JailbreakResult',
    'VulnerabilitySeverity',
    # Helper
    'StorageHelper',
    'get_storage',
]
