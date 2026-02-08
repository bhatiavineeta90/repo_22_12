# config/__init__.py
"""Configuration loader for config.ini and app_registry.yml"""

import configparser
import sys
import os
import re
from pathlib import Path

_config_dir = os.path.dirname(os.path.abspath(__file__))
_repo_root = os.path.dirname(_config_dir)

# Add lib/deepteam to path
_lib_path = os.path.join(_repo_root, "lib", "deepteam")
if _lib_path not in sys.path:
    sys.path.insert(0, _lib_path)

# Paths
PROJECT_ROOT = Path(_repo_root)
RESULTS_DIR = PROJECT_ROOT / "apiv2" / "results" / "runs"
REPORTS_DIR = PROJECT_ROOT / "apiv2" / "results" / "reports"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# run_id validation (prevents path traversal)
_RUN_ID_RE = re.compile(r'^[a-zA-Z0-9_\-]+$')

def validate_run_id(run_id):
    if not run_id or len(run_id) > 128:
        return False
    return bool(_RUN_ID_RE.match(run_id))

def get_result_filepath(run_id):
    if not validate_run_id(run_id):
        raise ValueError(f"Invalid run_id: {run_id}")
    return RESULTS_DIR / f"{run_id}.json"


# config.ini
_config = configparser.ConfigParser()
_config.read(os.path.join(_config_dir, "config.ini"))

def get(section, key, default=None):
    try:
        return _config.get(section, key)
    except:
        return default


# app_registry.yml
_agents = {}
try:
    import yaml
    with open(os.path.join(_config_dir, "app_registry.yml"), 'r') as f:
        _agents = yaml.safe_load(f).get("agents", {})
except:
    pass

def get_agent(name=None):
    if name is None:
        name = get("agent", "active_agent", "utilities_local_agent")
    return _agents.get(name, {})
