# config/__init__.py
"""Simple configuration loader for config.ini and app_registry.yml"""

import configparser
import sys
import os

# ============================================
# Path Setup
# ============================================
_config_dir = os.path.dirname(os.path.abspath(__file__))
_repo_root = os.path.dirname(_config_dir)

# Add lib folder to Python path for deepteam imports
_lib_path = os.path.join(_repo_root, "lib")
if _lib_path not in sys.path:
    sys.path.insert(0, _lib_path)

# ============================================
# Load config.ini
# ============================================
_config = configparser.ConfigParser()
_config.read(os.path.join(_config_dir, "config.ini"))

def get(section: str, key: str, default: str = None) -> str:
    """Get a config value. Example: get('gemini', 'api_key')"""
    try:
        return _config.get(section, key)
    except:
        return default

# ============================================
# Load app_registry.yml
# ============================================
_agents = {}
try:
    import yaml
    with open(os.path.join(_config_dir, "app_registry.yml"), 'r') as f:
        _agents = yaml.safe_load(f).get("agents", {})
except:
    pass

def get_agent(name: str = None) -> dict:
    """Get agent config by name. If no name, uses active_agent from config.ini"""
    if name is None:
        name = get("agent", "active_agent", "utilities_local_agent")
    return _agents.get(name, {})
