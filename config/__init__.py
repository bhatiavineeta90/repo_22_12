# ============================================
# Configuration Module
# ============================================
# This module loads configuration from config.ini and app_registry.yml
# and provides helper functions to access configuration values.

import configparser
import sys
import os
from typing import Dict, Any, Optional

# ============================================
# Path Setup
# ============================================

# Get the repository root directory
_config_dir = os.path.dirname(os.path.abspath(__file__))
_repo_root = os.path.dirname(_config_dir)

# Add lib folder to Python path for deepteam imports
_lib_path = os.path.join(_repo_root, "lib")
if _lib_path not in sys.path:
    sys.path.insert(0, _lib_path)

# ============================================
# Configuration Loading
# ============================================

# Load config.ini from the config directory
_config_path = os.path.join(_config_dir, "config.ini")

config = configparser.ConfigParser()
config.read(_config_path)

# Load app_registry.yml for agent configurations
_app_registry_path = os.path.join(_config_dir, "app_registry.yml")
_app_registry: Dict[str, Any] = {}

try:
    import yaml
    if os.path.exists(_app_registry_path):
        with open(_app_registry_path, 'r') as f:
            _app_registry = yaml.safe_load(f) or {}
except ImportError:
    # PyYAML not installed, try to parse simple YAML manually
    pass
except Exception as e:
    print(f"Warning: Could not load app_registry.yml: {e}")


# ============================================
# Config.ini Helper Functions
# ============================================

def get(section: str, key: str, default: str = None) -> str:
    """
    Get a configuration value from config.ini.
    
    Args:
        section: The section name in config.ini (e.g., 'gemini', 'openai', 'agent')
        key: The key name within the section
        default: Default value if section/key not found
        
    Returns:
        The configuration value or default if not found
    """
    try:
        return config.get(section, key)
    except (configparser.NoSectionError, configparser.NoOptionError):
        return default


def get_int(section: str, key: str, default: int = 0) -> int:
    """
    Get a configuration value as an integer.
    
    Args:
        section: The section name in config.ini
        key: The key name within the section
        default: Default value if section/key not found or invalid
        
    Returns:
        The configuration value as int or default if not found/invalid
    """
    try:
        return config.getint(section, key)
    except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
        return default


def get_bool(section: str, key: str, default: bool = False) -> bool:
    """
    Get a configuration value as a boolean.
    
    Args:
        section: The section name in config.ini
        key: The key name within the section
        default: Default value if section/key not found
        
    Returns:
        The configuration value as bool or default if not found
    """
    try:
        return config.getboolean(section, key)
    except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
        return default


# ============================================
# App Registry Helper Functions
# ============================================

def get_agent(agent_name: str = None) -> Dict[str, Any]:
    """
    Get agent configuration from app_registry.yml.
    
    Args:
        agent_name: Name of the agent to get config for.
                   If None, returns the default agent.
        
    Returns:
        Dict with agent config (base_url, endpoint_path, timeout_secs)
        Returns empty dict if agent not found.
    """
    if not _app_registry:
        # Fall back to config.ini [agent] section
        return {
            "base_url": get("agent", "base_url", "http://127.0.0.1:8000"),
            "endpoint_path": get("agent", "endpoint_path", "/aa-api/v1/utility/get_query"),
            "timeout_secs": get_int("agent", "timeout_secs", 10)
        }
    
    agents = _app_registry.get("agents", {})
    
    # Use active_agent from config.ini if not specified
    if agent_name is None:
        agent_name = get("agent", "active_agent", "utilities_local_agent")
    
    return agents.get(agent_name, {})


def get_agent_url(agent_name: str = None) -> str:
    """
    Get the full URL for an agent endpoint.
    
    Args:
        agent_name: Name of the agent. If None, uses default agent.
        
    Returns:
        Full URL string (base_url + endpoint_path)
    """
    agent = get_agent(agent_name)
    base_url = agent.get("base_url", "http://127.0.0.1:8000").rstrip("/")
    endpoint_path = agent.get("endpoint_path", "/").lstrip("/")
    return f"{base_url}/{endpoint_path}"


def list_agents() -> list:
    """
    List all available agent names from app_registry.yml.
    
    Returns:
        List of agent names
    """
    if not _app_registry:
        return ["default"]
    return list(_app_registry.get("agents", {}).keys())


def get_default_agent_name() -> str:
    """
    Get the name of the default agent.
    
    Returns:
        Default agent name string
    """
    return _app_registry.get("default_agent", "utilities_local_agent")

