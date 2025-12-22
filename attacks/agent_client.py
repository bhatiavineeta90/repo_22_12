# attacks/agent_client.py
"""
Centralized agent endpoint configuration and client.
All attack modules should import from here to ensure consistent configuration.

Supports agent selection from config/app_registry.yml by agent name.
"""

import os
from typing import Dict, Optional
from hashlib import sha1
import requests

# Load configuration from config module
from config import get as config_get, get_int as config_get_int
from config import get_agent as config_get_agent, get_agent_url as config_get_agent_url

# ============================================================
#  Configuration (Default Agent)
# ============================================================

# Default agent endpoint - loaded from app_registry.yml or config.ini fallback
_default_agent = config_get_agent()
AGENT_BASE_URL = _default_agent.get("base_url", "http://127.0.0.1:8000")
AGENT_ENDPOINT_PATH = _default_agent.get("endpoint_path", "/aa-api/v1/utility/get_query")
AGENT_TIMEOUT_SECS = _default_agent.get("timeout_secs", 10)


# ============================================================
#  Agent Client Function
# ============================================================

def call_agent_app(
    prompt: str,
    timeout_secs: Optional[int] = None,
    session_id: Optional[str] = None,
    base_url: Optional[str] = None,
    endpoint_path: Optional[str] = None,
    session_prefix: str = "AGENT",
    agent_name: Optional[str] = None,
) -> Dict[str, str]:
    """
    Call the agent application endpoint.
    
    This is the centralized function for making requests to the agent.
    All attack modules should use this function instead of defining their own.
    
    Args:
        prompt: The prompt/message to send to the agent
        timeout_secs: Request timeout in seconds (defaults to agent config)
        session_id: Optional session ID for multi-turn conversations
        base_url: Override the agent base URL
        endpoint_path: Override the agent endpoint path
        session_prefix: Prefix for auto-generated session IDs (e.g., "JB", "PI", "BLJ")
        agent_name: Agent name from app_registry.yml (e.g., "utilities_local_agent")
                   If provided, overrides base_url and endpoint_path
        
    Returns:
        Dict with 'response' and 'session_id' keys
    """
    # If agent_name is provided, get config from app_registry.yml
    if agent_name:
        agent_config = config_get_agent(agent_name)
        if agent_config:
            base_url = base_url or agent_config.get("base_url")
            endpoint_path = endpoint_path or agent_config.get("endpoint_path")
            timeout_secs = timeout_secs if timeout_secs is not None else agent_config.get("timeout_secs", AGENT_TIMEOUT_SECS)
    
    # Use defaults if not provided
    base_url = base_url or AGENT_BASE_URL
    endpoint_path = endpoint_path or AGENT_ENDPOINT_PATH
    timeout = timeout_secs if timeout_secs is not None else AGENT_TIMEOUT_SECS
    
    # Generate session ID if not provided
    if session_id is None:
        session_id = f"{session_prefix}-" + sha1(prompt.encode("utf-8")).hexdigest()[:12]
    
    # Build URL
    url = f"{base_url.rstrip('/')}/{endpoint_path.lstrip('/')}"
    payload = {"user_input": prompt, "session_id": session_id}
    
    try:
        r = requests.post(url, json=payload, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        return {
            "response": data.get("response", ""),
            "session_id": data.get("session_id", session_id),
        }
    except Exception as e:
        return {"response": f"ERROR: {e}", "session_id": session_id}


# ============================================================
#  Helper Functions
# ============================================================

def get_agent_url(agent_name: str = None) -> str:
    """
    Get the full agent endpoint URL.
    
    Args:
        agent_name: Optional agent name from app_registry.yml
        
    Returns:
        Full URL string
    """
    if agent_name:
        return config_get_agent_url(agent_name)
    return f"{AGENT_BASE_URL.rstrip('/')}/{AGENT_ENDPOINT_PATH.lstrip('/')}"


def list_available_agents() -> list:
    """
    List all available agent names from app_registry.yml.
    
    Returns:
        List of agent names
    """
    from config import list_agents
    return list_agents()

