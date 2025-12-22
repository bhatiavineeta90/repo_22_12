# attacks/agent_client.py
"""
Centralized agent endpoint client.
Supports agent selection from config/app_registry.yml by agent name.
"""

from typing import Dict, Optional
from hashlib import sha1
import requests

from config import get_agent

# Load default agent config
_agent = get_agent()
AGENT_BASE_URL = _agent.get("base_url", "http://127.0.0.1:8000")
AGENT_ENDPOINT_PATH = _agent.get("endpoint_path", "/aa-api/v1/utility/get_query")
AGENT_TIMEOUT_SECS = _agent.get("timeout_secs", 10)


def call_agent_app(
    prompt: str,
    timeout_secs: Optional[int] = None,
    session_id: Optional[str] = None,
    agent_name: Optional[str] = None,
    session_prefix: str = "AGENT",
) -> Dict[str, str]:
    """
    Call the agent endpoint.
    
    Args:
        prompt: Message to send to agent
        timeout_secs: Request timeout (default from agent config)
        session_id: Optional session ID for multi-turn
        agent_name: Agent name from app_registry.yml (e.g., "utilities_local_agent", "airline")
        session_prefix: Prefix for auto-generated session IDs
        
    Returns:
        Dict with 'response' and 'session_id' keys
    """
    # Get agent config
    if agent_name:
        agent = get_agent(agent_name)
        base_url = agent.get("base_url", AGENT_BASE_URL)
        endpoint_path = agent.get("endpoint_path", AGENT_ENDPOINT_PATH)
        timeout = agent.get("timeout_secs", AGENT_TIMEOUT_SECS)
    else:
        base_url = AGENT_BASE_URL
        endpoint_path = AGENT_ENDPOINT_PATH
        timeout = AGENT_TIMEOUT_SECS
    
    if timeout_secs is not None:
        timeout = timeout_secs
    
    # Generate session ID if not provided
    if session_id is None:
        session_id = f"{session_prefix}-" + sha1(prompt.encode("utf-8")).hexdigest()[:12]
    
    # Build URL and call
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


def get_agent_url(agent_name: str = None) -> str:
    """Get full URL for an agent."""
    agent = get_agent(agent_name) if agent_name else _agent
    base_url = agent.get("base_url", AGENT_BASE_URL).rstrip("/")
    endpoint_path = agent.get("endpoint_path", AGENT_ENDPOINT_PATH).lstrip("/")
    return f"{base_url}/{endpoint_path}"
