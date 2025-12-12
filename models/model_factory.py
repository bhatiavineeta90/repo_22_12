# models/model_factory.py
"""
Model factory to create LLM instances based on provider configuration.
Supports: Gemini, OpenAI, Azure OpenAI
"""

from typing import Union
from deepeval.models.base_model import DeepEvalBaseLLM


def get_model(llm_provider: str = "gemini") -> DeepEvalBaseLLM:
    """
    Factory function to create the appropriate LLM based on provider.
    
    Args:
        llm_provider: One of "gemini", "openai", "azure_openai"
        
    Returns:
        DeepEvalBaseLLM instance for the requested provider
        
    Environment variables required based on provider:
        gemini:
            - GEMINI_API_KEY
            - GEMINI_MODEL_NAME (optional, default: gemini-2.0-flash)
        
        openai:
            - OPENAI_API_KEY
            - OPENAI_MODEL_NAME (optional, default: gpt-4o)
            
        azure_openai:
            - AZURE_OPENAI_API_KEY
            - AZURE_OPENAI_ENDPOINT
            - AZURE_OPENAI_DEPLOYMENT
            - AZURE_OPENAI_API_VERSION (optional, default: 2024-08-01-preview)
    """
    llm_provider = llm_provider.lower().strip() if llm_provider else "gemini"
    
    if llm_provider == "openai":
        from models.openai_model import OpenAIModel
        return OpenAIModel()
    
    elif llm_provider == "azure_openai":
        from models.azure_openai_model import AzureOpenAIModel
        return AzureOpenAIModel()
    
    else:  # Default to Gemini
        from models.gemini_model import GeminiModel
        return GeminiModel()


def get_model_info(llm_provider: str = "gemini") -> dict:
    """
    Get information about a model provider without instantiating it.
    
    Args:
        llm_provider: One of "gemini", "openai", "azure_openai"
        
    Returns:
        Dict with provider info and required environment variables
    """
    providers = {
        "gemini": {
            "name": "Google Gemini",
            "required_env": ["GEMINI_API_KEY"],
            "optional_env": ["GEMINI_MODEL_NAME"],
            "default_model": "gemini-2.0-flash"
        },
        "openai": {
            "name": "OpenAI",
            "required_env": ["OPENAI_API_KEY"],
            "optional_env": ["OPENAI_MODEL_NAME"],
            "default_model": "gpt-4o"
        },
        "azure_openai": {
            "name": "Azure OpenAI",
            "required_env": ["AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_DEPLOYMENT"],
            "optional_env": ["AZURE_OPENAI_API_VERSION"],
            "default_model": "gpt-4o (deployment name)"
        }
    }
    
    return providers.get(llm_provider.lower(), providers["gemini"])
