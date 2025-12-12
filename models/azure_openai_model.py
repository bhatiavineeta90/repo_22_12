# models/azure_openai_model.py
"""
Azure OpenAI LLM wrapper for DeepEval integration.
Uses Azure OpenAI endpoint with Azure-specific configuration.
"""

import os
import json
import re
import time
from typing import Optional, Type, Union, List, get_origin, get_args
from dotenv import load_dotenv
from openai import AzureOpenAI
from deepeval.models.base_model import DeepEvalBaseLLM
from pydantic import BaseModel

# Load environment variables
load_dotenv()


class AzureOpenAIModel(DeepEvalBaseLLM):
    """
    Azure OpenAI LLM implementation for DeepEval metrics.
    
    Environment variables required:
        AZURE_OPENAI_API_KEY: Your Azure OpenAI API key
        AZURE_OPENAI_ENDPOINT: Your Azure OpenAI endpoint URL
        AZURE_OPENAI_DEPLOYMENT: Your deployment name
        AZURE_OPENAI_MODEL_NAME: Model name (optional, defaults to deployment name)
        AZURE_OPENAI_API_VERSION: API version (default: 2024-08-01-preview)
    
    Usage:
        model = AzureOpenAIModel()
        response = model.generate("Write me a joke")
    """
    
    def __init__(
        self, 
        deployment_name: str = None,
        azure_endpoint: str = None,
        api_key: str = None,
        api_version: str = None
    ):
        """Initialize the Azure OpenAI model."""
        self.deployment_name = deployment_name or os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        if self.deployment_name:
            self.deployment_name = self.deployment_name.strip()
        
        azure_endpoint = azure_endpoint or os.getenv("AZURE_OPENAI_ENDPOINT")
        if azure_endpoint:
            azure_endpoint = azure_endpoint.strip()
        if not azure_endpoint:
            raise ValueError(
                "AZURE_OPENAI_ENDPOINT not found. "
                "Please set it in your .env file or environment variables."
            )
        
        api_key = api_key or os.getenv("AZURE_OPENAI_API_KEY")
        if api_key:
            api_key = api_key.strip()
        if not api_key:
            raise ValueError(
                "AZURE_OPENAI_API_KEY not found. "
                "Please set it in your .env file or environment variables."
            )
        
        api_version = api_version or os.getenv("AZURE_OPENAI_API_VERSION", "2024-08-01-preview")
        
        self.client = AzureOpenAI(
            azure_endpoint=azure_endpoint,
            api_key=api_key,
            api_version=api_version
        )
        
        # Model name can be different from deployment name
        self.model_name = os.getenv("AZURE_OPENAI_MODEL_NAME", self.deployment_name)
        if self.model_name:
            self.model_name = self.model_name.strip()
    
    def load_model(self):
        """Return the client instance."""
        return self.client
    
    def _clean_json_response(self, text: str) -> str:
        """Clean JSON from markdown code blocks."""
        text = text.strip()
        
        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()
        
        # Extract JSON object or array
        json_obj_match = re.search(r'\{.*\}', text, re.DOTALL)
        json_arr_match = re.search(r'\[.*\]', text, re.DOTALL)
        
        if json_obj_match:
            return json_obj_match.group(0).strip()
        elif json_arr_match:
            return json_arr_match.group(0).strip()
        
        return text
    
    def _get_default_for_type(self, annotation, error_msg: str = ""):
        """Get a sensible default value for a given type annotation."""
        if annotation is None:
            return None
        
        origin = get_origin(annotation)
        args = get_args(annotation)
        
        # Handle Optional types
        if origin is Union:
            non_none_args = [a for a in args if a is not type(None)]
            if non_none_args:
                return self._get_default_for_type(non_none_args[0], error_msg)
            return None
        
        # Handle List types
        if origin is list or origin is List:
            return []
        
        # Handle basic types
        if annotation == str:
            return error_msg if error_msg else ""
        elif annotation == int:
            return 0
        elif annotation == float:
            return 0.0
        elif annotation == bool:
            return False
        elif annotation == list:
            return []
        elif annotation == dict:
            return {}
        
        return None
    
    def _create_default_schema_instance(self, schema: Type[BaseModel], error_msg: str = ""):
        """Create a default instance of a Pydantic schema with sensible defaults."""
        defaults = {}
        schema_name = schema.__name__ if hasattr(schema, '__name__') else str(schema)
        
        # Handle specific schemas used by deepteam/deepeval
        if schema_name == "ReasonScore":
            return schema(score=None, reason=error_msg or "Failed to generate response")
        elif schema_name == "NonRefusal":
            # For NonRefusal schema, must be 'Non-refusal' or 'Refusal'
            return schema(classification="Non-refusal")
        elif schema_name == "OnTopic":
            return schema(on_topic=True)
        elif schema_name == "Rating":
            return schema(rating=1)
        elif schema_name == "ImprovementPrompt":
            return schema(improvement=error_msg or "No improvement", prompt=error_msg or "Unable to generate")
        elif schema_name == "Purpose":
            return schema(purpose=error_msg if error_msg else "")
        elif schema_name == "Entities":
            return schema(entities=[])
        
        # Generic fallback: build defaults for all fields
        for field_name, field_info in schema.model_fields.items():
            defaults[field_name] = self._get_default_for_type(field_info.annotation, error_msg)
        
        return schema(**defaults)
    
    def generate(self, prompt: str, schema: Optional[Type[BaseModel]] = None) -> Union[str, BaseModel]:
        """
        Generate a response from Azure OpenAI.
        
        Args:
            prompt: The input prompt
            schema: Optional Pydantic schema for structured JSON output
            
        Returns:
            String response or Pydantic model instance
        """
        try:
            if schema is not None:
                schema_dict = schema.model_json_schema() if hasattr(schema, 'model_json_schema') else {}
                schema_name = schema.__name__ if hasattr(schema, '__name__') else str(schema)
                
                max_retries = 3
                last_error = None
                
                for attempt in range(max_retries):
                    try:
                        if attempt == 0:
                            json_prompt = f"""{prompt}

IMPORTANT: You MUST respond with valid JSON only. No markdown, no explanation, no text before or after.
The JSON MUST match this exact schema:
{json.dumps(schema_dict, indent=2)}

Respond with valid JSON only:"""
                        else:
                            json_prompt = f"""{prompt}

CRITICAL REQUIREMENT: Your response MUST be ONLY valid JSON matching the schema below.
DO NOT include any text, explanation, or markdown formatting.
START your response with {{ and END with }}.

Schema to match:
{json.dumps(schema_dict, indent=2)}

Valid JSON response:"""
                        
                        response = self.client.chat.completions.create(
                            model=self.deployment_name,
                            messages=[{"role": "user", "content": json_prompt}],
                            response_format={"type": "json_object"}
                        )
                        
                        text = response.choices[0].message.content
                        text = self._clean_json_response(text)
                        parsed = json.loads(text)
                        
                        # Handle fields that may be None but need defaults
                        for field_name, field_info in schema.model_fields.items():
                            if field_name not in parsed or parsed[field_name] is None:
                                # Check if field has a Literal type (like NonRefusal.classification)
                                if hasattr(field_info.annotation, '__origin__'):
                                    origin = get_origin(field_info.annotation)
                                    if str(origin) == "<class 'typing.Literal'>":
                                        args = get_args(field_info.annotation)
                                        if args:
                                            parsed[field_name] = args[0]  # Use first valid value
                                else:
                                    parsed[field_name] = self._get_default_for_type(field_info.annotation, "")
                        
                        return schema(**parsed)
                    
                    except Exception as e:
                        last_error = e
                        if attempt < max_retries - 1:
                            time.sleep(2 ** attempt)
                            continue
                        
                        print(f"[AzureOpenAI] JSON parsing failed after {max_retries} attempts: {last_error}")
                        return self._create_default_schema_instance(
                            schema, f"JSON parsing failed: {str(last_error)}"
                        )
            else:
                # Plain text generation
                response = self.client.chat.completions.create(
                    model=self.deployment_name,
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.choices[0].message.content or ""
            
        except Exception as e:
            print(f"[AzureOpenAI] Error: {e}")
            if schema is not None:
                return self._create_default_schema_instance(schema, f"Error: {e}")
            return f"[Azure OpenAI ERROR] {e}"
    
    async def a_generate(self, prompt: str, schema: Optional[Type[BaseModel]] = None) -> Union[str, BaseModel]:
        """Async version - currently uses sync."""
        return self.generate(prompt, schema)
    
    def get_model_name(self) -> str:
        return f"Azure OpenAI {self.deployment_name}"
    
    def __str__(self):
        return f"AzureOpenAIModel(deployment='{self.deployment_name}')"
    
    def __repr__(self):
        return self.__str__()


def get_azure_openai_model(deployment_name: str = None) -> AzureOpenAIModel:
    """Factory function to create an AzureOpenAIModel instance."""
    return AzureOpenAIModel(deployment_name=deployment_name)
