# models/gemini_model.py
"""
Custom Gemini LLM wrapper for DeepEval integration.
Follows the DeepEvalBaseLLM pattern for custom model support.
Supports JSON-constrained output for DeepEval metrics.
"""

import os
import json
import re
import time
import warnings
from typing import Optional, Type, Union, List, get_origin, get_args
from pydantic import BaseModel

# Use google.generativeai SDK (suppress deprecation warning)
with warnings.catch_warnings():
    warnings.simplefilter("ignore", FutureWarning)
    import google.generativeai as genai

# Try to import DeepEval base model (may fail with newer versions)
try:
    from deepeval.models.base_model import DeepEvalBaseLLM
except ImportError:
    # Create a simple base class if DeepEval not available
    class DeepEvalBaseLLM:
        def load_model(self):
            pass
        def generate(self, prompt: str):
            pass
        async def a_generate(self, prompt: str):
            pass
        def get_model_name(self) -> str:
            pass

# Load configuration
from config import get as config_get


class GeminiModel(DeepEvalBaseLLM):
    """
    Custom Gemini LLM implementation for DeepEval metrics and evaluation.
    Supports both plain text and JSON structured outputs.
    
    Usage:
        # Initialize the model
        gemini = GeminiModel(model_name="gemini-2.0-flash")
        
        # Use with DeepEval metrics
        from deepeval.metrics import AnswerRelevancyMetric
        metric = AnswerRelevancyMetric(model=gemini)
        
        # Or use directly
        response = gemini.generate("Write me a joke")
    """
    
    def __init__(self, model_name: str = None):
        """
        Initialize the Gemini model.
        
        Args:
            model_name: The Gemini model to use. Options include:
                - "gemini-2.5-flash-lite" (default from env)
                - "gemini-2.0-flash" (fast and efficient)
                - "gemini-1.5-pro" (more capable)
                If not provided, reads from GEMINI_MODEL_NAME env variable.
        """
        # Use config.ini as default if model_name not provided
        self.model_name = config_get("gemini", "model_name", "gemini-2.0-flash")
        if self.model_name:
            self.model_name = self.model_name.strip()
        
        # Configure with API key from config
        api_key = config_get("gemini", "api_key")
        if api_key:
            api_key = api_key.strip()
        if not api_key:
            raise ValueError(
                "Gemini API key not found in config/config.ini. "
                "Please set [gemini] api_key in your config.ini file."
            )
        
        # Configure the API
        genai.configure(api_key=api_key)
        
        # Configure safety settings for red team testing (less restrictive)
        self.safety_settings = [
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        ]
        
        self.model = genai.GenerativeModel(
            model_name=self.model_name,
            safety_settings=self.safety_settings
        )
    
    def load_model(self):
        """Return the loaded model instance."""
        return self.model
    
    def _extract_text_from_response(self, response) -> str:
        """Extract text from Gemini response object."""
        try:
            if response.candidates and len(response.candidates) > 0:
                candidate = response.candidates[0]
                if candidate.content and candidate.content.parts:
                    return candidate.content.parts[0].text
            if hasattr(response, 'text'):
                return response.text
        except Exception:
            pass
        return ""
    
    def _clean_json_response(self, text: str) -> str:
        """Clean JSON from markdown code blocks and extract from text if present."""
        text = text.strip()
        
        # Remove markdown code blocks
        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()
        
        # Try to extract JSON object or array using regex
        # Look for the first { or [ and match to the last } or ]
        json_obj_match = re.search(r'\{.*\}', text, re.DOTALL)
        json_arr_match = re.search(r'\[.*\]', text, re.DOTALL)
        
        # Prefer object match over array match (most schemas are objects)
        if json_obj_match:
            return json_obj_match.group(0).strip()
        elif json_arr_match:
            return json_arr_match.group(0).strip()
        
        return text
    
    def _get_default_for_type(self, annotation, error_msg: str = "") -> any:
        """Get a default value for a given type annotation."""
        # Handle None/NoneType
        if annotation is None or annotation is type(None):
            return None
        
        # Get the origin type (e.g., list from List[str])
        origin = get_origin(annotation)
        
        # Handle List types
        if origin is list:
            return []
        
        # Handle basic types
        if annotation == str:
            return error_msg if error_msg else ""
        elif annotation == float:
            return 0.0
        elif annotation == int:
            return 0
        elif annotation == bool:
            return False
        elif annotation == list:
            return []
        
        # Handle string representation check for complex types
        annotation_str = str(annotation).lower()
        if 'list' in annotation_str:
            return []
        
        return None
    
    def _create_default_schema_instance(self, schema: Type[BaseModel], error_msg: str = ""):
        """Create a default instance of a Pydantic schema with empty/default values."""
        defaults = {}
        
        # Special handling for common DeepEval schemas
        schema_name = schema.__name__ if hasattr(schema, '__name__') else str(schema)
        
        if schema_name == "ReasonScore":
            # For PII and other metrics: score should be None to indicate failure
            # reason should explain what went wrong
            return schema(
                score=None,
                reason=error_msg if error_msg else "Failed to generate valid evaluation response"
            )
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
        Generate a response from the Gemini model.
        
        Args:
            prompt: The input prompt to send to the model
            schema: Optional Pydantic schema for structured JSON output
            
        Returns:
            If schema is None: returns string response
            If schema is provided: returns Pydantic model instance
        """
        try:
            model = self.load_model()
            
            # If schema is provided, use JSON mode with schema and retry logic
            if schema is not None:
                # Get schema as JSON for prompt
                schema_dict = schema.model_json_schema() if hasattr(schema, 'model_json_schema') else {}
                schema_name = schema.__name__ if hasattr(schema, '__name__') else str(schema)
                
                max_retries = 3
                last_error = None
                
                for attempt in range(max_retries):
                    try:
                        # Build enhanced prompt requesting JSON (strengthen on retries)
                        if attempt == 0:
                            json_prompt = f"""{prompt}

IMPORTANT: You MUST respond with valid JSON only. No markdown, no explanation, no text before or after.
The JSON MUST match this exact schema:
{json.dumps(schema_dict, indent=2)}

Respond with valid JSON only:"""
                        else:
                            # Strengthen prompt on retries
                            json_prompt = f"""{prompt}

CRITICAL REQUIREMENT: Your response MUST be ONLY valid JSON matching the schema below. 
DO NOT include any text, explanation, or markdown formatting.
START your response with {{ and END with }}.

Schema to match:
{json.dumps(schema_dict, indent=2)}

Valid JSON response:"""
                        
                        # Use JSON response mode
                        generation_config = genai.GenerationConfig(
                            response_mime_type="application/json"
                        )
                        
                        response = model.generate_content(
                            json_prompt,
                            generation_config=generation_config
                        )
                        
                        # Extract and parse JSON
                        text = self._extract_text_from_response(response)
                        text = self._clean_json_response(text)
                        
                        # Try to parse JSON
                        parsed = json.loads(text)
                        # Return Pydantic model instance
                        return schema(**parsed)
                    
                    except (json.JSONDecodeError, Exception) as e:
                        last_error = e
                        error_msg = f"Attempt {attempt + 1}/{max_retries} failed for {schema_name}: {str(e)}"
                        
                        # Log the failure (only print on last attempt or if verbose)
                        if attempt == max_retries - 1:
                            print(f"[GeminiModel] {error_msg}")
                            if attempt < max_retries - 1:
                                print(f"[GeminiModel] Raw response: {text[:200]}...")
                        
                        # If not last attempt, wait and retry
                        if attempt < max_retries - 1:
                            wait_time = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                            time.sleep(wait_time)
                            continue
                        
                        # Last attempt failed - return default instance
                        try:
                            return self._create_default_schema_instance(
                                schema, 
                                f"JSON parsing failed after {max_retries} attempts: {str(last_error)}"
                            )
                        except Exception as default_err:
                            # Last resort: re-raise original error
                            print(f"[GeminiModel] Failed to create default instance: {default_err}")
                            raise last_error
            
            else:
                # Plain text generation
                response = model.generate_content(prompt)
                return self._extract_text_from_response(response) or "[No response generated]"
            
        except Exception as e:
            if schema is not None:
                # Try to return default schema instance on error
                try:
                    return self._create_default_schema_instance(schema, f"Error: {e}")
                except Exception:
                    pass
            return f"[Gemini ERROR] {e}"
    
    async def a_generate(self, prompt: str, schema: Optional[Type[BaseModel]] = None) -> Union[str, BaseModel]:
        """
        Async version of generate. Currently uses sync implementation.
        
        Args:
            prompt: The input prompt to send to the model
            schema: Optional Pydantic schema for structured JSON output
            
        Returns:
            The generated response (string or Pydantic model)
        """
        # For now, use synchronous implementation
        return self.generate(prompt, schema)
    
    def get_model_name(self) -> str:
        """Return the model name for logging/display."""
        return f"Gemini {self.model_name}"
    
    def __str__(self):
        return f"GeminiModel(model_name='{self.model_name}')"
    
    def __repr__(self):
        return self.__str__()


# Convenience function to create a GeminiModel instance
def get_gemini_model(model_name: str = None) -> GeminiModel:
    """
    Factory function to create a GeminiModel instance.
    
    Args:
        model_name: The Gemini model to use. If not provided, reads from GEMINI_MODEL_NAME env variable.
        
    Returns:
        GeminiModel instance
    """
    return GeminiModel(model_name=model_name)
