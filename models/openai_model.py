# models/openai_model.py
"""
OpenAI LLM wrapper for DeepEval integration.
Uses direct OpenAI API (not Azure).
"""

import os
import json
import re
import time
from typing import Optional, Type, Union
from dotenv import load_dotenv
from openai import OpenAI
from deepeval.models.base_model import DeepEvalBaseLLM
from pydantic import BaseModel

# Load environment variables
load_dotenv()


class OpenAIModel(DeepEvalBaseLLM):
    """
    OpenAI LLM implementation using direct OpenAI API.
    
    Environment variables required:
        OPENAI_API_KEY: Your OpenAI API key
        OPENAI_MODEL_NAME: Model name (default: gpt-4o)
    
    Usage:
        model = OpenAIModel()
        response = model.generate("Write me a joke")
    """
    
    def __init__(self, model_name: str = None, api_key: str = None):
        """
        Initialize the OpenAI model.
        
        Args:
            model_name: The OpenAI model to use (e.g., "gpt-4o", "gpt-4-turbo")
            api_key: Optional API key (defaults to OPENAI_API_KEY env var)
        """
        self.model_name = model_name or os.getenv("OPENAI_MODEL_NAME", "gpt-4o")
        if self.model_name:
            self.model_name = self.model_name.strip()
        
        api_key = api_key or os.getenv("OPENAI_API_KEY")
        if api_key:
            api_key = api_key.strip()
        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY not found. "
                "Please set it in your .env file or environment variables."
            )
        
        self.client = OpenAI(api_key=api_key)
    
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
        
        # Generic fallback
        for field_name, field_info in schema.model_fields.items():
            annotation = field_info.annotation
            if annotation == str:
                defaults[field_name] = error_msg if error_msg else ""
            elif annotation == float:
                defaults[field_name] = 0.0
            elif annotation == int:
                defaults[field_name] = 0
            elif annotation == bool:
                defaults[field_name] = False
            elif annotation == list or 'list' in str(annotation).lower():
                defaults[field_name] = []
            else:
                defaults[field_name] = None
        
        return schema(**defaults)
    
    def generate(self, prompt: str, schema: Optional[Type[BaseModel]] = None) -> Union[str, BaseModel]:
        """
        Generate a response from OpenAI.
        
        Args:
            prompt: The input prompt
            schema: Optional Pydantic schema for structured JSON output
            
        Returns:
            String response or Pydantic model instance
        """
        try:
            if schema is not None:
                schema_dict = schema.model_json_schema() if hasattr(schema, 'model_json_schema') else {}
                
                max_retries = 3
                last_error = None
                
                for attempt in range(max_retries):
                    try:
                        json_prompt = f"""{prompt}

IMPORTANT: Respond with valid JSON only matching this schema:
{json.dumps(schema_dict, indent=2)}

JSON response:"""
                        
                        response = self.client.chat.completions.create(
                            model=self.model_name,
                            messages=[{"role": "user", "content": json_prompt}],
                            response_format={"type": "json_object"} if "gpt-4" in self.model_name else None
                        )
                        
                        text = response.choices[0].message.content
                        text = self._clean_json_response(text)
                        parsed = json.loads(text)
                        return schema(**parsed)
                    
                    except Exception as e:
                        last_error = e
                        if attempt < max_retries - 1:
                            time.sleep(2 ** attempt)
                            continue
                        
                        return self._create_default_schema_instance(
                            schema, f"JSON parsing failed: {str(last_error)}"
                        )
            else:
                # Plain text generation
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.choices[0].message.content or ""
            
        except Exception as e:
            if schema is not None:
                return self._create_default_schema_instance(schema, f"Error: {e}")
            return f"[OpenAI ERROR] {e}"
    
    async def a_generate(self, prompt: str, schema: Optional[Type[BaseModel]] = None) -> Union[str, BaseModel]:
        """Async version - currently uses sync."""
        return self.generate(prompt, schema)
    
    def get_model_name(self) -> str:
        return f"OpenAI {self.model_name}"
    
    def __str__(self):
        return f"OpenAIModel(model_name='{self.model_name}')"
    
    def __repr__(self):
        return self.__str__()


def get_openai_model(model_name: str = None) -> OpenAIModel:
    """Factory function to create an OpenAIModel instance."""
    return OpenAIModel(model_name=model_name)
