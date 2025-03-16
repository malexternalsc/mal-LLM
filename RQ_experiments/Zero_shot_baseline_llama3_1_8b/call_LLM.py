import os
import json
import dotenv
import asyncio
from openai import OpenAI,AsyncOpenAI
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from huggingface_hub import InferenceClient
from huggingface_hub import AsyncInferenceClient


dotenv.load_dotenv()


class LLM:

    def __init__(self, model: str, api_key: str):
        """
        Initializes the LLM with the specified model and API key.
        Determines if the model is OpenAI or Hugging Face based on the name.
        """
        self.LLM_MODEL = model
        self.API_KEY = api_key

        if "gpt" in model:  # OpenAI model detection
            self.USE_HUGGINGFACE = False
            self.llm =  AsyncOpenAI(api_key=self.API_KEY)
        else:  # Hugging Face model detection (LLaMA-3 or other instruct models)

            self.USE_HUGGINGFACE = True
            self.llm  = AsyncInferenceClient(api_key=self.API_KEY)
    
    
    async def convert_json_schema(self,original_schema):
        """
        Converts the given JSON schema format into the required format dynamically.
        """
        converted_schema = {
            "type": "json",
            "value": {
                "properties": {},
                "required": []
            }
        }
        
        properties = original_schema["json_schema"]["schema"]["properties"]
        required_fields = original_schema["json_schema"]["schema"].get("required", [])
        
        for key, value in properties.items():
            if value["type"] == "object":
                sub_properties = value["properties"]
                for sub_key, sub_value in sub_properties.items():
                    converted_schema["value"]["properties"][sub_key] = {
                        "type": sub_value["type"]
                    }
                    if "minimum" in sub_value:
                        converted_schema["value"]["properties"][sub_key]["minimum"] = sub_value["minimum"]
                    if "maximum" in sub_value:
                        converted_schema["value"]["properties"][sub_key]["maximum"] = sub_value["maximum"]
                    
                    if sub_key in value.get("required", []):
                        converted_schema["value"]["required"].append(sub_key)
            else:
                converted_schema["value"]["properties"][key] = {
                    "type": value["type"]
                }
                if key in required_fields:
                    converted_schema["value"]["required"].append(key)
        
        return converted_schema
    
    
    
    
    
           
    
            
    async def call_llm(self, prompt,response_format) -> str:
        """
        Calls the selected LLM model API (Hugging Face for text generation or OpenAI GPT for chat completion).
        """
       

        try:
            if self.USE_HUGGINGFACE:
                # ✅ Use chat_completion() for instruct models
                grammer =await self.convert_json_schema(response_format)
                stream = await self.llm.chat_completion(messages=prompt, model=self.LLM_MODEL, max_tokens=500,
                                                    response_format=grammer)
                response = stream.choices[0].message.content
                return response
    
            else:
                # ✅ OpenAI chat model
                
                stream = await self.llm.chat.completions.create(model='gpt-4o-mini',messages =prompt,
                                                          response_format= response_format)
                
                response = stream.choices[0].message.content
                


            return response 
        except Exception as e:
            print(f"❌ LLM API Error: {e}")
            return "Error in LLM inference."
