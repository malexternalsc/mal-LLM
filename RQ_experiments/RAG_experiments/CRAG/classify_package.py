import os
import dotenv
import asyncio
import aiofiles
import csv
import json
import re
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field
from langchain_huggingface import HuggingFaceEndpoint
from huggingface_hub import AsyncInferenceClient

dotenv.load_dotenv()

# Data model for LLM output format
response_schema = {
    "type": "json",
    "value": {
        "properties": {
            "package_name": {"type": "string", "description": "Name of the Python package"},
            "prediction": {"type": "boolean", "description": "Prediction of whether the package is Malicious or Benign"},
            "explanation": {"type": "string", "description": "A brief explanation of why the file is classified this way in two sentences"},
            },
        "required": ["prediction", "explanation"],
        "additionalProperties": False
    },
}

# Initialize the LLM with correct parameters
llm = AsyncInferenceClient(api_key=os.getenv("HUGGING_FACE_KEY"))


async def get_prompt(context: str, code_snippet: str,package_name:str,file_list) -> str:
    """Generates a prompt for the LLM to grade the relevance of a document to a code snippet."""
 
    # System instruction for the model
    SYS_PROMPT = f"""You are a cybersecurity expert analyzing potential malware in Python packages. "
                       "Your task is to determine if a package is malicious or benign based on the YARA rule context.
                       
                       The Python package **{package_name}** contains the following files:\n"
                       f"{json.dumps(file_list, ensure_ascii=False, indent=2)}\n\n"
                       "Use the following YARA rule context to verify if the snippet from `setup.py` "
                       "can cause the entire package to be detected as malicious. "
                       "if no context is provided default to your internal knowledge.\n\n"
                       "**If you don't know the answer, just say that you don't know.**
                       """
    prompt =[
        {"role": "developer", 
         "content": SYS_PROMPT},
        {"role": "user",
            "content": f"code snippet:\n{code_snippet}"
            },
         {"role": "user",
            "content": f"context:\n{context}"
            },
        
    ]
    return prompt


async def extract_llm_output(raw_text: str):
    """Attempts to extract filename, prediction, and a truncated explanation from a malformed JSON response."""
    
    # ✅ Try to find the filename
    filename_match = re.search(r'"package_name"\s*:\s*"([^"]+)"', raw_text)
    filename = filename_match.group(1) if filename_match else "Unknown"

    # ✅ Try to find the prediction (true/false)
    prediction_match = re.search(r'"prediction"\s*:\s*(true|false)', raw_text, re.IGNORECASE)
    prediction = prediction_match.group(1).lower() == "true" if prediction_match else False

    # ✅ Try to find the explanation
    explanation_match = re.search(r'"explanation"\s*:\s*"([^"]+)"', raw_text, re.DOTALL)
    explanation = explanation_match.group(1) if explanation_match else ""

    # ✅ Truncate explanation to the first 2 sentences
    sentences = re.split(r'(?<=[.!?])\s+', explanation)  # Split by sentence boundaries
    truncated_explanation = " ".join(sentences[:2])  # Keep first 2 sentences

    return {
        "prediction": prediction,
        "explanation": truncated_explanation
    }



    
async def classify(package_name:str, code_snippet: str, contexts: str, file_list) -> list:
    """classifies if a package is malicious or benign based on the YARA rule context."""


    messages = await get_prompt(context=contexts, code_snippet=code_snippet,package_name=package_name,file_list=file_list)
        
        # Generate response from LLM
    stream = await llm.chat_completion(messages=messages, model=os.getenv('LLAMA_MODEL'), max_tokens=512,
                                             response_format=response_schema)

    response = stream.choices[0].message.content
    try:
        response_data = json.loads(response)
        llm_prediction = response_data["prediction"]
        explanation = response_data["explanation"]
        
        return package_name, llm_prediction, explanation
        
    except json.JSONDecodeError:
        print(f"❌ JSON Decode Error for {package_name}")
        formated_output = await extract_llm_output(response)
        return package_name, formated_output['prediction'], formated_output['explanation']

async def write_to_csv_async(file_path, data, header=['package_name', 'label', 'llm_prediction', 'explanation']):
    """
    Asynchronously appends a row of data to a CSV file.
    """
    file_exists = os.path.exists(file_path)

    async with aiofiles.open(file_path, mode='a', newline='', encoding='utf-8') as file:
        if not file_exists and header:
            await file.write(','.join(header) + '\n')
        await file.write(','.join(map(str, data)) + '\n')
