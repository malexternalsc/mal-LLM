import os
import dotenv
import asyncio
import re
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field
from huggingface_hub import InferenceClient
from langchain_huggingface import HuggingFaceEndpoint
from huggingface_hub import AsyncInferenceClient
from langchain_core.messages import SystemMessage, HumanMessage

dotenv.load_dotenv()

# Data model for LLM output format
response_schema = {
    "type": "json",
    "value": {
        "properties": {
            "level": {"type": "string","enum": ["high", "low", "medium"]},
            },
        "required": ["grade"],
    },
}

# Initialize the LLM with correct parameters
llm = AsyncInferenceClient(api_key=os.getenv("HUGGING_FACE_KEY"))


async def get_prompt(context: str, code_snippet: str) -> str:
    """Generates a prompt for the LLM to grade the relevance of a document to a code snippet."""
 
    # System instruction for the model
    SYS_PROMPT = """You are an expert grader assessing the level of relevance of a retrieved document to a code snippet.
    Follow these instructions for grading:
    - If the YARA rules or git advisory explained by the context are really significant or explains the code snippet, set level as high, 
    else judge it as low or medium.
    - Your grade should be either 'high' or 'low' or 'medium' to indicate the level of the relevance  to the code snippet or not.
    - Provide only 'high' or 'low' or 'medium' as your final response without additional explanations."""
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



def extract_level(response: str) -> str:
    """Extracts 'yes' or 'no' from the LLM response."""
    match = re.search(r'\b(high|medium|low)\b', response, re.IGNORECASE)
    return match.group(0).lower() if match else "low"  # Default to 'low' if unclear

async def evaluate_documents(code_snippet: str, documents: list) -> list:
    """Grades the relevance of each document to the given code snippet."""
    levels = []

    for doc in documents:
        # Format the prompt as a list of messages
        messages = await get_prompt(doc, code_snippet)
        
        # Generate response from LLM
        stream = await llm.chat_completion(messages=messages, model=os.getenv('LLAMA_MODEL'), max_tokens=64,
                                             response_format=response_schema)

        response = stream.choices[0].message.content
        final_level = extract_level(response)
        levels.append(final_level)
        

    return levels

