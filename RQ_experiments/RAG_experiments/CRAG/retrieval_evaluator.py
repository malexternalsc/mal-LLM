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
            "grade": {"type": "string","enum": ["yes", "no"]},
            },
        "required": ["grade"],
    },
}

# Initialize the LLM with correct parameters
llm = AsyncInferenceClient(api_key=os.getenv("HUGGING_FACE_KEY"))


async def get_prompt(context: str, code_snippet: str) -> str:
    """Generates a prompt for the LLM to grade the relevance of a document to a code snippet."""
 
    # System instruction for the model
    SYS_PROMPT = """You are an expert grader assessing the relevance of a retrieved document to a code snippet.
    Follow these instructions for grading:
    - If the YARA rules or git advisory explained by the context are relevant to the code snippet, grade it as relevant.
    - Your grade should be either 'yes' or 'no' to indicate whether the document is relevant to the code snippet or not.
    - Provide only 'yes' or 'no' as your final response without additional explanations."""
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



def extract_yes_no(response: str) -> str:
    """Extracts 'yes' or 'no' from the LLM response."""
    match = re.search(r'\b(yes|no)\b', response, re.IGNORECASE)
    return match.group(0).lower() if match else "no"  # Default to 'no' if unclear

async def evaluate_documents(code_snippet: str, documents: list) -> list:
    """Grades the relevance of each document to the given code snippet."""
    grades = []
    
    for doc in documents:
        # Format the prompt as a list of messages
        messages = await get_prompt(doc, code_snippet)
        
        # Generate response from LLM
        stream = await llm.chat_completion(messages=messages, model=os.getenv('LLAMA_MODEL'), max_tokens=64,
                                             response_format=response_schema)

        response = stream.choices[0].message.content


        # Extract 'yes' or 'no' from the response
        final_grade = extract_yes_no(response)
        grades.append(final_grade)

    return grades

# Example usage:
# asyncio.run(evaluate_documents("print('Hello, World!')", ["Example document about YARA rules"]))
