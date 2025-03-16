import os
import json
import aiofiles
import csv
import pandas as pd
import argparse
import asyncio
from tqdm import tqdm
import dotenv
import re

from langchain_openai import OpenAIEmbeddings
from langchain_core.documents import Document
from langchain_postgres.vectorstores import PGVector
from langchain_core.prompts import PromptTemplate
from langgraph.graph import START, StateGraph

from call_LLM import LLM

dotenv.load_dotenv()

parser = argparse.ArgumentParser(description="Simulate the testing of the LLM model on the test dataset.")
parser.add_argument("--model", "-m", type=str, help="The name of the LLM model to use.", choices=["gpt", "llama"], default="llama")
parser.add_argument("--result_file", "-r", type=str, help="where to save the results of the test.")

args = parser.parse_args()
model = args.model
result_file = args.result_file

if model == "gpt":
    api_key = os.getenv("OPENAI_API_KEY")
    model_name = "gpt-4o-mini"
else:
    api_key = os.getenv("HUGGING_FACE_KEY")
    model_name = "meta-llama/Llama-3.1-8B-Instruct"

# Initialize LLM
llm = LLM(model=model_name, api_key=api_key)

# Initialize Embeddings
embeddings = OpenAIEmbeddings(api_key=os.getenv("OPENAI_API_KEY"))
COLLECTION_NAME = "malicious_setup_py"

DB_PARAMS = {
    "database": "malware_kb",
    "user": "malware_admin",
    "password": "admin_secure_password",
    "host": "localhost",
    "port": "5432"
}
PGVECTOR_CONNECTION_STRING = (
    f"postgresql+psycopg://{DB_PARAMS['user']}:{DB_PARAMS['password']}@"
    f"{DB_PARAMS['host']}:{DB_PARAMS['port']}/{DB_PARAMS['database']}?options=-csearch_path=malware"
)

# Initialize Vector Store
vectorstore = PGVector(
    embeddings=embeddings,
    collection_name=COLLECTION_NAME,
    connection=PGVECTOR_CONNECTION_STRING,
    use_jsonb=True,
    async_mode=False,
)

import json

def get_prompt(package_name, file_list, snippet, context):
    """
    Generates a structured role-content format prompt for an LLM.
    """
    return [
        {
            "role": "developer",
            "content": """You are a cybersecurity expert analyzing potential malware in Python packages. "
                       "Your task is to determine if a package is malicious or benign based sample code malicious code that is provided in the context.
                       Evaluate the provided code snippet and the context to determine if the package is malicious or benign.
                       """
        },
        {
            "role": "developer",
            "content": f"The Python package **{package_name}** contains the following files:\n"
                       f"{json.dumps(file_list, ensure_ascii=False, indent=2)}\n\n"
                       "Use the sample malicious code in the context to verify if the snippet from `setup.py` "
                       "can cause the entire package to be detected as malicious. "
                       "Verify if the advisories described in the context relates to the package\n\n"
                       "**If you don't know the answer, just say that you don't know.**"
        },
        {
            "role": "user",
            "content": f"**Sample Malicious code:**\n{context}"
        },
        {
            "role": "user",
            "content": f"**Code Snippet:**\n{snippet}"
        },
        {
            "role": "user",
            "content": "**Strict Response Format:**\n"
                       "- **Filename**: {package_name}\n"
                       "- **Result**:\n"
                       "- **Predicted Classification**: (1 for Malicious, 0 for Benign)\n"
                       "- **Explanation**: (Concise reasoning in two sentences)"
        }
    ]


# Response Format Schema
RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "python_package_classification_schema",
        "schema": {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "The name of the file being classified"
                },
                "result": {
                    "type": "object",
                    "properties": {
                        "prediction": {
                            "type": "boolean",
                            "description": "Prediction of whether the package is Malicious or Benign"
                        },
                        "explanation": {
                            "type": "string",
                            "description": "A brief explanation of why the file is classified this way in two sentences"
                        }
                    },
                    "required": ["prediction", "explanation"]
                }
            },
            "required": ["filename", "result"],
            "additionalProperties": False
        }
    }
}

async def retrieve(snippet: str):
    """
    Retrieves relevant YARA rules from the vector store.
    """
    retrieved_docs = vectorstore.similarity_search(snippet, k=1)
    return retrieved_docs


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



async def generate(package_name, snippet, retrieved_docs,file_list):
    """
    Generates a classification result using LLM.
    """
    docs_content = "\n\n".join(doc.page_content for doc in retrieved_docs)
    messages = get_prompt(package_name, file_list, snippet, docs_content)
    #prompt.invoke({"package_name": package_name, "snippet": snippet, "context": docs_content, "file_list": file_list})
     
    response = await llm.call_llm(messages, RESPONSE_FORMAT)
    
    if model == "gpt":
        response_data = json.loads(response)
        llm_prediction = response_data["result"]["prediction"]
        explanation = response_data["result"]["explanation"]
    else:  # Model is Llama
        try:
            response_data = json.loads(response)
            llm_prediction = response_data["prediction"]
            explanation = response_data["explanation"]
            
            return package_name, llm_prediction, f'"{explanation}"'
        
        except json.JSONDecodeError:
            print(f"❌ JSON Decode Error for {package_name}")
            formated_output = await extract_llm_output(response)
            return package_name, formated_output['prediction'], f"\'{formated_output['explanation']}\'"

    return package_name, llm_prediction, explanation


async def write_to_csv_async(file_path, data, header=['filename', 'label', 'llm_prediction', 'explanation']):
    """
    Asynchronously appends a row of data to a CSV file.
    """
    file_exists = os.path.exists(file_path)

    async with aiofiles.open(file_path, mode='a', newline='', encoding='utf-8') as file:
        if not file_exists and header:
            await file.write(','.join(header) + '\n')
        await file.write(','.join(map(str, data)) + '\n')

def load_tests_files():
    """
    Loads test datasets from JSON files.
    """
    mal_tests = pd.read_json(".\data\\test_malicious_packages_final.json")
    benign_tests = pd.read_json(".\data\\test_benign_packages_final.json")

    mal_tests['label'] = 1
    benign_tests['label'] = 0

    test_dataset = pd.concat([mal_tests, benign_tests]).sample(frac=1).reset_index(drop=True)
    test_dataset["setup.py"] = test_dataset["setup.py"].apply(lambda x: x[:300] if isinstance(x, str) else x)

    print(f"Test dataset loaded: {test_dataset.shape[0]} packages.")
    return test_dataset

async def simulate_test(test_dataset):
    """
    Simulates the LLM classification for each test package.
    """
    for _, row in tqdm(test_dataset.iterrows(), total=test_dataset.shape[0]):
        package_name = row['package_name']
        snippet = row["setup.py"]
        label = row["label"]
        file_list = row["file_list"]

        try:
            retrieved_docs = await retrieve(snippet)
            
            filename, llm_prediction, explanation = await generate(package_name, snippet, retrieved_docs, file_list)
            await write_to_csv_async(result_file, [package_name, label, llm_prediction, explanation])
            
        except Exception as e:
            print(f"❌ Error processing {package_name}")

if __name__ == "__main__":
    test_dataset = load_tests_files()
    asyncio.run(simulate_test(test_dataset))
