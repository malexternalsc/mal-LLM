import os
import json
import aiofiles
import csv
import os
import pandas as pd
import argparse
import asyncio
from call_LLM import LLM
import dotenv

from tqdm import tqdm
dotenv.load_dotenv()

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




parser = argparse.ArgumentParser(description="Simulate the testing of the LLM model on the test dataset.")
parser.add_argument("--model","-m", type=str, help="The name of the LLM model to use.", choices=["gpt","llama"], default="llama")
parser.add_argument("--result_file","-r", type=str, help="where to save the results of the test.")

args = parser.parse_args()
model = args.model
result_file = args.result_file

if model == "gpt":
    api_key = os.getenv("OPENAI_API_KEY")
    model_name = "gpt-4o-mini"
else:
    api_key = os.getenv("HUGGING_FACE_KEY")
    model_name = "meta-llama/Llama-3.1-8B-Instruct"


async def get_prompt(package_name,file_list, file_content):
    """
    Generates a prompt for the user and developer to classify a package called as Malicious or Benign.
    """
    PROMPT = [{"role": "developer", 
                "content": f"""You are a cybersecurity expert analyzing potential malware in a Python package called {package_name}.
            You are provided with the names of the files in the package: {json.dumps(file_list, ensure_ascii=False)}.
            Below is the first 300 characters from the `setup.py` file.
            
            Your task: 
            - Determine if the package is **Malicious (1) or Benign (0)**.
            - Provide a **brief explanation** (max 2 sentences) of why it is classified that way.

            **Strict Response Format**:
            - **Filename**: {package_name}
            - **Result**:
            - **Predicted Classification**: (1 for Malicious, 0 for Benign)
            - **Explanation**: (Concise reasoning in two sentences)
            """
            },
            {
                "role": "user", 
                "content": f"file content: {file_content}"
            }
        ] 
    return PROMPT


def load_tests_files():
    mal_tests = pd.read_json(".\data\\test_malicious_packages_final.json")
    benign_tests = pd.read_json(".\data\\test_benign_packages_final.json")
    
    mal_tests['label'] = 1
    benign_tests['label'] = 0
    
    test_dataset = pd.concat([mal_tests, benign_tests])
    test_dataset = test_dataset.sample(frac=1).reset_index(drop=True)
    test_dataset["setup.py"] = test_dataset["setup.py"].apply(lambda x: x[:300] if isinstance(x, str) else x)
    print(f"Test dataset loaded: {test_dataset.shape[0]} packages loaded.")
    return test_dataset



async def write_to_csv_async(file_path, data, header=['filename', 'label','llm_prediction', 'explanation']):
    """
    Asynchronously appends a row of data to a CSV file. Creates the file if it does not exist.

    Parameters:
        file_path (str): Path to the CSV file.
        data (list): A list representing a row to write.
        header (list, optional): Column headers (written only once if file is new).
    """
    file_exists = os.path.exists(file_path)

    async with aiofiles.open(file_path, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)

        # Write the header only if the file is new
        if not file_exists and header:
            await file.write(','.join(header) + '\n')  # Manually write headers (csv.writer does not support async)

        # Write the new row
        await file.write(','.join(map(str, data)) + '\n')  # Convert data to CSV format


async def simulate_test(llm, test_dataset):
    """
    Simulates the testing of the LLM model on the test dataset.
    """
    for index, row in tqdm(test_dataset.iterrows()):
        prompt = await get_prompt(row['package_name'],row["file_list"], row["setup.py"])
        try:
            response = await llm.call_llm(prompt, RESPONSE_FORMAT)
            try:
                response = json.loads(response)
            except json.JSONDecodeError:
                print(f"❌ Error: Could not decode JSON response: {response}")
                filename = row['package_name']
                label = row['label']
                llm_prediction = None
                explanation = response
                await write_to_csv_async(result_file, [filename, label, llm_prediction, explanation])
                continue
            filename = row['package_name']
            label = row['label']
            if model == "gpt":
                llm_prediction = response["result"]["prediction"]
                explanation = response["result"]["explanation"]
            elif model == "llama":
                llm_prediction = response["prediction"]
                explanation = response["explanation"]
            await write_to_csv_async(result_file, [filename, label, llm_prediction, explanation])
    
        except Exception as e:
            print(f"❌ Error: {e}")
if __name__ == "__main__":
    test_dataset = load_tests_files()
    llm = LLM(model_name, api_key)
    asyncio.run(simulate_test(llm, test_dataset))
