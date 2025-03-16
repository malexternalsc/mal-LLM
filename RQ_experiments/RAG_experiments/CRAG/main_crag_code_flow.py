import retrieval_evaluator as retrieval_evaluator
import os
import json
import aiofiles
import csv
import pandas as pd
import argparse
import asyncio
from tqdm import tqdm
import dotenv
import retrieval_relevance_level as ret_rel_level
import retrieval_evaluator as ret_eval
import classify_package as classify_package

from langchain_openai import OpenAIEmbeddings
from langchain_core.documents import Document
from langchain_postgres.vectorstores import PGVector



dotenv.load_dotenv()

parser = argparse.ArgumentParser(description="Simulate the testing of the LLM model on the test dataset.")
parser.add_argument("--result_file", "-r", type=str, help="where to save the results of the test.")

args = parser.parse_args()
result_file = args.result_file


DB_PARAMS = {
    "database": "malware_kb",
    "user": "malware_admin",
    "password": "admin_secure_password",
    "host": "localhost",
    "port": "5432"
}

embeddings = OpenAIEmbeddings(api_key=os.getenv("OPENAI_API_KEY"))

PGVECTOR_CONNECTION_STRING = (
    f"postgresql+psycopg://{DB_PARAMS['user']}:{DB_PARAMS['password']}@"
    f"{DB_PARAMS['host']}:{DB_PARAMS['port']}/{DB_PARAMS['database']}?options=-csearch_path=malware"
)

yara_vectorstore = PGVector(
    embeddings=embeddings,
    collection_name="malware.yara_rules2",
    connection=PGVECTOR_CONNECTION_STRING,
    use_jsonb=True,
    async_mode=False,
)

git_vectorstore = PGVector(
    embeddings=embeddings,
    collection_name="github_advisories",
    connection=PGVECTOR_CONNECTION_STRING,
    use_jsonb=True,
    async_mode=False,
)

async def retrieval_function(vectorstore, snippet:str):
  
    retrieved_docs = vectorstore.similarity_search(snippet, k=4)
    return retrieved_docs



def load_tests_files():
    """
    Loads test datasets from JSON files.
    """
    mal_tests = pd.read_json(".\data\\test_malicious_packages_final.json")
    benign_tests = pd.read_json(".\data\\test_benign_packages_final.json")

    mal_tests['label'] = 1
    benign_tests['label'] = 0

    test_dataset = pd.concat([mal_tests, benign_tests]).sample(frac=1).reset_index(drop=True)
    test_dataset["setup.py"] = test_dataset["setup.py"].apply(
    lambda x: f"first 300 bytes:{x[:300]}  \nlast 300 bytes:{x[-300:]}"if isinstance(x, str) and len(x) > 600 else x
)

    print(f"Test dataset loaded: {test_dataset.shape[0]} packages.")
    return test_dataset

async def evaluate_context_relevance(code_snippet, vectorstore):
    chosen_contexts =[]
    matched_rules = await retrieval_function(vectorstore=vectorstore, snippet=code_snippet)
    matched_rules_grade = await ret_eval.evaluate_documents(documents=[x.page_content for x in matched_rules],code_snippet= code_snippet)
    
    chosen_rules = [x for x,grade in zip(matched_rules,matched_rules_grade) if grade == 'yes']
    if chosen_rules:
        chosen_rules_relevance = await ret_rel_level.evaluate_documents(
            code_snippet=code_snippet, documents=[x.page_content for x in chosen_rules]
        )
        chosen_contexts = [rule.page_content for rule, level in zip(chosen_rules, chosen_rules_relevance) if level in ['high', 'medium']]
        return " \n".join(chosen_contexts) if chosen_contexts else 'No relevant context found'


async def generate_final_context(yara_context,git_context):
    if yara_context == 'No relevant context found' and git_context == 'No relevant context found':
            context = 'No relevant context found'
    elif yara_context == 'No relevant context found':
        context = f"Git advisories: \n{git_context}"
    elif git_context == 'No relevant context found':
        context = f"YARA rules: \n{yara_context}"
    else:
        context = f"YARA rules: \n{yara_context} \nGit advisories: \n{git_context}"
    return context

async def classify_pipeline(test_dataset):
    classified_packages = []
    with open(result_file, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            package_name = line.split(",")[0]
            classified_packages.append(package_name)

    for _, row in tqdm(test_dataset.iterrows(), total=test_dataset.shape[0]):
        try:
            package_name = row["package_name"]
            if package_name in classified_packages:
                continue
            code_snippet = row["setup.py"]
            label = row["label"]
            file_list = row["file_list"]
            print(f"Classifying package: {package_name}")
            if code_snippet is None:
                print(f"Error classifying package: {package_name}")
                continue   
            yara_context = await evaluate_context_relevance(code_snippet=code_snippet, vectorstore=yara_vectorstore)
            git_context = await evaluate_context_relevance(code_snippet=code_snippet, vectorstore=git_vectorstore)
            final_context = await generate_final_context(yara_context,git_context)
            
            package_name, llm_prediction, explanation = await classify_package.classify(package_name=package_name, code_snippet=code_snippet, contexts=final_context, file_list=file_list)
            
            await classify_package.write_to_csv_async(file_path=result_file, data=[package_name, label, llm_prediction, explanation])
        except Exception as e:
            print(f"Error classifying package: {package_name}")
            continue    

if __name__ == "__main__":
    test_dataset = load_tests_files()
    asyncio.run(classify_pipeline(test_dataset))
        
        
        
        
        
        
        
                                                                     
        
        
        
        

