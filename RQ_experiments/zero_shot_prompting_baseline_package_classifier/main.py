import json
import os
import asyncio
import dotenv
from pathlib import Path
from zeroshot_classifiers import classify_files  # Import the function directly

dotenv.load_dotenv()

# Define root directory
package_dir = Path("../data/structured_output_plain/sample_packages")
results_dir = Path("../Results/zero_shot_prompting_baseline_package_classifier/llama-3.3-70B-Instruct")  # Change to "gpt-4o" if using OpenAI
log_file_path = Path("../processed_files_log.txt") # Log file to keep track of processed packages

# Define Model and API Key
MODEL_NAME = "meta-llama/Llama-3.3-70B-Instruct"  # Change to "gpt-4o" if using OpenAI
API_KEY = os.getenv("HUGGING_FACE_KEY")  # Fetch API key chane to "OPENAI_API_KEY" if using OpenAI

# Validate API Key
if not API_KEY:
    raise ValueError("API Key not found! Set OPENAI_API_KEY in the environment.")

# Get all JSON files in the root directory and subdirectories
mal_packages_files = sorted(list(package_dir.rglob("*.json")))  # ✅ Enforce sorted order

# Get already processed files
processed_files = set()

async def process_files():
    for root, dirs, files in os.walk(results_dir):
        for file in files:
            processed_files.add(Path(root) / file)

    print(f"📂 Total JSON files found: {len(mal_packages_files)}")

    for mal_package in mal_packages_files:
        relative_path = mal_package.relative_to(package_dir)
        result_file = results_dir / relative_path

        if result_file in processed_files:
            print(f"⚠️ Skipping already processed file: {mal_package.name}")
            continue

        print(f'🚀 Processing package: {mal_package.name}')

        try:
            with open(mal_package, "r", encoding="utf-8") as file:
                files_data = json.load(file)

            # Debugging: Print order of files before classification
            print(f"🔍 Processing file: {mal_package.name}")

            # Run classification sequentially
            result = await classify_files(files_data, MODEL_NAME, API_KEY)

            # Ensure directory exists
            result_dir = result_file.parent
            result_dir.mkdir(parents=True, exist_ok=True)  

            # Save results
            with open(result_file, "w", encoding="utf-8") as json_file:
                json.dump(result, json_file, indent=4, ensure_ascii=False)

            # Update the log file
            with open(log_file_path, "a", encoding="utf-8") as log_file:
                log_file.write(f"{relative_path}\n")

            print(f"✅ Processed: {mal_package.name}") 
            
        except json.JSONDecodeError as e:
            print(f"❌ JSON error in {mal_package.name}: {e}")
        except Exception as e:
            print(f"❌ Error processing {mal_package.name}: {e}")
        finally:
            print(f"Finished processing package: {mal_package.name}")
            
# Run the async function
asyncio.run(process_files())
