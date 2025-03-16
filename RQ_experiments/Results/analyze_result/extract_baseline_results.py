import os
import json
import pandas as pd
from pathlib import Path
import argparse

parser = argparse.ArgumentParser(prog='Extract Result', description="Extracts the results of the Malware Detection model.")
parser.add_argument('--result_dir', '-r', type=str, help='The directory containing the Result JSON files.', required=True)
parser.add_argument('--output_file', '-o', type=str, help='The directory to save the extracted results.', required=False)

args = parser.parse_args()

# Define input directory
input_dir = Path(args.result_dir)

# List all JSON files
json_files = list(input_dir.rglob("*.json"))

# Initialize storage
result_data = []

# Process each JSON file
for json_file in json_files:
    malicious_files = []
    benign_files = []
    malicious_scores = []
    malicious_explanations = []
    
    with open(json_file, "r", encoding="utf-8") as file:
        data = json.load(file)

    # Extract individual file details
    for filename, details in data.items():
        if isinstance(details, dict) and "result" in details:
            classification = details["result"]["Predicted Classification"]
            score = details["result"]["Malicious Score"]
            explanation = details["result"]["Explanation"]

            if "malicious" in classification.lower():
                malicious_files.append(filename)
                malicious_scores.append(score)
                malicious_explanations.append(f"'{explanation}'")
                
            else:
                benign_files.append(filename)

    # Extract overall classification
    classification = data.get("overall_prediction", "Unknown")
    classification = 1 if "malicious" in classification.lower() else 0 if  "benign" in classification.lower() else -1
    
    overall_score = data.get("overall_malicious_score", 0)
    overall_explanation = data.get("overall_explanation", "No explanation available.")

    # Append results to list
    result_data.append({
        "package_name": json_file.stem.replace('.json', ''),
        "benign_files": benign_files,
        "malicious_files": malicious_files,
        "malicious_file_scores": malicious_scores,
        "malicious_file_explanations": malicious_explanations,
        "overall_classification": classification,
        "overall_Score": overall_score,
        "overall_Explanation": overall_explanation
    })

# Convert to DataFrame
result_df = pd.DataFrame(result_data)

# Save the results to a CSV file
if args.output_file:
    result_df.to_excel(f"{args.output_file}.xlsx", index=False)

print(f"✅ Extracted results saved to {args.output_file}.xlsx")
