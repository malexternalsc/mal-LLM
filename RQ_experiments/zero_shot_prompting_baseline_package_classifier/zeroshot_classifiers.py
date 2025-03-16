import json
import asyncio
import generate_prompt as gp
import response_formats as rf
from call_model import LLM
from typing import Dict, Any

class FileAnalyzer:
    def __init__(self, model: str, api_key: str):
        """
        Initializes the analyzer with the specified model and API key.
        """
        self.llm = LLM(model, api_key)

    async def analyze_file(self, file_name: str, file_content: str) -> Dict[str, Any]:
        """
        Uses LLM to analyze whether a file is malicious and provides a detailed explanation.
        """
        prompt = gp.generate_zeroshot_file_analysis_prompt(file_name, file_content)
        result_text = await self.llm.call_llm(prompt,rf.RESPONSE_FORMAT)

        try:
            # ✅ Convert string response to a dictionary
            result_json = json.loads(result_text)
            
            if self.llm.USE_HUGGINGFACE:
                classification = result_json["Predicted Classification"]
                score = result_json["Malicious Score"]
                explanation = result_json["Explanation"]
            else:
                classification = result_json['result']["Predicted Classification"]
                score = result_json['result']["Malicious Score"]
                explanation = result_json['result']["Explanation"]

            return {"classification": classification, "score": score, "explanation": explanation}
        
        except json.JSONDecodeError as e:
            print(f"❌ JSON Parsing Error: {e}")
            return {"classification": "Unknown", "score": 0, "explanation": "Error parsing response."}

async def classify_files(files_data: Dict[str, Dict[str, str]], model: str, api_key: str) -> Dict[str, Any]:
    """
    Processes multiple files, assigns a classification, and determines an overall package risk assessment.
    """
    analyzer = FileAnalyzer(model=model, api_key=api_key)
    results = {}
    malicious_count, benign_count, total_score = 0, 0, 0
    package_info = ""
    for filename, file_info in files_data.items():
        content = file_info["content"]
        analysis_result = await analyzer.analyze_file(filename, content)

        # ✅ Ensure results match the required schema
        results[filename] = {
            "filename": filename,  # Ensure filename is properly assigned
            "result": {
                "Predicted Classification": analysis_result["classification"],
                "Malicious Score": analysis_result["score"],
                "Explanation": analysis_result["explanation"]
            }
        }

        # ✅ Generate a formatted package report
        package_info += (
            f"File {results[filename]['filename']} in {file_info['file path']}, "
            f"was predicted as {results[filename]['result']['Predicted Classification']}, "
            f"with a malicious score of {results[filename]['result']['Malicious Score']}, "
            f"based on the following reasons: {results[filename]['result']['Explanation']}.\n"
        )

        # ✅ Update counters for malicious and benign files
        total_score += analysis_result["score"]
        if analysis_result["classification"] == "Malicious":
            malicious_count += 1
        else:
            benign_count += 1

    # ✅ Compute the average malicious score
    avg_malicious_score = total_score / len(files_data)

        
    overall_prompt = gp.generate_overall_analysis_prompt(malicious_count, benign_count, avg_malicious_score,package_info)
    overall_result_text = await analyzer.llm.call_llm(overall_prompt, rf.OVERALL_RESPONSE_FORMAT)
    try:
        
        
        
        # ✅ Convert overall response to dictionary
        overall_result = json.loads(overall_result_text)
        if analyzer.llm.USE_HUGGINGFACE:
            results["overall_prediction"] = overall_result["overall Classification"]
            results["overall_malicious_score"] = overall_result["overall Malicious Score"]
            results["overall_explanation"] = overall_result["overall Explanation"]
        else:
            results["overall_prediction"] = overall_result['result']["overall Classification"]
            results["overall_malicious_score"] = overall_result['result']["overall Malicious Score"]
            results["overall_explanation"] = overall_result['result']["overall Explanation"]

    except json.JSONDecodeError as e:
        print(f"❌ JSON Parsing Error: {e}")
        results["overall_prediction"] = "Unknown"
        results["overall_malicious_score"] = 0
        results["overall_explanation"] = "Error parsing overall response."

    return results


