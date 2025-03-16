from langchain_core.messages import (
    HumanMessage,
    SystemMessage,
)



def generate_zeroshot_file_analysis_prompt(file_name, file_content):
    """
    Generates a structured prompt for LLM analysis of an individual file.
    """
    messages=[
        {
            "role": "developer", 
            "content": f"You are a cybersecurity expert analyzing potential malware. \
    Read the file content in {file_name} below and determine if it is Malicious or Benign. \
    Explain your decision in detail. \
    Answer in this format: \
    - **Predicted Classification**: (Malicious or Benign) \
    - **Malicious Score**: (0-100, where 100 means highly malicious) \
    - **Explanation**: (Brief description of why is it classified this way in two sentences?)"
        },
        {
            "role": "user", 
            "content": f"file content: {file_content}"
        }
    ] 

    return messages


def generate_overall_analysis_prompt(malicious_count, benign_count, avg_malicious_score,package_info):
    """
    Generates a structured prompt for LLM to determine overall package risk.
    """
    messages =[
        {
            "role": "user", 
                "content": """Given the analysis of multiple files in a package, determine the overall risk.
                Number of Malicious Files: {malicious_count}
                Number of Benign Files: {benign_count}
                Average Malicious Score: {avg_malicious_score:.2f}
                Answer in this format: 
                - **Ovearall Classification**: (Malicious or Benign) 
                - **overall Malicious Score**: (0-100, where 100 means highly malicious)
                - **overall Explanation**: (Brief description of why is it classified this way in two sentences?)"""
                },
            {
                "role": "user",
    "content":f'''Provide a summary explanation about whether the overall package should be classified as malicious or benign given this info{package_info}.
            '''}
    ]

    return messages
    