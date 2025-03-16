
# Simple RAG Experiments

## RQ3: RAG-Enhanced LLM Capabilities  
**Can Retrieval-Augmented Generation (RAG) techniques improve the performance of open-source LLMs in detecting malicious intent in code and packages?**

This folder contains three experiments utilizing a simple RAG technique to enhance the detection of malicious code:

1. **RAG using YARA rules as knowledge**
2. **RAG using GitHub security advisories**
3. **RAG using malicious `setup.py` scripts as reference samples**

These experiments leverage the **instruct model of Meta’s LLaMA 3.1 (8B)** for classification .



## Folder Structure

- `call_LLM.py` – Defines functions to interact with the LLM.
- `simulate_git_adv_rag.py` – Simulates RAG using GitHub advisory knowledge.
- `simulate_yara_rag.py` – Simulates RAG using YARA rules.
- `simulate_mal_code_rag.py` – Simulates RAG using sample malicious `setup.py` scripts.



## Requirements

1. **Access to the LLM Model** – Ensure you have access to the **LLaMA 3.1 (8B) model**.
2. **Hugging Face API Token** – Create a Hugging Face token and save it in a `.env` file.
3. **Knowledge Base Setup** – Follow the instructions in the `Knowledge_base_setup/README.md` to create the necessary knowledge base.

---

## Running the Experiments

Execute any of the experiments using the following commands for the experiment you are interested n:

```bash
python simulate_git_adv_rag.py
```

```bash
python simulate_yara_rag.py
```

```bash
python simulate_mal_code_rag.py
```
