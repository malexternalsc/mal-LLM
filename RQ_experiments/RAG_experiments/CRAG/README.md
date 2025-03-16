
# Corrective RAG (CRAG) Experiments

## RQ3: RAG-Enhanced LLM Capabilities  
**Can Retrieval-Augmented Generation (RAG) techniques improve the performance of open-source LLMs in detecting malicious intent in code and packages?**

This experiment designs a **Corrective RAG (CRAG) pipeline** that enhances the standard RAG approach by **evaluating the importance and relevance of retrieved knowledge** before it is used for classification by the **LLM model**.

---

## Folder Structure

- `retrieval_evaluator.py` – Evaluates whether the retrieved knowledge is important or not.
- `retrieval_relevance_level.py` – Assesses the significance of the retrieved information.
- `classify_packages.py` – Handles classification tasks based on refined retrieval data.
- `main_crag_code_flow.py` – Main script executing the **CRAG pipeline** using code-based retrieval.
- `main_crag_ast_flow.py` – Main script executing the **CRAG pipeline** using **Abstract Syntax Tree (AST) analysis dataset used for training

---

## Running the Experiment

To execute the experiment, run either of the following:

```bash
python main_crag_code_flow.py
```

or

```bash
python main_crag_ast_flow.py
```

---

## Requirements

1. **Access to the LLM Model** – Ensure you have access to the **LLaMA 3.1 (8B) model**.
2. **Hugging Face API Token** – Create a Hugging Face token and save it in a `.env` file.
3. **Knowledge Base Setup** – Follow the instructions in the `Knowledge_base_setup/README.md` to create the necessary knowledge base.

