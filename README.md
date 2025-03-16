Here’s a refined version of your `README.md` with improved clarity, structure, and consistency:

```markdown
# mal-LLM

## Overview

This project evaluates the ability of **Large Language Models (LLMs)** to detect **malicious code**. The repository contains code for both:

1. **Retrieval-Augmented Generation (RAG) Experiments**
2. **Fine-Tuning Experiments**

---

## Repository Structure

### 🔹 RQ2: General LLM Capabilities  
**Can open-source LLMs detect malicious intent in code and packages as effectively as proprietary LLMs?**

- The scripts for these experiments are located in:  
  ```bash
  RQ_experiments/zero_shot_prompting_baseline_package_classifier
  ```
- To run the experiments, refer to the `README.md` file within the folder.

---

### 🔹 Retrieval-Augmented Generation (RAG) Experiments  
- All scripts for the **RAG Experiments** are stored in the:  
  ```bash
  RAG_experiments
  ```
- To start the RAG experiments, follow the instructions in the respective subfolder.

---

This refined version improves readability, structure, and conciseness while ensuring all key details are present. Let me know if you need any further modifications! 🚀
```



### 🔹 RQ4: Fine-Tuning Performance (Fine-Tuning LLaMA 3 (8B))  
- The fine-tuning code is in:  
  ```bash
  RQ_experiments/finetuning_experiments
  ```
- This folder contains the `Fine_tuning_llama_3_8b.ipynb` notebook, which provides a pipeline for **fine-tuning Meta’s LLaMA 3.1 (8B) model** to classify a package's code textual description as **benign** or **malicious**.
- The fine-tuning process leverages **LoRA (Low-Rank Adaptation)** and **4-bit quantization** to optimize training efficiency.

Refer to the `README.md` file within the folder for detailed setup and execution steps.

---

