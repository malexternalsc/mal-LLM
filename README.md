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

### 🔹RQ3: RAG-Enhanced LLM Capabilities
**Can RAG techniques improve the performance of open-source LLMs in detecting malicious intent in code and packages?**
    
- All scripts for this experiments are located in
 ``` 
RQ_experiments\RAG_experiments
  ```
- To start the RAG experiments, 
1. Set up the knowledge base by following instructions in the ```RQ_experiments\RAG_experiments\knowledge_base_setup\Readme.md``` 
2. Run the simple RAG exeriments by following the steps in ``` RQ_experiments\RAG_experiments\Simple_RAG```

3. Run the Corrective RAG exeriments by following the steps in ``` RQ_experiments\RAG_experiments\CRAG```


### 🔹 RQ4: Fine-Tuning Performance (Fine-Tuning LLaMA 3 (8B))  
- The fine-tuning code is in:  
  ```bash
  RQ_experiments/finetuning_experiments
  ```
- This folder contains the `Fine_tuning_llama_3_8b.ipynb` notebook, which provides a pipeline for **fine-tuning Meta’s LLaMA 3.1 (8B) model** to classify a package's code textual description as **benign** or **malicious**.
- The fine-tuning process leverages **LoRA (Low-Rank Adaptation)** and **4-bit quantization** to optimize training efficiency.

Refer to the `README.md` file within the folder for detailed setup and execution steps.

---

