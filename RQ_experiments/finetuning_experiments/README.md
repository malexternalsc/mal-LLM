# Fine-Tuning

### RQ4: Fine-Tuning Performance  
**How well does a fine-tuned open-source LLM perform in detecting malicious code?**

This folder contains the fine-tuning pipeline for **Meta’s LLaMA 3.1 (8B) model**, specifically adapted for classifying a package's code textual description as **benign** or **malicious**. The fine-tuning process utilizes **LoRA (Low-Rank Adaptation)** and **4-bit quantization** to enhance training efficiency.

---

## Folder Structure

- `data/` – Contains processed datasets used for fine-tuning the **LLaMA 3.1 (8B)** model:
  - `test.csv`
  - `train.csv`
  - `validation.csv`
- `Fine_tuning_llama_3_8b.ipynb` – Jupyter Notebook providing the complete fine-tuning pipeline.

---

## Prerequisites

1. **Access to Meta’s LLaMA 3.1 (8B) model**  
   - You must have access to Meta’s **LLaMA 3.1 (8B)** gated repository on **Hugging Face**.
   - Ensure you are logged in to your **Hugging Face** account before running the notebook.

2. **Hardware Requirements**
   - A **GPU** is required for efficient fine-tuning.

