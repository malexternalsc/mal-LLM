# mal-LLM
This project consists of code used to evaluate the ability of LLM to detect malicious code.

## Fine-Tuning LLaMA 3 (8B)

This repository provides a pipeline for **fine-tuning Meta’s LLaMA 3.1 (8B) model to classify package's code textual description as benign or malicious**. The fine-tuning process leverages **LoRA (Low-Rank Adaptation)** and **4-bit quantization** to optimize training efficiency.


### Prerequisites
- You **must** have access to Meta’s **LLaMA 3.1 (8B)** gated repository on **Hugging Face**.
- Log in to your **Hugging Face** account before, as you see in notebook.