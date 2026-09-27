# Model Card: CyberShield AI Multi-Modal Email Security Model

## Model Details
- **Model Name:** CyberShield-Email-Security-v1
- **Developer:** CyberShield AI Security Engineering Team
- **Model Type:** Multi-Modal Stacking Ensemble with Probability Calibration
- **Base Components:**
  1. *Model A (Text):* `all-MiniLM-L6-v2` dense embeddings + Multi-Layer Perceptron / Regularized Linear Classifier
  2. *Model B (Structure):* `HistGradientBoostingClassifier` (58 structured header, HTML, attachment, and lexical features)
  3. *Model C (URL Security):* CyberShield CompPhish V4 Random Forest Model
  4. *Meta-Learner:* 5-Fold Out-of-Fold (OOF) Logistic Regression Stacking + Platt Calibrator
- **Feature Schema Version:** 1.0.0
- **Release Date:** September 2026

---

## Intended Use
- **Primary Use:** Local, real-time detection and risk-scoring of email spam, credential phishing, spoofing, and malicious email lures without transmitting sensitive email content to external third-party LLM providers.
- **Input Formats:** RFC 5322 `.eml` raw MIME byte streams, pasted email text, or separated sender/subject/body fields.
- **Output:** Calibrated malicious probability $[0.0, 1.0]$, categorical verdict (`Safe`, `Suspicious`, `Malicious`), 3-way distribution (`legitimate`, `spam`, `phishing`), sub-model signal breakdown, and deterministic XAI evidence points.

---

## Out-of-Scope & Misuse
- **Malware Sandbox Emulation:** This model performs static attachment metadata inspection (extension, MIME, dual-extensions) and does not perform dynamic binary detonating or reverse engineering.
- **Sole Source of Truth for Legal Action:** Calibrated probabilities represent statistical risk under observed data distributions; high-stakes containment decisions should pair model scores with human security analyst review.

---

## Training & Evaluation Data
- **Training Corpora:**
  - Enron-Spam Corpus (8,000 samples)
  - SpamAssassin Public Corpus (3,896 samples)
  - MeAJOR Phishing & Benign Corpus (10,000 samples)
  - TREC 2007 Spam Track (4,728 samples)
- **Total Training Samples:** 19,238 samples (100% zero domain leakage asserted).
- **Validation Holdout:** 2,021 samples.
- **In-Distribution Test Holdout:** 1,888 samples.
- **Cross-Dataset Generalization Test Holdout:** 2,726 samples (held-out SpamAssassin and MeAJOR instances).

---

## Empirical Benchmark Performance

| Evaluation Split | Accuracy | Precision | Recall | F1-Score | ROC-AUC | PR-AUC | Brier Score | ECE |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **In-Distribution Test** | **95.97%** | **95.80%** | **97.37%** | **96.58%** | **0.9915** | **0.9936** | **0.0313** | **0.0144** |
| **Cross-Dataset (OOD)** | **96.55%** | **97.04%** | **96.04%** | **96.54%** | **0.9917** | **0.9927** | **0.0284** | **0.0079** |

- **Phishing Specific Recall (In-Dist):** 96.41%
- **Phishing Specific Recall (Cross-Dataset):** 96.13%
- **Legitimate Email False Positive Rate (FPR):** 5.97% (In-Dist) / 2.94% (Cross-Dataset)

---

## Known Limitations & Biases
1. **Punycode / IDN Obfuscation:** While lexical and punycode flags are extracted, highly novel zero-day homoglyph scripts may have reduced visual representation in ASCII tokenizers.
2. **Missing Network Headers in Pasted Text:** When users paste plain body text without RFC headers, header authentication features (`spf_pass`, `dkim_pass`, `received_hops`) default to neutral/missing states, placing reliance on text embeddings and URL heuristics.
3. **Encrypted Attachments:** Password-protected archive attachments (`.zip` / `.7z`) cannot have internal payloads statically inspected; they are flagged with archive indicators for caution.
