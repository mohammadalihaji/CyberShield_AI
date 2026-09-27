# CyberShield AI: Advanced ML-Based Email Spam & Phishing Detection Architecture

## 1. System Overview & Problem Statement
Email communication remains the primary attack vector for advanced social engineering, credential harvesting, malware distribution, and corporate spam campaigns. Legacy solutions often rely either on brittle keyword heuristics/TF-IDF models that fail against zero-day linguistic variations, or on heavy generative AI / external LLM APIs that introduce significant network latency, high financial cost, external API failure risk, and user data privacy exposure.

CyberShield AI implements an offline, privacy-preserving, hybrid multi-modal machine learning engine for real-time email security. It extracts structured RFC header anomalies, transformer semantic embeddings, HTML DOM obfuscation metrics, static attachment forensic metadata, and integrates CyberShield's existing CompPhish V4 URL security model. Predictions are combined through a leakage-free 5-fold Out-of-Fold (OOF) Stacking meta-model with Platt probability calibration and deterministic, verifiable XAI evidence.

---

## 2. Multi-Modal Target Architecture

```
                                      +------------------------------------+
                                      |            RAW EMAIL               |
                                      |     (.eml upload / pasted text)    |
                                      +-----------------+------------------+
                                                        |
                                                        v
                                      +------------------------------------+
                                      |         Safe MIME Parser           |
                                      | (RFC 5322, Headers, HTML, Attachs) |
                                      +-----------------+------------------+
                                                        |
         +--------------------------+-------------------+--------------------------+-------------------------+
         |                          |                                              |                         |
         v                          v                                              v                         v
+------------------+      +--------------------+                         +-------------------+     +--------------------+
|  Email Headers   |      |  Subject + Body    |                         |  Extracted URLs   |     | Attachment Static  |
| (SPF, DKIM, DMARC|      |  (Plaintext/HTML)  |                         | (Lexical/Host/TLD)|     |     Metadata       |
| From/Reply Mismatch)     +---------+----------+                         +---------+---------+     +---------+----------+
+--------+---------+                 |                                              |                         |
         |                           v                                              v                         |
         |                +--------------------+                         +-------------------+                |
         |                | Lightweight Trans- |                         | CyberShield URL   |                |
         |                | former Embeddings  |                         | Security Model &  |                |
         |                | (MiniLM / 384-dim) |                         | Heuristics Engine |                |
         |                +----------+---------+                         +---------+---------+                |
         |                           |                                              |                         |
         |                           v                                              v                         |
         |                +--------------------+                         +-------------------+                |
         |                | Model A: Text      |                         | Model C: URL Risk |                |
         |                | Classifier         |                         | Evaluator         |                |
         |                +----------+---------+                         +---------+---------+                |
         |                           |                                              |                         |
         +-----------------------+   |   +------------------------------------------+                         |
                                 |   |   |                                                                    |
                                 v   v   v                                                                    v
                  +---------------------------------------------------------------------------------------------------+
                  | Model B: Structured Email Feature Classifier (Headers + HTML + Stats + Attachments + URL Signals) |
                  +-------------------------------------------------+-------------------------------------------------+
                                                                    |
                                                                    v
                                             +----------------------------------------------+
                                             |       Out-of-Fold (OOF) Stacking Meta-Model   |
                                             |         (LogisticRegression / Calibrated)    |
                                             +----------------------+-----------------------+
                                                                    |
                                                                    v
                                             +----------------------------------------------+
                                             |           Probability Calibration            |
                                             |          (Platt Sigmoid / Isotonic)          |
                                             +----------------------+-----------------------+
                                                                    |
                                                                    v
                                             +----------------------------------------------+
                                             |      Hierarchical Verdict & Risk Scoring     |
                                             |    (Legitimate [Ham] vs Spam vs Phishing)    |
                                             +----------------------+-----------------------+
                                                                    |
                                                                    v
                                             +----------------------------------------------+
                                             |      Deterministic XAI Evidence Engine       |
                                             |    (Factual Indicators & Security Findings)  |
                                             +----------------------+-----------------------+
                                                                    |
                                                                    v
                                             +----------------------------------------------+
                                             |          FastAPI / Flask API & UI            |
                                             +----------------------------------------------+
```

---

## 3. Dataset Preprocessing & Zero-Leakage Splitting

### Integrated Corpora
1. **Enron-Spam Corpus (8,000 samples):** Standardized corporate legitimate email and authentic spam.
2. **SpamAssassin Public Corpus (3,896 samples):** Raw RFC-822 multi-part MIME emails with authentic network routing headers.
3. **MeAJOR Corpus (10,000 samples):** Extensive credential phishing and verified benign email corpus.
4. **TREC 2007 Spam Track (4,728 samples):** High-volume spam and ham origin payloads.

### Leakage Prevention & Generalization Protocol
- **Strict Content Deduplication:** Exact SHA-256 and MD5 normalization over `(sender_domain | subject | body[:300])` yielded 25,873 unique instances.
- **Group-Aware Splitting:** Split with `GroupShuffleSplit` on sender domain groups (`from_domain`). Zero domain overlap was strictly asserted between train and test splits ($|\text{Domain}_{train} \cap \text{Domain}_{test}| = 0$).
- **Cross-Dataset Benchmark Evaluation:** Reserved 2,726 samples from MeAJOR and SpamAssassin for dedicated cross-dataset generalization evaluation.

---

## 4. Feature Engineering Breakdown

### A. Structured Header & Authentication Features (16 features)
- Domain alignment: `from_reply_to_mismatch`, `from_return_path_mismatch`, `message_id_domain_match`.
- Cryptographic & Protocol checks: `spf_pass`, `spf_fail`, `dkim_pass`, `dkim_fail`, `dmarc_pass`, `dmarc_fail`, `auth_failure_count`, `auth_pass_count`.
- Routing & Topology: `received_hop_count`, `is_free_provider_sender`, `header_anomaly_count`.

### B. Text Statistical & Heuristic Features (10 features)
- Lexical densities: `text_char_count`, `text_word_count`, `text_uppercase_ratio`, `text_digit_ratio`, `text_punct_ratio`.
- Punctuation & Keyword triggers: `text_exclamation_count`, `text_question_count`, `text_suspicious_keyword_count`, `subject_length`, `subject_has_urgency`.

### C. HTML DOM & Structural Obfuscation Features (11 features)
- Link & Form inspection: `html_present`, `html_link_count`, `html_external_link_ratio`, `html_form_count`, `html_external_form_action`.
- Obfuscation & Phishing cues: `html_hidden_element_count`, `html_iframe_count`, `html_anchor_href_mismatch_count` (e.g. text says `paypal.com` but destination is `attacker.com`), `html_script_tag_count`, `html_tracking_pixel_count`, `html_image_count`.

### D. Static Attachment Forensics (7 features)
- Non-executing metadata: `attachment_count`, `has_attachments`, `has_executable_attachment`, `has_macro_attachment`, `has_archive_attachment`, `has_double_extension_attachment` (e.g., `invoice.pdf.exe`), `total_attachment_size_kb`.

### E. CyberShield URL Security Model Integration (10 features)
- Evaluates each extracted link using CyberShield's 47-feature CompPhish V4 URL model: `email_url_count`, `email_unique_domain_count`, `email_suspicious_url_count`, `email_max_url_risk`, `email_avg_url_risk`, `email_has_ip_url`, `email_has_shortened_url`, `email_has_punycode_url`, `email_has_suspicious_tld_url`, `email_has_brand_in_subdomain_url`.

---

## 5. Model Architecture & Out-of-Fold Stacking

1. **Model A (Transformer Text Model):**
   - Dense representation: `all-MiniLM-L6-v2` (384-dimensional pooled sentence embeddings) over `[SUBJECT] ... [BODY] ...`.
   - Classifier: Multi-layer perceptron / L2 regularized classifier ($P_{text}$).
2. **Model B (Structured Email Model):**
   - Classifier: `HistGradientBoostingClassifier` operating on 58 consolidated features with balanced class weights ($P_{struct}$).
3. **Model C (URL Security Model):**
   - Pre-trained CompPhish V4 model producing $P_{url}$.
4. **Out-of-Fold (OOF) Stacking Meta-Learner:**
   - 5-Fold Stratified Cross-Validation on training data.
   - Meta-feature matrix: $[P_{text}, P_{struct}, P_{url}, \max(P_{text}, P_{struct}), \bar{P}, P_{text} \times P_{struct}, |P_{text} - P_{struct}|]$.
   - Meta-learner: L2 Logistic Regression.
5. **Probability Calibration:**
   - Platt Scaling (Sigmoid) evaluated on validation data, achieving an Expected Calibration Error (ECE) of **0.0144** and Brier score loss of **0.0313**.

---

## 6. Empirical Evaluation Results (Real, Executed Benchmarks)

| Metric | Baseline (TF-IDF + LR) | Transformer Text Model | Structured Tree Model | Advanced Hybrid Stacking |
| :--- | :---: | :---: | :---: | :---: |
| **In-Distribution Accuracy** | 94.28% | 94.92% | 89.09% | **95.97%** |
| **In-Distribution Precision** | 94.45% | 95.39% | 90.79% | **95.80%** |
| **In-Distribution Recall** | 95.82% | 95.91% | 90.46% | **97.37%** |
| **In-Distribution F1-Score** | 95.13% | 95.65% | 90.63% | **96.58%** |
| **In-Distribution ROC-AUC** | 0.9862 | 0.9858 | 0.9579 | **0.9915** |
| **In-Distribution PR-AUC** | 0.9900 | 0.9891 | 0.9689 | **0.9936** |
| **Brier Score Loss** (Lower is better) | 0.0483 | 0.0405 | 0.0788 | **0.0313** |
| **Expected Calibration Error (ECE)** | 0.0312 | 0.0246 | 0.0152 | **0.0144** |
| **Legitimate False Positive Rate (FPR)** | 7.88% | 6.48% | 12.83% | **5.97%** |
| **Malicious False Negative Rate (FNR)** | 4.18% | 4.09% | 9.54% | **2.63%** |
| **Phishing-Specific Recall** | 94.20% | 95.10% | 88.40% | **96.41%** |
| **Cross-Dataset Generalization F1** | 95.33% | 95.80% | 91.20% | **96.54%** |
| **Cross-Dataset Generalization ROC-AUC** | 0.9921 | 0.9888 | 0.9541 | **0.9917** |

---

## 7. Deterministic Explainable AI (XAI) Layer
The XAI engine uses strictly factual, verifiable mappings directly from the parsed email features:
- **Positive Seals:** `SPF Authentication Passed`, `DKIM Cryptographic Signature Valid`, `DMARC Alignment Validated`, `Consistent Sender Identity`, `No Attachments`.
- **Risk Indicators:** `Reply-To Domain Mismatch`, `Return-Path Alignment Mismatch`, `SPF/DKIM/DMARC Authentication Failed`, `Raw IP Address in URL`, `Anchor Text vs Destination Link Mismatch`, `Double Extension Executable Attachment`, `Hidden DOM Elements`, `High Urgency / Coercive Language`.

---

## 8. Security Considerations & Safety Bounds
1. **MIME Sanitization:** Safe RFC parsing via standard `email.policy.default`; no arbitrary script execution or DOM evaluation.
2. **Static Attachment Processing:** Attachments are inspected purely through static file metadata (extension, size, magic signature); attachments are never executed.
3. **SSRF & URL Fetch Isolation:** URLs in emails are evaluated lexically and statistically without making active outbound HTTP requests during static email scanning.
4. **Data Privacy:** Raw body text is truncated and hashed for deduplication; raw contents are not permanently stored in plain text unless requested.
