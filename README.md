# AEGIS ML — Honest On-Device App Malware Classifier (P5 Model)

This repository contains the complete Machine Learning training, evaluation, benchmark suite, Android on-device integration, and **Inference REST API** for **AEGIS App Malware Detection (P5)**.

---

## 1. Problem Overview
AEGIS replaced fragile heuristic rule-based permission counting with a calibrated, on-device Machine Learning model that classifies installed APKs as Benign vs Malicious.

- **The Challenge:** Remote Access Trojans (e.g. **AndroRAT** `com.example.reverseshell2` disguised as "Google Service Framework") and legitimate business apps (e.g. enterprise CRM tools, password managers, classifieds) share overlapping sets of dangerous permissions (`CAMERA`, `READ_CONTACTS`, `LOCATION`, `SMS`).
- **The Solution:** A joint-distribution model over **80 static features** where **behavioral DEX bytecode signals** (`/system/bin/sh`, `ProcessBuilder`, `Socket`, `SmsManager`, `Runtime.exec`, `DexClassLoader`, `Base64`, `AccessibilityNodeInfo`) carry over 78% of the decision weight.

---

## 2. Real-World Labeled Corpus (AndroZoo 100K) — ZERO Label Leakage
The models are trained and evaluated on **real Android APKs** from the **AndroZoo / MH-100K** dataset:
- **Train Set:** 8,008 real APKs (1,601 malware, 6,407 benign).
- **Holdout Test Set:** 2,508 real APKs (251 malware, 2,257 benign, realistic ~10% malware base rate).
- **Zero Leakage:** No metadata is synthesized conditionally on the label.

---

## 3. Honest Performance & Evaluation Results

### Holdout Test Set (2,508 Real APKs)

| Model | ROC-AUC | PR-AUC | Brier Score | FPR @ 95% Recall |
| :--- | :--- | :--- | :--- | :--- |
| **Rule Engine (Old AEGIS Baseline)** | **0.6836** | **0.2202** | **0.1074** | **99.42%** |
| **Logistic Regression (L2 Baseline)** | **0.9519** | **0.6941** | **0.0732** | **17.15%** |
| **Random Forest** | **0.9572** | **0.7174** | **0.0663** | **15.68%** |
| **Calibrated Gradient Boosted Trees (P5 Model)** | **0.9595** | **0.7453** | **0.0425** | **12.80%** |

### Top Discriminative Features (Behavioral DEX Dominance):
1. `dex_shell_bin_sh` (`/system/bin/sh` or `su` command string): **`33.93%`**
2. `dex_total_suspicious_patterns` (DEX API call count): **`22.29%`**
3. `dex_base64_payload` (Base64 payload unpacking): **`12.93%`**
4. `dex_accessibility_dispatch` (`AccessibilityNodeInfo` click dispatching): **`4.74%`**
5. `dex_socket_direct` (`java.net.Socket` raw TCP networking): **`4.34%`**

---

## 4. Train / Serve Parity (Java 17 JVM vs Python)
- Evaluated against real `malware.apk` using compiled Java 17 bytecode parser (`JvmExtractor.java`) vs Python Androguard (`extractor.py`).
- **Result:** **100% Exact 80-Feature Alignment (Max Diff = `0.000043`, 0 / 80 mismatches)**.

---

## 5. Inference REST API & Swagger UI

```bash
# Start the API server on port 8000
uvicorn ml.api.server:app --host 127.0.0.1 --port 8000
```
- Open `http://127.0.0.1:8000/docs` in your browser.