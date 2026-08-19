# AEGIS ML — Real-World On-Device App Malware Classifier (P5 Model)

This repository contains the complete Machine Learning training, evaluation, benchmark suite, and Android on-device integration for **AEGIS App Malware Detection (P5)**.

---

## 1. Problem Overview
AEGIS replaced simple rule-based permission counting with a calibrated, on-device Machine Learning model that classifies installed APKs as Benign vs Malicious.

- **The Challenge:** Live Remote Access Trojans (e.g. **AndroRAT** `com.example.reverseshell2` disguised as "Google Service Framework") and legitimate business apps (e.g. sideloaded enterprise CRM tools) often hold similar sets of dangerous permissions.
- **The Solution:** A joint-distribution model over **80 static features** across permissions, DEX bytecode API calls (`ProcessBuilder`, `Socket`, `SmsManager`, `Runtime.exec`, `DexClassLoader`, IMEI harvesting), manifest topology, signing provenance, and legacy `targetSdkVersion <= 22` auto-grant tells.

---

## 2. Real-World Labeled Corpus (AndroZoo 100K)
The models are trained and evaluated on **real Android APKs** from the **AndroZoo / MH-100K** dataset (101,934 samples):
- **Train Set:** 8,006 real APKs (1,600 malware, 6,406 benign).
- **Holdout Test Set:** 2,507 real APKs (251 malware, 2,256 benign, realistic ~10% malware base rate).

---

## 3. Real Performance & Evaluation Results

### Holdout Test Set (2,507 Real APKs)

| Model | ROC-AUC | PR-AUC | Brier Score | FPR @ 95% Recall |
| :--- | :--- | :--- | :--- | :--- |
| **Rule Engine (Old AEGIS Baseline)** | **0.9187** | **0.6172** | **0.0666** | **38.12%** |
| **Logistic Regression (L2 Baseline)** | **0.9820** | **0.9100** | **0.0530** | **10.86%** |
| **Random Forest** | **0.9835** | **0.9137** | **0.0570** | **9.80%** |
| **Calibrated Gradient Boosted Trees (P5 Model)** | **0.9869** | **0.9285** | **0.0233** | **7.98%** |

### Per-Malware Family Recall Breakdown:
- **Banking Trojans**: **97.3%** (73 / 75)
- **Droppers & Dynamic Loaders**: **94.7%** (54 / 57)
- **RATs & Spyware**: **94.2%** (65 / 69)
- **SMS Fraud**: **94.0%** (47 / 50)

### Zero-Tolerance Allowlist Hard Gate
Evaluated on curated Indian UPI/banking apps and top Play Store charts:
- **YONO SBI** (`com.sbi.lotusintouch`): **`0.0019` (SAFE)** — `[PASS]`
- **PhonePe** (`com.phonepe.app`): **`0.0042` (SAFE)** — `[PASS]`
- **Paytm** (`net.one97.paytm`): **`0.0042` (SAFE)** — `[PASS]`
- **Google Pay** (`com.google.android.apps.nbu.paisa.user`): **`0.0019` (SAFE)** — `[PASS]`
- **WhatsApp Messenger** (`com.whatsapp`): **`0.0026` (SAFE)** — `[PASS]`
- **Velox Field CRM** (`com.enterprise.salescrm`): **`0.1322` (SAFE)** — `[PASS]`

### Acceptance Test on Real APK
- **Real AndroRAT APK (`malware.apk`):** `99 / 100` (**CRITICAL / MALWARE**)
- **Benign Sideloaded CRM (`Biz Drive`):** `13 / 100` (**SAFE**)

### Train / Serve Parity (Python vs Java 17 JVM)
- **Target:** `malware.apk`
- **Result:** **100% Exact 80-Feature Alignment (Max Diff = `0.000043`, 0 / 80 mismatches)**.

### On-Device Footprint & Latency
- **Model Size:** **740 KB** (`app/src/main/assets/aegis_malware_model.json`)
- **Inference Latency:** **0.34 ms / app** (over 2,930 apps/second)
- **Zero-Dependency:** Runs on pure Kotlin tree evaluator without external C++ or native runtime dependencies.

---

## 4. How to Run

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Extract real AndroZoo dataset
python ml/data/real_androzoo_pipeline.py

# 3. Train models
python ml/models/train.py

# 4. Run evaluation & allowlist hard gate
python ml/evaluation/evaluate.py

# 5. Run acceptance test on real malware.apk
python ml/evaluation/test_acceptance.py

# 6. Verify train/serve parity against Java 17 JVM
python ml/evaluation/verify_train_serve_parity.py

# 7. Run latency benchmark
python ml/evaluation/benchmark_latency.py

# 8. Export model to Android assets
python ml/export/exporter.py
```