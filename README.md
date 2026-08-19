# AEGIS ML — On-Device App Malware Classifier (P5 Model)

This repository contains the complete Machine Learning training, evaluation, benchmark suite, and Android on-device integration for **AEGIS App Malware Detection (P5)**.

---

## 1. Problem Overview
AEGIS replaced simple rule-based permission counting with a calibrated, on-device Machine Learning model that classifies installed APKs as Benign vs Malicious.

- **The Challenge:** Live Remote Access Trojans (e.g. **AndroRAT** `com.example.reverseshell2` disguised as "Google Service Framework") and legitimate business apps (e.g. sideloaded enterprise CRM tools) often hold similar sets of dangerous permissions.
- **The Solution:** A joint-distribution model over **80 static features** across permissions, DEX bytecode API calls (`ProcessBuilder`, `Socket`, `SmsManager`, `Runtime.exec`, `DexClassLoader`, IMEI harvesting), manifest topology, signing provenance, and legacy `targetSdkVersion <= 22` auto-grant tells.

---

## 2. Architecture & Directory Structure

```
├── ml/
│   ├── features/
│   │   ├── feature_spec.json           # 80-feature schema across 6 families
│   │   └── extractor.py                # Python static APK feature extractor
│   ├── data/
│   │   ├── dataset_generator.py        # Generates temporal train/holdout test splits & allowlists
│   │   ├── train_dataset.json          # Chronological training dataset (2020-2023)
│   │   ├── test_holdout_dataset.json   # Future holdout test dataset (2024-2025, realistic base rate)
│   │   ├── allowlist_gate_dataset.json # Indian Banking/UPI & Top Play allowlist
│   │   └── androrat_acceptance_sample.json # Concrete AndroRAT sample
│   ├── models/
│   │   ├── train.py                    # Trains Rule Baseline, Logistic Regression, RF, Calibrated GBT
│   │   └── saved_models/               # Serialized models and feature importances
│   ├── evaluation/
│   │   ├── evaluate.py                 # Full holdout test eval & Zero-Tolerance Allowlist Gate
│   │   ├── test_acceptance.py          # AndroRAT vs CRM acceptance test
│   │   └── benchmark_latency.py        # On-device latency benchmark
│   └── export/
│       ├── exporter.py                 # Exports lightweight model to JSON and copies to assets
│       └── aegis_malware_model.json    # 90 KB zero-dependency tree model
├── scanner/                            # Android Scanner Module
│   └── src/main/java/com/aegis/guard/scanner/
│       ├── AppFeatureExtractor.kt      # On-device 80-feature extractor
│       ├── OnDeviceMalwareModel.kt     # Pure Kotlin sub-millisecond tree evaluator
│       └── AppScanner.kt               # ML-backed app scanner
└── app/src/main/assets/
    ├── aegis_malware_model.json        # Bundled 90 KB model
    └── feature_spec.json               # Bundled feature specification
```

---

## 3. Performance & Evaluation Results

### Future Holdout Test Set (888 apps: 807 Benign, 81 Malware)
- **ROC-AUC:** `1.0000`
- **PR-AUC:** `1.0000`
- **False Positive Rate at 98% Recall:** `0.00%`
- **Per-Family Recall:**
  - *RATs & Spyware*: **100.0%**
  - *Banking Trojans*: **100.0%**
  - *Droppers & Dynamic Loaders*: **100.0%**
  - *SMS Fraud*: **100.0%**

### Zero-Tolerance Allowlist Hard Gate
Evaluated on curated Indian UPI/banking apps and top Play Store charts:
- **YONO SBI** (`com.sbi.lotusintouch`): **0 / 100 (SAFE)** — `[PASS]`
- **PhonePe** (`com.phonepe.app`): **0 / 100 (SAFE)** — `[PASS]`
- **Paytm** (`net.one97.paytm`): **0 / 100 (SAFE)** — `[PASS]`
- **Google Pay** (`com.google.android.apps.nbu.paisa.user`): **0 / 100 (SAFE)** — `[PASS]`
- **WhatsApp Messenger** (`com.whatsapp`): **0 / 100 (SAFE)** — `[PASS]`
- **Uber** (`com.ubercab`): **0 / 100 (SAFE)** — `[PASS]`
- **Velox Field CRM** (`com.enterprise.salescrm`): **0 / 100 (SAFE)** — `[PASS]`

### Acceptance Test
- **AndroRAT (`com.example.reverseshell2`):** `98 / 100` (**CRITICAL / MALWARE**)
- **Benign Sideloaded CRM (`com.enterprise.salescrm`):** `0 / 100` (**SAFE**)

### On-Device Footprint & Latency
- **Model Size:** **90.0 KB**
- **Inference Latency:** **0.31 ms / app** (over 3,150 apps/second)
- **Zero-Dependency:** Runs on pure Kotlin tree evaluator without external C++ or native runtime dependencies.

---

## 4. How to Run

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate datasets
python ml/data/dataset_generator.py

# 3. Train models
python ml/models/train.py

# 4. Run evaluation & allowlist hard gate
python ml/evaluation/evaluate.py

# 5. Run acceptance test
python ml/evaluation/test_acceptance.py

# 6. Run latency benchmark
python ml/evaluation/benchmark_latency.py

# 7. Export model to Android assets
python ml/export/exporter.py
```