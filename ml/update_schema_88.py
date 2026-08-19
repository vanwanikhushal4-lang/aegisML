"""
Comprehensive ML Feature Pipeline with Native Structural, Packaging & Anti-Analysis Dimensions (88 Features)
Natively trains GBT, Random Forest, Logistic Regression, and TFLite Neural Network on:
- 30 Permission Dimensions
- 19 DEX Bytecode Dimensions
- 12 Manifest Dimensions
- 6 Certificate Dimensions
- 9 Metadata Dimensions
- 4 Legacy Joint Tells
- 8 Structural, Packaging & Anti-Analysis Dimensions
"""

import os, sys, math, json, zipfile
from collections import Counter
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import roc_auc_score, average_precision_score, brier_score_loss, roc_curve

MODELS_DIR = os.path.abspath("ml/models/saved_models")
DATA_DIR = os.path.abspath("ml/data")

# 1. Expand Feature Spec to 88 Dimensions
NEW_FEATURES = [
    {"index": 80, "name": "struct_zip_anti_analysis", "type": "binary", "description": "Anti-analysis zip tampering (fake encryption bit flag 0x0001 or size mismatch)"},
    {"index": 81, "name": "struct_asset_max_entropy", "type": "continuous", "description": "Maximum Shannon entropy across asset files (entropy / 8.0)"},
    {"index": 82, "name": "struct_has_encrypted_asset_blob", "type": "binary", "description": "High-entropy encrypted payload blob present in assets (>50KB, entropy > 7.80)"},
    {"index": 83, "name": "struct_thin_dex_stub", "type": "binary", "description": "Thin DEX loader stub (<40KB) paired with native .so unpacker"},
    {"index": 84, "name": "struct_has_native_lib", "type": "binary", "description": "Presence of native .so shared libraries in lib/ or assets/"},
    {"index": 85, "name": "struct_webview_phishing_density", "type": "continuous", "description": "Density of financial card/credential harvesting strings in HTML/JS assets (count / 20.0)"},
    {"index": 86, "name": "joint_packed_sms_stealer", "type": "binary", "description": "Encrypted asset blob + SMS interception permissions + sideloaded"},
    {"index": 87, "name": "joint_tampered_dropper", "type": "binary", "description": "Anti-analysis zip header + Thin DEX stub + dynamic load/install permissions"}
]

print("="*80)
print("EXPANDING AEGIS FEATURE SPECIFICATION TO 88 DIMENSIONS")
print("="*80)

with open("app/src/main/assets/feature_spec.json", "r", encoding="utf-8-sig") as f:
    spec = json.load(f)

# Ensure no duplicate entries
spec["features"] = [f for f in spec["features"] if f["index"] < 80]
for nf in NEW_FEATURES:
    spec["features"].append(nf)
spec["num_features"] = 88

with open("app/src/main/assets/feature_spec.json", "w", encoding="utf-8") as f:
    json.dump(spec, f, indent=2)
with open("ml/export/feature_spec.json", "w", encoding="utf-8") as f:
    json.dump(spec, f, indent=2)

print(f"Updated feature_spec.json: {spec['num_features']} total dimensions.")