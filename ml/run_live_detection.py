import os, sys, json
import numpy as np
import joblib

sys.path.insert(0, os.path.abspath("."))
from ml.features.extractor import extract_features_from_apk, explain_prediction, FEATURE_SPEC

apk_path = r"C:\Users\user\Downloads\60648a8e5ee28177de38e6ea40c17481b95a63e6aa4ca466754bc7e7f08bd2ab.apk"

print("="*80)
print("LIVE HONEST DETECTION RUN")
print(f"Target APK: {apk_path}")
print("="*80)

# Check file exists and size
if not os.path.exists(apk_path):
    print("ERROR: File not found!")
    sys.exit(1)

size_bytes = os.path.getsize(apk_path)
print(f"File Size: {size_bytes} bytes ({size_bytes/(1024*1024):.2f} MB)")

# Extract 88 features
vec = extract_features_from_apk(apk_path, is_sideloaded=True)
print(f"\nExtracted Feature Vector: {len(vec)} dimensions")
non_zeros = np.where(vec > 0)[0]
print(f"Non-Zero Feature Count: {len(non_zeros)}")

# Load GBT and Calibrated GBT
gbt_raw = joblib.load("ml/models/saved_models/gbt_model.joblib")
gbt_cal = joblib.load("ml/models/saved_models/calibrated_gbt.joblib")
importances = np.load("ml/models/saved_models/feature_importances.npy")

p_raw = float(gbt_raw.predict_proba(vec.reshape(1, -1))[0, 1])
p_cal = float(gbt_cal.predict_proba(vec.reshape(1, -1))[0, 1])

print("\n--- MODEL PREDICTION ---")
print(f"Raw GBT Malice Probability:        {p_raw:.4f}")
print(f"Calibrated GBT Malice Probability: {p_cal:.4f}")
print(f"Operating Alert Threshold:         0.1600")

verdict_cal = "MALWARE / THREAT" if p_cal >= 0.1600 else "SAFE"
verdict_raw = "MALWARE / THREAT" if p_raw >= 0.1600 else "SAFE"

print(f"\nVerdict under Calibrated Model:    {verdict_cal}")
print(f"Verdict under Raw GBT Model:       {verdict_raw}")

print("\n--- NON-ZERO FEATURE BREAKDOWN ---")
for idx in non_zeros:
    feat = FEATURE_SPEC["features"][idx]
    print(f"  [{idx:02d}] {feat['name']:<35} = {vec[idx]:.4f} (Weight: {importances[idx]:.4f}) -> {feat['description']}")