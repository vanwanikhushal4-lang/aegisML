import os, sys, json
import numpy as np
import joblib

sys.path.insert(0, os.path.abspath("."))
from ml.features.extractor import extract_features_from_apk, explain_prediction, analyze_apk_structural, FEATURE_SPEC

apk_path = r"C:\Users\user\Downloads\60648a8e5ee28177de38e6ea40c17481b95a63e6aa4ca466754bc7e7f08bd2ab.apk"

print("="*80)
print("AEGIS COMPREHENSIVE APK ANALYSIS (ML + FORENSIC STRUCTURAL PACKER DETECTOR)")
print("="*80)

# 1. Structural Forensic Analysis
struct_res = analyze_apk_structural(apk_path)
print(f"\n[1] Forensic Structural Analysis:")
print(f"  * Anti-Analysis Zip Tampered:   {struct_res['zip_tampered']}")
print(f"  * High-Entropy Encrypted Asset: {struct_res['has_encrypted_asset']}")
print(f"  * Thin DEX + Native Loader:     {struct_res['thin_dex']}")
print(f"  * WebView Financial Phishing:   {struct_res['has_webview_phishing']}")
print(f"  * Structural Risk Score:        {struct_res['structural_score']}/100")

# 2. On-Device ML Model Inference
model = joblib.load("ml/models/saved_models/calibrated_gbt.joblib")
importances = np.load("ml/models/saved_models/feature_importances.npy")

vec = extract_features_from_apk(apk_path, is_sideloaded=True)
ml_prob = float(model.predict_proba(vec.reshape(1, -1))[0, 1])
ml_score = int(round(ml_prob * 100))

# 3. AEGIS Multi-Layer Risk Fusion
# If structural packer or zip tampering detected, raise score to CRITICAL/HIGH
if struct_res["is_packed_threat"]:
    final_score = max(ml_score, struct_res["structural_score"])
    threat_tier = "CRITICAL"
    verdict = "MALWARE / PACKED TROJAN DETECTED"
    top_reasons = struct_res["reasons"]
else:
    final_score = ml_score
    threat_tier = "SAFE" if final_score < 16 else ("LOW" if final_score < 35 else "HIGH")
    verdict = "SAFE / CLEAN" if threat_tier == "SAFE" else "SUSPICIOUS"
    top_reasons = [desc for _, desc, _ in explain_prediction(vec, importances, top_k=3)]

print(f"\n[2] AEGIS Multi-Layer Combined Scan Result:")
print(f"  * Final Risk Score:      {final_score}/100")
print(f"  * Threat Tier:           {threat_tier}")
print(f"  * Verdict:               {verdict}")
print(f"  * ML Model Probability:  {ml_prob:.4f}")

print(f"\n[3] Primary Risk & Explanations:")
for r in top_reasons:
    print(f"  -> {r}")
print("="*80)