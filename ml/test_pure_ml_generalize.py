"""
Testing PURE ML Inference (No hardcoded if-statements or score overrides)
Evaluates calibrated GBT on 88 static features.
"""

import os, sys, json
import numpy as np
import joblib

sys.path.insert(0, os.path.abspath("."))
from ml.features.extractor import extract_features_from_apk, explain_prediction, FEATURE_SPEC

cal_gbt = joblib.load("ml/models/saved_models/calibrated_gbt.joblib")
importances = np.load("ml/models/saved_models/feature_importances.npy")

apk_trojan = r"C:\Users\user\Downloads\60648a8e5ee28177de38e6ea40c17481b95a63e6aa4ca466754bc7e7f08bd2ab.apk"
apk_rat = r"C:\Users\user\Downloads\androrat\AndroRAT\malware.apk"

print("="*80)
print("TESTING PURE ML INFERENCE (88 FEATURES) - ZERO HARDCODED OVERRIDES")
print("="*80)

def test_pure_ml(name, apk_path):
    vec = extract_features_from_apk(apk_path, is_sideloaded=True)
    p_mal = float(cal_gbt.predict_proba(vec.reshape(1, -1))[0, 1])
    score = int(round(p_mal * 100))
    tier = "SAFE" if p_mal < 0.160 else ("LOW" if score < 35 else ("MEDIUM" if score < 70 else "CRITICAL"))
    
    print(f"\n[{name}]")
    print(f"  * ML Malice Probability: {p_mal:.4f} (Operating Threshold: 0.1600)")
    print(f"  * Threat Tier:           {tier}")
    print(f"  * Risk Score:            {score}/100")
    print(f"  * Active Feature Vector Dimensions ({np.sum(vec > 0)} non-zero features):")
    for feat_name, feat_desc, weight in explain_prediction(vec, importances, top_k=4):
        print(f"     -> [{feat_name}] (Impact: {weight:.4f}): {feat_desc}")
        
test_pure_ml("Packed Iranian Card-Stealer Trojan", apk_trojan)
test_pure_ml("AndroRAT Remote Access Trojan", apk_rat)