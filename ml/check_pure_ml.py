import joblib, os, sys
sys.path.insert(0, '.')
import numpy as np
from ml.features.extractor import extract_features_from_apk, FEATURE_SPEC

cal_gbt = joblib.load("ml/models/saved_models/calibrated_gbt.joblib")
importances = np.load("ml/models/saved_models/feature_importances.npy")

apk_trojan = r"C:\Users\user\Downloads\60648a8e5ee28177de38e6ea40c17481b95a63e6aa4ca466754bc7e7f08bd2ab.apk"
vec = extract_features_from_apk(apk_trojan, is_sideloaded=True)
p_mal = float(cal_gbt.predict_proba(vec.reshape(1, -1))[0, 1])

print("="*80)
print(f"Packed Trojan Pure ML Probability: {p_mal:.4f}")
print(f"Operating Threshold: 0.1600")
print(f"Is Flagged as Malware by Pure ML: {p_mal >= 0.1600}")
print(f"Total non-zero features: {np.sum(vec > 0)}")
for idx in np.where(vec > 0)[0]:
    feat = FEATURE_SPEC["features"][idx]
    print(f"  [{idx}] {feat['name']}: {vec[idx]:.4f} (Weight: {importances[idx]:.4f})")
print("="*80)
