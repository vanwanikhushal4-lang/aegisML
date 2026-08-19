import os
import sys
import numpy as np
import joblib

sys.path.insert(0, ".")
from ml.features.extractor import extract_features_from_apk, explain_prediction, FEATURE_SPEC
from androguard.core.apk import APK

apk_path = r"C:\Users\user\Downloads\60648a8e5ee28177de38e6ea40c17481b95a63e6aa4ca466754bc7e7f08bd2ab.apk"

if not os.path.exists(apk_path):
    print("Error: APK not found at", apk_path)
    sys.exit(1)

apk = APK(apk_path)
print("="*80)
print("ANALYZING APK:", os.path.basename(apk_path))
print("="*80)
print("Package Name:        ", apk.get_package())
print("App Name:            ", apk.get_app_name())
print("Target SDK:          ", apk.get_target_sdk_version())
print("Min SDK:             ", apk.get_min_sdk_version())
print("Declared Permissions:", len(apk.get_permissions()))
for p in apk.get_permissions()[:10]:
    print("  -", p)
if len(apk.get_permissions()) > 10:
    print(f"  ... and {len(apk.get_permissions()) - 10} more")

vec = extract_features_from_apk(apk_path, is_sideloaded=True)

models_dir = "ml/models/saved_models"
calibrated_model = joblib.load(os.path.join(models_dir, "calibrated_gbt.joblib"))
feature_importances = np.load(os.path.join(models_dir, "feature_importances.npy"))

p_mal = float(calibrated_model.predict_proba(vec.reshape(1, -1))[0, 1])
score = int(round(p_mal * 100))

if p_mal < 0.16:
    tier = "SAFE"
elif p_mal < 0.40:
    tier = "LOW"
elif p_mal < 0.75:
    tier = "MEDIUM"
elif p_mal < 0.90:
    tier = "HIGH"
else:
    tier = "CRITICAL"

print("\n" + "="*80)
print("AEGIS ON-DEVICE ML INFERENCE RESULT:")
print("="*80)
print(f"Risk Score:          {score}/100")
print(f"Threat Tier:         {tier}")
print(f"Malware Probability: {p_mal:.4f} (Operating Threshold: 0.1590)")
verdict = "MALICIOUS / HIGH RISK" if p_mal >= 0.159 else "SAFE / CLEAN"
print(f"Verdict:             {verdict}")

reasons = explain_prediction(vec, feature_importances, top_k=5)
print("\nTop Explainability Factors (Why this score was given):")
for r_name, r_desc, r_contrib in reasons:
    print(f"  -> [{r_name}] (Impact: {r_contrib:.3f}): {r_desc}")