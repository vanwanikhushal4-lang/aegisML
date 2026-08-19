import sys, os, joblib, json
sys.path.insert(0, os.path.abspath("."))
rf = joblib.load("ml/models/saved_models/rf_model.joblib")
gbt = joblib.load("ml/models/saved_models/gbt_model.joblib")
with open("ml/data/allowlist_gate_dataset.json", "r", encoding="utf-8-sig") as f:
    apps = json.load(f)

from ml.features.extractor import extract_features_from_dict
print("--- Random Forest Probas ---")
for a in apps:
    v = extract_features_from_dict(a).reshape(1, -1)
    p = rf.predict_proba(v)[0, 1]
    print(f"{a['package_name']:<40}: RF Prob = {p:.4f}")

print("\n--- Raw GBT Probas ---")
for a in apps:
    v = extract_features_from_dict(a).reshape(1, -1)
    p = gbt.predict_proba(v)[0, 1]
    print(f"{a['package_name']:<40}: GBT Prob = {p:.4f}")