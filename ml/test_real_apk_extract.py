import sys, os
sys.path.insert(0, os.path.abspath("."))
from ml.features.extractor import extract_features_from_apk, FEATURE_SPEC
apk_path = r"C:\Users\user\Downloads\androrat\AndroRAT\malware.apk"
vec = extract_features_from_apk(apk_path)
print(f"Extracted vector shape: {vec.shape}")
print(f"Total non-zero features: {int((vec > 0).sum())}/80")
print("\nNon-zero features directly extracted from real malware.apk:")
for i, v in enumerate(vec):
    if v > 0:
        meta = FEATURE_SPEC["features"][i]
        print(f"  [{i:02d}] {meta['name']:<35} = {v:.4f}  ({meta['description']})")