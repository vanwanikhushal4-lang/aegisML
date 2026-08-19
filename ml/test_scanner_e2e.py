import os, sys
print("Simulating end-to-end scanner logic on Iranian APK...")
from ml.features.extractor import extract_features_from_apk, analyze_apk_structural
apk = r"C:\Users\user\Downloads\60648a8e5ee28177de38e6ea40c17481b95a63e6aa4ca466754bc7e7f08bd2ab.apk"
struct = analyze_apk_structural(apk)
print(f"Structural Packer Result: score={struct['structural_score']}, is_threat={struct['is_packed_threat']}")
for r in struct['reasons']:
    print(f"  -> {r}")