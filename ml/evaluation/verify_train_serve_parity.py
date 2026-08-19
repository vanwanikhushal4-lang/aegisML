"""
AEGIS Train / Serve Parity Verification Suite
Executes the compiled JVM Java extractor on real malware.apk and diffs against Python Androguard extractor.
"""

import os
import sys
import json
import subprocess
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from ml.features.extractor import extract_features_from_apk, FEATURE_SPEC

REAL_MALWARE_APK = "C:/Users/user/Downloads/androrat/AndroRAT/malware.apk"

def extract_via_jvm(apk_path: str) -> np.ndarray:
    """Runs the compiled Java/JVM extractor on the real APK and parses the resulting vector."""
    cmd = ["java", "-cp", "ml/evaluation", "JvmExtractor", apk_path]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    out = res.stdout.strip()
    raw_vec = json.loads(out)
    return np.array(raw_vec, dtype=np.float32)

def verify_parity():
    print("="*80)
    print("AEGIS TRAIN / SERVE PARITY VERIFICATION (Real APK: malware.apk)")
    print("  [Python (Androguard)] vs [JVM (Java 17 / Kotlin-equivalent)]")
    print("="*80)

    if not os.path.exists(REAL_MALWARE_APK):
        print(f"Error: Real malware APK not found at {REAL_MALWARE_APK}")
        return False

    train_vector = extract_features_from_apk(REAL_MALWARE_APK)
    jvm_vector = extract_via_jvm(REAL_MALWARE_APK)

    max_diff = 0.0
    diff_count = 0

    print(f"{'Idx':<4} | {'Feature Name':<35} | {'Train (Python)':<15} | {'Serve (JVM)':<15} | {'Status'}")
    print("-" * 85)

    for i in range(FEATURE_SPEC["num_features"]):
        f_name = FEATURE_SPEC["features"][i]["name"]
        v_train = float(train_vector[i])
        v_jvm = float(jvm_vector[i])
        diff = abs(v_train - v_jvm)
        
        if diff > max_diff:
            max_diff = diff

        status = "MATCH"
        if diff > 1e-4:
            status = f"DIFF ({diff:.4f})"
            diff_count += 1

        if v_train > 0.0 or v_jvm > 0.0 or diff > 1e-4:
            print(f"{i:02d}   | {f_name:<35} | {v_train:<15.4f} | {v_jvm:<15.4f} | {status}")

    print("-" * 85)
    print(f"Max Absolute Difference Across All 80 Dimensions: {max_diff:.6f}")
    print(f"Mismatched Dimensions:                             {diff_count} / 80")

    if diff_count == 0:
        print("\n[SUCCESS] TRAIN/SERVE PARITY VERIFIED: 100% Exact 80-Feature Alignment Between Python & JVM!")
        return True
    else:
        print(f"\n[FAILURE] TRAIN/SERVE SKEW DETECTED: {diff_count} features differ.")
        return False

if __name__ == '__main__':
    verify_parity()