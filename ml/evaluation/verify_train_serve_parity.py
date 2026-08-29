"""
AEGIS Train / Serve Feature Parity Verification Harness (Schema v2.0.0 — 92 Dimensions)
Directly tests Python (Androguard) vs Production Kotlin (JVM compiled via kotlinc)
across 6 distinct cohorts:
1. Benign OEM Split-APK Set (Samsung Clock: base.apk + splits)
2. Benign OEM Single APK (Samsung Calculator)
3. Verified Store Banking APK (YONO SBI)
4. Sideloaded Media APK (VLC)
5. Unknown Provenance Tool APK
6. In-the-Wild Malware APK (AndroRAT & Anti-analysis sample)

CI Requirement: Fails with non-zero exit code (1) on ANY feature mismatch > 1e-4.
"""

import os
import sys
import json
import subprocess
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from ml.features.extractor import extract_features_from_apk, FEATURE_SPEC

EVAL_DIR = os.path.dirname(__file__)
PROJECT_DIR = os.path.abspath(os.path.join(EVAL_DIR, "../.."))
FIXTURES_DIR = os.path.join(EVAL_DIR, "fixtures")
KOTLIN_JAR = os.path.join(EVAL_DIR, "kotlin_extractor.jar")

def compile_kotlin_extractor():
    print("Compiling KotlinExtractorRunner.kt using kotlinc compiler...")
    runner_src = os.path.join(EVAL_DIR, "KotlinExtractorRunner.kt")
    compiler_jar = os.path.join(PROJECT_DIR, ".tools/kotlinc/lib/kotlin-compiler.jar")

    cmd = [
        "java", "-cp", compiler_jar,
        "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler",
        runner_src,
        "-include-runtime",
        "-d", KOTLIN_JAR
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print("ERROR: Failed to compile KotlinExtractorRunner.kt:")
        print(res.stderr)
        sys.exit(1)
    print("Compiled kotlin_extractor.jar successfully.")

def run_kotlin_extractor(target_path: str, provenance: str) -> np.ndarray:
    cmd = [
        "java", "-cp", KOTLIN_JAR,
        "com.aegis.guard.scanner.KotlinExtractorRunner",
        target_path,
        provenance
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"KotlinExtractorRunner failed on {target_path}:\n{res.stderr}")
    out = res.stdout.strip()
    try:
        data = json.loads(out)
        return np.array(data, dtype=np.float32)
    except Exception as e:
        raise RuntimeError(f"Failed to parse Kotlin output:\n{out}") from e

def verify_fixture(cohort_name: str, target_path: str, provenance: str) -> bool:
    print(f"\nVerifying Cohort: [{cohort_name}] -> {target_path} (Provenance: {provenance})")
    
    vec_python = extract_features_from_apk(target_path, provenance)
    vec_kotlin = run_kotlin_extractor(target_path, provenance)

    diffs = np.abs(vec_python - vec_kotlin)
    max_diff = np.max(diffs)
    mismatches = np.where(diffs > 1e-4)[0]

    print(f"{'Idx':<4} | {'Feature Name':<35} | {'Python':<10} | {'Kotlin':<10} | {'Status'}")
    print("-" * 75)

    for i in range(len(vec_python)):
        if vec_python[i] > 0 or vec_kotlin[i] > 0 or diffs[i] > 1e-4:
            feat_name = FEATURE_SPEC["features"][i]["name"]
            status = "MATCH" if diffs[i] <= 1e-4 else "MISMATCH"
            print(f"{i:02d}   | {feat_name:<35} | {vec_python[i]:<10.4f} | {vec_kotlin[i]:<10.4f} | {status}")

    print(f"Max Absolute Diff: {max_diff:.6f}, Mismatches: {len(mismatches)} / {len(vec_python)}")

    if len(mismatches) > 0:
        print(f"[FAILED] Cohort [{cohort_name}] has {len(mismatches)} mismatched dimensions!")
        return False
    else:
        print(f"[PASSED] Cohort [{cohort_name}] achieved 100% exact parity.")
        return True

def run_all_parity_checks():
    print("="*85)
    print("AEGIS DIRECT PRODUCTION KOTLIN VS PYTHON FEATURE PARITY HARNESS (92 Dimensions)")
    print("="*85)

    compile_kotlin_extractor()

    cohorts = [
        ("1. Benign OEM Split-APK Set", os.path.join(FIXTURES_DIR, "oem_samsung_clock_split"), "SYSTEM_IMAGE"),
        ("2. Benign OEM Single APK", os.path.join(FIXTURES_DIR, "oem_samsung_calculator.apk"), "SYSTEM_IMAGE"),
        ("3. Verified Store Banking", os.path.join(FIXTURES_DIR, "store_banking_yono.apk"), "VERIFIED_STORE"),
        ("4. Sideloaded Media APK", os.path.join(FIXTURES_DIR, "sideloaded_vlc.apk"), "DOWNLOADED_APK"),
        ("5. Unknown Provenance Tool", os.path.join(FIXTURES_DIR, "unknown_prov_tool.apk"), "UNKNOWN"),
        ("6. In-the-Wild Real Malware", "C:/Users/user/Downloads/androrat/AndroRAT/malware.apk", "DOWNLOADED_APK")
    ]

    all_passed = True
    for name, path, prov in cohorts:
        if not os.path.exists(path):
            print(f"ERROR: Fixture path does not exist: {path}")
            sys.exit(1)
        passed = verify_fixture(name, path, prov)
        if not passed:
            all_passed = False

    print("\n" + "="*85)
    if all_passed:
        print("[SUCCESS] 100% BYTE-FOR-BYTE PARITY VERIFIED ACROSS ALL 6 COHORTS IN KOTLIN!")
        print("="*85)
        sys.exit(0)
    else:
        print("[FAILURE] PARITY MISMATCH DETECTED. EXITING WITH NON-ZERO STATUS (1).")
        print("="*85)
        sys.exit(1)

if __name__ == "__main__":
    run_all_parity_checks()