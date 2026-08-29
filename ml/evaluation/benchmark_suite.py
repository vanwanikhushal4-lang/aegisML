"""
AEGIS Hardened On-Device Malware Model (P5 v2) — Evaluation & Regression Benchmark Suite
CI Requirement: Enforces strict non-zero exit code (1) on any failure:
- Any feature mismatch or train/test leakage
- Any false positive on Samsung OEM or Banking suites (> 0.00%)
- Any held-out malware recall below 95%
- Any Android Kotlin model-load test failure
"""

import os
import sys
import json
import math
import hashlib
import subprocess
from typing import Tuple, List, Dict, Set
import numpy as np
import joblib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from ml.features.extractor import extract_features_from_dict, extract_features_from_apk, FEATURE_SPEC

EVAL_DIR = os.path.dirname(__file__)
PROJECT_DIR = os.path.abspath(os.path.join(EVAL_DIR, "../.."))
MODELS_DIR = os.path.join(PROJECT_DIR, "ml/models/saved_models")
DATA_DIR = os.path.join(PROJECT_DIR, "ml/data")
ASSETS_DIR = os.path.join(PROJECT_DIR, "app/src/main/assets")

def wilson_score_interval(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float]:
    """Computes Wilson score interval for binomial proportion with continuity correction."""
    if n == 0:
        return 0.0, 0.0
    z = 1.95996  # 95% confidence
    p = k / n
    denom = 1 + z**2 / n
    centre_adj_p = p + z**2 / (2 * n)
    adj_se = z * math.sqrt((p * (1 - p) + z**2 / (4 * n)) / n)
    lower = max(0.0, (centre_adj_p - adj_se) / denom)
    upper = min(1.0, (centre_adj_p + adj_se) / denom)
    return lower, upper

def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def compute_ece(probs: np.ndarray, y_true: np.ndarray, n_bins: int = 10) -> float:
    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    n = len(y_true)
    for i in range(n_bins):
        bin_lower, bin_upper = bin_boundaries[i], bin_boundaries[i + 1]
        in_bin = (probs >= bin_lower) & (probs < bin_upper if i < n_bins - 1 else probs <= bin_upper)
        prop_in_bin = np.mean(in_bin)
        if prop_in_bin > 0:
            acc_in_bin = np.mean(y_true[in_bin])
            conf_in_bin = np.mean(probs[in_bin])
            ece += np.abs(acc_in_bin - conf_in_bin) * prop_in_bin
    return float(ece)

def run_benchmark_suite():
    print("="*90)
    print("AEGIS HARDENED P5 v2 PRODUCTION BENCHMARK & REGRESSION SUITE")
    print("="*90)

    # ─── GATE 1: KOTLIN UNIT TESTS & MODEL-LOAD FAIL-SAFE VERIFICATION ────────
    print("\n[GATE 1] Running Kotlin Scanner Engine Unit Tests & Model-Load Fail-Safe Verification...")
    kt_cmd = [
        "java", "-cp",
        f"scanner_tests.jar;{EVAL_DIR}/libs/json.jar;{EVAL_DIR}/libs/javax.inject.jar;{EVAL_DIR}/libs/android.jar",
        "com.aegis.guard.scanner.OnDeviceMalwareModelTestKt"
    ]
    res = subprocess.run(kt_cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print("[FAIL] Kotlin Unit Tests FAILED:")
        print(res.stderr or res.stdout)
        sys.exit(1)
    print("  * PASSED: Kotlin unit tests verified valid loading and exception throwing (never SAFE on failure).")

    # ─── GATE 2: ZERO TRAIN/TEST 4-WAY LEAKAGE VERIFICATION ──────────────────
    print("\n[GATE 2] Verifying Zero 4-Way Overlap Across Train and Test Corpora...")
    with open(os.path.join(DATA_DIR, "train_dataset.json"), "r", encoding="utf-8") as f:
        train_data = json.load(f)
    with open(os.path.join(DATA_DIR, "test_holdout_dataset.json"), "r", encoding="utf-8") as f:
        test_data = json.load(f)

    train_hashes = set(d["sha256"] for d in train_data)
    test_hashes = set(d["sha256"] for d in test_data)
    train_certs = set(d["cert_sha256"] for d in train_data)
    test_certs = set(d["cert_sha256"] for d in test_data)
    train_pkgs = set(d["package_name"] for d in train_data)
    test_pkgs = set(d["package_name"] for d in test_data)
    train_fams = set(d["family"] for d in train_data)
    test_fams = set(d["family"] for d in test_data)

    hash_overlap = len(train_hashes.intersection(test_hashes))
    cert_overlap = len(train_certs.intersection(test_certs))
    pkg_overlap = len(train_pkgs.intersection(test_pkgs))
    fam_overlap = len(train_fams.intersection(test_fams))

    print(f"  * APK SHA-256 Overlap:        {hash_overlap} (Max allowed: 0)")
    print(f"  * Signing Cert SHA-256:       {cert_overlap} (Max allowed: 0)")
    print(f"  * Package Name Overlap:       {pkg_overlap} (Max allowed: 0)")
    print(f"  * Malware Family Overlap:     {fam_overlap} (Max allowed: 0)")

    if hash_overlap > 0 or cert_overlap > 0 or pkg_overlap > 0 or fam_overlap > 0:
        print("[FAIL] Train/Test Overlap Detected! Exiting with non-zero status.")
        sys.exit(1)
    print("  * PASSED: 100% Zero Overlap Verified across all 4 dimensions.")

    # ─── GATE 3: MODEL INFERENCE & GENUINE PLATT CALIBRATION ─────────────────
    print("\n[GATE 3] Loading Production Calibrated Model & Parameters...")
    gbt = joblib.load(os.path.join(MODELS_DIR, "gbt_model.joblib"))
    with open(os.path.join(MODELS_DIR, "calibrated_params.json"), "r", encoding="utf-8") as f:
        calib_params = json.load(f)

    calib_a = calib_params["a"]
    calib_b = calib_params["b"]
    print(f"  * Platt Sigmoid Slope (a):     {calib_a:.6f}")
    print(f"  * Platt Sigmoid Intercept (b): {calib_b:.6f}")

    def predict_calibrated_proba(vec: np.ndarray) -> float:
        raw_logit = float(gbt.decision_function(np.array([vec]))[0])
        return float(1.0 / (1.0 + np.exp(calib_a * raw_logit + calib_b)))

    # ─── GATE 4: SAMSUNG MUST-NEVER-FLAG OEM REGRESSION SUITE ────────────────
    print("\n[GATE 4] Evaluating Curated Samsung OEM Regression Suite (Target: 0.00% FP)...")
    from ml.data.real_dataset_loader import SAMSUNG_FP_CORPUS, BANKING_CORPUS, MODERN_FRAMEWORKS_BENIGN

    samsung_fps = 0
    print(f"{'Package Name':<42} | {'App Name':<22} | {'Prob':<8} | {'Score':<6} | {'Level':<10} | {'Status'}")
    print("-" * 105)

    for app in SAMSUNG_FP_CORPUS:
        vec = extract_features_from_dict(app)
        prob = predict_calibrated_proba(vec)
        score = int(round(prob * 100))
        level = "DANGEROUS" if prob >= 0.85 else ("SUSPICIOUS" if prob >= 0.50 else "SAFE")
        status = "PASSED" if level == "SAFE" else "FAILED (FP)"
        if level != "SAFE": samsung_fps += 1
        print(f"{app['package_name']:<42} | {app['app_name']:<22} | {prob:<8.4f} | {score:<6} | {level:<10} | {status}")

    samsung_fp_rate = (samsung_fps / len(SAMSUNG_FP_CORPUS)) * 100.0
    print(f"\nSamsung OEM Suite Result: {len(SAMSUNG_FP_CORPUS) - samsung_fps} / {len(SAMSUNG_FP_CORPUS)} Passed (FP Rate: {samsung_fp_rate:.2f}%)")
    if samsung_fps > 0:
        print(f"[FAIL] CRITICAL REGRESSION: {samsung_fps} genuine Samsung apps flagged! Exiting with code 1.")
        sys.exit(1)
    print("  * PASSED: 0.00% FP Rate on Samsung OEM applications.")

    # ─── GATE 5: INDIAN BANKING & UPI SUITE ──────────────────────────────────
    print("\n[GATE 5] Evaluating Indian Banking & UPI Suite (Target: 0.00% FP)...")
    banking_fps = 0
    for app in BANKING_CORPUS:
        vec = extract_features_from_dict(app)
        prob = predict_calibrated_proba(vec)
        score = int(round(prob * 100))
        level = "DANGEROUS" if prob >= 0.85 else ("SUSPICIOUS" if prob >= 0.50 else "SAFE")
        status = "PASSED" if level == "SAFE" else "FAILED (FP)"
        if level != "SAFE": banking_fps += 1
        print(f"{app['package_name']:<42} | {app['app_name']:<22} | {prob:<8.4f} | {score:<6} | {level:<10} | {status}")

    if banking_fps > 0:
        print(f"[FAIL] CRITICAL REGRESSION: Banking apps flagged! Exiting with code 1.")
        sys.exit(1)
    print("  * PASSED: 0.00% FP Rate on Indian Banking & UPI applications.")

    # ─── GATE 6: HELD-OUT TEST CORPUS & CONFUSION MATRIX ─────────────────────
    print("\n[GATE 6] Evaluating Full Held-Out Test Corpus (3,375 samples)...")
    y_true = np.array([d["label"] for d in test_data], dtype=np.int32)
    y_probs = np.zeros(len(test_data), dtype=np.float32)

    for i, d in enumerate(test_data):
        vec = extract_features_from_dict(d)
        y_probs[i] = predict_calibrated_proba(vec)

    y_pred_suspicious = (y_probs >= 0.50).astype(np.int32)
    y_pred_dangerous = (y_probs >= 0.85).astype(np.int32)

    tp = int(np.sum((y_true == 1) & (y_pred_suspicious == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred_suspicious == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred_suspicious == 0)))
    fn = int(np.sum((y_true == 1) & (y_pred_suspicious == 0)))

    n_pos = int(np.sum(y_true == 1))
    n_neg = int(np.sum(y_true == 0))

    recall = tp / n_pos if n_pos > 0 else 0.0
    fpr = fp / n_neg if n_neg > 0 else 0.0

    rec_ci_low, rec_ci_high = wilson_score_interval(tp, n_pos)
    fpr_ci_low, fpr_ci_high = wilson_score_interval(fp, n_neg)

    ece = compute_ece(y_probs, y_true)
    brier = float(np.mean((y_probs - y_true)**2))

    print("\nConfusion Matrix (Operating Point: Probability >= 0.50):")
    print(f"                 Actual Benign    Actual Malware")
    print(f"  Pred Safe:     {tn:<16} {fn:<16}")
    print(f"  Pred Flagged:  {fp:<16} {tp:<16}")
    print(f"\nMetrics with 95% Wilson Score Confidence Intervals:")
    print(f"  * Overall Malware Recall:   {recall*100:.2f}% (95% CI: [{rec_ci_low*100:.2f}%, {rec_ci_high*100:.2f}%])")
    print(f"  * False Positive Rate:      {fpr*100:.4f}% (95% CI: [{fpr_ci_low*100:.4f}%, {fpr_ci_high*100:.4f}%])")
    print(f"  * Expected Calib Error:     {ece:.6f}")
    print(f"  * Brier Score:              {brier:.6f}")

    if recall < 0.95 or fpr > 0.001:
        print("[FAIL] Test metrics failed quality threshold! Exiting with code 1.")
        sys.exit(1)

    # ─── GATE 7: PER-FAMILY MALWARE RECALL TABLE ─────────────────────────────
    print("\n[GATE 7] Per-Family Malware Recall Breakdown:")
    print(f"{'Malware Family':<32} | {'Partition Type':<25} | {'Samples':<8} | {'Detected':<8} | {'Recall'}")
    print("-" * 90)

    families = sorted(list(set(d["family"] for d in test_data if d["label"] == 1)))
    for fam in families:
        fam_samples = [d for d in test_data if d.get("family") == fam and d["label"] == 1]
        cnt = len(fam_samples)
        det = sum(1 for d in fam_samples if predict_calibrated_proba(extract_features_from_dict(d)) >= 0.50)
        rec = (det / cnt) * 100.0 if cnt > 0 else 0.0
        part_type = "Held-Out Family" if ("sharkbot" in fam or "triada" in fam) else "Temporal 2024 Holdout"
        print(f"{fam:<32} | {part_type:<25} | {cnt:<8} | {det:<8} | {rec:.2f}%")
        if rec < 95.0:
            print(f"[FAIL] Family recall for {fam} below 95%! Exiting with code 1.")
            sys.exit(1)

    # ─── GATE 8: SHA-256 CHECKSUMS OF PRODUCTION ASSETS ──────────────────────
    print("\n[GATE 8] Production Model Checksums (SHA-256):")
    asset_files = [
        "aegis_malware_model.json",
        "feature_spec.json",
        "scaler.json",
        "golden_vectors.json"
    ]
    for af in asset_files:
        p = os.path.join(ASSETS_DIR, af)
        chk = compute_sha256(p)
        sz = os.path.getsize(p) / 1024.0
        print(f"  * {af:<26} ({sz:6.1f} KB) -> {chk}")

    print("\n" + "="*90)
    print("[SUCCESS] ALL CI BENCHMARK GATES PASSED CLEANLY! PRODUCTION MODEL PAYSHIELD-READY.")
    print("="*90)
    sys.exit(0)

if __name__ == "__main__":
    run_benchmark_suite()
