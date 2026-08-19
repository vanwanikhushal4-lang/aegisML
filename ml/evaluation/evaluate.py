"""
AEGIS On-Device Malware Classifier (P5 Model) — Evaluation Harness
Evaluates ROC-AUC, PR-AUC, Brier score, FPR @ 95% recall on clean holdout data with zero leakage.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import roc_auc_score, average_precision_score, brier_score_loss, roc_curve

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from ml.features.extractor import extract_features_from_dict, FEATURE_SPEC
from ml.models.train import RuleEngineBaseline

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../models/saved_models"))
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data"))

def evaluate_pipeline():
    print("="*80)
    print("AEGIS ON-DEVICE MALWARE CLASSIFIER - CLEAN HOLDOUT & GATE EVALUATION")
    print("="*80)

    # 1. Load Test Holdout Data
    with open(os.path.join(DATA_DIR, "test_holdout_dataset.json"), "r", encoding="utf-8-sig") as f:
        test_apps = json.load(f)

    X_test = np.zeros((len(test_apps), FEATURE_SPEC["num_features"]), dtype=np.float32)
    y_test = np.zeros(len(test_apps), dtype=np.int32)
    families = []

    for i, app in enumerate(test_apps):
        X_test[i] = extract_features_from_dict(app)
        y_test[i] = app["label"]
        families.append(app.get("family", "unknown"))

    print(f"\nLoaded Test Set: {len(test_apps)} samples (Malware: {np.sum(y_test==1)}, Benign: {np.sum(y_test==0)})")

    # 2. Load Trained Models
    models = {
        "Rule Engine (Current AEGIS Baseline)": RuleEngineBaseline(),
        "Logistic Regression (L2)": joblib.load(os.path.join(MODELS_DIR, "logistic_regression.joblib")),
        "Random Forest": joblib.load(os.path.join(MODELS_DIR, "rf_model.joblib")),
        "Gradient Boosted Trees (Raw P5 Model)": joblib.load(os.path.join(MODELS_DIR, "gbt_model.joblib")),
        "Calibrated GBT (Sigmoid CV)": joblib.load(os.path.join(MODELS_DIR, "calibrated_gbt.joblib"))
    }

    # 3. Compute Metrics
    print("\n" + "-"*90)
    print(f"{'Model':<45} | {'ROC-AUC':<8} | {'PR-AUC':<8} | {'Brier':<8} | {'FPR @ 95% Recall'}")
    print("-"*90)

    for name, model in models.items():
        probs = model.predict_proba(X_test)[:, 1]
        
        roc_auc = roc_auc_score(y_test, probs)
        pr_auc = average_precision_score(y_test, probs)
        brier = brier_score_loss(y_test, probs)
        
        fpr, tpr, thresholds = roc_curve(y_test, probs)
        idx_95 = np.where(tpr >= 0.95)[0]
        if len(idx_95) > 0:
            target_idx = idx_95[0]
            target_fpr = fpr[target_idx]
            target_th = thresholds[target_idx]
            fpr_str = f"{target_fpr*100:.2f}% (th={target_th:.3f})"
        else:
            target_fpr = 1.0
            target_th = 0.5
            fpr_str = "N/A"

        print(f"{name:<45} | {roc_auc:<8.4f} | {pr_auc:<8.4f} | {brier:<8.4f} | {fpr_str}")

    # 4. Per-Family Recall Breakdown for Calibrated GBT
    chosen_model = models["Calibrated GBT (Sigmoid CV)"]
    chosen_th = 0.160
    gbt_probs = chosen_model.predict_proba(X_test)[:, 1]

    print("\n" + "="*80)
    print(f"PER-FAMILY RECALL BREAKDOWN (Calibrated GBT at Operating Threshold th={chosen_th:.3f})")
    print("="*80)

    df_eval = pd.DataFrame({
        "label": y_test,
        "family": families,
        "prob": gbt_probs
    })

    mal_df = df_eval[df_eval["label"] == 1]
    for fam, group in mal_df.groupby("family"):
        tot = len(group)
        det = (group["prob"] >= chosen_th).sum()
        rec = det / tot * 100 if tot > 0 else 0
        print(f"  * Family: {fam:<20} | Total Samples: {tot:<4} | Detected: {det:<4} | Recall: {rec:.1f}%")

    # 5. Allowlist Hard Gate Evaluation
    print("\n" + "="*80)
    print("ZERO-TOLERANCE ALLOWLIST HARD GATE EVALUATION")
    print("="*80)

    with open(os.path.join(DATA_DIR, "allowlist_gate_dataset.json"), "r", encoding="utf-8-sig") as f:
        allowlist_apps = json.load(f)
        
    allowlist_passed = True
    print(f"{'Package / App Name':<40} | {'Type':<22} | {'ML Malice Prob':<15} | {'Risk Tier':<10} | {'Status'}")
    print("-"*105)
    
    for app in allowlist_apps:
        vec = extract_features_from_dict(app).reshape(1, -1)
        p_mal = float(chosen_model.predict_proba(vec)[0, 1])
        tier = "SAFE" if p_mal < chosen_th else ("LOW" if p_mal < 0.35 else "MEDIUM+")
        status = "[PASS]" if p_mal < chosen_th else "[FAIL - REGRESSION]"
        
        if p_mal >= chosen_th:
            allowlist_passed = False
            
        app_display = f"{app['package_name']} ({app['app_name']})"
        if len(app_display) > 38:
            app_display = app_display[:35] + "..."
            
        print(f"{app_display:<40} | {app.get('family', 'benign'):<22} | {p_mal:<15.4f} | {tier:<10} | {status}")

    print("-"*105)
    if allowlist_passed:
        print("[SUCCESS] HARD GATE PASSED: Zero False Positives on all critical banking, UPI, and business apps.")
    else:
        print("[FAILURE] HARD GATE FAILED: False Positives detected on allowlist.")
    print("="*80)

if __name__ == "__main__":
    evaluate_pipeline()