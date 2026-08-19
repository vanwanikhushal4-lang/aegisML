import json
import os
import sys
import numpy as np
import joblib

from sklearn.metrics import (
    roc_auc_score, average_precision_score, brier_score_loss,
    confusion_matrix, precision_recall_fscore_support
)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from ml.features.extractor import extract_features_from_dict, explain_prediction, FEATURE_SPEC
from ml.models.train import RuleEngineBaseline, load_dataset

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../models/saved_models'))
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../data'))
OUTPUT_DIR = os.path.dirname(__file__)


def evaluate_models():
    print("="*80)
    print("AEGIS ON-DEVICE MALWARE CLASSIFIER - TEMPORAL HOLDOUT & GATE EVALUATION")
    print("="*80)

    # 1. Load Test Holdout Data
    X_test, y_test, test_meta = load_dataset('test_holdout_dataset.json')
    print(f"\nLoaded Test Set: {X_test.shape[0]} samples (Malware: {np.sum(y_test)}, Benign: {len(y_test) - np.sum(y_test)})")
    
    # 2. Load Models
    rule_engine = RuleEngineBaseline()
    lr = joblib.load(os.path.join(MODELS_DIR, 'logistic_regression.joblib'))
    gbt = joblib.load(os.path.join(MODELS_DIR, 'gbt_model.joblib'))
    calibrated_gbt = joblib.load(os.path.join(MODELS_DIR, 'calibrated_gbt.joblib'))
    rf = joblib.load(os.path.join(MODELS_DIR, 'rf_model.joblib'))
    feature_importances = np.load(os.path.join(MODELS_DIR, 'feature_importances.npy'))

    models = {
        "Rule Engine (Current AEGIS Baseline)": rule_engine,
        "Logistic Regression (L2)": lr,
        "Random Forest": rf,
        "Gradient Boosted Trees (Raw P5 Model)": gbt,
        "Calibrated GBT (Sigmoid CV)": calibrated_gbt
    }

    results = {}

    print("\n" + "-"*85)
    print(f"{'Model':<45} | {'ROC-AUC':<8} | {'PR-AUC':<8} | {'Brier':<8} | {'FPR @ 98% Recall':<15}")
    print("-"*85)

    operating_thresholds = {}
    for name, model in models.items():
        proba = model.predict_proba(X_test)[:, 1]
        
        roc_auc = roc_auc_score(y_test, proba)
        pr_auc = average_precision_score(y_test, proba)
        brier = brier_score_loss(y_test, proba)
        
        thresholds = np.linspace(0.01, 0.99, 100)
        chosen_fpr = 1.0
        chosen_thresh = 0.5
        for th in thresholds:
            preds = (proba >= th).astype(int)
            tn, fp, fn, tp = confusion_matrix(y_test, preds).ravel()
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            if recall >= 0.98:
                chosen_fpr = fpr
                chosen_thresh = th
                
        operating_thresholds[name] = chosen_thresh
        print(f"{name:<45} | {roc_auc:.4f}   | {pr_auc:.4f}   | {brier:.4f}  | {chosen_fpr*100:.2f}% (th={chosen_thresh:.2f})")
        
        results[name] = {
            "roc_auc": float(roc_auc),
            "pr_auc": float(pr_auc),
            "brier_score": float(brier),
            "fpr_at_98_recall": float(chosen_fpr),
            "operating_threshold": float(chosen_thresh)
        }

    # 3. Per-Family Recall Breakdown at Operating Threshold
    chosen_model = calibrated_gbt
    chosen_th = operating_thresholds["Calibrated GBT (Sigmoid CV)"]
    print("\n" + "="*80)
    print(f"PER-FAMILY RECALL BREAKDOWN (Calibrated GBT at Operating Threshold th={chosen_th:.2f})")
    print("="*80)
    
    gbt_proba = chosen_model.predict_proba(X_test)[:, 1]
    gbt_preds = (gbt_proba >= chosen_th).astype(int)
    
    family_counts = {}
    family_correct = {}
    
    for i, meta in enumerate(test_meta):
        fam = meta.get("family", "unknown")
        label = meta.get("label", 0)
        if label == 1:
            family_counts[fam] = family_counts.get(fam, 0) + 1
            if gbt_preds[i] == 1:
                family_correct[fam] = family_correct.get(fam, 0) + 1
                
    for fam, total in family_counts.items():
        correct = family_correct.get(fam, 0)
        rec = (correct / total) * 100.0 if total > 0 else 0.0
        print(f"  * Family: {fam:<20} | Total Samples: {total:<3} | Detected: {correct:<3} | Recall: {rec:.1f}%")

    # 4. Allowlist Hard Gate Verification
    print("\n" + "="*80)
    print("ZERO-TOLERANCE ALLOWLIST HARD GATE EVALUATION")
    print("="*80)
    
    with open(os.path.join(DATA_DIR, 'allowlist_gate_dataset.json'), 'r', encoding='utf-8-sig') as f:
        allowlist_apps = json.load(f)
        
    allowlist_passed = True
    print(f"{'Package / App Name':<40} | {'Type':<22} | {'ML Malice Prob':<15} | {'Risk Tier':<10} | {'Status'}")
    print("-"*105)
    
    for app in allowlist_apps:
        vec = extract_features_from_dict(app).reshape(1, -1)
        p_mal = float(chosen_model.predict_proba(vec)[0, 1])
        tier = "SAFE" if p_mal < chosen_th else ("LOW" if p_mal < chosen_th * 1.5 else "MEDIUM+")
        status = "[PASS]" if p_mal < chosen_th else "[FAIL - REGRESSION]"
        
        if p_mal >= chosen_th:
            allowlist_passed = False
            
        app_display = f"{app['package_name']} ({app['app_name']})"
        if len(app_display) > 38:
            app_display = app_display[:35] + "..."
        print(f"{app_display:<40} | {app.get('family', 'allowlist'):<22} | {p_mal:.4f}          | {tier:<10} | {status}")

    print("-"*105)
    if allowlist_passed:
        print("[SUCCESS] HARD GATE PASSED: Zero False Positives on all critical banking, UPI, and business apps.")
    else:
        print("[FAILURE] HARD GATE FAILED: False Positives detected on allowlist.")

    results["allowlist_gate_passed"] = allowlist_passed

    with open(os.path.join(OUTPUT_DIR, 'evaluation_results.json'), 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

    return results

if __name__ == '__main__':
    evaluate_models()