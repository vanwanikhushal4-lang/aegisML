"""
AEGIS On-Device Malware Classifier (P5 v2 Model) — Training Pipeline (Schema v2.0.0 — 92 Features)
Trains calibrated tree ensembles on real-world benign & malware corpora with zero 4-way leakage.
Extracts and exports genuine Platt scaling calibration parameters (a, b) and computes Brier/ECE scores.
"""

import os
import sys
import json
import numpy as np
import joblib
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import roc_auc_score, average_precision_score, brier_score_loss

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from ml.features.extractor import extract_features_from_dict, FEATURE_SPEC

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "saved_models"))
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data"))
os.makedirs(MODELS_DIR, exist_ok=True)

def compute_ece(probs: np.ndarray, y_true: np.ndarray, n_bins: int = 10) -> float:
    """Computes Expected Calibration Error (ECE)."""
    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    n = len(y_true)
    for i in range(n_bins):
        bin_lower, bin_upper = bin_boundaries[i], bin_boundaries[i + 1]
        in_bin = (probs >= bin_lower) & (probs < bin_upper if i < n_bins - 1 else probs <= bin_upper)
        prop_in_bin = np.mean(in_bin)
        if prop_in_bin > 0:
            accuracy_in_bin = np.mean(y_true[in_bin])
            avg_confidence_in_bin = np.mean(probs[in_bin])
            ece += np.abs(accuracy_in_bin - avg_confidence_in_bin) * prop_in_bin
    return float(ece)

def train_pipeline():
    print("="*85)
    print("AEGIS ON-DEVICE MALWARE CLASSIFIER (P5 v2) — BALANCED TRAINING & CALIBRATION PIPELINE")
    print("="*85)

    # 1. Load Training Data
    with open(os.path.join(DATA_DIR, "train_dataset.json"), "r", encoding="utf-8") as f:
        train_apps = json.load(f)

    with open(os.path.join(DATA_DIR, "test_holdout_dataset.json"), "r", encoding="utf-8") as f:
        test_apps = json.load(f)

    X_train = np.zeros((len(train_apps), FEATURE_SPEC["num_features"]), dtype=np.float32)
    y_train = np.zeros(len(train_apps), dtype=np.int32)
    for i, app in enumerate(train_apps):
        X_train[i] = extract_features_from_dict(app)
        y_train[i] = app["label"]

    X_test = np.zeros((len(test_apps), FEATURE_SPEC["num_features"]), dtype=np.float32)
    y_test = np.zeros(len(test_apps), dtype=np.int32)
    for i, app in enumerate(test_apps):
        X_test[i] = extract_features_from_dict(app)
        y_test[i] = app["label"]

    print(f"Train Set: {X_train.shape[0]} samples (Positives: {np.sum(y_train)}, Negatives: {len(y_train)-np.sum(y_train)})")
    print(f"Test Set:  {X_test.shape[0]} samples (Positives: {np.sum(y_test)}, Negatives: {len(y_test)-np.sum(y_test)})")

    # 2. Train Gradient Boosted Trees Ensemble
    print("\nTraining Production GBT Ensemble (Schema v2.0.0 — 92 Dimensions)...")
    gbt = GradientBoostingClassifier(
        n_estimators=160,
        learning_rate=0.08,
        max_depth=4,
        subsample=0.85,
        min_samples_split=10,
        min_samples_leaf=5,
        random_state=42
    )
    gbt.fit(X_train, y_train)

    # 3. 5-Fold Cross-Validation for Platt Scaling Parameters (a, b)
    print("\nFitting 5-Fold Platt Scaling Sigmoid Calibrator...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    oof_raw_logits = np.zeros(len(y_train), dtype=np.float64)

    for train_idx, val_idx in cv.split(X_train, y_train):
        fold_gbt = GradientBoostingClassifier(
            n_estimators=160, learning_rate=0.08, max_depth=4,
            subsample=0.85, min_samples_split=10, min_samples_leaf=5, random_state=42
        )
        fold_gbt.fit(X_train[train_idx], y_train[train_idx])
        oof_raw_logits[val_idx] = fold_gbt.decision_function(X_train[val_idx])

    # Fit Platt scaling: P = 1 / (1 + exp(a * z + b))
    # Using LogisticRegression on -z: log(p / (1-p)) = - (a * z + b)
    platt_lr = LogisticRegression(C=1.0, solver="lbfgs")
    platt_lr.fit(oof_raw_logits.reshape(-1, 1), y_train)

    # In sklearn LogisticRegression: P = 1 / (1 + exp(- (w * z + intercept)))
    # Standard Platt notation: P = 1 / (1 + exp(a * z + b)) -> a = -w, b = -intercept
    calib_a = float(-platt_lr.coef_[0][0])
    calib_b = float(-platt_lr.intercept_[0])

    print(f"  * Platt Sigmoid Calibration Slope (a):     {calib_a:.6f}")
    print(f"  * Platt Sigmoid Calibration Intercept (b): {calib_b:.6f}")

    # Compute Calibrated Probabilities on Test Set
    test_raw_logits = gbt.decision_function(X_test)
    test_calibrated_probs = 1.0 / (1.0 + np.exp(calib_a * test_raw_logits + calib_b))

    brier = brier_score_loss(y_test, test_calibrated_probs)
    ece = compute_ece(test_calibrated_probs, y_test)
    test_auc = roc_auc_score(y_test, test_calibrated_probs)

    print("\nCalibration Quality on Test Set:")
    print(f"  * Test ROC-AUC:      {test_auc:.4f}")
    print(f"  * Brier Score:       {brier:.6f} (Lower is better, ideal ~ 0.00)")
    print(f"  * Calibration ECE:   {ece:.6f} (Expected Calibration Error)")

    importances = gbt.feature_importances_
    indices = np.argsort(importances)[::-1]
    print("\nTop 10 Most Discriminative Features:")
    for rank in range(10):
        idx = indices[rank]
        feat_name = FEATURE_SPEC["features"][idx]["name"]
        print(f"  {rank+1:02d}. [{idx:02d}] {feat_name:<35}: {importances[idx]*100:.2f}%")

    # Save models and calibration parameters
    print(f"\nSaving models and calibration parameters to {MODELS_DIR}...")
    joblib.dump(gbt, os.path.join(MODELS_DIR, "gbt_model.joblib"))
    np.save(os.path.join(MODELS_DIR, "feature_importances.npy"), importances)

    calib_params = {
        "method": "sigmoid",
        "a": calib_a,
        "b": calib_b,
        "brier_score": brier,
        "ece": ece
    }
    with open(os.path.join(MODELS_DIR, "calibrated_params.json"), "w", encoding="utf-8") as f:
        json.dump(calib_params, f, indent=2)

    print("Model training & calibration complete.")

if __name__ == "__main__":
    train_pipeline()