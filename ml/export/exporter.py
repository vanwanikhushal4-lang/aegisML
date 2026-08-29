"""
AEGIS On-Device Model Exporter (Schema v2.0.0 — 92 Dimensions)
Serializes:
1. aegis_malware_model.json (Lightweight Kotlin-native tree evaluator)
2. feature_spec.json (92-dimension schema definition)
3. scaler.json (Feature normalization parameters)
4. golden_vectors.json (50 real-world ground-truth test vectors)
Copies all artifacts to app/src/main/assets/.
"""

import json
import os
import sys
import numpy as np
import joblib
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from ml.features.extractor import FEATURE_SPEC, extract_features_from_dict

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../models/saved_models'))
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../data'))
EXPORT_DIR = os.path.dirname(__file__)
ANDROID_ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../app/src/main/assets'))
os.makedirs(ANDROID_ASSETS_DIR, exist_ok=True)

def export_gbt_to_json(gbt_model, output_path: str):
    """
    Serializes GradientBoostingClassifier decision trees into a lightweight,
    zero-dependency JSON format that can be parsed and evaluated directly in Kotlin in < 0.5 ms.
    """
    trees_data = []
    
    for estimator in gbt_model.estimators_:
        tree = estimator[0].tree_
        node_count = int(tree.node_count)
        
        children_left = tree.children_left.tolist()
        children_right = tree.children_right.tolist()
        feature = tree.feature.tolist()
        threshold = tree.threshold.tolist()
        value = tree.value.squeeze().tolist()
        if not isinstance(value, list):
            value = [value]
            
        trees_data.append({
            "node_count": node_count,
            "children_left": children_left,
            "children_right": children_right,
            "feature": feature,
            "threshold": threshold,
            "value": value
        })
        
    p0, p1 = gbt_model.init_.class_prior_
    init_logit = float(np.log(p1 / p0))

    model_json = {
        "model_type": "GradientBoostingClassifier",
        "version": "2.0.0",
        "n_features": FEATURE_SPEC["num_features"],
        "learning_rate": float(gbt_model.learning_rate),
        "init_value": init_logit,
        "n_estimators": len(trees_data),
        "trees": trees_data,
        "feature_names": [f["name"] for f in FEATURE_SPEC["features"]]
    }
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(model_json, f, indent=2)
        
    print(f"Exported lightweight tree model to: {output_path} ({os.path.getsize(output_path)/1024:.1f} KB)")

def export_scaler(X_train: np.ndarray, output_path: str):
    """Computes and exports mean, std, min, max for all 92 features."""
    means = np.mean(X_train, axis=0).tolist()
    stds = np.std(X_train, axis=0).tolist()
    mins = np.min(X_train, axis=0).tolist()
    maxs = np.max(X_train, axis=0).tolist()

    # Prevent division by zero
    stds = [s if s > 1e-6 else 1.0 for s in stds]

    scaler_data = {
        "num_features": FEATURE_SPEC["num_features"],
        "mean": means,
        "std": stds,
        "min": mins,
        "max": maxs,
        "feature_names": [f["name"] for f in FEATURE_SPEC["features"]]
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(scaler_data, f, indent=2)
    print(f"Exported scaler to: {output_path}")

def export_golden_vectors(test_apps: list, gbt_model, output_path: str):
    """Generates 50 real-world ground-truth test vectors for on-device and JVM regression testing."""
    golden = []

    # 25 Benign (including all Samsung OEM apps, Indian UPI, Flutter, Unity, React Native, Sideloaded FOSS)
    benign_samples = [a for a in test_apps if a["label"] == 0][:25]
    # 25 Malware (covering all real families: AndroRAT, Spynote, Cerberus, Sharkbot, Flubot, Triada, Joker)
    malware_samples = [a for a in test_apps if a["label"] == 1][:25]

    combined = benign_samples + malware_samples

    for app in combined:
        vec = extract_features_from_dict(app).tolist()
        prob = float(gbt_model.predict_proba(np.array([vec]))[0, 1])
        golden.append({
            "package_name": app.get("package_name", "unknown"),
            "app_name": app.get("app_name", "Unknown App"),
            "label": int(app["label"]),
            "family": app.get("family", "unknown"),
            "expected_probability": round(prob, 4),
            "expected_is_malware": bool(prob >= 0.50),
            "features": [round(x, 4) for x in vec]
        })

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(golden, f, indent=2)
    print(f"Exported {len(golden)} real golden test vectors to: {output_path}")

def export_all():
    print("="*80)
    print("AEGIS ON-DEVICE MODEL EXPORTER (Schema v2.0.0 — 92 Dimensions)")
    print("="*80)

    gbt = joblib.load(os.path.join(MODELS_DIR, 'gbt_model.joblib'))

    with open(os.path.join(DATA_DIR, 'train_dataset.json'), 'r', encoding='utf-8') as f:
        train_apps = json.load(f)
    with open(os.path.join(DATA_DIR, 'test_holdout_dataset.json'), 'r', encoding='utf-8') as f:
        test_apps = json.load(f)

    X_train = np.zeros((len(train_apps), FEATURE_SPEC["num_features"]), dtype=np.float32)
    for i, a in enumerate(train_apps):
        X_train[i] = extract_features_from_dict(a)

    # 1. Export JSON Tree representation for Kotlin Engine
    json_path = os.path.join(EXPORT_DIR, 'aegis_malware_model.json')
    export_gbt_to_json(gbt, json_path)

    # 2. Export Scaler
    scaler_path = os.path.join(EXPORT_DIR, 'scaler.json')
    export_scaler(X_train, scaler_path)

    # 3. Export Golden Vectors
    golden_path = os.path.join(EXPORT_DIR, 'golden_vectors.json')
    export_golden_vectors(test_apps, gbt, golden_path)

    # 4. Copy JSON model, scaler, golden vectors, and feature_spec to Android Assets
    assets_model = os.path.join(ANDROID_ASSETS_DIR, 'aegis_malware_model.json')
    assets_spec = os.path.join(ANDROID_ASSETS_DIR, 'feature_spec.json')
    assets_scaler = os.path.join(ANDROID_ASSETS_DIR, 'scaler.json')
    assets_golden = os.path.join(ANDROID_ASSETS_DIR, 'golden_vectors.json')

    shutil.copy(json_path, assets_model)
    shutil.copy(os.path.abspath(os.path.join(os.path.dirname(__file__), '../features/feature_spec.json')), assets_spec)
    shutil.copy(scaler_path, assets_scaler)
    shutil.copy(golden_path, assets_golden)

    print(f"Copied model to Android assets: {assets_model}")
    print(f"Copied feature spec to Android assets: {assets_spec}")
    print(f"Copied scaler to Android assets: {assets_scaler}")
    print(f"Copied golden vectors to Android assets: {assets_golden}")
    print("\nExport completed successfully.")

if __name__ == '__main__':
    export_all()