import json
import os
import sys
import numpy as np
import joblib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from ml.features.extractor import FEATURE_SPEC

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../models/saved_models'))
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
        "version": "1.0.0",
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


def export_all():
    print("="*80)
    print("AEGIS ON-DEVICE MODEL EXPORTER")
    print("="*80)

    gbt = joblib.load(os.path.join(MODELS_DIR, 'gbt_model.joblib'))
    
    # 1. Export JSON Tree representation for Kotlin Engine
    json_path = os.path.join(EXPORT_DIR, 'aegis_malware_model.json')
    export_gbt_to_json(gbt, json_path)
    
    # 2. Copy JSON model and feature_spec to Android Assets
    assets_model = os.path.join(ANDROID_ASSETS_DIR, 'aegis_malware_model.json')
    assets_spec = os.path.join(ANDROID_ASSETS_DIR, 'feature_spec.json')
    
    import shutil
    shutil.copy(json_path, assets_model)
    shutil.copy(os.path.abspath(os.path.join(os.path.dirname(__file__), '../features/feature_spec.json')), assets_spec)
    
    print(f"Copied model to Android assets: {assets_model}")
    print(f"Copied feature spec to Android assets: {assets_spec}")
    print("\nExport completed successfully.")

if __name__ == '__main__':
    export_all()