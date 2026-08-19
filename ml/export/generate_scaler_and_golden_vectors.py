"""
AEGIS ML Scaler, Feature Spec, and Golden Test Vectors Generator (88 Features)
Generates:
1. feature_spec.json (88 features)
2. scaler.json (88 features)
3. golden_test_vectors.json (10 verified golden vectors over 88 dimensions)
"""

import os
import sys
import json
import numpy as np
import joblib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from ml.features.extractor import FEATURE_SPEC, extract_features_from_apk, extract_features_from_dict

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../models/saved_models"))
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data"))
EXPORT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "."))
ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../app/src/main/assets"))

def generate_artifacts():
    print("="*80)
    print("GENERATING SCALER, FEATURE SPEC, AND GOLDEN TEST VECTORS (88 FEATURES)")
    print("="*80)

    # 1. Feature Spec
    with open(os.path.join(EXPORT_DIR, "feature_spec.json"), "w", encoding="utf-8") as f:
        json.dump(FEATURE_SPEC, f, indent=2)
    with open(os.path.join(ASSETS_DIR, "feature_spec.json"), "w", encoding="utf-8") as f:
        json.dump(FEATURE_SPEC, f, indent=2)
    print(f"[1] Exported feature_spec.json ({len(FEATURE_SPEC['features'])} features)")

    # 2. Scaler Spec
    scaler_spec = {
        "num_features": FEATURE_SPEC["num_features"],
        "scaling_type": "min_max_normalization",
        "description": "Deterministic scaling parameters and normalization denominators for AEGIS 88-feature vector",
        "features": []
    }
    for feat in FEATURE_SPEC["features"]:
        name = feat["name"]
        idx = feat["index"]
        cat = feat.get("category", name.split("_")[0])
        
        scale_divisor = 1.0
        if name == "perm_dangerous_count": scale_divisor = 20.0
        elif name == "perm_total_count": scale_divisor = 60.0
        elif name == "dex_total_suspicious_patterns": scale_divisor = 15.0
        elif name == "manifest_exported_activities": scale_divisor = 20.0
        elif name in ("manifest_exported_services", "manifest_exported_receivers"): scale_divisor = 10.0
        elif name == "manifest_total_components": scale_divisor = 50.0
        elif name == "cert_validity_years": scale_divisor = 50.0
        elif name == "cert_count": scale_divisor = 5.0
        elif name in ("meta_target_sdk_normalized", "meta_min_sdk_normalized"): scale_divisor = 35.0
        elif name == "meta_package_segment_depth": scale_divisor = 8.0
        elif name == "struct_asset_max_entropy": scale_divisor = 8.0
        elif name == "struct_webview_phishing_density": scale_divisor = 20.0

        scaler_spec["features"].append({
            "index": idx,
            "name": name,
            "category": cat,
            "type": feat["type"],
            "scale_divisor": float(scale_divisor),
            "min_val": 0.0,
            "max_val": 1.0
        })

    with open(os.path.join(EXPORT_DIR, "scaler.json"), "w", encoding="utf-8") as f:
        json.dump(scaler_spec, f, indent=2)
    with open(os.path.join(ASSETS_DIR, "scaler.json"), "w", encoding="utf-8") as f:
        json.dump(scaler_spec, f, indent=2)
    print(f"[2] Exported scaler.json ({len(scaler_spec['features'])} feature scalers)")

    # 3. Golden Test Cases
    calibrated_model = joblib.load(os.path.join(MODELS_DIR, "calibrated_gbt.joblib"))
    raw_gbt_model = joblib.load(os.path.join(MODELS_DIR, "gbt_model.joblib"))

    golden_cases = []

    def make_entry(cid, desc, vec):
        p_cal = float(calibrated_model.predict_proba(vec.reshape(1, -1))[0, 1])
        p_raw = float(raw_gbt_model.predict_proba(vec.reshape(1, -1))[0, 1])
        is_mal = p_cal >= 0.160
        tier = "SAFE" if p_cal < 0.16 else ("LOW" if p_cal < 0.40 else ("MEDIUM" if p_cal < 0.75 else "CRITICAL"))
        return {
            "case_id": cid,
            "description": desc,
            "expected_threat_tier": tier,
            "expected_is_malware": is_mal,
            "expected_calibrated_prob": round(p_cal, 4),
            "expected_raw_prob": round(p_raw, 4),
            "expected_risk_score": int(round(p_cal * 100)),
            "vector_88": [round(float(x), 4) for x in vec]
        }

    # Case A: Real AndroRAT
    real_rat_path = "C:/Users/user/Downloads/androrat/AndroRAT/malware.apk"
    if os.path.exists(real_rat_path):
        v_rat = extract_features_from_apk(real_rat_path, is_sideloaded=True)
        golden_cases.append(make_entry("real_androrat_apk", "Real AndroRAT Trojan sample (com.example.reverseshell2)", v_rat))

    # Case B: Real Packed Card Stealer Trojan
    real_trojan_path = "C:/Users/user/Downloads/60648a8e5ee28177de38e6ea40c17481b95a63e6aa4ca466754bc7e7f08bd2ab.apk"
    if os.path.exists(real_trojan_path):
        v_trojan = extract_features_from_apk(real_trojan_path, is_sideloaded=True)
        golden_cases.append(make_entry("real_packed_trojan_apk", "Real Packed Iranian Card-Stealer Trojan", v_trojan))

    # Case C: Allowlist Banking Apps
    with open(os.path.join(DATA_DIR, "allowlist_gate_dataset.json"), "r", encoding="utf-8-sig") as f:
        allowlist_apps = json.load(f)
    for app_meta in allowlist_apps:
        v_app = extract_features_from_dict(app_meta)
        golden_cases.append(make_entry(f"allowlist_{app_meta['package_name']}", f"Allowlist / Business sample: {app_meta['app_name']}", v_app))

    # Case D: Boundary Vectors
    v_zero = np.zeros(FEATURE_SPEC["num_features"], dtype=np.float32)
    golden_cases.append(make_entry("boundary_all_zeros", "Boundary test: 88 zeros", v_zero))

    v_ones = np.ones(FEATURE_SPEC["num_features"], dtype=np.float32)
    golden_cases.append(make_entry("boundary_all_ones_maximum_threat", "Boundary test: 88 ones (maximum malice triggers)", v_ones))

    golden_payload = {
        "schema_version": "1.0.0",
        "num_features": FEATURE_SPEC["num_features"],
        "operating_threshold": 0.160,
        "total_test_cases": len(golden_cases),
        "test_cases": golden_cases
    }

    with open(os.path.join(EXPORT_DIR, "golden_test_vectors.json"), "w", encoding="utf-8") as f:
        json.dump(golden_payload, f, indent=2)
    with open(os.path.join(ASSETS_DIR, "golden_test_vectors.json"), "w", encoding="utf-8") as f:
        json.dump(golden_payload, f, indent=2)
    print(f"[3] Exported golden_test_vectors.json ({len(golden_cases)} verified golden vectors)")

if __name__ == "__main__":
    generate_artifacts()