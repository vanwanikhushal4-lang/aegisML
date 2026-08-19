import os, sys, json
import numpy as np
import joblib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from ml.features.extractor import FEATURE_SPEC

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../models/saved_models"))
EXPORT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../export"))
GOLDEN_PATH = os.path.join(EXPORT_DIR, "golden_test_vectors.json")

def run_golden_tests():
    print("="*80)
    print(f"RUNNING AEGIS GOLDEN TEST VECTORS VERIFICATION ({FEATURE_SPEC['num_features']} FEATURES)")
    print("="*80)

    with open(GOLDEN_PATH, "r", encoding="utf-8-sig") as f:
        golden_data = json.load(f)

    test_cases = golden_data["test_cases"]
    calibrated_model = joblib.load(os.path.join(MODELS_DIR, "calibrated_gbt.joblib"))

    passed_count = 0
    total_count = len(test_cases)

    print(f"\n{'Case ID':<35} | {'Expected':<10} | {'Actual Cal Prob':<16} | {'Risk':<6} | {'Status'}")
    print("-" * 80)

    for case in test_cases:
        cid = case["case_id"]
        v = np.array(case.get("vector_88", case.get("vector_80")), dtype=np.float32).reshape(1, -1)
        expected_tier = case["expected_threat_tier"]
        expected_is_mal = case["expected_is_malware"]
        expected_prob = case["expected_calibrated_prob"]

        prob_cal = float(calibrated_model.predict_proba(v)[0, 1])
        score = int(round(prob_cal * 100))

        prob_match = abs(prob_cal - expected_prob) < 0.05
        is_mal = prob_cal >= golden_data["operating_threshold"]
        verdict_match = (is_mal == expected_is_mal)

        status = "[PASS]"
        if not (prob_match and verdict_match):
            status = f"[FAIL - DIFF {abs(prob_cal - expected_prob):.4f}]"
        else:
            passed_count += 1

        print(f"{cid:<35} | {expected_tier:<10} | {prob_cal:<16.4f} | {score:<6} | {status}")

    print("-" * 80)
    print(f"Golden Vector Verification Result: {passed_count} / {total_count} PASSED")
    return passed_count == total_count

if __name__ == "__main__":
    run_golden_tests()