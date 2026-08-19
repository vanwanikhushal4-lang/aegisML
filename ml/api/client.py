"""
AEGIS Malware Classifier — API Client & Test Suite
Enables scanning APKs, JSON metadata, or feature vectors against the running FastAPI server.
"""

import os
import sys
import argparse
import requests
import json

API_BASE_URL = "http://127.0.0.1:8000"

def test_health():
    print("\n[1] Testing GET /health...")
    resp = requests.get(f"{API_BASE_URL}/health")
    if resp.status_code == 200:
        print("  [+] Server is healthy:", resp.json())
        return True
    else:
        print("  [-] Health check failed:", resp.text)
        return False

def test_scan_apk(apk_path: str):
    print(f"\n[2] Testing POST /scan/apk with '{apk_path}'...")
    if not os.path.exists(apk_path):
        print(f"  [-] APK file not found at {apk_path}")
        return False

    with open(apk_path, "rb") as f:
        files = {"file": (os.path.basename(apk_path), f, "application/vnd.android.package-archive")}
        resp = requests.post(f"{API_BASE_URL}/scan/apk", files=files, params={"is_sideloaded": True})

    if resp.status_code == 200:
        data = resp.json()
        print_scan_result("REAL APK SCAN RESULT", data)
        return True
    else:
        print("  [-] APK scan failed:", resp.text)
        return False

def test_scan_json():
    print("\n[3] Testing POST /scan/app-json with benign CRM payload...")
    payload = {
        "package_name": "com.enterprise.salescrm",
        "app_name": "Biz Drive CRM",
        "is_system_app": False,
        "is_sideloaded": True,
        "target_sdk": 33,
        "min_sdk": 26,
        "permissions": [
            "android.permission.INTERNET",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG"
        ],
        "dex_strings": ["retrofit2.Retrofit", "java.net.Socket", "Base64.decode"],
        "manifest": {
            "exported_activities": 1,
            "exported_services": 0,
            "exported_receivers": 0,
            "has_boot_receiver": False,
            "has_sms_receiver": False,
            "has_foreground_service": False,
            "has_accessibility_service": False,
            "has_device_admin": False,
            "has_system_alert_window": False,
            "has_launcher_activity": True,
            "total_components": 12
        },
        "certificate": {
            "is_debug_key": False,
            "is_self_signed": True,
            "is_known_publisher": False,
            "validity_years": 25.0
        }
    }
    resp = requests.post(f"{API_BASE_URL}/scan/app-json", json=payload)
    if resp.status_code == 200:
        data = resp.json()
        print_scan_result("JSON METADATA SCAN RESULT", data)
        return True
    else:
        print("  [-] JSON scan failed:", resp.text)
        return False

def test_benchmark_samples():
    print("\n[4] Testing GET /benchmark/samples...")
    resp = requests.get(f"{API_BASE_URL}/benchmark/samples")
    if resp.status_code == 200:
        data = resp.json()
        print(f"  [+] Retrieved {data['benchmark_count']} benchmark comparisons:")
        print(f"  {'-'*80}")
        print(f"  {'Sample / App':<40} | {'Score':<8} | {'Tier':<10} | {'Malice Prob':<12} | {'Flagged'}")
        print(f"  {'-'*80}")
        for item in data["samples"]:
            res = item["result"]
            name = f"{res['app_name']} ({res['package_name']})"
            if len(name) > 38: name = name[:35] + "..."
            flag_str = "THREAT" if res["is_flagged_as_threat"] else "CLEAN"
            print(f"  {name:<40} | {res['risk_score']:<8} | {res['threat_level']:<10} | {res['malware_probability']:<12.4f} | {flag_str}")
        print(f"  {'-'*80}")
        return True
    else:
        print("  [-] Benchmark endpoint failed:", resp.text)
        return False

def print_scan_result(title: str, res: dict):
    print(f"\n  {'='*70}")
    print(f"  {title}")
    print(f"  {'='*70}")
    print(f"  App Name:            {res.get('app_name')}")
    print(f"  Package Name:        {res.get('package_name')}")
    print(f"  Risk Score:          {res.get('risk_score')}/100")
    print(f"  Threat Level:        {res.get('threat_level')}")
    print(f"  Malware Probability: {res.get('malware_probability')}")
    print(f"  Operating Threshold: {res.get('operating_threshold')}")
    print(f"  Verdict:             {'[!] MALWARE / THREAT DETECTED' if res.get('is_flagged_as_threat') else '[+] CLEAN / BENIGN'}")
    print(f"  Latency:             {res.get('latency_ms')} ms")
    print(f"  Top Explainable Reasons (for UI 'Why' line):")
    for r in res.get("top_reasons", []):
        print(f"    -> [{r['feature_name']}]: {r['description']} (impact: {r['contribution_score']:.3f})")
    print(f"  {'='*70}")

def run_all_tests():
    print("="*80)
    print("RUNNING FULL AEGIS INFERENCE API SUITE VERIFICATION")
    print("="*80)
    
    ok1 = test_health()
    ok2 = test_scan_apk("C:/Users/user/Downloads/androrat/AndroRAT/malware.apk")
    ok3 = test_scan_json()
    ok4 = test_benchmark_samples()
    
    if ok1 and ok2 and ok3 and ok4:
        print("\n[SUCCESS] ALL INFERENCE API ENDPOINTS VERIFIED & WORKING!")
    else:
        print("\n[FAILURE] One or more API endpoints failed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS Inference API Client")
    parser.add_argument("--test", action="store_true", help="Run full API verification suite")
    parser.add_argument("--apk", type=str, help="Path to APK file to scan")
    parser.add_argument("--health", action="store_true", help="Check server health")
    args = parser.parse_args()

    if args.health:
        test_health()
    elif args.apk:
        test_scan_apk(args.apk)
    else:
        run_all_tests()