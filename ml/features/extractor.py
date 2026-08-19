"""
AEGIS Static APK Feature Extractor
Extracts an 80-dimensional normalized feature vector matching feature_spec.json
"""

import json
import os
import re
from typing import Dict, Any, List, Tuple
import numpy as np

SPEC_PATH = os.path.join(os.path.dirname(__file__), "feature_spec.json")
with open(SPEC_PATH, "r", encoding="utf-8-sig") as f:
    FEATURE_SPEC = json.load(f)

NUM_FEATURES = FEATURE_SPEC["num_features"]

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": 0,
    "android.permission.RECEIVE_SMS": 1,
    "android.permission.SEND_SMS": 2,
    "android.permission.READ_CALL_LOG": 3,
    "android.permission.WRITE_CALL_LOG": 4,
    "android.permission.READ_CONTACTS": 5,
    "android.permission.WRITE_CONTACTS": 6,
    "android.permission.ACCESS_FINE_LOCATION": 7,
    "android.permission.ACCESS_COARSE_LOCATION": 8,
    "android.permission.RECORD_AUDIO": 9,
    "android.permission.CAMERA": 10,
    "android.permission.SYSTEM_ALERT_WINDOW": 11,
    "android.permission.READ_PHONE_STATE": 12,
    "android.permission.PROCESS_OUTGOING_CALLS": 13,
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 14,
    "android.permission.BIND_DEVICE_ADMIN": 15,
    "android.permission.REQUEST_INSTALL_PACKAGES": 16,
    "android.permission.INSTALL_PACKAGES": 17,
    "android.permission.QUERY_ALL_PACKAGES": 18,
    "android.permission.ACCESS_BACKGROUND_LOCATION": 19,
    "android.permission.USE_BIOMETRIC": 20,
    "android.permission.WRITE_SETTINGS": 21,
    "android.permission.GET_ACCOUNTS": 22
}

TRUSTED_PUBLISHERS = {
    "com.google.android",
    "com.google.android.apps",
    "com.whatsapp",
    "com.phonepe.app",
    "net.one97.paytm",
    "com.sbi.lotusintouch",
    "com.hdfcbank.payzapp",
    "com.msf.kbank.mobile",
    "com.icicibank.mobile",
    "com.ubercab",
    "com.spotify.music",
    "org.mozilla.firefox",
    "com.microsoft.teams"
}

SYSTEM_IMPERSONATION_TARGETS = [
    "google service", "google play", "system update", "google framework", 
    "android system", "security plugin", "battery optimizer", "device manager",
    "sbi yono", "hdfc bank", "phonepe", "paytm", "gpay", "whatsapp"
]

SUSPICIOUS_PACKAGE_TOKENS = [
    "com.example", "reverseshell", "payload", "rat", "bot", "hack", "dropper", "spy", "stealth"
]

def extract_features_from_dict(app: Dict[str, Any]) -> np.ndarray:
    vec = np.zeros(NUM_FEATURES, dtype=np.float32)
    
    perms = set(app.get("permissions", []))
    sig_perms = set(app.get("signature_permissions", []))
    dex = set(app.get("dex_strings", []))
    manifest = app.get("manifest", {})
    cert = app.get("certificate", {})
    
    package_name = app.get("package_name", "").lower()
    app_name = app.get("app_name", "").lower()
    target_sdk = int(app.get("target_sdk", 33))
    min_sdk = int(app.get("min_sdk", 21))
    is_sideloaded = 1.0 if app.get("is_sideloaded", True) else 0.0
    is_system = 1.0 if app.get("is_system_app", False) else 0.0

    # Family 1: Permissions (0 - 29)
    dang_count = 0
    for perm_name, idx in DANGEROUS_PERMISSIONS.items():
        if perm_name in perms:
            vec[idx] = 1.0
            dang_count += 1
            
    read_sms = (vec[0] == 1.0 or vec[1] == 1.0)
    send_sms = (vec[2] == 1.0)
    vec[23] = 1.0 if (read_sms and send_sms) else 0.0
    
    surveillance = (vec[9] == 1.0 and (vec[7] == 1.0 or vec[8] == 1.0) and vec[10] == 1.0)
    vec[24] = 1.0 if surveillance else 0.0
    
    overlay_access = (vec[11] == 1.0 and vec[14] == 1.0)
    vec[25] = 1.0 if overlay_access else 0.0
    
    harvest = (vec[3] == 1.0 and read_sms and vec[5] == 1.0)
    vec[26] = 1.0 if harvest else 0.0
    
    vec[27] = min(float(dang_count) / 20.0, 1.0)
    vec[28] = min(float(len(perms)) / 60.0, 1.0)
    vec[29] = min(float(len(sig_perms)) / 10.0, 1.0)

    # Family 2: DEX Usage (30 - 48)
    dex_suspicious_count = 0
    def check_dex(patterns: List[str], idx: int) -> bool:
        nonlocal dex_suspicious_count
        hit = any(p in dex or any(p in s for s in dex) for p in patterns)
        if hit:
            vec[idx] = 1.0
            dex_suspicious_count += 1
            return True
        return False

    check_dex(["content://sms", "content://telephony/sms"], 30)
    check_dex(["content://call_log", "content://call_log/calls"], 31)
    check_dex(["content://contacts", "content://com.android.contacts"], 32)
    check_dex(["android.telephony.SmsManager", "sendTextMessage", "sendMultipartTextMessage"], 33)
    check_dex(["java.lang.ProcessBuilder", "ProcessBuilder"], 34)
    check_dex(["Runtime.getRuntime().exec", "Runtime.exec", "/system/bin/sh"], 35)
    check_dex(["dalvik.system.DexClassLoader", "DexClassLoader", "InMemoryDexClassLoader"], 36)
    check_dex(["java.lang.reflect.Method.invoke", "Method.invoke"], 37)
    check_dex(["java.net.Socket", "Socket(", "connectSocket"], 38)
    check_dex(["getDeviceId", "getImei", "getSubscriberId", "getSimSerialNumber", "getMacAddress"], 39)
    check_dex(["/system/bin/sh", "su", "chmod 777", "/system/xbin/su"], 40)
    check_dex(["javax.crypto.Cipher", "DESede", "AES/CBC/PKCS5Padding"], 41)
    check_dex(["android.util.Base64.decode", "Base64.decode", "base64_payload"], 42)
    check_dex(["/system/app/Superuser.apk", "which su", "test-keys", "busybox"], 43)
    
    has_raw_ip = any(re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b", s) for s in dex)
    if has_raw_ip or "raw_c2_ip" in dex:
        vec[44] = 1.0
        dex_suspicious_count += 1
        
    check_dex(["AccessibilityNodeInfo.performAction", "ACTION_CLICK", "dispatchGesture"], 45)
    check_dex(["AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED", "OnKeyListener", "keylogger"], 46)
    check_dex(["SurfaceTexture(0)", "hidden_camera_capture", "camera_surface_null"], 47)
    
    vec[48] = min(float(dex_suspicious_count) / 15.0, 1.0)

    # Family 3: Manifest Structure (49 - 60)
    exp_act = manifest.get("exported_activities", 1)
    exp_srv = manifest.get("exported_services", 0)
    exp_rec = manifest.get("exported_receivers", 0)
    tot_comp = manifest.get("total_components", max(1, exp_act + exp_srv + exp_rec + 2))
    
    vec[49] = min(float(exp_act) / 20.0, 1.0)
    vec[50] = min(float(exp_srv) / 10.0, 1.0)
    vec[51] = min(float(exp_rec) / 10.0, 1.0)
    vec[52] = 1.0 if manifest.get("has_boot_receiver", False) else 0.0
    vec[53] = 1.0 if manifest.get("has_sms_receiver", False) else 0.0
    vec[54] = 1.0 if manifest.get("has_foreground_service", False) else 0.0
    vec[55] = 1.0 if manifest.get("has_accessibility_service", False) else 0.0
    vec[56] = 1.0 if manifest.get("has_device_admin", False) else 0.0
    vec[57] = 1.0 if manifest.get("has_system_alert_window", False) else 0.0
    vec[58] = 1.0 if manifest.get("has_launcher_activity", True) else 0.0
    vec[59] = min(float(tot_comp) / 50.0, 1.0)
    vec[60] = float(exp_act + exp_srv + exp_rec) / float(tot_comp) if tot_comp > 0 else 0.0

    # Family 4: Signing / Certificate (61 - 66)
    vec[61] = 1.0 if cert.get("is_debug_key", False) else 0.0
    vec[62] = 1.0 if cert.get("is_self_signed", False) else 0.0
    
    is_known = cert.get("is_known_publisher", False) or any(package_name.startswith(p) for p in TRUSTED_PUBLISHERS)
    vec[63] = 1.0 if is_known else 0.0
    
    validity = float(cert.get("validity_years", 25.0))
    vec[64] = min(validity / 50.0, 1.0)
    vec[65] = 1.0 if cert.get("is_generic_issuer", False) else 0.0
    vec[66] = min(float(cert.get("cert_count", 1)) / 5.0, 1.0)

    # Family 5: Provenance & Metadata (67 - 75)
    vec[67] = is_sideloaded
    vec[68] = min(float(target_sdk) / 35.0, 1.0)
    vec[69] = 1.0 if target_sdk <= 22 else 0.0
    vec[70] = 1.0 if target_sdk <= 28 else 0.0
    vec[71] = min(float(min_sdk) / 35.0, 1.0)
    vec[72] = is_system
    
    impersonates = False
    for target in SYSTEM_IMPERSONATION_TARGETS:
        if target in app_name and not is_system and not is_known:
            impersonates = True
            break
    vec[73] = 1.0 if impersonates else 0.0
    
    has_susp_token = any(tok in package_name for tok in SUSPICIOUS_PACKAGE_TOKENS)
    vec[74] = 1.0 if (has_susp_token and not is_known) else 0.0
    
    segments = len(package_name.split("."))
    vec[75] = min(float(segments) / 8.0, 1.0)

    # Family 6: Joint High-Order Threat Tells (76 - 79)
    has_rat_dex = (vec[34] == 1.0 or vec[38] == 1.0 or vec[40] == 1.0)
    has_rat_perms = (read_sms or vec[3] == 1.0)
    vec[76] = 1.0 if (has_rat_dex and is_sideloaded and vec[69] == 1.0 and has_rat_perms) else 0.0
    
    has_bank_perms = (read_sms or vec[5] == 1.0)
    vec[77] = 1.0 if (vec[25] == 1.0 and is_sideloaded and has_bank_perms) else 0.0
    
    has_drop_perm = (vec[16] == 1.0 or vec[17] == 1.0)
    has_drop_dex = (vec[36] == 1.0 or vec[42] == 1.0)
    vec[78] = 1.0 if (has_drop_perm and has_drop_dex and is_sideloaded) else 0.0
    
    has_spy_stealth = (vec[58] == 0.0 or vec[52] == 1.0)
    vec[79] = 1.0 if (vec[24] == 1.0 and is_sideloaded and has_spy_stealth and vec[39] == 1.0) else 0.0

    return vec

def explain_prediction(feature_vector: np.ndarray, feature_importances: np.ndarray = None, top_k: int = 3) -> List[Tuple[str, str, float]]:
    reasons = []
    features_meta = FEATURE_SPEC["features"]
    
    high_signal_indices = [76, 77, 78, 79, 69, 73, 24, 25, 26, 34, 38, 40, 44, 45, 61, 74]
    
    scored_features = []
    for idx in range(len(feature_vector)):
        val = feature_vector[idx]
        if val > 0.0:
            weight = feature_importances[idx] if feature_importances is not None else 1.0
            if idx in high_signal_indices:
                weight *= 3.0
            score = float(val * weight)
            scored_features.append((score, idx))
            
    scored_features.sort(key=lambda x: x[0], reverse=True)
    
    for score, idx in scored_features[:top_k]:
        meta = features_meta[idx]
        reasons.append((meta["name"], meta["description"], round(score, 3)))
        
    return reasons