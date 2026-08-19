"""
AEGIS Static Feature Extractor (88 Features)
Natively extracts 88 static dimensions:
- Permissions (0-29)
- DEX Strings (30-48)
- Manifest Structure (49-60)
- Certificates (61-66)
- Provenance & Metadata (67-75)
- Joint Threat Tells (76-79)
- Packaging, Asset Entropy & Anti-Analysis Dimensions (80-87)
"""

import os
import sys
import math
import zipfile
import json
from collections import Counter
from typing import Dict, Any, List, Tuple
import numpy as np

with open(os.path.join(os.path.dirname(__file__), "../export/feature_spec.json"), "r", encoding="utf-8-sig") as f:
    FEATURE_SPEC = json.load(f)

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
    "android.permission.GET_ACCOUNTS": 22,
}

def shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    return -sum((c/len(data)) * math.log2(c/len(data)) for c in Counter(data).values())

def extract_features_from_apk(apk_path: str, is_sideloaded: bool = True) -> np.ndarray:
    """Extracts 88-dimensional feature vector directly from an APK file."""
    vec = np.zeros(FEATURE_SPEC["num_features"], dtype=np.float32)
    if not os.path.exists(apk_path):
        return vec

    normalized_path = apk_path.replace("\\", "/")
    from androguard.core.apk import APK
    apk = APK(normalized_path)

    # 1. Manifest Permissions (0-29)
    declared_perms = set(apk.get_permissions() or [])
    dang_count = 0
    for perm_name, idx in DANGEROUS_PERMISSIONS.items():
        if perm_name in declared_perms:
            vec[idx] = 1.0
            dang_count += 1

    read_sms = (vec[0] == 1.0 or vec[1] == 1.0)
    send_sms = (vec[2] == 1.0)
    if read_sms and send_sms: vec[23] = 1.0
    if vec[9] == 1.0 and (vec[7] == 1.0 or vec[8] == 1.0) and vec[10] == 1.0: vec[24] = 1.0
    if vec[11] == 1.0 and vec[14] == 1.0: vec[25] = 1.0
    if vec[3] == 1.0 and read_sms and vec[5] == 1.0: vec[26] = 1.0

    vec[27] = min(dang_count / 20.0, 1.0)
    vec[28] = min(len(declared_perms) / 60.0, 1.0)
    vec[29] = 1.0 if any("signature" in p.lower() for p in declared_perms) else 0.0

    # 2. Hardened Multi-DEX Bytecode Scan & Structural Asset Scan
    dex_susp_count = 0
    dex_strings_all = set()
    total_dex_size = 0
    has_native_lib = False
    max_asset_entropy = 0.0
    has_encrypted_asset = False
    html_card_mentions = 0
    zip_tampered = False

    zf = zipfile.ZipFile(apk_path)
    for info in zf.infolist():
        if info.flag_bits & 0x1:
            zip_tampered = True

        info.flag_bits &= ~0x1 # bypass fake encryption flag
        try:
            raw_data = zf.read(info.filename)
        except Exception:
            continue

        if info.filename.endswith(".dex"):
            total_dex_size += len(raw_data)
            content = raw_data.decode("latin-1", errors="ignore")
            targets = {
                "content://sms": 30, "content://telephony/sms": 30,
                "content://call_log": 31,
                "content://contacts": 32,
                "SmsManager": 33,
                "ProcessBuilder": 34,
                "Runtime.getRuntime().exec": 35, "Runtime.exec": 35,
                "DexClassLoader": 36,
                "Method.invoke": 37,
                "java.net.Socket": 38,
                "getDeviceId": 39, "getSubscriberId": 39, "getImei": 39,
                "/system/bin/sh": 40, "which su": 40, "chmod 777": 40,
                "javax.crypto.Cipher": 41,
                "Base64": 42,
                "/system/app/Superuser.apk": 43,
                "DeviceAdminReceiver": 44,
                "AccessibilityNodeInfo": 45,
                "OnKeyListener": 46, "KeyEvent": 46,
                "api.telegram.org": 47
            }
            for pattern, feat_idx in targets.items():
                if pattern in content:
                    if vec[feat_idx] == 0.0:
                        vec[feat_idx] = 1.0
                        dex_susp_count += 1
                        dex_strings_all.add(pattern)
        elif info.filename.endswith(".so") or "lib/" in info.filename:
            has_native_lib = True
        elif info.filename.startswith("assets/"):
            ent = shannon_entropy(raw_data)
            if ent > max_asset_entropy:
                max_asset_entropy = ent
            if len(raw_data) > 50000 and (ent > 7.80 or raw_data.startswith(b"\x7fEPDATA") or raw_data.startswith(b"dex\n")):
                has_encrypted_asset = True
            if info.filename.endswith(".html") or info.filename.endswith(".js"):
                text = raw_data.decode("utf-8", errors="ignore").lower()
                card_count = text.count("card")
                if card_count >= 5:
                    html_card_mentions += card_count

    vec[48] = min(dex_susp_count / 15.0, 1.0)

    # 3. Manifest Components (49-60)
    activities = apk.get_activities() or []
    services = apk.get_services() or []
    receivers = apk.get_receivers() or []

    vec[49] = min(len(activities) / 20.0, 1.0)
    vec[50] = min(len(services) / 10.0, 1.0)
    vec[51] = min(len(receivers) / 10.0, 1.0)

    try:
        manifest_xml = apk.get_android_manifest_xml()
        xml_str = manifest_xml.decode("utf-8", errors="ignore") if isinstance(manifest_xml, bytes) else str(manifest_xml)
    except Exception:
        xml_str = ""

    vec[52] = 1.0 if "BOOT_COMPLETED" in xml_str or "android.intent.action.BOOT_COMPLETED" in declared_perms else 0.0
    vec[53] = 1.0 if "SMS_RECEIVED" in xml_str or "android.provider.Telephony.SMS_RECEIVED" in declared_perms else 0.0
    vec[54] = 1.0 if "FOREGROUND_SERVICE" in xml_str or "android.permission.FOREGROUND_SERVICE" in declared_perms else 0.0
    vec[55] = vec[14]
    vec[56] = vec[15]
    vec[57] = vec[11]
    vec[58] = 1.0 if (apk.get_main_activity() is not None or len(activities) > 0) else 0.0

    tot_comp = len(activities) + len(services) + len(receivers)
    vec[59] = min(tot_comp / 50.0, 1.0)
    vec[60] = 0.50

    # 4. Certificates (61-66)
    certs = apk.get_certificates() or []
    vec[66] = min(len(certs) / 5.0, 1.0)
    vec[61] = 0.0
    vec[62] = 1.0 if is_sideloaded else 0.0
    vec[64] = 0.50
    vec[65] = 0.0

    # 5. Metadata (67-75)
    target_sdk = int(apk.get_target_sdk_version() or 28)
    min_sdk = int(apk.get_min_sdk_version() or 21)
    pkg_name = apk.get_package() or ""
    app_label = str(apk.get_app_name() or "").lower()

    vec[67] = 1.0 if is_sideloaded else 0.0
    vec[68] = min(target_sdk / 35.0, 1.0)
    vec[69] = 1.0 if target_sdk <= 22 else 0.0
    vec[70] = 1.0 if target_sdk <= 28 else 0.0
    vec[71] = min(min_sdk / 35.0, 1.0)
    vec[72] = 0.0

    susp_pkg = 1.0 if any(p in pkg_name.lower() for p in ["reverseshell", "rat", "payload", "spy", "stealer", "trojan"]) else 0.0
    vec[74] = susp_pkg

    known_brands = ["divar", "sbi", "phonepe", "paytm", "google pay", "whatsapp", "telegram", "instagram"]
    is_impersonation = 0.0
    if is_sideloaded:
        for brand in known_brands:
            if brand in app_label and not (brand in pkg_name.lower()):
                is_impersonation = 1.0
                break
    vec[73] = is_impersonation
    vec[75] = min(len(pkg_name.split(".")) / 8.0, 1.0)

    # 6. Joint Tells (76-79)
    has_rat_dex = (vec[34] == 1.0 or vec[38] == 1.0 or vec[40] == 1.0)
    has_rat_perms = (read_sms or vec[3] == 1.0)
    if has_rat_dex and is_sideloaded and vec[69] == 1.0 and has_rat_perms: vec[76] = 1.0
    if vec[25] == 1.0 and is_sideloaded and (read_sms or vec[5] == 1.0): vec[77] = 1.0
    if (vec[16] == 1.0 or vec[17] == 1.0) and (vec[36] == 1.0 or vec[42] == 1.0) and is_sideloaded: vec[78] = 1.0
    if vec[24] == 1.0 and is_sideloaded and (vec[58] == 0.0 or vec[52] == 1.0) and vec[39] == 1.0: vec[79] = 1.0

    # 7. Structural, Packaging & Anti-Analysis Dimensions (80-87)
    thin_dex = (0 < total_dex_size < 40000 and has_native_lib)
    vec[80] = 1.0 if zip_tampered else 0.0
    vec[81] = min(max_asset_entropy / 8.0, 1.0)
    vec[82] = 1.0 if has_encrypted_asset else 0.0
    vec[83] = 1.0 if thin_dex else 0.0
    vec[84] = 1.0 if has_native_lib else 0.0
    vec[85] = min(html_card_mentions / 20.0, 1.0)
    vec[86] = 1.0 if (has_encrypted_asset and read_sms and is_sideloaded) else 0.0
    vec[87] = 1.0 if (zip_tampered and thin_dex and (vec[16] == 1.0 or vec[17] == 1.0 or vec[36] == 1.0)) else 0.0

    return vec

def extract_features_from_dict(app: Dict[str, Any]) -> np.ndarray:
    """Extracts 88-dimensional feature vector from a dictionary representation."""
    vec = np.zeros(FEATURE_SPEC["num_features"], dtype=np.float32)
    
    perms = set(app.get("permissions", []))
    dang_count = 0
    for perm_name, idx in DANGEROUS_PERMISSIONS.items():
        if perm_name in perms:
            vec[idx] = 1.0
            dang_count += 1

    read_sms = (vec[0] == 1.0 or vec[1] == 1.0)
    send_sms = (vec[2] == 1.0)
    if read_sms and send_sms: vec[23] = 1.0
    if vec[9] == 1.0 and (vec[7] == 1.0 or vec[8] == 1.0) and vec[10] == 1.0: vec[24] = 1.0
    if vec[11] == 1.0 and vec[14] == 1.0: vec[25] = 1.0
    if vec[3] == 1.0 and read_sms and vec[5] == 1.0: vec[26] = 1.0

    vec[27] = min(dang_count / 20.0, 1.0)
    vec[28] = min(len(perms) / 60.0, 1.0)
    vec[29] = 1.0 if len(app.get("signature_permissions", [])) > 0 else 0.0

    dex_strings = app.get("dex_strings", [])
    dex_susp_count = 0
    dex_map = {
        "content://sms": 30, "content://telephony/sms": 30,
        "content://call_log": 31,
        "content://contacts": 32,
        "SmsManager": 33,
        "ProcessBuilder": 34,
        "Runtime.exec": 35, "Runtime.getRuntime().exec": 35,
        "DexClassLoader": 36,
        "Method.invoke": 37,
        "Socket": 38, "java.net.Socket": 38,
        "getDeviceId": 39, "getSubscriberId": 39, "getImei": 39,
        "/system/bin/sh": 40, "which su": 40, "chmod 777": 40, "su": 40,
        "Cipher": 41, "javax.crypto.Cipher": 41,
        "Base64": 42,
        "Superuser.apk": 43,
        "DeviceAdminReceiver": 44,
        "AccessibilityNodeInfo": 45,
        "OnKeyListener": 46, "KeyEvent": 46,
        "api.telegram.org": 47
    }
    for s in dex_strings:
        for pat, idx in dex_map.items():
            if pat in s:
                if vec[idx] == 0.0:
                    vec[idx] = 1.0
                    dex_susp_count += 1
    vec[48] = min(dex_susp_count / 15.0, 1.0)

    # Manifest
    m = app.get("manifest", {})
    vec[49] = min(m.get("exported_activities", 1) / 20.0, 1.0)
    vec[50] = min(m.get("exported_services", 0) / 10.0, 1.0)
    vec[51] = min(m.get("exported_receivers", 0) / 10.0, 1.0)
    vec[52] = 1.0 if m.get("has_boot_receiver", False) else 0.0
    vec[53] = 1.0 if m.get("has_sms_receiver", False) else 0.0
    vec[54] = 1.0 if m.get("has_foreground_service", False) else 0.0
    vec[55] = 1.0 if m.get("has_accessibility_service", False) else 0.0
    vec[56] = 1.0 if m.get("has_device_admin", False) else 0.0
    vec[57] = 1.0 if m.get("has_system_alert_window", False) else 0.0
    vec[58] = 1.0 if m.get("has_launcher_activity", True) else 0.0
    vec[59] = min(m.get("total_components", 5) / 50.0, 1.0)
    vec[60] = 0.50

    # Cert
    c = app.get("certificate", {})
    vec[61] = 1.0 if c.get("is_debug_key", False) else 0.0
    vec[62] = 1.0 if c.get("is_self_signed", False) else 0.0
    vec[63] = 1.0 if c.get("is_known_publisher", False) else 0.0
    vec[64] = min(c.get("validity_years", 25.0) / 50.0, 1.0)
    vec[65] = 1.0 if c.get("is_debug_key", False) else 0.0
    vec[66] = 0.20

    # Meta
    is_side = app.get("is_sideloaded", True)
    target_sdk = app.get("target_sdk", 33)
    min_sdk = app.get("min_sdk", 21)
    pkg = app.get("package_name", "")
    app_label = app.get("app_name", "").lower()

    vec[67] = 1.0 if is_side else 0.0
    vec[68] = min(target_sdk / 35.0, 1.0)
    vec[69] = 1.0 if target_sdk <= 22 else 0.0
    vec[70] = 1.0 if target_sdk <= 28 else 0.0
    vec[71] = min(min_sdk / 35.0, 1.0)
    vec[72] = 1.0 if app.get("is_system_app", False) else 0.0
    vec[73] = 1.0 if ("google" in app_label and "google" not in pkg) else 0.0
    vec[74] = 1.0 if any(p in pkg.lower() for p in ["reverseshell", "rat", "payload"]) else 0.0
    vec[75] = min(len(pkg.split(".")) / 8.0, 1.0)

    # Joint
    has_rat_dex = (vec[34] == 1.0 or vec[38] == 1.0 or vec[40] == 1.0)
    has_rat_perms = (read_sms or vec[3] == 1.0)
    if has_rat_dex and is_side and vec[69] == 1.0 and has_rat_perms: vec[76] = 1.0
    if vec[25] == 1.0 and is_side and (read_sms or vec[5] == 1.0): vec[77] = 1.0
    if (vec[16] == 1.0 or vec[17] == 1.0) and (vec[36] == 1.0 or vec[42] == 1.0) and is_side: vec[78] = 1.0
    if vec[24] == 1.0 and is_side and (vec[58] == 0.0 or vec[52] == 1.0) and vec[39] == 1.0: vec[79] = 1.0

    # Structural packaging features for dict
    st = app.get("structural", {})
    vec[80] = 1.0 if st.get("zip_tampered", False) else 0.0
    vec[81] = min(st.get("asset_max_entropy", 5.0) / 8.0, 1.0)
    vec[82] = 1.0 if st.get("has_encrypted_asset", False) else 0.0
    vec[83] = 1.0 if st.get("thin_dex", False) else 0.0
    vec[84] = 1.0 if st.get("has_native_lib", False) else 0.0
    vec[85] = min(st.get("html_card_mentions", 0) / 20.0, 1.0)
    vec[86] = 1.0 if (vec[82] == 1.0 and read_sms and is_side) else 0.0
    vec[87] = 1.0 if (vec[80] == 1.0 and vec[83] == 1.0) else 0.0

    return vec

def explain_prediction(vec: np.ndarray, feature_importances: np.ndarray, top_k: int = 3) -> List[Tuple[str, str, float]]:
    active_indices = np.where(vec > 0.0)[0]
    scored = []
    for idx in active_indices:
        if idx < len(FEATURE_SPEC["features"]):
            feat = FEATURE_SPEC["features"][idx]
            weight = float(feature_importances[idx]) * float(vec[idx])
            scored.append((feat["name"], feat["description"], weight))
    scored.sort(key=lambda x: x[2], reverse=True)
    return scored[:top_k]
