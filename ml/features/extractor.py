"""
AEGIS Static Feature Extractor (Schema v2.0.0 — 92 Dimensions)
Natively extracts 92 static dimensions with 7-way provenance and corroborated structural forensics:
- Permissions (0-29)
- DEX Strings / Bytecode Patterns (30-48)
- Manifest Structure (49-60)
- Certificates (61-66)
- Provenance & Metadata (67-79) [7-way categorical provenance]
- Joint Threat Tells (80-83)
- Corroborated Structural Forensics & Packaging (84-91)
"""

import os
import sys
import math
import zipfile
import json
import re
from collections import Counter
from typing import Dict, Any, List, Tuple, Optional
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

TRUSTED_PUBLISHERS = {
    "com.google.android", "com.google.android.apps", "com.whatsapp",
    "com.phonepe.app", "net.one97.paytm", "com.sbi.lotusintouch",
    "com.hdfcbank.payzapp", "com.msf.kbank.mobile", "com.icicibank.mobile",
    "com.ubercab", "com.spotify.music", "org.mozilla.firefox", "com.microsoft.teams",
    "com.sec.android", "com.samsung.android", "com.oneplus", "com.oppo", "com.coloros",
    "com.realme", "com.miui", "com.xiaomi"
}

KNOWN_STORES = {
    "com.android.vending", "com.sec.android.app.samsungapps", "com.heytap.market",
    "com.oppo.market", "com.xiaomi.mipicks", "com.amazon.venezia"
}

OEM_RESTORE_INSTALLERS = {
    "com.sec.android.easyMover", "com.oneplus.backuprestore", "com.coloros.backuprestore",
    "com.miui.huanji", "com.huawei.dbank.vpush"
}

UNTRUSTED_DOWNLOADERS = {
    "com.android.chrome", "org.mozilla.firefox", "com.opera.browser", "com.brave.browser",
    "org.telegram.messenger", "com.whatsapp", "com.discord", "com.facebook.katana"
}

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    return -sum((c / len(data)) * math.log2(c / len(data)) for c in Counter(data).values())

def extract_features_from_apk(apk_path: str, provenance: str = "UNKNOWN") -> np.ndarray:
    """Extracts 92-dimensional feature vector directly from an APK file."""
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
    if read_sms and send_sms:
        vec[23] = 1.0
    if vec[9] == 1.0 and (vec[7] == 1.0 or vec[8] == 1.0) and vec[10] == 1.0:
        vec[24] = 1.0
    if vec[11] == 1.0 and vec[14] == 1.0:
        vec[25] = 1.0
    if vec[3] == 1.0 and read_sms and vec[5] == 1.0:
        vec[26] = 1.0

    vec[27] = min(dang_count / 20.0, 1.0)
    vec[28] = min(len(declared_perms) / 60.0, 1.0)
    vec[29] = 1.0 if any("signature" in p.lower() for p in declared_perms) else 0.0

    # 2. Hardened Multi-DEX Bytecode Scan & Structural Asset Scan
    dex_susp_count = 0
    total_dex_size = 0
    has_native_lib = False
    max_asset_entropy = 0.0
    html_card_mentions = 0
    zip_tampered = False

    zf = zipfile.ZipFile(apk_path)
    for info in zf.infolist():
        if info.flag_bits & 0x1:
            zip_tampered = True

        info.flag_bits &= ~0x1  # bypass fake encryption flag
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
                "content://contacts": 32, "content://com.android.contacts": 32,
                "android.telephony.SmsManager": 33, "sendTextMessage": 33, "SmsManager": 33,
                "java.lang.ProcessBuilder": 34, "ProcessBuilder": 34,
                "Runtime.getRuntime().exec": 35, "Runtime.exec": 35,
                "dalvik.system.DexClassLoader": 36, "DexClassLoader": 36, "InMemoryDexClassLoader": 36,
                "java.lang.reflect.Method.invoke": 37, "Method.invoke": 37,
                "java.net.Socket": 38, "Socket(": 38, "connectSocket": 38,
                "getDeviceId": 39, "getSubscriberId": 39, "getImei": 39, "getSimSerialNumber": 39,
                "/system/bin/sh": 40, "which su": 40, "chmod 777": 40, "/system/xbin/su": 40,
                "javax.crypto.Cipher": 41, "DESede": 41, "AES/CBC/PKCS5Padding": 41,
                "android.util.Base64.decode": 42, "Base64.decode": 42, "Base64": 42,
                "/system/app/Superuser.apk": 43, "test-keys": 43, "busybox": 43,
                "AccessibilityNodeInfo.performAction": 45, "ACTION_CLICK": 45, "dispatchGesture": 45, "AccessibilityNodeInfo": 45,
                "AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED": 46, "OnKeyListener": 46, "keylogger": 46, "KeyEvent": 46,
                "SurfaceTexture(0)": 47, "hidden_camera_capture": 47, "camera_surface_null": 47, "api.telegram.org": 47
            }
            for pattern, feat_idx in targets.items():
                if pattern in content:
                    if vec[feat_idx] == 0.0:
                        vec[feat_idx] = 1.0
                        dex_susp_count += 1
            if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b", content):
                if vec[44] == 0.0:
                    vec[44] = 1.0
                    dex_susp_count += 1
        elif info.filename.endswith(".so") or info.filename.startswith("lib/"):
            has_native_lib = True
        elif info.filename.startswith("assets/"):
            if len(raw_data) > 50000:
                ent = shannon_entropy(raw_data[:8192])
                if ent > max_asset_entropy:
                    max_asset_entropy = ent
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

    vec[52] = 1.0 if "BOOT_COMPLETED" in xml_str or "android.permission.RECEIVE_BOOT_COMPLETED" in declared_perms else 0.0
    vec[53] = 1.0 if "SMS_RECEIVED" in xml_str or "android.provider.Telephony.SMS_RECEIVED" in declared_perms or "android.permission.RECEIVE_SMS" in declared_perms else 0.0
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
    vec[62] = 0.0
    pkg_name = (apk.get_package() or "").lower()
    is_known_pub = any(pkg_name.startswith(p) for p in TRUSTED_PUBLISHERS)
    vec[63] = 1.0 if is_known_pub else 0.0
    vec[64] = 0.50
    vec[65] = 0.0

    # 5. Provenance & Metadata (67-79)
    # Provenance 7-way one-hot
    prov_upper = provenance.upper()
    if prov_upper == "SYSTEM_IMAGE":
        vec[67] = 1.0
    elif prov_upper == "UPDATED_SYSTEM_APP":
        vec[68] = 1.0
    elif prov_upper == "VERIFIED_STORE":
        vec[69] = 1.0
    elif prov_upper == "CONFIRMED_LOCAL_APK":
        vec[70] = 1.0
    elif prov_upper == "DOWNLOADED_APK":
        vec[71] = 1.0
    elif prov_upper == "RESTORED_OEM":
        vec[72] = 1.0
    else:  # UNKNOWN
        vec[73] = 1.0

    target_sdk = int(apk.get_target_sdk_version() or 33)
    min_sdk = int(apk.get_min_sdk_version() or 21)
    app_label = str(apk.get_app_name() or "").lower()

    vec[74] = min(target_sdk / 35.0, 1.0)
    vec[75] = 1.0 if target_sdk <= 22 else 0.0
    vec[76] = 1.0 if target_sdk <= 28 else 0.0
    vec[77] = min(min_sdk / 35.0, 1.0)

    is_system = (vec[67] == 1.0 or vec[68] == 1.0)
    known_brands = ["google service", "google play", "system update", "google framework", "android system",
                    "sbi yono", "hdfc bank", "phonepe", "paytm", "gpay", "whatsapp", "divar", "telegram"]
    is_impersonation = 0.0
    if not is_system and not is_known_pub:
        for brand in known_brands:
            if brand in app_label and not any(k in pkg_name for k in ["google", "sbi", "hdfc", "phonepe", "paytm", "whatsapp", "telegram"]):
                is_impersonation = 1.0
                break
    vec[78] = is_impersonation

    susp_tokens = ["reverseshell", "payload", "rat", "bot", "hack", "dropper", "spy", "stealer", "trojan"]
    vec[79] = 1.0 if any(p in pkg_name for p in susp_tokens) and not is_known_pub else 0.0

    # 6. Joint High-Order Threat Tells (80-83)
    untrusted = (vec[71] == 1.0 or vec[73] == 1.0 or vec[70] == 1.0)
    has_rat_dex = (vec[34] == 1.0 or vec[38] == 1.0 or vec[40] == 1.0)
    has_rat_perms = (read_sms or vec[3] == 1.0)
    if has_rat_dex and untrusted and vec[75] == 1.0 and has_rat_perms:
        vec[80] = 1.0
    if vec[25] == 1.0 and untrusted and (read_sms or vec[5] == 1.0):
        vec[81] = 1.0
    if (vec[16] == 1.0 or vec[17] == 1.0) and (vec[36] == 1.0 or vec[42] == 1.0) and untrusted:
        vec[82] = 1.0
    if vec[24] == 1.0 and untrusted and (vec[58] == 0.0 or vec[52] == 1.0) and vec[39] == 1.0:
        vec[83] = 1.0

    # 7. Structural Forensics & Packaging (84-91)
    thin_dex = (0 < total_dex_size < 40000 and has_native_lib)
    # Corroborated high entropy: high entropy asset (>7.80) ONLY WHEN corroborated by code loader, thin DEX stub, reflection, or tampered zip
    is_corroborated_packed = (max_asset_entropy >= 7.80 and (vec[36] == 1.0 or thin_dex or vec[37] == 1.0 or zip_tampered))

    vec[84] = 1.0 if zip_tampered else 0.0
    vec[85] = 1.0 if is_corroborated_packed else 0.0
    vec[86] = 1.0 if thin_dex else 0.0
    vec[87] = 1.0 if has_native_lib else 0.0
    vec[88] = min(html_card_mentions / 20.0, 1.0)
    vec[89] = 1.0 if (is_corroborated_packed and read_sms and untrusted) else 0.0
    vec[90] = 1.0 if (zip_tampered and thin_dex and (vec[16] == 1.0 or vec[17] == 1.0 or vec[36] == 1.0)) else 0.0
    vec[91] = min(len(pkg_name.split(".")) / 8.0, 1.0)

    return vec

def extract_features_from_dict(app: Dict[str, Any]) -> np.ndarray:
    """Extracts 92-dimensional feature vector from a dictionary representation."""
    vec = np.zeros(FEATURE_SPEC["num_features"], dtype=np.float32)

    perms = set(app.get("permissions", []))
    dang_count = 0
    for perm_name, idx in DANGEROUS_PERMISSIONS.items():
        if perm_name in perms:
            vec[idx] = 1.0
            dang_count += 1

    read_sms = (vec[0] == 1.0 or vec[1] == 1.0)
    send_sms = (vec[2] == 1.0)
    if read_sms and send_sms:
        vec[23] = 1.0
    if vec[9] == 1.0 and (vec[7] == 1.0 or vec[8] == 1.0) and vec[10] == 1.0:
        vec[24] = 1.0
    if vec[11] == 1.0 and vec[14] == 1.0:
        vec[25] = 1.0
    if vec[3] == 1.0 and read_sms and vec[5] == 1.0:
        vec[26] = 1.0

    vec[27] = min(dang_count / 20.0, 1.0)
    vec[28] = min(len(perms) / 60.0, 1.0)
    sig_perms = app.get("signature_permissions", [])
    vec[29] = min(len(sig_perms) / 10.0, 1.0)

    # DEX Usage
    dex_strings = set(app.get("dex_strings", []))
    dex_susp_count = 0
    targets = {
        "content://sms": 30, "content://telephony/sms": 30,
        "content://call_log": 31,
        "content://contacts": 32, "content://com.android.contacts": 32,
        "SmsManager": 33, "sendTextMessage": 33, "android.telephony.SmsManager": 33,
        "ProcessBuilder": 34, "java.lang.ProcessBuilder": 34,
        "Runtime.exec": 35, "Runtime.getRuntime().exec": 35,
        "DexClassLoader": 36, "dalvik.system.DexClassLoader": 36, "InMemoryDexClassLoader": 36,
        "Method.invoke": 37, "java.lang.reflect.Method.invoke": 37,
        "Socket": 38, "java.net.Socket": 38, "Socket(": 38,
        "getDeviceId": 39, "getSubscriberId": 39, "getImei": 39, "getSimSerialNumber": 39,
        "/system/bin/sh": 40, "which su": 40, "chmod 777": 40, "/system/xbin/su": 40,
        "Cipher": 41, "javax.crypto.Cipher": 41, "DESede": 41,
        "Base64": 42, "Base64.decode": 42,
        "Superuser": 43, "test-keys": 43, "busybox": 43,
        "AccessibilityNodeInfo": 45, "AccessibilityNodeInfo.performAction": 45,
        "OnKeyListener": 46, "keylogger": 46, "KeyEvent": 46,
        "SurfaceTexture(0)": 47, "hidden_camera_capture": 47, "camera_surface_null": 47, "api.telegram.org": 47
    }
    for pattern, feat_idx in targets.items():
        if any(pattern in s for s in dex_strings):
            if vec[feat_idx] == 0.0:
                vec[feat_idx] = 1.0
                dex_susp_count += 1

    if any(re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b", s) for s in dex_strings):
        if vec[44] == 0.0:
            vec[44] = 1.0
            dex_susp_count += 1

    vec[48] = min(dex_susp_count / 15.0, 1.0)

    # Manifest Structure
    manifest = app.get("manifest", {})
    act_count = manifest.get("exported_activities", 1)
    srv_count = manifest.get("exported_services", 0)
    rec_count = manifest.get("exported_receivers", 0)
    tot_comp = manifest.get("total_components", act_count + srv_count + rec_count)

    vec[49] = min(act_count / 20.0, 1.0)
    vec[50] = min(srv_count / 10.0, 1.0)
    vec[51] = min(rec_count / 10.0, 1.0)
    vec[52] = 1.0 if manifest.get("has_boot_receiver", False) else 0.0
    vec[53] = 1.0 if manifest.get("has_sms_receiver", False) else 0.0
    vec[54] = 1.0 if manifest.get("has_foreground_service", False) else 0.0
    vec[55] = 1.0 if manifest.get("has_accessibility_service", False) else vec[14]
    vec[56] = 1.0 if manifest.get("has_device_admin", False) else vec[15]
    vec[57] = 1.0 if manifest.get("has_system_alert_window", False) else vec[11]
    vec[58] = 1.0 if manifest.get("has_launcher_activity", True) else 0.0
    vec[59] = min(tot_comp / 50.0, 1.0)
    vec[60] = min((act_count + srv_count + rec_count) / max(tot_comp, 1), 1.0)

    # Certificates
    cert = app.get("certificate", {})
    vec[61] = 1.0 if cert.get("is_debug_key", False) else 0.0
    vec[62] = 1.0 if cert.get("is_self_signed", False) else 0.0
    pkg_name = app.get("package_name", "").lower()
    is_known_pub = cert.get("is_known_publisher", any(pkg_name.startswith(p) for p in TRUSTED_PUBLISHERS))
    vec[63] = 1.0 if is_known_pub else 0.0
    vec[64] = min(cert.get("validity_years", 25.0) / 50.0, 1.0)
    vec[65] = 1.0 if cert.get("is_generic_issuer", False) else 0.0
    vec[66] = min(cert.get("cert_count", 1) / 5.0, 1.0)

    # Provenance & Metadata (67-79)
    # Parse provenance field or derive from flags
    prov = app.get("provenance", None)
    is_sys = app.get("is_system_app", False)
    is_side = app.get("is_sideloaded", False)

    if prov is not None:
        prov_u = str(prov).upper()
        if prov_u == "SYSTEM_IMAGE":
            vec[67] = 1.0
        elif prov_u == "UPDATED_SYSTEM_APP":
            vec[68] = 1.0
        elif prov_u == "VERIFIED_STORE":
            vec[69] = 1.0
        elif prov_u == "CONFIRMED_LOCAL_APK":
            vec[70] = 1.0
        elif prov_u == "DOWNLOADED_APK":
            vec[71] = 1.0
        elif prov_u == "RESTORED_OEM":
            vec[72] = 1.0
        else:
            vec[73] = 1.0
    else:
        if is_sys:
            vec[67] = 1.0
        elif not is_side:
            vec[69] = 1.0
        else:
            vec[71] = 1.0

    target_sdk = app.get("target_sdk", 33)
    min_sdk = app.get("min_sdk", 21)
    app_label = app.get("app_name", pkg_name).lower()

    vec[74] = min(target_sdk / 35.0, 1.0)
    vec[75] = 1.0 if target_sdk <= 22 else 0.0
    vec[76] = 1.0 if target_sdk <= 28 else 0.0
    vec[77] = min(min_sdk / 35.0, 1.0)

    is_system = (vec[67] == 1.0 or vec[68] == 1.0)
    known_brands = ["google service", "google play", "system update", "google framework", "android system",
                    "sbi yono", "hdfc bank", "phonepe", "paytm", "gpay", "whatsapp", "divar", "telegram"]
    is_impersonation = 0.0
    if not is_system and not is_known_pub:
        for brand in known_brands:
            if brand in app_label and not any(k in pkg_name for k in ["google", "sbi", "hdfc", "phonepe", "paytm", "whatsapp", "telegram"]):
                is_impersonation = 1.0
                break
    vec[78] = is_impersonation

    susp_tokens = ["reverseshell", "payload", "rat", "bot", "hack", "dropper", "spy", "stealer", "trojan"]
    vec[79] = 1.0 if any(p in pkg_name for p in susp_tokens) and not is_known_pub else 0.0

    # Joint Tells (80-83)
    untrusted = (vec[71] == 1.0 or vec[73] == 1.0 or vec[70] == 1.0)
    has_rat_dex = (vec[34] == 1.0 or vec[38] == 1.0 or vec[40] == 1.0)
    has_rat_perms = (read_sms or vec[3] == 1.0)
    if has_rat_dex and untrusted and vec[75] == 1.0 and has_rat_perms:
        vec[80] = 1.0
    if vec[25] == 1.0 and untrusted and (read_sms or vec[5] == 1.0):
        vec[81] = 1.0
    if (vec[16] == 1.0 or vec[17] == 1.0) and (vec[36] == 1.0 or vec[42] == 1.0) and untrusted:
        vec[82] = 1.0
    if vec[24] == 1.0 and untrusted and (vec[58] == 0.0 or vec[52] == 1.0) and vec[39] == 1.0:
        vec[83] = 1.0

    # Structural Forensics (84-91)
    struct = app.get("structural", {})
    zip_tampered = struct.get("is_zip_tampered", False)
    is_thin_dex = struct.get("is_thin_dex", False)
    has_native = struct.get("has_native_lib", False)
    max_entropy = struct.get("max_asset_entropy", 0.0)
    html_cards = struct.get("html_card_mentions", 0)

    is_corroborated_packed = (max_entropy >= 7.80 and (vec[36] == 1.0 or is_thin_dex or vec[37] == 1.0 or zip_tampered))

    vec[84] = 1.0 if zip_tampered else 0.0
    vec[85] = 1.0 if is_corroborated_packed else 0.0
    vec[86] = 1.0 if is_thin_dex else 0.0
    vec[87] = 1.0 if has_native else 0.0
    vec[88] = min(html_cards / 20.0, 1.0)
    vec[89] = 1.0 if (is_corroborated_packed and read_sms and untrusted) else 0.0
    vec[90] = 1.0 if (zip_tampered and is_thin_dex and (vec[16] == 1.0 or vec[17] == 1.0 or vec[36] == 1.0)) else 0.0
    vec[91] = min(len(pkg_name.split(".")) / 8.0, 1.0)

    return vec
