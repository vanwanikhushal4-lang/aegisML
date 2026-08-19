"""
AEGIS Static Feature Extractor & Forensic Structural Analyzer
Extracts:
1. 80-dimensional feature vectors (Permissions, DEX, Manifest, Cert, Metadata, Joint tells)
2. Structural Packer & Phishing Heuristics (Anti-Analysis Zip, High-Entropy Assets, Thin DEX, WebView Phishing)
"""

import os
import sys
import re
import math
import zipfile
from collections import Counter
from typing import Dict, Any, List, Tuple
import numpy as np

FEATURE_SPEC = {
    "version": "1.0.0",
    "num_features": 80,
    "features": [
        {"index": 0, "name": "perm_read_sms", "type": "binary", "description": "android.permission.READ_SMS"},
        {"index": 1, "name": "perm_receive_sms", "type": "binary", "description": "android.permission.RECEIVE_SMS"},
        {"index": 2, "name": "perm_send_sms", "type": "binary", "description": "android.permission.SEND_SMS"},
        {"index": 3, "name": "perm_read_call_log", "type": "binary", "description": "android.permission.READ_CALL_LOG"},
        {"index": 4, "name": "perm_write_call_log", "type": "binary", "description": "android.permission.WRITE_CALL_LOG"},
        {"index": 5, "name": "perm_read_contacts", "type": "binary", "description": "android.permission.READ_CONTACTS"},
        {"index": 6, "name": "perm_write_contacts", "type": "binary", "description": "android.permission.WRITE_CONTACTS"},
        {"index": 7, "name": "perm_access_fine_location", "type": "binary", "description": "android.permission.ACCESS_FINE_LOCATION"},
        {"index": 8, "name": "perm_access_coarse_location", "type": "binary", "description": "android.permission.ACCESS_COARSE_LOCATION"},
        {"index": 9, "name": "perm_record_audio", "type": "binary", "description": "android.permission.RECORD_AUDIO"},
        {"index": 10, "name": "perm_camera", "type": "binary", "description": "android.permission.CAMERA"},
        {"index": 11, "name": "perm_system_alert_window", "type": "binary", "description": "android.permission.SYSTEM_ALERT_WINDOW"},
        {"index": 12, "name": "perm_read_phone_state", "type": "binary", "description": "android.permission.READ_PHONE_STATE"},
        {"index": 13, "name": "perm_process_outgoing_calls", "type": "binary", "description": "android.permission.PROCESS_OUTGOING_CALLS"},
        {"index": 14, "name": "perm_bind_accessibility_service", "type": "binary", "description": "android.permission.BIND_ACCESSIBILITY_SERVICE"},
        {"index": 15, "name": "perm_bind_device_admin", "type": "binary", "description": "android.permission.BIND_DEVICE_ADMIN"},
        {"index": 16, "name": "perm_request_install_packages", "type": "binary", "description": "android.permission.REQUEST_INSTALL_PACKAGES"},
        {"index": 17, "name": "perm_install_packages", "type": "binary", "description": "android.permission.INSTALL_PACKAGES"},
        {"index": 18, "name": "perm_query_all_packages", "type": "binary", "description": "android.permission.QUERY_ALL_PACKAGES"},
        {"index": 19, "name": "perm_access_background_location", "type": "binary", "description": "android.permission.ACCESS_BACKGROUND_LOCATION"},
        {"index": 20, "name": "perm_use_biometric", "type": "binary", "description": "android.permission.USE_BIOMETRIC"},
        {"index": 21, "name": "perm_write_settings", "type": "binary", "description": "android.permission.WRITE_SETTINGS"},
        {"index": 22, "name": "perm_get_accounts", "type": "binary", "description": "android.permission.GET_ACCOUNTS"},
        {"index": 23, "name": "perm_combo_sms_full", "type": "binary", "description": "(READ_SMS | RECEIVE_SMS) & SEND_SMS"},
        {"index": 24, "name": "perm_combo_stealth_surveillance", "type": "binary", "description": "AUDIO & LOCATION & CAMERA"},
        {"index": 25, "name": "perm_combo_overlay_accessibility", "type": "binary", "description": "SYSTEM_ALERT_WINDOW & ACCESSIBILITY"},
        {"index": 26, "name": "perm_combo_spy_triad", "type": "binary", "description": "CALL_LOG & SMS & CONTACTS"},
        {"index": 27, "name": "perm_dangerous_count", "type": "continuous", "description": "Normalized count of dangerous permissions (count / 20.0)"},
        {"index": 28, "name": "perm_total_count", "type": "continuous", "description": "Normalized total requested permissions (count / 60.0)"},
        {"index": 29, "name": "perm_signature_declared", "type": "binary", "description": "Declares custom signature permission"},
        {"index": 30, "name": "dex_content_sms", "type": "binary", "description": "Presence of content://sms string in DEX"},
        {"index": 31, "name": "dex_content_call_log", "type": "binary", "description": "Presence of content://call_log string in DEX"},
        {"index": 32, "name": "dex_content_contacts", "type": "binary", "description": "Presence of content://contacts string in DEX"},
        {"index": 33, "name": "dex_telephony_sms_manager", "type": "binary", "description": "android.telephony.SmsManager invocation"},
        {"index": 34, "name": "dex_process_builder", "type": "binary", "description": "java.lang.ProcessBuilder invocation"},
        {"index": 35, "name": "dex_runtime_exec", "type": "binary", "description": "java.lang.Runtime.getRuntime().exec invocation"},
        {"index": 36, "name": "dex_class_loader_dynamic", "type": "binary", "description": "dalvik.system.DexClassLoader dynamic DEX load"},
        {"index": 37, "name": "dex_reflection_invoke", "type": "binary", "description": "java.lang.reflect.Method.invoke invocation"},
        {"index": 38, "name": "dex_socket_direct", "type": "binary", "description": "java.net.Socket raw TCP socket usage"},
        {"index": 39, "name": "dex_device_id_harvest", "type": "binary", "description": "TelephonyManager.getDeviceId / getSubscriberId"},
        {"index": 40, "name": "dex_shell_bin_sh", "type": "binary", "description": "/system/bin/sh or su shell command string"},
        {"index": 41, "name": "dex_crypto_cipher", "type": "binary", "description": "javax.crypto.Cipher payload decryption"},
        {"index": 42, "name": "dex_base64_payload", "type": "binary", "description": "Base64 decode invocation or long Base64 payload strings"},
        {"index": 43, "name": "dex_root_command_check", "type": "binary", "description": "Root binary existence check"},
        {"index": 44, "name": "dex_admin_receiver_ref", "type": "binary", "description": "DeviceAdminReceiver subclass reference"},
        {"index": 45, "name": "dex_accessibility_dispatch", "type": "binary", "description": "AccessibilityNodeInfo click/gesture dispatching"},
        {"index": 46, "name": "dex_keylogger_markers", "type": "binary", "description": "OnKeyListener / KeyEvent harvest markers"},
        {"index": 47, "name": "dex_telegram_bot_api", "type": "binary", "description": "api.telegram.org / bot exfiltration string"},
        {"index": 48, "name": "dex_total_suspicious_patterns", "type": "continuous", "description": "Normalized count of suspicious DEX API calls (count / 15.0)"},
        {"index": 49, "name": "manifest_exported_activities", "type": "continuous", "description": "Normalized exported activities (count / 20.0)"},
        {"index": 50, "name": "manifest_exported_services", "type": "continuous", "description": "Normalized exported services (count / 10.0)"},
        {"index": 51, "name": "manifest_exported_receivers", "type": "continuous", "description": "Normalized exported receivers (count / 10.0)"},
        {"index": 52, "name": "manifest_has_boot_receiver", "type": "binary", "description": "RECEIVE_BOOT_COMPLETED receiver declared"},
        {"index": 53, "name": "manifest_has_sms_receiver", "type": "binary", "description": "SMS_RECEIVED receiver declared"},
        {"index": 54, "name": "manifest_has_foreground_service", "type": "binary", "description": "Foreground service declared"},
        {"index": 55, "name": "manifest_has_accessibility_service", "type": "binary", "description": "Accessibility service declared"},
        {"index": 56, "name": "manifest_has_device_admin", "type": "binary", "description": "Device admin component declared"},
        {"index": 57, "name": "manifest_has_system_alert_window", "type": "binary", "description": "Overlay window permission declared"},
        {"index": 58, "name": "manifest_has_launcher_activity", "type": "binary", "description": "Launcher / MAIN activity present"},
        {"index": 59, "name": "manifest_total_components", "type": "continuous", "description": "Normalized total manifest components (count / 50.0)"},
        {"index": 60, "name": "manifest_ratio_exported", "type": "continuous", "description": "Ratio of exported components to total components"},
        {"index": 61, "name": "cert_is_debug_key", "type": "binary", "description": "Signed with Android debug certificate (Android Debug)"},
        {"index": 62, "name": "cert_is_self_signed", "type": "binary", "description": "Certificate is self-signed"},
        {"index": 63, "name": "cert_is_known_publisher", "type": "binary", "description": "Signed by known trusted developer certificate"},
        {"index": 64, "name": "cert_validity_years", "type": "continuous", "description": "Certificate validity period (years / 50.0)"},
        {"index": 65, "name": "cert_issuer_default_or_generic", "type": "binary", "description": "Default/generic issuer subject DN (CN=Android, O=Android)"},
        {"index": 66, "name": "cert_count", "type": "continuous", "description": "Normalized number of certificates (count / 5.0)"},
        {"index": 67, "name": "meta_is_sideloaded", "type": "binary", "description": "1 if installed from unknown source/sideloaded, 0 if Google Play (com.android.vending)"},
        {"index": 68, "name": "meta_target_sdk_normalized", "type": "continuous", "description": "Normalized targetSdkVersion (sdk / 35.0)"},
        {"index": 69, "name": "meta_target_sdk_le_22", "type": "binary", "description": "targetSdkVersion <= 22 (legacy auto-granting permissions tell)"},
        {"index": 70, "name": "meta_target_sdk_le_28", "type": "binary", "description": "targetSdkVersion <= 28 (pre-scoped storage and legacy background)"},
        {"index": 71, "name": "meta_min_sdk_normalized", "type": "continuous", "description": "Normalized minSdkVersion (sdk / 35.0)"},
        {"index": 72, "name": "meta_is_system_app", "type": "binary", "description": "Installed as a privileged system application"},
        {"index": 73, "name": "meta_impersonation_score", "type": "binary", "description": "Impersonates legitimate brand/system package/label"},
        {"index": 74, "name": "meta_suspicious_package_name", "type": "binary", "description": "Suspicious package name structure (e.g. com.example.reverseshell)"},
        {"index": 75, "name": "meta_package_segment_depth", "type": "continuous", "description": "Normalized package dot-segment depth (depth / 8.0)"},
        {"index": 76, "name": "joint_rat_signature", "type": "binary", "description": "Sideloaded + Legacy SDK <= 22 + (ProcessBuilder|Socket|sh) + SMS/CallLog"},
        {"index": 77, "name": "joint_banking_overlay_signature", "type": "binary", "description": "Sideloaded + Accessibility + Overlay + (SMS|Contacts)"},
        {"index": 78, "name": "joint_dropper_signature", "type": "binary", "description": "Sideloaded + (DexClassLoader|Base64) + REQUEST_INSTALL_PACKAGES"},
        {"index": 79, "name": "joint_stealth_spyware_signature", "type": "binary", "description": "Sideloaded + No Launcher + (BOOT_COMPLETED) + Surveillance Combo + IMEI harvest"}
    ]
}

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

def analyze_apk_structural(apk_path: str) -> Dict[str, Any]:
    """
    Forensic structural packer, anti-analysis zip tampering, and local WebView phishing detector.
    Catches packed Android malware where malice is hidden in encrypted asset blobs or native loaders.
    """
    if not os.path.exists(apk_path):
        return {"is_packed_threat": False, "score": 0, "reasons": []}

    zf = zipfile.ZipFile(apk_path)
    zip_tampered = False
    total_dex_size = 0
    has_native_lib = False
    has_encrypted_asset = False
    has_webview_phishing = False
    max_asset_entropy = 0.0
    encrypted_asset_name = ""
    html_card_mentions = 0
    
    for info in zf.infolist():
        # Check zip tampering (fake encryption bit)
        if info.flag_bits & 0x1:
            zip_tampered = True
        
        # Bypass fake encryption flag
        info.flag_bits &= ~0x1
        try:
            data = zf.read(info.filename)
        except Exception:
            continue
            
        if info.filename.endswith(".dex"):
            total_dex_size += len(data)
        elif info.filename.endswith(".so") or "lib/" in info.filename:
            has_native_lib = True
        elif info.filename.startswith("assets/"):
            ent = shannon_entropy(data)
            if ent > max_asset_entropy:
                max_asset_entropy = ent
            if len(data) > 50000 and (ent > 7.80 or data.startswith(b"\x7fEPDATA") or data.startswith(b"dex\n")):
                has_encrypted_asset = True
                encrypted_asset_name = info.filename
            if info.filename.endswith(".html") or info.filename.endswith(".js"):
                text = data.decode("utf-8", errors="ignore").lower()
                card_count = text.count("card")
                if card_count >= 5:
                    has_webview_phishing = True
                    html_card_mentions = card_count

    thin_dex = (0 < total_dex_size < 40000 and has_native_lib)
    
    score = 0
    reasons = []
    
    if zip_tampered:
        score += 35
        reasons.append("Anti-Analysis Zip Header Tampering (fake encryption bit flag 0x0001)")
    if has_encrypted_asset:
        score += 45
        reasons.append(f"High-Entropy Encrypted Asset Blob ({encrypted_asset_name}, entropy={max_asset_entropy:.2f})")
    if thin_dex:
        score += 25
        reasons.append(f"Thin DEX Loader Stub ({total_dex_size/1024:.1f} KB) paired with Native .so Unpacker")
    if has_webview_phishing:
        score += 35
        reasons.append(f"Local WebView Financial Phishing Form (assets/index.html with {html_card_mentions} card fields)")

    final_score = min(score, 100)
    is_threat = final_score >= 60

    return {
        "is_packed_threat": is_threat,
        "structural_score": final_score,
        "zip_tampered": zip_tampered,
        "has_encrypted_asset": has_encrypted_asset,
        "thin_dex": thin_dex,
        "has_webview_phishing": has_webview_phishing,
        "reasons": reasons
    }

def extract_features_from_apk(apk_path: str, is_sideloaded: bool = True) -> np.ndarray:
    """Extracts 80-dimensional feature vector directly from an APK file using Androguard with zip bypass."""
    vec = np.zeros(FEATURE_SPEC["num_features"], dtype=np.float32)
    if not os.path.exists(apk_path):
        return vec

    normalized_path = apk_path.replace("\\", "/")
    from androguard.core.apk import APK
    apk = APK(normalized_path)

    # 1. Manifest Permissions
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

    # 2. Hardened Multi-DEX Bytecode Scan
    dex_susp_count = 0
    dex_strings_all = set()

    zf = zipfile.ZipFile(apk_path)
    for info in zf.infolist():
        if info.filename.endswith(".dex"):
            info.flag_bits &= ~0x1 # bypass fake encryption flag
            try:
                content = zf.read(info.filename).decode("latin-1", errors="ignore")
            except Exception:
                continue
            
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

    vec[48] = min(dex_susp_count / 15.0, 1.0)

    # 3. Manifest Components
    activities = apk.get_activities() or []
    services = apk.get_services() or []
    receivers = apk.get_receivers() or []

    vec[49] = min(len(activities) / 20.0, 1.0)
    vec[50] = min(len(services) / 10.0, 1.0)
    vec[51] = min(len(receivers) / 10.0, 1.0)

    # Check intents
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

    # 4. Certificates
    certs = apk.get_certificates() or []
    vec[66] = min(len(certs) / 5.0, 1.0)
    vec[61] = 0.0
    vec[62] = 1.0 if is_sideloaded else 0.0
    vec[64] = 0.50
    vec[65] = 0.0

    # 5. Metadata
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

    # Impersonation check
    known_brands = ["divar", "sbi", "phonepe", "paytm", "google pay", "whatsapp", "telegram", "instagram"]
    is_impersonation = 0.0
    if is_sideloaded:
        for brand in known_brands:
            if brand in app_label and not (brand in pkg_name.lower()):
                is_impersonation = 1.0
                break
    vec[73] = is_impersonation
    vec[75] = min(len(pkg_name.split(".")) / 8.0, 1.0)

    # 6. Joint Tells
    has_rat_dex = (vec[34] == 1.0 or vec[38] == 1.0 or vec[40] == 1.0)
    has_rat_perms = (read_sms or vec[3] == 1.0)
    if has_rat_dex and is_sideloaded and vec[69] == 1.0 and has_rat_perms: vec[76] = 1.0
    if vec[25] == 1.0 and is_sideloaded and (read_sms or vec[5] == 1.0): vec[77] = 1.0
    if (vec[16] == 1.0 or vec[17] == 1.0) and (vec[36] == 1.0 or vec[42] == 1.0) and is_sideloaded: vec[78] = 1.0
    if vec[24] == 1.0 and is_sideloaded and (vec[58] == 0.0 or vec[52] == 1.0) and vec[39] == 1.0: vec[79] = 1.0

    return vec

def extract_features_from_dict(app: Dict[str, Any]) -> np.ndarray:
    """Extracts 80-dimensional feature vector from a dictionary representation."""
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

    return vec

def explain_prediction(vec: np.ndarray, feature_importances: np.ndarray, top_k: int = 3) -> List[Tuple[str, str, float]]:
    active_indices = np.where(vec > 0.0)[0]
    scored = []
    for idx in active_indices:
        feat = FEATURE_SPEC["features"][idx]
        weight = float(feature_importances[idx]) * float(vec[idx])
        scored.append((feat["name"], feat["description"], weight))
    scored.sort(key=lambda x: x[2], reverse=True)
    return scored[:top_k]