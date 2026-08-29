"""
AEGIS On-Device App Feature Extractor (Schema v2.0.0 — 92 Dimensions)
Transforms an Android application (APK, Split-APK directory, or Package dict) into a 92-element vector.
Uses cryptographic certificate verification (not package prefixes) and treats provenance strictly as external evidence.
"""

import json
import os
import re
import math
import zipfile
import hashlib
from typing import Dict, Any, List, Set, Union, Optional
import numpy as np

# Load Schema v2.0.0 Specification
FEATURE_SPEC_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "feature_spec.json"))
with open(FEATURE_SPEC_PATH, "r", encoding="utf-8") as f:
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
    "android.permission.GET_ACCOUNTS": 22
}

TRUSTED_CERT_SHA256_SET = {
    # Google LLC Platform & App Keys
    "3184771213aaa571eb74bc34f461cf694aa552a0d05a166053661fe334dc2f3a",
    "38918a453d07199354f8b19af05ec6562ced5788d60a8c38548b5dbf6670a3b4",
    "f0fd6c5ec410f2157d093b8099e04b609e2cb4ef60e445d4e83f16334f5d82dc",
    # Samsung Electronics / Knox One UI Keys
    "9b9ebef87d4c7dcc740812f280e026df5db094f510d2af443cb42789030e30c9",
    "ae3bf39f22975896a3ddcc7f4084af538a48026c6cfdc4b62cf8a4778f424e99",
    "58e3e81e0e7e29401e18d102d3f03e1826b4f44060f687e844243c4e09ec1638",
    # Xiaomi / MIUI / HyperOS Platform Keys
    "f9e21ac0410b6d48162ba288e1a7086f2b819b6289489a39e809cdc534d89332",
    "1bd4f1422fde8b0c3b877e99ffe0ed5b8944c5c8563ba1eaaf506d59d577798b",
    "287e07662c1d06371cf792518e1b6f005c331a9c3756dfc1e55099351e06c7e2",
    # OnePlus (OxygenOS) Platform Keys
    "eb485a89673ba2cd621dc52ae3d2726af4370e42bf9f24b0b5158f75a328e24f",
    "6465dc41094038a8e1039989f6645367b140669b33a5796a84d4361546944e89",
    # OPPO / Realme (ColorOS / Realme UI) Platform Keys
    "0da273d28326a60aaabe1c53fa2bc1d700e01f1795e49317657972db72f65212",
    "c06d3f3371f8b17b498ec05ba7155726ba1db15ba699451344d163e4d2bc1347",
    "e43a71a5092101f6a161af1630bb7ff1ddde3a7633e21d6006466ebd413b2b4e",
    # Huawei / Honor (HarmonyOS / EMUI) Platform Keys
    "dd5a2a9b7c7b9e4c447b2d6ac2ccf2900b86d32e15ddb0c742d2be8ccc351518",
    "bf17d057a70a8d46a6f6df600e0544425aa1453270424d31f602d693213e42fd",
    # Vivo / iQOO (FuntouchOS / OriginOS) Platform Keys
    "832aae9a7368771d4d2ee93fd572be681a2d12e3d4b358b1c65053290d50b560",
    "1954a9307d2199c05e22036400c3cd9e80e2995b93fe6d309ee1d6150994fb63",
    # Indian Banking / UPI / NPCI
    "102d059606fc9859dbc7029e95914132f248f4952c1d48ca3dc7bee65d7db606",
    "d2bbe55f4b3aa28780d761a144ab4b29e8e41c8fb47d4d44500c2688b6d49092",
    "c4436573c52e8964e52627048a1c97a80b7204eb0a696328fb68ef21199a0994"
}

def compute_entropy(data: bytes) -> float:
    """Computes Shannon entropy over a byte sequence [0.0 - 8.0]."""
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy

def extract_features_from_apk(apk_path: str, provenance: str = "UNKNOWN") -> np.ndarray:
    """Extracts 92-dimensional feature vector directly from an APK file or Split-APK set directory."""
    vec = np.zeros(FEATURE_SPEC["num_features"], dtype=np.float32)
    if not os.path.exists(apk_path):
        return vec

    # Support directory of split APKs or single APK
    apk_files = []
    if os.path.isdir(apk_path):
        for f in os.listdir(apk_path):
            if f.endswith(".apk"):
                apk_files.append(os.path.join(apk_path, f))
    else:
        apk_files.append(apk_path)

    if not apk_files:
        return vec

    # Primary base APK for manifest & certificate parsing
    base_apk_path = next((f for f in apk_files if "base" in os.path.basename(f).lower()), apk_files[0])
    normalized_path = base_apk_path.replace("\\", "/")

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

    # 2. Hardened Multi-DEX Bytecode Scan & Structural Asset Scan across all split APKs
    hostile_dex_count = 0
    total_dex_size = 0
    has_native_lib = False
    max_asset_entropy = 0.0
    html_card_mentions = 0
    zip_tampered = False

    hostile_tokens = {
        "content://sms": 30, "content://telephony/sms": 30,
        "content://call_log": 31,
        "android.telephony.SmsManager": 33, "sendTextMessage": 33, "SmsManager": 33,
        "java.lang.ProcessBuilder": 34, "ProcessBuilder": 34,
        "Runtime.getRuntime().exec": 35, "Runtime.exec": 35,
        "dalvik.system.DexClassLoader": 36, "DexClassLoader": 36, "InMemoryDexClassLoader": 36,
        "getDeviceId": 39, "getSubscriberId": 39, "getImei": 39, "getSimSerialNumber": 39,
        "/system/bin/sh": 40, "which su": 40, "chmod 777": 40, "/system/xbin/su": 40,
        "/system/app/Superuser.apk": 43, "test-keys": 43, "busybox": 43,
        "AccessibilityNodeInfo.performAction": 45, "ACTION_CLICK": 45, "dispatchGesture": 45, "AccessibilityNodeInfo": 45,
        "AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED": 46, "OnKeyListener": 46, "keylogger": 46, "KeyEvent": 46,
        "SurfaceTexture(0)": 47, "hidden_camera_capture": 47, "camera_surface_null": 47, "api.telegram.org": 47
    }

    utility_tokens = {
        "content://contacts": 32, "content://com.android.contacts": 32,
        "java.lang.reflect.Method.invoke": 37, "Method.invoke": 37,
        "java.net.Socket": 38, "Socket(": 38, "connectSocket": 38,
        "javax.crypto.Cipher": 41, "DESede": 41, "AES/CBC/PKCS5Padding": 41,
        "android.util.Base64.decode": 42, "Base64.decode": 42, "Base64": 42
    }

    for single_apk in apk_files:
        try:
            zf = zipfile.ZipFile(single_apk)
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
                    for pattern, feat_idx in hostile_tokens.items():
                        if pattern in content:
                            if vec[feat_idx] == 0.0:
                                vec[feat_idx] = 1.0
                                hostile_dex_count += 1
                    for pattern, feat_idx in utility_tokens.items():
                        if pattern in content:
                            vec[feat_idx] = 1.0
                    if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b", content):
                        if vec[44] == 0.0:
                            vec[44] = 1.0
                            hostile_dex_count += 1
                elif info.filename.endswith(".so") or info.filename.startswith("lib/"):
                    has_native_lib = True
                elif info.filename.startswith("assets/"):
                    if len(raw_data) > 50000:
                        sample = raw_data[:8192]
                        ent = compute_entropy(sample)
                        if ent > max_asset_entropy:
                            max_asset_entropy = ent
                    if info.filename.endswith(".html") or info.filename.endswith(".js"):
                        text_lower = raw_data.decode("utf-8", errors="ignore").lower()
                        card_hits = text_lower.count("card")
                        if card_hits >= 5:
                            html_card_mentions += card_hits
        except Exception:
            pass

    vec[48] = min(hostile_dex_count / 10.0, 1.0)

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

    # 4. Certificates & Cryptographic Publisher Verification (61-66)
    certs = []
    try:
        certs = apk.get_certificates() or []
    except Exception:
        certs = []

    if not certs:
        try:
            with zipfile.ZipFile(base_apk_path, "r") as zf:
                for zname in zf.namelist():
                    if zname.startswith("META-INF/") and (zname.endswith(".RSA") or zname.endswith(".DSA") or zname.endswith(".der")):
                        raw_c = zf.read(zname)
                        try:
                            from cryptography import x509
                            from cryptography.hazmat.backends import default_backend
                            parsed = x509.load_der_x509_certificate(raw_c, default_backend())
                            certs.append(parsed)
                        except Exception:
                            pass
        except Exception:
            pass

    vec[66] = min(len(certs) / 5.0, 1.0)
    
    is_debug = False
    is_known_pub = False
    for cert in certs:
        subj = str(getattr(cert, 'subject', '')).lower()
        issuer = str(getattr(cert, 'issuer', '')).lower()
        if "debug" in subj or "debug" in issuer or "test-keys" in subj or "testkey" in subj:
            is_debug = True
        else:
            cert_sha = ""
            try:
                from cryptography.hazmat.primitives import serialization
                cert_sha = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest().lower()
            except Exception:
                try:
                    cert_sha = hashlib.sha256(cert.dump()).hexdigest().lower()
                except Exception:
                    try:
                        cert_sha = hashlib.sha256(cert.public_bytes()).hexdigest().lower()
                    except Exception:
                        pass
            if cert_sha in TRUSTED_CERT_SHA256_SET:
                is_known_pub = True

    vec[61] = 1.0 if is_debug else 0.0
    vec[62] = 0.0
    vec[63] = 1.0 if (is_known_pub and not is_debug) else 0.0
    vec[64] = 0.50
    vec[65] = 0.0

    # 5. Provenance & Metadata (67-79)
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
    pkg_name = (apk.get_package() or "").lower()

    vec[74] = min(target_sdk / 35.0, 1.0)
    vec[75] = 1.0 if target_sdk <= 22 else 0.0
    vec[76] = 1.0 if target_sdk <= 28 else 0.0
    vec[77] = min(min_sdk / 35.0, 1.0)

    is_system = (vec[67] == 1.0 or vec[68] == 1.0)
    known_brands = ["google service", "google play", "system update", "google framework", "android system",
                    "sbi yono", "hdfc bank", "phonepe", "paytm", "gpay", "whatsapp", "divar", "telegram"]
    is_impersonation = 0.0
    if not is_system and vec[63] == 0.0:
        for brand in known_brands:
            if brand in app_label and not any(k in pkg_name for k in ["google", "sbi", "hdfc", "phonepe", "paytm", "whatsapp", "telegram"]):
                is_impersonation = 1.0
                break
    vec[78] = is_impersonation

    susp_tokens = ["reverseshell", "payload", "rat", "bot", "hack", "dropper", "spy", "stealer", "trojan"]
    vec[79] = 1.0 if any(p in pkg_name for p in susp_tokens) and vec[63] == 0.0 else 0.0

    # 6. Joint High-Order Threat Tells (80-83)
    # UNKNOWN is strictly distinct from DOWNLOADED / SIDELOADED
    untrusted = (vec[71] == 1.0) or (vec[70] == 1.0 and vec[63] == 0.0)
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

    # 7. Structural Forensics & Corroborated Packing (84-91)
    is_thin_dex = (0 < total_dex_size < 40000 and has_native_lib)
    is_corroborated_packed = (max_asset_entropy >= 7.80 and (vec[36] == 1.0 or is_thin_dex or vec[37] == 1.0 or zip_tampered))

    vec[84] = 1.0 if zip_tampered else 0.0
    vec[85] = 1.0 if is_corroborated_packed else 0.0
    vec[86] = 1.0 if is_thin_dex else 0.0
    vec[87] = 1.0 if has_native_lib else 0.0
    vec[88] = min(html_card_mentions / 20.0, 1.0)

    if is_corroborated_packed and read_sms and untrusted:
        vec[89] = 1.0
    if zip_tampered and is_thin_dex and (vec[16] == 1.0 or vec[17] == 1.0 or vec[36] == 1.0):
        vec[90] = 1.0

    vec[91] = min(len(pkg_name.split(".")) / 8.0, 1.0)

    return vec

def extract_features_from_dict(app: Dict[str, Any]) -> np.ndarray:
    """Extracts 92-dimensional vector from structured app dictionary with schema v2.0.0."""
    vec = np.zeros(FEATURE_SPEC["num_features"], dtype=np.float32)

    # 1. Permissions (0-29)
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
    vec[29] = 1.0 if any("signature" in p.lower() for p in perms) else 0.0

    # 2. DEX Bytecode Signals (30-48)
    dex_strings = app.get("dex_strings", [])
    hostile_dex_count = 0
    def check_dex(patterns, idx, is_hostile=False):
        nonlocal hostile_dex_count
        if any(any(p.lower() in s.lower() for p in patterns) for s in dex_strings):
            vec[idx] = 1.0
            if is_hostile:
                hostile_dex_count += 1

    check_dex(["content://sms", "content://telephony/sms"], 30, is_hostile=True)
    check_dex(["content://call_log"], 31, is_hostile=True)
    check_dex(["content://contacts", "content://com.android.contacts"], 32, is_hostile=False)
    check_dex(["android.telephony.SmsManager", "sendTextMessage", "SmsManager"], 33, is_hostile=True)
    check_dex(["java.lang.ProcessBuilder", "ProcessBuilder"], 34, is_hostile=True)
    check_dex(["Runtime.getRuntime().exec", "Runtime.exec"], 35, is_hostile=True)
    check_dex(["dalvik.system.DexClassLoader", "DexClassLoader", "InMemoryDexClassLoader"], 36, is_hostile=True)
    check_dex(["java.lang.reflect.Method.invoke", "Method.invoke"], 37, is_hostile=False)
    check_dex(["java.net.Socket", "Socket(", "connectSocket"], 38, is_hostile=False)
    check_dex(["getDeviceId", "getSubscriberId", "getImei", "getSimSerialNumber"], 39, is_hostile=True)
    check_dex(["/system/bin/sh", "chmod 777", "/system/xbin/su", "which su"], 40, is_hostile=True)
    check_dex(["javax.crypto.Cipher", "DESede", "AES/CBC/PKCS5Padding"], 41, is_hostile=False)
    check_dex(["android.util.Base64.decode", "Base64.decode", "Base64"], 42, is_hostile=False)
    check_dex(["/system/app/Superuser.apk", "test-keys", "busybox"], 43, is_hostile=True)

    has_c2_ip = any(re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b", s) for s in dex_strings)
    if has_c2_ip:
        vec[44] = 1.0
        hostile_dex_count += 1

    check_dex(["AccessibilityNodeInfo.performAction", "ACTION_CLICK", "dispatchGesture", "AccessibilityNodeInfo"], 45, is_hostile=True)
    check_dex(["AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED", "OnKeyListener", "keylogger", "KeyEvent"], 46, is_hostile=True)
    check_dex(["SurfaceTexture(0)", "hidden_camera_capture", "camera_surface_null", "api.telegram.org"], 47, is_hostile=True)

    vec[48] = min(hostile_dex_count / 10.0, 1.0)

    # 3. Manifest Structure (49-60)
    man = app.get("manifest", {})
    act_count = man.get("exported_activities", 1)
    srv_count = man.get("exported_services", 0)
    rec_count = man.get("exported_receivers", 0)
    tot_comp = man.get("total_components", act_count + srv_count + rec_count)

    vec[49] = min(act_count / 20.0, 1.0)
    vec[50] = min(srv_count / 10.0, 1.0)
    vec[51] = min(rec_count / 10.0, 1.0)
    vec[52] = 1.0 if man.get("has_boot_receiver", False) else 0.0
    vec[53] = 1.0 if man.get("has_sms_receiver", False) else 0.0
    vec[54] = 1.0 if man.get("has_foreground_service", False) else 0.0
    vec[55] = 1.0 if man.get("has_accessibility_service", False) or vec[14] == 1.0 else 0.0
    vec[56] = 1.0 if man.get("has_device_admin", False) or vec[15] == 1.0 else 0.0
    vec[57] = 1.0 if man.get("has_system_alert_window", False) or vec[11] == 1.0 else 0.0
    vec[58] = 1.0 if man.get("has_launcher_activity", True) else 0.0
    vec[59] = min(tot_comp / 50.0, 1.0)
    vec[60] = min(man.get("ratio_exported", 0.50), 1.0)

    # 4. Certificates & Signing (61-66)
    cert = app.get("certificate", {})
    vec[61] = 1.0 if cert.get("is_debug_key", False) else 0.0
    vec[62] = 1.0 if cert.get("is_self_signed", False) else 0.0
    is_known_pub = bool(cert.get("is_known_publisher", False)) and vec[61] == 0.0
    vec[63] = 1.0 if is_known_pub else 0.0
    vec[64] = min(cert.get("validity_years", 25.0) / 50.0, 1.0)
    vec[65] = 1.0 if cert.get("has_generic_issuer", False) else 0.0
    vec[66] = min(cert.get("cert_count", 1) / 5.0, 1.0)

    # 5. Provenance & Metadata (67-79)
    prov = str(app.get("provenance", "UNKNOWN")).upper()
    if prov == "SYSTEM_IMAGE": vec[67] = 1.0
    elif prov == "UPDATED_SYSTEM_APP": vec[68] = 1.0
    elif prov == "VERIFIED_STORE": vec[69] = 1.0
    elif prov == "CONFIRMED_LOCAL_APK": vec[70] = 1.0
    elif prov == "DOWNLOADED_APK": vec[71] = 1.0
    elif prov == "RESTORED_OEM": vec[72] = 1.0
    else: vec[73] = 1.0 # UNKNOWN

    t_sdk = int(app.get("target_sdk", 33))
    m_sdk = int(app.get("min_sdk", 21))
    vec[74] = min(t_sdk / 35.0, 1.0)
    vec[75] = 1.0 if t_sdk <= 22 else 0.0
    vec[76] = 1.0 if t_sdk <= 28 else 0.0
    vec[77] = min(m_sdk / 35.0, 1.0)

    pkg_name = str(app.get("package_name", "")).lower()
    app_name = str(app.get("app_name", "")).lower()
    is_sys = bool(app.get("is_system_app", False)) or (vec[67] == 1.0 or vec[68] == 1.0)

    known_brands = ["google service", "google play", "system update", "google framework", "android system",
                    "sbi yono", "hdfc bank", "phonepe", "paytm", "gpay", "whatsapp", "divar", "telegram"]
    impersonates = 0.0
    if not is_sys and vec[63] == 0.0:
        for b in known_brands:
            if b in app_name and not any(k in pkg_name for k in ["google", "sbi", "hdfc", "phonepe", "paytm", "whatsapp", "telegram"]):
                impersonates = 1.0
                break
    vec[78] = impersonates

    susp_tokens = ["reverseshell", "payload", "rat", "bot", "hack", "dropper", "spy", "stealer", "trojan"]
    vec[79] = 1.0 if any(t in pkg_name for t in susp_tokens) and vec[63] == 0.0 else 0.0

    # 6. Joint High-Order Threat Tells (80-83)
    # UNKNOWN is strictly distinct from DOWNLOADED / SIDELOADED
    untrusted = (vec[71] == 1.0) or (vec[70] == 1.0 and vec[63] == 0.0)
    has_rat_dex = (vec[34] == 1.0 or vec[38] == 1.0 or vec[40] == 1.0)
    has_rat_perms = (read_sms or vec[3] == 1.0)
    if has_rat_dex and untrusted and vec[75] == 1.0 and has_rat_perms: vec[80] = 1.0
    if vec[25] == 1.0 and untrusted and (read_sms or vec[5] == 1.0): vec[81] = 1.0
    if (vec[16] == 1.0 or vec[17] == 1.0) and (vec[36] == 1.0 or vec[42] == 1.0) and untrusted: vec[82] = 1.0
    if vec[24] == 1.0 and untrusted and (vec[58] == 0.0 or vec[52] == 1.0) and vec[39] == 1.0: vec[83] = 1.0

    # 7. Structural Forensics & Corroborated Packing (84-91)
    struct = app.get("structural", {})
    max_entropy = float(struct.get("max_asset_entropy", 0.0))
    has_native = bool(struct.get("has_native_lib", False))
    is_thin = bool(struct.get("is_thin_dex", False))
    zip_tampered = bool(struct.get("is_zip_tampered", False))

    is_corroborated_packed = (max_entropy >= 7.80 and (vec[36] == 1.0 or is_thin or vec[37] == 1.0 or zip_tampered))

    vec[84] = 1.0 if zip_tampered else 0.0
    vec[85] = 1.0 if is_corroborated_packed else 0.0
    vec[86] = 1.0 if is_thin else 0.0
    vec[87] = 1.0 if has_native else 0.0
    vec[88] = min(float(struct.get("html_card_mentions", 0)) / 20.0, 1.0)

    if is_corroborated_packed and read_sms and untrusted: vec[89] = 1.0
    if zip_tampered and is_thin and (vec[16] == 1.0 or vec[17] == 1.0 or vec[36] == 1.0): vec[90] = 1.0

    vec[91] = min(len(pkg_name.split(".")) / 8.0, 1.0)

    return vec
