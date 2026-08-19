import os, sys, math, zipfile
from collections import Counter

apk_path = r"C:\Users\user\Downloads\60648a8e5ee28177de38e6ea40c17481b95a63e6aa4ca466754bc7e7f08bd2ab.apk"

def shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    return -sum((c/len(data)) * math.log2(c/len(data)) for c in Counter(data).values())

def analyze_apk_structural(apk_path: str):
    zf = zipfile.ZipFile(apk_path)
    
    zip_tampered = False
    thin_dex = False
    has_native_lib = False
    has_encrypted_asset = False
    has_webview_phishing = False
    max_asset_entropy = 0.0
    encrypted_asset_name = ""
    html_card_mentions = 0
    total_dex_size = 0
    
    for info in zf.infolist():
        # Check zip tampering
        if info.flag_bits & 0x1:
            zip_tampered = True
        
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
            if len(data) > 50000 and (ent > 7.80 or data.startswith(b"\x7fEPDATA")):
                has_encrypted_asset = True
                encrypted_asset_name = info.filename
            if info.filename.endswith(".html") or info.filename.endswith(".js"):
                text = data.decode("utf-8", errors="ignore").lower()
                card_count = text.count("card")
                if card_count >= 5:
                    has_webview_phishing = True
                    html_card_mentions = card_count

    if 0 < total_dex_size < 40000 and has_native_lib:
        thin_dex = True

    # Calculate structural threat score (0-100)
    score = 0
    reasons = []
    
    if zip_tampered:
        score += 35
        reasons.append("Anti-Analysis Zip Header Tampering (fake encryption bit flag 0x0001)")
    if has_encrypted_asset:
        score += 40
        reasons.append(f"High-Entropy Encrypted Asset Blob ({encrypted_asset_name}, entropy={max_asset_entropy:.2f}, magic=\\x7fEPDATA)")
    if thin_dex:
        score += 25
        reasons.append(f"Thin DEX Loader Stub ({total_dex_size/1024:.1f} KB) paired with Native .so Loader")
    if has_webview_phishing:
        score += 30
        reasons.append(f"Local WebView Financial Phishing Template (assets/index.html with {html_card_mentions} card mentions)")

    final_score = min(score, 100)
    tier = "CRITICAL" if final_score >= 80 else ("HIGH" if final_score >= 60 else ("MEDIUM" if final_score >= 35 else "SAFE"))
    
    return {
        "score": final_score,
        "threat_tier": tier,
        "zip_tampered": zip_tampered,
        "thin_dex": thin_dex,
        "has_encrypted_asset": has_encrypted_asset,
        "has_webview_phishing": has_webview_phishing,
        "reasons": reasons
    }

res = analyze_apk_structural(apk_path)
print("="*80)
print("STRUCTURAL PACKER & PHISHING DETECTOR RESULT:")
print("="*80)
print(f"Risk Score:   {res['score']}/100")
print(f"Threat Tier:  {res['threat_tier']}")
print("Triggered Heuristics:")
for r in res['reasons']:
    print(f"  [!] {r}")