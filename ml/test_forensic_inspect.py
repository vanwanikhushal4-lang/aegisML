import os, sys, math, zipfile
from collections import Counter

apk_path = r"C:\Users\user\Downloads\60648a8e5ee28177de38e6ea40c17481b95a63e6aa4ca466754bc7e7f08bd2ab.apk"

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for count in Counter(data).values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

print("="*80)
print("DEEP FORENSIC INSPECTION OF MALWAREBAZAAR SAMPLE")
print("="*80)

with open(apk_path, "rb") as f:
    raw_apk = f.read()

print(f"Total APK Size: {len(raw_apk)} bytes ({len(raw_apk)/(1024*1024):.2f} MB)")

zf = zipfile.ZipFile(apk_path)
dex_sizes = {}
assets = {}
libs = []
anti_analysis_flags = []

for info in zf.infolist():
    # Check general purpose bit flag for anti-analysis (Bit 0 = encrypted)
    is_encrypted_flag = bool(info.flag_bits & 0x1)
    if is_encrypted_flag:
        anti_analysis_flags.append(f"Entry '{info.filename}' has fake encryption bit set (0x{info.flag_bits:04x})")
    
    # Read entry bytes
    try:
        data = zf.read(info.filename)
    except Exception as e:
        # Fallback reading raw compressed stream
        data = b""
        anti_analysis_flags.append(f"Standard unzip error on '{info.filename}': {e}")
        
    ent = shannon_entropy(data)
    if info.filename.endswith(".dex"):
        dex_sizes[info.filename] = (len(data), ent)
    elif info.filename.startswith("assets/"):
        assets[info.filename] = (len(data), ent, data[:16])
    elif info.filename.endswith(".so") or "lib/" in info.filename:
        libs.append((info.filename, len(data), ent))

print(f"\n[1] Anti-Analysis Zip Flags ({len(anti_analysis_flags)} detected):")
for f in anti_analysis_flags[:5]:
    print("  *", f)

print(f"\n[2] DEX Files ({len(dex_sizes)}):")
for name, (size, ent) in dex_sizes.items():
    print(f"  * {name}: {size} bytes ({size/1024:.1f} KB), entropy={ent:.2f}")

print(f"\n[3] Native Libraries ({len(libs)}):")
for name, size, ent in libs:
    print(f"  * {name}: {size} bytes ({size/1024:.1f} KB), entropy={ent:.2f}")

print(f"\n[4] Assets ({len(assets)}):")
for name, (size, ent, magic) in assets.items():
    print(f"  * {name}: {size} bytes ({size/1024:.1f} KB), entropy={ent:.2f}, magic={magic}")