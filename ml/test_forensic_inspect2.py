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

zf = zipfile.ZipFile(apk_path)

print("Bypassing anti-analysis bit flags and reading entries...")
for info in zf.infolist():
    # Clear fake encryption bit
    info.flag_bits &= ~0x1
    data = zf.read(info.filename)
    if info.filename.endswith(".dex") or info.filename.startswith("assets/") or info.filename.endswith(".so"):
        ent = shannon_entropy(data)
        magic = data[:16] if len(data) >= 16 else data
        print(f"  * {info.filename:<35} | Size: {len(data):<8} ({len(data)/1024:.1f} KB) | Entropy: {ent:.2f} | Magic: {magic}")
        if info.filename == "assets/index.html":
            text = data.decode("utf-8", errors="ignore")
            print(f"     -> index.html occurrences of 'card': {text.lower().count('card')}, 'password': {text.lower().count('password')}")