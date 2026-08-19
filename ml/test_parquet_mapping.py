import pyarrow.parquet as pq
import pandas as pd
import numpy as np
import json
import os
import sys

sys.path.insert(0, os.path.abspath("."))
from ml.features.extractor import FEATURE_SPEC, DANGEROUS_PERMISSIONS

labels_df = pd.read_csv("ml/data/real_corpora/mh100-labels.csv")
y_all = labels_df["class"].values

table = pq.read_table("ml/data/real_corpora/mh100.parquet")
col_names = table.column_names

print(f"Total real APK samples: {len(y_all)} (Benign: {np.sum(y_all==0)}, Malware: {np.sum(y_all==1)})")

# Find column index mappings for our 80 features
col_map = {}
for i, col in enumerate(col_names):
    # Check permissions
    if col.startswith("Permission::"):
        perm_short = col.replace("Permission::", "")
        perm_full = f"android.permission.{perm_short}"
        if perm_full in DANGEROUS_PERMISSIONS:
            idx = DANGEROUS_PERMISSIONS[perm_full]
            col_map[col] = ("perm", idx)
            
    # Check API Calls
    if "ProcessBuilder" in col:
        col_map[col] = ("dex", 34)
    elif "Runtime.exec" in col or "/system/bin/sh" in col:
        col_map[col] = ("dex", 35)
    elif "DexClassLoader" in col:
        col_map[col] = ("dex", 36)
    elif "Method.invoke" in col:
        col_map[col] = ("dex", 37)
    elif "Socket" in col and "SocketException" not in col:
        col_map[col] = ("dex", 38)
    elif "getDeviceId" in col or "getSubscriberId" in col or "getImei" in col:
        col_map[col] = ("dex", 39)
    elif "Cipher" in col:
        col_map[col] = ("dex", 41)
    elif "Base64" in col:
        col_map[col] = ("dex", 42)
    elif "AccessibilityNodeInfo" in col or "AccessibilityEvent" in col:
        col_map[col] = ("dex", 45)
    elif "OnKeyListener" in col or "KeyEvent" in col:
        col_map[col] = ("dex", 46)
        
    # Check Intents
    if "BOOT_COMPLETED" in col:
        col_map[col] = ("intent", 52)
    elif "SMS_RECEIVED" in col or "SMS_DELIVER" in col:
        col_map[col] = ("intent", 53)

print(f"Mapped {len(col_map)} real AndroZoo feature columns to our 80-feature schema!")