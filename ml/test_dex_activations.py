import pyarrow.parquet as pq
import pandas as pd
import numpy as np
import os
import sys

sys.path.insert(0, ".")
from ml.features.extractor import FEATURE_SPEC, DANGEROUS_PERMISSIONS

labels_df = pd.read_csv("ml/data/real_corpora/mh100-labels.csv")
y_all = labels_df["class"].values

table = pq.read_table("ml/data/real_corpora/mh100.parquet")
col_names = table.column_names

print(f"Total samples: {len(y_all)}")

# Check behavioral DEX features mapped in AndroZoo
dex_col_map = {}
for col in col_names:
    if "SmsManager" in col or "sendTextMessage" in col:
        dex_col_map[col] = 30
    elif "getDeviceId" in col or "getSubscriberId" in col or "getImei" in col:
        dex_col_map[col] = 39
    elif "Base64" in col:
        dex_col_map[col] = 42
    elif "AccessibilityNodeInfo" in col or "AccessibilityEvent" in col:
        dex_col_map[col] = 45
    elif "KeyEvent" in col or "OnKeyListener" in col:
        dex_col_map[col] = 46
    elif "tagSocket" in col or "DatagramSocket" in col:
        dex_col_map[col] = 38
    elif "SSLCertificate" in col or "Cipher" in col:
        dex_col_map[col] = 41

print(f"Found {len(dex_col_map)} behavioral DEX API columns in AndroZoo!")

# Load subset and inspect activations
sub_table = pq.read_table("ml/data/real_corpora/mh100.parquet", columns=list(dex_col_map.keys())[:50])
sub_df = sub_table.to_pandas()

mal_idx = np.where(y_all == 1)[0][:1000]
ben_idx = np.where(y_all == 0)[0][:1000]

mal_act = (sub_df.iloc[mal_idx].sum(axis=1) > 0).mean()
ben_act = (sub_df.iloc[ben_idx].sum(axis=1) > 0).mean()

print(f"Behavioral DEX feature activation rate in Real Malware: {mal_act*100:.1f}%")
print(f"Behavioral DEX feature activation rate in Real Benign:  {ben_act*100:.1f}%")