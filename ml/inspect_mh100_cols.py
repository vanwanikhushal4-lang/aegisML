import pyarrow.parquet as pq
import pandas as pd
import numpy as np

table = pq.read_table("ml/data/real_corpora/mh100.parquet")
col_names = table.column_names

api_cols = [c for c in col_names if c.startswith("APICall::")]
print(f"Total API Call / DEX columns in mh100: {len(api_cols)}")

targets = [
    "ProcessBuilder", "Runtime.exec", "DexClassLoader", "Method.invoke", "Socket",
    "getDeviceId", "getSubscriberId", "Cipher", "Base64", "Accessibility", "KeyEvent",
    "SmsManager", "sendTextMessage", "telephony", "install", "PackageInstaller"
]
for t in targets:
    matching = [c for c in col_names if t.lower() in c.lower()]
    print(f"Target '{t}': {len(matching)} matching columns")
    if matching:
        print(f"   -> {matching[:2]}")