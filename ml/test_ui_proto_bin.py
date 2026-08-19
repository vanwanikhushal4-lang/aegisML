import struct, math, os, sys
import numpy as np

sys.path.insert(0, os.path.abspath("."))
from ml.features.extractor import extract_features_from_apk

# Read apk_malware_trees.bin from UI-proto
bin_data = None
import subprocess
p = subprocess.Popen(["git", "show", "UI-proto:scanner/src/main/assets/ml/apk_malware_trees.bin"], stdout=subprocess.PIPE)
bin_data, _ = p.communicate()

print(f"Loaded apk_malware_trees.bin from UI-proto: {len(bin_data)} bytes")

# Parse binary format:
# magic: 8 bytes (AEGSTREE)
# version: int (4 bytes)
# tree_count: int (4 bytes)
# node_count: int (4 bytes)
# base_value: float (4 bytes)
offset = 0
magic = bin_data[offset:offset+8].decode("ascii")
offset += 8
version, tree_count, node_count, base_value = struct.unpack("<iiif", bin_data[offset:offset+16])
offset += 16

print(f"Magic: {magic}, Version: {version}, Trees: {tree_count}, Nodes: {node_count}, Base Value: {base_value}")

roots = struct.unpack(f"<{tree_count}i", bin_data[offset:offset+4*tree_count])
offset += 4 * tree_count

feature_ids = []
values = []
true_indices = []
false_indices = []
missing_left = []

for i in range(node_count):
    f_id, val, t_idx, f_idx = struct.unpack("<ifii", bin_data[offset:offset+16])
    offset += 16
    m_left = struct.unpack("<?", bin_data[offset:offset+1])[0]
    offset += 1
    feature_ids.append(f_id)
    values.append(val)
    true_indices.append(t_idx)
    false_indices.append(f_idx)
    missing_left.append(m_left)

def predict_binary_trees(features):
    raw = base_value
    for tree_idx in range(len(roots)):
        curr = roots[tree_idx]
        while True:
            feat = feature_ids[curr]
            if feat < 0:
                raw += values[curr]
                break
            x = features[feat] if feat < len(features) else 0.0
            thresh = values[curr]
            if x <= thresh:
                curr = true_indices[curr]
            else:
                curr = false_indices[curr]
    prob = 1.0 / (1.0 + math.exp(-raw))
    return prob

apk_trojan = r"C:\Users\user\Downloads\60648a8e5ee28177de38e6ea40c17481b95a63e6aa4ca466754bc7e7f08bd2ab.apk"
apk_rat = r"C:\Users\user\Downloads\androrat\AndroRAT\malware.apk"

v_trojan = extract_features_from_apk(apk_trojan, is_sideloaded=True)
v_rat = extract_features_from_apk(apk_rat, is_sideloaded=True)

p_trojan = predict_binary_trees(v_trojan)
p_rat = predict_binary_trees(v_rat)

print("="*80)
print(f"EVALUATION OF apk_malware_trees.bin ON UI-proto BRANCH:")
print(f"  * Iranian Divar Trojan Probability: {p_trojan:.4f}")
print(f"  * AndroRAT Trojan Probability:      {p_rat:.4f}")
print(f"  * OPERATING_THRESHOLD in Model:     0.5000")
print("="*80)