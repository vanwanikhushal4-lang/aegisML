"""
Integrating Structural, Packaging & Anti-Analysis Dimensions Directly into ML Training Pipeline
Expands the feature representation so the ML model natively learns the joint distribution of:
- Packed Native Trojens
- High Entropy Asset Droppers
- Anti-Analysis Zip Tampering
- Bytecode & Manifest Indicators
"""

import os, sys, json
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import roc_auc_score, average_precision_score

sys.path.insert(0, os.path.abspath("."))
from ml.features.extractor import extract_features_from_dict, extract_features_from_apk, FEATURE_SPEC

print("="*80)
print("INTEGRATING STRUCTURAL & PACKER DIMENSIONS DIRECTLY INTO ML MODEL")
print("="*80)

# Load existing datasets
with open("ml/data/train_dataset.json", "r", encoding="utf-8-sig") as f:
    train_data = json.load(f)
with open("ml/data/test_holdout_dataset.json", "r", encoding="utf-8-sig") as f:
    test_data = json.load(f)

print(f"Loaded {len(train_data)} train samples and {len(test_data)} test samples.")