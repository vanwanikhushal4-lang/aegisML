import json
import os
import sys
import numpy as np
import joblib

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from ml.features.extractor import extract_features_from_dict, explain_prediction, FEATURE_SPEC

MODELS_DIR = os.path.join(os.path.dirname(__file__), 'saved_models')
os.makedirs(MODELS_DIR, exist_ok=True)

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../data'))

def load_dataset(filename: str):
    path = os.path.join(DATA_DIR, filename)
    with open(path, 'r', encoding='utf-8-sig') as f:
        raw_apps = json.load(f)
    
    X = np.zeros((len(raw_apps), FEATURE_SPEC['num_features']), dtype=np.float32)
    y = np.zeros(len(raw_apps), dtype=np.int32)
    meta = []
    
    for i, app in enumerate(raw_apps):
        X[i] = extract_features_from_dict(app)
        y[i] = app.get('label', 0)
        meta.append(app)
        
    return X, y, meta

class RuleEngineBaseline:
    """Simulates the hand-written rule engine baseline currently in AEGIS."""
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        probas = np.zeros((X.shape[0], 2))
        for i in range(X.shape[0]):
            vec = X[i]
            dang_perm_count = vec[27] * 20.0
            perm_score = min(dang_perm_count * 6.0, 30.0)
            dex_score = (vec[30] + vec[31] + vec[34] + vec[38] + vec[40]) * 5.0
            prov_score = 15.0 if vec[67] == 1.0 else 0.0
            total_score = min(perm_score + dex_score + prov_score, 100.0)
            p_mal = total_score / 100.0
            probas[i, 0] = 1.0 - p_mal
            probas[i, 1] = p_mal
        return probas

    def predict(self, X: np.ndarray, threshold: float = 0.6) -> np.ndarray:
        return (self.predict_proba(X)[:, 1] >= threshold).astype(int)

def train_models():
    print('Loading training data from train_dataset.json...')
    X_train, y_train, train_meta = load_dataset('train_dataset.json')
    print(f'Train shape: X={X_train.shape}, y={y_train.shape} (Positives: {np.sum(y_train)}, Negatives: {len(y_train) - np.sum(y_train)})')

    # 1. Baseline: Logistic Regression
    print('Training L2 Logistic Regression baseline...')
    lr = LogisticRegression(max_iter=1000, class_weight='balanced', C=1.0, random_state=42)
    lr.fit(X_train, y_train)

    # 2. Model A: Calibrated Gradient Boosted Trees (Primary Model)
    # Using max_features=0.4 and subsample=0.8 to force learning across all feature families
    print('Training Robust Gradient Boosted Trees (GBT)...')
    gbt = GradientBoostingClassifier(
        n_estimators=150,
        learning_rate=0.06,
        max_depth=5,
        max_features=0.4,
        subsample=0.8,
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=42
    )
    gbt.fit(X_train, y_train)

    print('Calibrating GBT model probabilities (5-fold CV)...')
    calibrated_gbt = CalibratedClassifierCV(
        estimator=GradientBoostingClassifier(
            n_estimators=150, learning_rate=0.06, max_depth=5, max_features=0.4, subsample=0.8,
            min_samples_split=4, min_samples_leaf=2, random_state=42
        ),
        method='sigmoid',
        cv=5
    )
    calibrated_gbt.fit(X_train, y_train)

    # 3. Model B: Random Forest
    print('Training Random Forest Classifier...')
    rf = RandomForestClassifier(
        n_estimators=150,
        max_depth=7,
        max_features='sqrt',
        class_weight='balanced',
        random_state=42
    )
    rf.fit(X_train, y_train)

    importances = gbt.feature_importances_
    top_indices = np.argsort(importances)[::-1][:15]
    print('\nTop 15 Most Discriminative Features in GBT:')
    for rank, idx in enumerate(top_indices, 1):
        feat_meta = FEATURE_SPEC['features'][idx]
        print(f"  {rank}. [{idx}] {feat_meta['name']}: {importances[idx]:.4f} ({feat_meta['description']})")

    print('\nSaving models to ml/models/saved_models/...')
    joblib.dump(lr, os.path.join(MODELS_DIR, 'logistic_regression.joblib'))
    joblib.dump(gbt, os.path.join(MODELS_DIR, 'gbt_model.joblib'))
    joblib.dump(calibrated_gbt, os.path.join(MODELS_DIR, 'calibrated_gbt.joblib'))
    joblib.dump(rf, os.path.join(MODELS_DIR, 'rf_model.joblib'))
    np.save(os.path.join(MODELS_DIR, 'feature_importances.npy'), importances)

    print('Training pipeline complete.')
    return gbt, importances

if __name__ == '__main__':
    train_models()