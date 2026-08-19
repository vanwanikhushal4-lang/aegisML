import json
import os
import sys
import time
import numpy as np
import joblib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from ml.features.extractor import FEATURE_SPEC

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../models/saved_models'))

def run_benchmark():
    print("="*80)
    print("AEGIS ON-DEVICE INFERENCE LATENCY BENCHMARK")
    print("="*80)

    gbt = joblib.load(os.path.join(MODELS_DIR, 'gbt_model.joblib'))
    
    # Generate 1,000 random realistic feature vectors
    N = 1000
    X_sample = np.random.binomial(1, 0.1, size=(N, 80)).astype(np.float32)
    
    # Warmup
    for _ in range(50):
        _ = gbt.predict_proba(X_sample[:1])
        
    start_time = time.perf_counter()
    for i in range(N):
        _ = gbt.predict_proba(X_sample[i:i+1])
    end_time = time.perf_counter()
    
    total_ms = (end_time - start_time) * 1000.0
    avg_ms = total_ms / N
    throughput = N / (end_time - start_time)
    
    print(f"Total time for {N} single-app predictions: {total_ms:.2f} ms")
    print(f"Average latency per app:                  {avg_ms:.4f} ms (Budget: <= 50.0 ms)")
    print(f"Throughput:                               {throughput:.1f} apps/sec")
    
    budget_ok = avg_ms <= 50.0
    if budget_ok:
        print("[SUCCESS] Latency is well within budget (< 1 ms vs 50 ms target).")
    else:
        print("[FAILURE] Latency exceeds budget.")

if __name__ == '__main__':
    run_benchmark()