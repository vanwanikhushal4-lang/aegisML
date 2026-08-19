"""
AEGIS On-Device Malware Classifier — Production FastAPI Server
Provides REST endpoints with Full Multi-Layer Forensic Structural Packer & Phishing Detection:
- POST /scan/apk: Deep forensic inspection of uploaded APK (Anti-analysis zip, encrypted asset blobs, thin DEX, webview phishing + 80-feature ML model).
- POST /scan/app-json: Fast inference from extracted metadata dictionary.
- POST /scan/vector: Direct 80-dimensional feature vector inference.
- GET /health: Healthcheck and model runtime status.
- GET /benchmark/samples: Retrieve verified test samples.
"""

import os
import sys
import json
import tempfile
import numpy as np
import joblib
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from ml.features.extractor import extract_features_from_apk, extract_features_from_dict, explain_prediction, analyze_apk_structural, FEATURE_SPEC

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../models/saved_models"))

app = FastAPI(
    title="AEGIS Malware Classifier API",
    description="Production Multi-Layer ML & Forensic Inspection Engine for Android Malware Detection (P5)",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

gbt_model = None
feature_importances = None
OPERATING_THRESHOLD = 0.160

@app.on_event("startup")
def load_models():
    global gbt_model, feature_importances
    print(f"Loading ML models from: {MODELS_DIR}")
    model_path = os.path.join(MODELS_DIR, "calibrated_gbt.joblib")
    if not os.path.exists(model_path):
        model_path = os.path.join(MODELS_DIR, "gbt_model.joblib")
    
    gbt_model = joblib.load(model_path)
    feat_imp_path = os.path.join(MODELS_DIR, "feature_importances.npy")
    if os.path.exists(feat_imp_path):
        feature_importances = np.load(feat_imp_path)
    else:
        feature_importances = np.ones(80, dtype=np.float32) / 80.0
    print("ML models and forensic engine loaded successfully.")

class VectorScanRequest(BaseModel):
    vector_80: List[float] = Field(..., min_items=80, max_items=80, description="80-dimensional normalized feature vector")

class AppJsonScanRequest(BaseModel):
    package_name: str = "com.example.app"
    app_name: str = "Example App"
    is_sideloaded: bool = True
    target_sdk: int = 33
    min_sdk: int = 21
    permissions: List[str] = []
    dex_strings: List[str] = []

class ScanResponse(BaseModel):
    app_name: str
    package_name: str
    risk_score: int
    threat_tier: str
    malware_probability: float
    operating_threshold: float = OPERATING_THRESHOLD
    is_threat: bool
    verdict: str
    structural_analysis: Optional[Dict[str, Any]] = None
    top_explanations: List[str]

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "AEGIS Malware Classifier & Forensic API",
        "model_loaded": gbt_model is not None,
        "operating_threshold": OPERATING_THRESHOLD,
        "features_count": FEATURE_SPEC["num_features"]
    }

@app.post("/scan/apk", response_model=ScanResponse)
async def scan_apk(file: UploadFile = File(...), is_sideloaded: bool = Query(True)):
    """Uploads an APK and runs multi-layer forensic structural analysis + ML inference."""
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Uploaded file must have an .apk extension")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        from androguard.core.apk import APK
        apk = APK(tmp_path)
        pkg_name = apk.get_package() or file.filename
        app_name = apk.get_app_name() or pkg_name

        # 1. Forensic Structural Analysis
        struct_res = analyze_apk_structural(tmp_path)

        # 2. ML Feature Extraction & Inference
        vec = extract_features_from_apk(tmp_path, is_sideloaded=is_sideloaded)
        p_mal = float(gbt_model.predict_proba(vec.reshape(1, -1))[0, 1])
        ml_score = int(round(p_mal * 100))

        # 3. Multi-Layer Risk Fusion
        if struct_res["is_packed_threat"]:
            final_score = max(ml_score, struct_res["structural_score"])
            threat_tier = "CRITICAL" if final_score >= 80 else "HIGH"
            verdict = "MALWARE / PACKED TROJAN DETECTED"
            reasons = struct_res["reasons"]
        else:
            final_score = ml_score
            threat_tier = "SAFE" if final_score < 16 else ("LOW" if final_score < 35 else "HIGH")
            verdict = "SAFE / CLEAN" if threat_tier == "SAFE" else "SUSPICIOUS"
            reasons = [desc for _, desc, _ in explain_prediction(vec, feature_importances, top_k=3)]

        return ScanResponse(
            app_name=app_name,
            package_name=pkg_name,
            risk_score=final_score,
            threat_tier=threat_tier,
            malware_probability=round(p_mal, 4),
            is_threat=(final_score >= 35),
            verdict=verdict,
            structural_analysis=struct_res,
            top_explanations=reasons
        )
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

@app.post("/scan/app-json", response_model=ScanResponse)
def scan_app_json(req: AppJsonScanRequest):
    data = req.dict()
    vec = extract_features_from_dict(data)
    p_mal = float(gbt_model.predict_proba(vec.reshape(1, -1))[0, 1])
    score = int(round(p_mal * 100))
    tier = "SAFE" if p_mal < OPERATING_THRESHOLD else ("LOW" if score < 35 else ("MEDIUM" if score < 70 else "CRITICAL"))
    verdict = "SAFE / CLEAN" if tier == "SAFE" else ("SUSPICIOUS" if tier in ("LOW", "MEDIUM") else "MALWARE DETECTED")
    reasons = [desc for _, desc, _ in explain_prediction(vec, feature_importances, top_k=3)]

    return ScanResponse(
        app_name=req.app_name,
        package_name=req.package_name,
        risk_score=score,
        threat_tier=tier,
        malware_probability=round(p_mal, 4),
        is_threat=(score >= 35),
        verdict=verdict,
        top_explanations=reasons
    )

@app.post("/scan/vector", response_model=ScanResponse)
def scan_vector(req: VectorScanRequest):
    vec = np.array(req.vector_80, dtype=np.float32)
    p_mal = float(gbt_model.predict_proba(vec.reshape(1, -1))[0, 1])
    score = int(round(p_mal * 100))
    tier = "SAFE" if p_mal < OPERATING_THRESHOLD else ("LOW" if score < 35 else ("MEDIUM" if score < 70 else "CRITICAL"))
    verdict = "SAFE / CLEAN" if tier == "SAFE" else ("SUSPICIOUS" if tier in ("LOW", "MEDIUM") else "MALWARE DETECTED")
    reasons = [desc for _, desc, _ in explain_prediction(vec, feature_importances, top_k=3)]

    return ScanResponse(
        app_name="Custom Vector App",
        package_name="custom.vector.evaluation",
        risk_score=score,
        threat_tier=tier,
        malware_probability=round(p_mal, 4),
        is_threat=(score >= 35),
        verdict=verdict,
        top_explanations=reasons
    )

@app.get("/benchmark/samples")
def get_benchmark_samples():
    return {
        "androrat_rat": {
            "name": "AndroRAT (Google Service Framework disguise)",
            "package": "com.example.reverseshell2",
            "threat_type": "Remote Access Trojan (RAT)",
            "expected_tier": "CRITICAL"
        },
        "divar_packed_trojan": {
            "name": "Divar Impersonation Trojan",
            "package": "ir.novinarya",
            "threat_type": "Packed Native Card-Stealer & SMS-OTP Trojan",
            "expected_tier": "CRITICAL"
        },
        "allowlist_upi": {
            "name": "PhonePe / Paytm / YONO SBI / WhatsApp",
            "threat_type": "Legitimate High-Capability Financial Apps",
            "expected_tier": "SAFE"
        }
    }