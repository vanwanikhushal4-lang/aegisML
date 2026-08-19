import os
import sys
import tempfile
import time
import json
from typing import Dict, Any, List, Optional
import numpy as np
import joblib
from fastapi import FastAPI, File, UploadFile, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from ml.features.extractor import extract_features_from_apk, extract_features_from_dict, explain_prediction, FEATURE_SPEC

app = FastAPI(
    title="AEGIS On-Device Malware Classifier API",
    description="Offline-capable APK malware inference engine and feature attribution API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../models/saved_models"))
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data"))

MODEL = None
CALIBRATED_MODEL = None
FEATURE_IMPORTANCES = None
OPERATING_THRESHOLD = 0.159

@app.on_event("startup")
def load_models():
    global MODEL, CALIBRATED_MODEL, FEATURE_IMPORTANCES, OPERATING_THRESHOLD
    print("Loading ML models from:", MODELS_DIR)
    MODEL = joblib.load(os.path.join(MODELS_DIR, "gbt_model.joblib"))
    CALIBRATED_MODEL = joblib.load(os.path.join(MODELS_DIR, "calibrated_gbt.joblib"))
    FEATURE_IMPORTANCES = np.load(os.path.join(MODELS_DIR, "feature_importances.npy"))
    print("ML models loaded successfully.")

class AppMetadataRequest(BaseModel):
    package_name: str = Field(..., example="com.example.reverseshell2")
    app_name: str = Field("Sample App", example="Google Service Framework")
    is_system_app: bool = Field(False, example=False)
    is_sideloaded: bool = Field(True, example=True)
    target_sdk: int = Field(33, example=22)
    min_sdk: int = Field(21, example=16)
    permissions: List[str] = Field(default_factory=list)
    signature_permissions: List[str] = Field(default_factory=list)
    dex_strings: List[str] = Field(default_factory=list)
    manifest: Dict[str, Any] = Field(default_factory=dict)
    certificate: Dict[str, Any] = Field(default_factory=dict)

class VectorInferenceRequest(BaseModel):
    features: List[float] = Field(...)

class ExplainReason(BaseModel):
    feature_name: str
    description: str
    contribution_score: float

class ScanResponse(BaseModel):
    package_name: Optional[str]
    app_name: Optional[str]
    risk_score: int
    threat_level: str
    malware_probability: float
    operating_threshold: float
    is_flagged_as_threat: bool
    top_reasons: List[ExplainReason]
    latency_ms: float

def compute_risk_response(vec: np.ndarray, pkg_name: str = None, app_name: str = None, start_time: float = 0.0) -> ScanResponse:
    v2d = vec.reshape(1, -1)
    p_mal = float(CALIBRATED_MODEL.predict_proba(v2d)[0, 1])
    score = int(round(p_mal * 100))
    
    if p_mal < 0.16:
        tier = "SAFE"
    elif p_mal < 0.40:
        tier = "LOW"
    elif p_mal < 0.75:
        tier = "MEDIUM"
    elif p_mal < 0.90:
        tier = "HIGH"
    else:
        tier = "CRITICAL"
        
    is_threat = p_mal >= OPERATING_THRESHOLD
    
    reasons_raw = explain_prediction(vec, FEATURE_IMPORTANCES, top_k=3)
    reasons = [
        ExplainReason(feature_name=r[0], description=r[1], contribution_score=r[2])
        for r in reasons_raw
    ]
    
    latency = (time.perf_counter() - start_time) * 1000.0 if start_time > 0 else 0.0
    
    return ScanResponse(
        package_name=pkg_name,
        app_name=app_name,
        risk_score=score,
        threat_level=tier,
        malware_probability=round(p_mal, 4),
        operating_threshold=OPERATING_THRESHOLD,
        is_flagged_as_threat=is_threat,
        top_reasons=reasons,
        latency_ms=round(latency, 2)
    )

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "model_type": "GradientBoostingClassifier (P5 Calibrated)",
        "num_features": FEATURE_SPEC["num_features"],
        "num_trees": len(MODEL.estimators_),
        "operating_threshold": OPERATING_THRESHOLD,
        "features_version": FEATURE_SPEC.get("version", "1.0.0")
    }

@app.post("/scan/apk", response_model=ScanResponse)
async def scan_apk_file(file: UploadFile = File(...), is_sideloaded: bool = Query(True)):
    start_time = time.perf_counter()
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Uploaded file must have .apk extension")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        from androguard.core.apk import APK
        apk_obj = APK(tmp_path)
        pkg_name = apk_obj.get_package() or file.filename
        app_name = apk_obj.get_app_name() or pkg_name
        
        vec = extract_features_from_apk(tmp_path, is_sideloaded=is_sideloaded)
        return compute_risk_response(vec, pkg_name=pkg_name, app_name=app_name, start_time=start_time)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

@app.post("/scan/app-json", response_model=ScanResponse)
def scan_app_metadata(app: AppMetadataRequest):
    start_time = time.perf_counter()
    vec = extract_features_from_dict(app.dict())
    return compute_risk_response(vec, pkg_name=app.package_name, app_name=app.app_name, start_time=start_time)

@app.post("/scan/vector", response_model=ScanResponse)
def scan_feature_vector(req: VectorInferenceRequest):
    start_time = time.perf_counter()
    if len(req.features) != FEATURE_SPEC["num_features"]:
        raise HTTPException(status_code=400, detail=f"Feature vector must have exactly {FEATURE_SPEC['num_features']} floats")
    vec = np.array(req.features, dtype=np.float32)
    return compute_risk_response(vec, start_time=start_time)

@app.get("/benchmark/samples")
def benchmark_samples():
    results = []
    real_rat_path = "C:/Users/user/Downloads/androrat/AndroRAT/malware.apk"
    if os.path.exists(real_rat_path):
        t0 = time.perf_counter()
        vec = extract_features_from_apk(real_rat_path, is_sideloaded=True)
        res = compute_risk_response(vec, pkg_name="com.example.reverseshell2", app_name="Google Service Framework", start_time=t0)
        results.append({"category": "Real AndroRAT Malware (Local APK)", "result": res})
        
    with open(os.path.join(DATA_DIR, "allowlist_gate_dataset.json"), "r", encoding="utf-8-sig") as f:
        allowlist = json.load(f)
        
    for app_meta in allowlist:
        t0 = time.perf_counter()
        vec = extract_features_from_dict(app_meta)
        res = compute_risk_response(vec, pkg_name=app_meta["package_name"], app_name=app_meta["app_name"], start_time=t0)
        results.append({"category": f"Allowlist ({app_meta['app_name']})", "result": res})
        
    return {"benchmark_count": len(results), "samples": results}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("ml.api.server:app", host="127.0.0.1", port=8000, reload=False)