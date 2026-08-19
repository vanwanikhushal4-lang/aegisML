import os, sys, json
sys.path.insert(0, os.path.abspath("."))
from ml.export.exporter import export_model
from ml.export.generate_scaler_and_golden_vectors import generate_artifacts
from ml.export.tflite_pure_builder import train_weights, build_tflite_flatbuffer

print("Exporting 88-feature models to assets...")
export_model()
generate_artifacts()

w, b = train_weights()
build_tflite_flatbuffer(w, b, "ml/export/aegis_malware_model.tflite")
build_tflite_flatbuffer(w, b, "app/src/main/assets/aegis_malware_model.tflite")

print("Export complete.")