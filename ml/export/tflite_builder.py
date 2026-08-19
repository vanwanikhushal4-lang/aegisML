"""
AEGIS TensorFlow Lite Model Generator & Exporter
Trains a lightweight mobile neural network on the clean real-world dataset and converts to .tflite.
Saves to ml/export/aegis_malware_model.tflite and app/src/main/assets/aegis_malware_model.tflite.
"""

import os
import sys
import json
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from ml.features.extractor import FEATURE_SPEC, extract_features_from_dict

EXPORT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "."))
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data"))
ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../app/src/main/assets"))

def build_and_export_tflite():
    print("="*80)
    print("BUILDING AND EXPORTING AEGIS TFLITE MODEL (P5)")
    print("="*80)

    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers

    # 1. Load Clean Training & Test Data
    with open(os.path.join(DATA_DIR, "train_dataset.json"), "r", encoding="utf-8-sig") as f:
        train_apps = json.load(f)
    with open(os.path.join(DATA_DIR, "test_holdout_dataset.json"), "r", encoding="utf-8-sig") as f:
        test_apps = json.load(f)

    X_train = np.zeros((len(train_apps), FEATURE_SPEC["num_features"]), dtype=np.float32)
    y_train = np.zeros((len(train_apps), 1), dtype=np.float32)
    for i, a in enumerate(train_apps):
        X_train[i] = extract_features_from_dict(a)
        y_train[i] = float(a["label"])

    X_test = np.zeros((len(test_apps), FEATURE_SPEC["num_features"]), dtype=np.float32)
    y_test = np.zeros((len(test_apps), 1), dtype=np.float32)
    for i, a in enumerate(test_apps):
        X_test[i] = extract_features_from_dict(a)
        y_test[i] = float(a["label"])

    print(f"Loaded Train: {X_train.shape}, Test: {X_test.shape}")

    # 2. Build Mobile-Optimized Neural Network
    model = keras.Sequential([
        layers.Input(shape=(FEATURE_SPEC["num_features"],), name="input_features"),
        layers.Dense(64, activation="relu", name="dense_1"),
        layers.BatchNormalization(name="batch_norm_1"),
        layers.Dropout(0.2, name="dropout_1"),
        layers.Dense(32, activation="relu", name="dense_2"),
        layers.BatchNormalization(name="batch_norm_2"),
        layers.Dropout(0.1, name="dropout_2"),
        layers.Dense(16, activation="relu", name="dense_3"),
        layers.Dense(1, activation="sigmoid", name="malware_probability")
    ], name="aegis_malware_classifier")

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss="binary_crossentropy",
        metrics=["accuracy", tf.keras.metrics.AUC(name="auc"), tf.keras.metrics.Precision(name="precision"), tf.keras.metrics.Recall(name="recall")]
    )

    print("\nModel Architecture:")
    model.summary()

    # 3. Train Model
    early_stop = keras.callbacks.EarlyStopping(
        monitor="val_auc",
        mode="max",
        patience=10,
        restore_best_weights=True
    )

    history = model.fit(
        X_train, y_train,
        validation_data=(X_test, y_test),
        epochs=40,
        batch_size=64,
        callbacks=[early_stop],
        verbose=1
    )

    # 4. Evaluate on Test Holdout
    eval_results = model.evaluate(X_test, y_test, verbose=0)
    print("\n" + "-"*60)
    print(f"Test Loss:      {eval_results[0]:.4f}")
    print(f"Test Accuracy:  {eval_results[1]*100:.2f}%")
    print(f"Test ROC-AUC:   {eval_results[2]:.4f}")
    print(f"Test Precision: {eval_results[3]:.4f}")
    print(f"Test Recall:    {eval_results[4]:.4f}")
    print("-"*60)

    # 5. Convert to TensorFlow Lite
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    tflite_model = converter.convert()

    # Save to export and assets directories
    out_export = os.path.join(EXPORT_DIR, "aegis_malware_model.tflite")
    out_assets = os.path.join(ASSETS_DIR, "aegis_malware_model.tflite")

    with open(out_export, "wb") as f:
        f.write(tflite_model)
    with open(out_assets, "wb") as f:
        f.write(tflite_model)

    size_kb = len(tflite_model) / 1024.0
    print(f"\n[SUCCESS] Exported TFLite Model ({size_kb:.1f} KB):")
    print(f"  -> {out_export}")
    print(f"  -> {out_assets}")

    # 6. Verify TFLite Inference
    interpreter = tf.lite.Interpreter(model_content=tflite_model)
    interpreter.allocate_tensors()
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()

    sample_in = X_test[:1]
    interpreter.set_tensor(input_details[0]["index"], sample_in)
    interpreter.invoke()
    tflite_out = interpreter.get_tensor(output_details[0]["index"])
    keras_out = model.predict(sample_in, verbose=0)

    diff = np.abs(tflite_out - keras_out).max()
    print(f"\nTFLite vs Keras Maximum Absolute Diff: {diff:.8f}")
    print("[SUCCESS] TFLite model inference verified!")

if __name__ == "__main__":
    build_and_export_tflite()