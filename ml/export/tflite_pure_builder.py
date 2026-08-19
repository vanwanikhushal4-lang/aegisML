"""
AEGIS Pure Python TFLite FlatBuffer Model Generator
Constructs a valid, production TensorFlow Lite (.tflite) binary FlatBuffer model for AEGIS P5
without requiring the 350MB TensorFlow compiler package.
"""

import os
import sys
import json
import struct
import numpy as np
import joblib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from ml.features.extractor import FEATURE_SPEC

EXPORT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "."))
MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../models/saved_models"))
ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../app/src/main/assets"))

def train_weights():
    """Extracts weights from trained models or fits a lightweight logistic/dense network."""
    logreg = joblib.load(os.path.join(MODELS_DIR, "logistic_regression.joblib"))
    # Shape: (80, 1) weights and (1,) bias
    weights = logreg.coef_.T.astype(np.float32) # shape (80, 1)
    bias = logreg.intercept_.astype(np.float32)  # shape (1,)
    return weights, bias

def build_tflite_flatbuffer(weights, bias, out_path):
    """
    Constructs a minimal, valid TFLite FlatBuffer model (Version 3)
    Op: FULLY_CONNECTED + LOGISTIC (Sigmoid)
    Input: [1, 80] Float32
    Output: [1, 1] Float32 (Malware Probability)
    """
    # FlatBuffers format building:
    # A TFLite model is a FlatBuffer table with root type Model
    # We can serialize using flatbuffers library or direct standard binary layout.
    import flatbuffers

    builder = flatbuffers.Builder(1024 * 16)

    # 1. Buffers (0 is empty, 1 is empty input, 2 is weights, 3 is bias, 4 is empty output)
    # Weights buffer: weights transposed for TFLite FC: shape (1, 80)
    w_bytes = weights.T.tobytes()
    b_bytes = bias.tobytes()

    # Create byte vectors for buffers
    # Buffer 0: empty
    # Buffer 1: empty
    # Buffer 2: weights
    # Buffer 3: bias
    # Buffer 4: empty
    
    # We will build buffers
    buf_offsets = []
    
    # Helper to create a Buffer table
    def create_buffer(data_bytes=None):
        if data_bytes:
            data_offset = builder.CreateByteVector(data_bytes)
            builder.StartObject(1)
            builder.PrependUOffsetTRelativeSlot(0, data_offset, 0)
            return builder.EndObject()
        else:
            builder.StartObject(1)
            return builder.EndObject()

    # Pre-create buffers in reverse
    b3 = create_buffer(b_bytes)
    b2 = create_buffer(w_bytes)
    b1 = create_buffer()
    b0 = create_buffer()

    builder.StartVector(4, 4, 4)
    builder.PrependUOffsetTRelative(b3)
    builder.PrependUOffsetTRelative(b2)
    builder.PrependUOffsetTRelative(b1)
    builder.PrependUOffsetTRelative(b0)
    buffers_vec = builder.EndVector()

    # 2. OperatorCodes (Opcode 0: FULLY_CONNECTED = 9, Opcode 1: LOGISTIC = 14)
    # OperatorCode table: builtin_code (0: int8/deprecated, 1: custom_code, 2: version, 3: builtin_code int32)
    def create_opcode(code_id):
        builder.StartObject(4)
        builder.PrependInt8Slot(0, min(code_id, 127), 0)
        builder.PrependInt32Slot(2, 1, 1) # version 1
        builder.PrependInt32Slot(3, code_id, 0)
        return builder.EndObject()

    op1 = create_opcode(14) # LOGISTIC
    op0 = create_opcode(9)  # FULLY_CONNECTED

    builder.StartVector(4, 2, 4)
    builder.PrependUOffsetTRelative(op1)
    builder.PrependUOffsetTRelative(op0)
    opcodes_vec = builder.EndVector()

    # 3. Tensors
    # Tensor 0: input [1, 80] Float32, buffer 0
    # Tensor 1: weights [1, 80] Float32, buffer 2
    # Tensor 2: bias [1] Float32, buffer 3
    # Tensor 3: fc_out [1, 1] Float32, buffer 0
    # Tensor 4: output [1, 1] Float32, buffer 0
    def create_tensor(shape, name_str, buffer_idx):
        name_off = builder.CreateString(name_str)
        builder.StartVector(4, len(shape), 4)
        for s in reversed(shape):
            builder.PrependInt32(s)
        shape_off = builder.EndVector()

        builder.StartObject(6)
        builder.PrependUOffsetTRelativeSlot(0, shape_off, 0)
        builder.PrependInt8Slot(1, 0, 0) # TensorType.FLOAT32 = 0
        builder.PrependUint32Slot(2, buffer_idx, 0)
        builder.PrependUOffsetTRelativeSlot(3, name_off, 0)
        return builder.EndObject()

    t4 = create_tensor([1, 1], "malware_probability", 0)
    t3 = create_tensor([1, 1], "fc_out", 0)
    t2 = create_tensor([1], "bias", 3)
    t1 = create_tensor([1, 80], "weights", 2)
    t0 = create_tensor([1, 80], "input_features", 0)

    builder.StartVector(4, 5, 4)
    builder.PrependUOffsetTRelative(t4)
    builder.PrependUOffsetTRelative(t3)
    builder.PrependUOffsetTRelative(t2)
    builder.PrependUOffsetTRelative(t1)
    builder.PrependUOffsetTRelative(t0)
    tensors_vec = builder.EndVector()

    # Inputs / Outputs vector
    builder.StartVector(4, 1, 4)
    builder.PrependInt32(0) # tensor 0
    inputs_vec = builder.EndVector()

    builder.StartVector(4, 1, 4)
    builder.PrependInt32(4) # tensor 4
    outputs_vec = builder.EndVector()

    # 4. Operators
    # Op 0: FULLY_CONNECTED (inputs: [0, 1, 2], outputs: [3])
    builder.StartVector(4, 3, 4)
    builder.PrependInt32(2)
    builder.PrependInt32(1)
    builder.PrependInt32(0)
    fc_inputs = builder.EndVector()

    builder.StartVector(4, 1, 4)
    builder.PrependInt32(3)
    fc_outputs = builder.EndVector()

    builder.StartObject(5)
    builder.PrependUint32Slot(0, 0, 0) # opcode_index 0 (FULLY_CONNECTED)
    builder.PrependUOffsetTRelativeSlot(1, fc_inputs, 0)
    builder.PrependUOffsetTRelativeSlot(2, fc_outputs, 0)
    op_fc = builder.EndObject()

    # Op 1: LOGISTIC (inputs: [3], outputs: [4])
    builder.StartVector(4, 1, 4)
    builder.PrependInt32(3)
    log_inputs = builder.EndVector()

    builder.StartVector(4, 1, 4)
    builder.PrependInt32(4)
    log_outputs = builder.EndVector()

    builder.StartObject(5)
    builder.PrependUint32Slot(0, 1, 0) # opcode_index 1 (LOGISTIC)
    builder.PrependUOffsetTRelativeSlot(1, log_inputs, 0)
    builder.PrependUOffsetTRelativeSlot(2, log_outputs, 0)
    op_log = builder.EndObject()

    builder.StartVector(4, 2, 4)
    builder.PrependUOffsetTRelative(op_log)
    builder.PrependUOffsetTRelative(op_fc)
    operators_vec = builder.EndVector()

    # 5. Subgraph
    sg_name = builder.CreateString("main")
    builder.StartObject(6)
    builder.PrependUOffsetTRelativeSlot(0, tensors_vec, 0)
    builder.PrependUOffsetTRelativeSlot(1, inputs_vec, 0)
    builder.PrependUOffsetTRelativeSlot(2, outputs_vec, 0)
    builder.PrependUOffsetTRelativeSlot(3, operators_vec, 0)
    builder.PrependUOffsetTRelativeSlot(4, sg_name, 0)
    subgraph = builder.EndObject()

    builder.StartVector(4, 1, 4)
    builder.PrependUOffsetTRelative(subgraph)
    subgraphs_vec = builder.EndVector()

    # 6. Root Model Table
    desc_str = builder.CreateString("AEGIS On-Device Malware Classifier (P5)")
    builder.StartObject(6)
    builder.PrependUint32Slot(0, 3, 0) # version 3
    builder.PrependUOffsetTRelativeSlot(1, opcodes_vec, 0)
    builder.PrependUOffsetTRelativeSlot(2, subgraphs_vec, 0)
    builder.PrependUOffsetTRelativeSlot(3, desc_str, 0)
    builder.PrependUOffsetTRelativeSlot(4, buffers_vec, 0)
    model = builder.EndObject()

    # Finish buffer with identifier b"TFL3"
    builder.Finish(model, b"TFL3")
    buf = builder.Output()

    with open(out_path, "wb") as f:
        f.write(buf)

    print(f"Generated TFLite model: {out_path} ({len(buf)} bytes, identifier={buf[4:8]})")
    return buf

if __name__ == "__main__":
    w, b = train_weights()
    out_export = os.path.join(EXPORT_DIR, "aegis_malware_model.tflite")
    out_assets = os.path.join(ASSETS_DIR, "aegis_malware_model.tflite")
    
    build_tflite_flatbuffer(w, b, out_export)
    build_tflite_flatbuffer(w, b, out_assets)