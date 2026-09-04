"""
Test inference using the trained and calibrated MCP-Shield risk model.
"""
import joblib
import numpy as np

bundle = joblib.load("models/export/mcp_shield_risk_model.joblib")
clf = bundle["model"]
scaler = bundle["scaler"]
use_scaled = bundle["use_scaled"]
feature_names = bundle["feature_names"]

print(f"Loaded model: {bundle['model_name']} ({bundle['version']})")
print(f"Features: {len(feature_names)}")

# Test Case 1: Benign File Read
benign_features = {f: 0.0 for f in feature_names}
benign_features['tool_cap_fs_read'] = 1.0
benign_features['req_payload_size_bytes'] = 340.0
benign_features['req_entropy'] = 3.9
benign_features['tool_publisher_trust'] = 0.95
benign_features['prov_publisher_identity_score'] = 0.92

v_benign = np.array([[benign_features[f] for f in feature_names]])
if use_scaled and scaler:
    v_benign = scaler.transform(v_benign)
p_benign = clf.predict_proba(v_benign)[0][1]

print(f"\n[Test Case 1: Benign File Read]")
print(f"  Model A Attack Prob:  {p_benign:.4f} (Risk Score: {p_benign * 100.0:.2f} / 100)")
print(f"  Model A Decision:     {'ALLOW' if p_benign < 0.20 else 'ALERT'}")

# Model B, C, D on Benign
if "model_b_family" in bundle and bundle["model_b_family"]:
    fam_b = bundle["model_b_family"].predict(v_benign)[0]
    print(f"  Model B Attack Family:{fam_b}")

if "model_c_sequence" in bundle and bundle["model_c_sequence"]:
    seq_feats = bundle["seq_features"]
    v_seq = np.array([[benign_features[f] for f in seq_feats]])
    p_seq = bundle["model_c_sequence"].predict_proba(v_seq)[0][1]
    print(f"  Model C Sequence Risk:{p_seq * 100.0:.2f} / 100")

if "model_d_novelty" in bundle and bundle["model_d_novelty"]:
    is_outlier = bundle["model_d_novelty"].predict(v_benign)[0] == -1
    print(f"  Model D Zero-Day Outlier: {is_outlier}")

# Test Case 2: Multi-vector Exfiltration Attack
attack_features = {f: 0.0 for f in feature_names}
attack_features['req_shell_metachars'] = 4.0
attack_features['req_interpreter_transitions'] = 2.0
attack_features['tool_cap_process_spawn'] = 1.0
attack_features['tool_destructive_capability'] = 1.0
attack_features['seq_velocity_ops_per_min'] = 85.0
attack_features['req_entropy'] = 6.4
attack_features['seq_trans_read_to_network'] = 1.0

v_attack = np.array([[attack_features[f] for f in feature_names]])
if use_scaled and scaler:
    v_attack = scaler.transform(v_attack)
p_attack = clf.predict_proba(v_attack)[0][1]

print(f"\n[Test Case 2: Multi-Vector Command Injection / Exploit]")
print(f"  Model A Attack Prob:  {p_attack:.4f} (Risk Score: {p_attack * 100.0:.2f} / 100)")
print(f"  Model A Decision:     {'BLOCK' if p_attack >= 0.85 else 'ALERT'}")

if "model_b_family" in bundle and bundle["model_b_family"]:
    fam_a = bundle["model_b_family"].predict(v_attack)[0]
    print(f"  Model B Attack Family:{fam_a}")

if "model_c_sequence" in bundle and bundle["model_c_sequence"]:
    seq_feats = bundle["seq_features"]
    v_seq_att = np.array([[attack_features[f] for f in seq_feats]])
    p_seq_att = bundle["model_c_sequence"].predict_proba(v_seq_att)[0][1]
    print(f"  Model C Sequence Risk:{p_seq_att * 100.0:.2f} / 100")

if "model_d_novelty" in bundle and bundle["model_d_novelty"]:
    is_outlier_att = bundle["model_d_novelty"].predict(v_attack)[0] == -1
    print(f"  Model D Zero-Day Outlier: {is_outlier_att}")
