"""
MCP-Shield - ML Risk Inference & Visual Diagnostic Dashboard
Built for Hugging Face Spaces (Free Gradio SDK).
Provides:
1. Interactive Web Dashboard for live security risk analysis.
2. Programmatic API endpoint (/predict and /api/predict) for MCP-Shield client queries.
"""

import os
import time
import json
import html
import joblib
import numpy as np
import gradio as gr

MODEL_PATH = os.getenv("MODEL_PATH", "models/export/mcp_shield_risk_model.joblib")

# Load model bundle
model_bundle = None
if os.path.exists(MODEL_PATH):
    try:
        model_bundle = joblib.load(MODEL_PATH)
        print(f"[Model Server] Successfully loaded {model_bundle.get('model_name')} from {MODEL_PATH}")
    except Exception as e:
        print(f"[Model Server] Failed loading {MODEL_PATH}: {e}")

FEATURE_NAMES = model_bundle.get("feature_names", []) if model_bundle else [
    'tool_schema_complexity', 'tool_param_count', 'tool_cap_fs_read', 'tool_cap_fs_write',
    'tool_cap_process_spawn', 'tool_cap_network_egress', 'tool_cap_secret_access', 'tool_cap_db_access',
    'tool_destructive_capability', 'tool_capability_mismatch', 'tool_schema_drift', 'tool_publisher_trust',
    'tool_server_age_days', 'tool_historical_incidents',
    'req_payload_size_bytes', 'req_entropy', 'req_encoding_count', 'req_url_count',
    'req_ip_literals', 'req_special_ip_rep', 'req_shell_metachars', 'req_interpreter_transitions',
    'req_path_traversal_indicators', 'req_secret_findings', 'req_prompt_injection_signals',
    'seq_unique_tools_last_5', 'seq_unique_tools_last_10', 'seq_trans_read_to_network',
    'seq_trans_read_encode_network', 'seq_trans_db_to_export', 'seq_trans_db_export_upload',
    'seq_trans_fs_archive_upload', 'seq_trans_new_cap_external_dest', 'seq_velocity_ops_per_min',
    'seq_unseen_tool_transition',
    'prov_binary_hash_changed', 'prov_dep_graph_changed', 'prov_schema_fingerprint_changed',
    'prov_publisher_identity_score', 'prov_first_seen_days', 'prov_deployment_history_score',
    'prov_previous_violations'
]

try:
    import spaces
except Exception:
    class spaces:
        @staticmethod
        def GPU(func=None, **kwargs):
            if func is not None:
                return func
            def decorator(f):
                return f
            return decorator

@spaces.GPU
def analyze_risk(
    tool_name,
    shell_metachars,
    path_traversal,
    prompt_injection,
    secret_findings,
    special_ip,
    entropy,
    payload_size_bytes,
    cap_process_spawn,
    cap_network_egress,
    cap_fs_read,
    seq_trans_read_network,
    seq_velocity,
    publisher_trust
):
    start_t = time.perf_counter()
    
    # Construct feature dictionary
    features = {f: 0.0 for f in FEATURE_NAMES}
    features['req_shell_metachars'] = float(shell_metachars)
    features['req_path_traversal_indicators'] = float(path_traversal)
    features['req_prompt_injection_signals'] = float(prompt_injection)
    features['req_secret_findings'] = float(secret_findings)
    features['req_special_ip_rep'] = 1.0 if special_ip else 0.0
    features['req_entropy'] = float(entropy)
    features['req_payload_size_bytes'] = float(payload_size_bytes)
    features['tool_cap_process_spawn'] = 1.0 if cap_process_spawn else 0.0
    features['tool_cap_network_egress'] = 1.0 if cap_network_egress else 0.0
    features['tool_cap_fs_read'] = 1.0 if cap_fs_read else 0.0
    features['seq_trans_read_to_network'] = 1.0 if seq_trans_read_network else 0.0
    features['seq_velocity_ops_per_min'] = float(seq_velocity)
    features['tool_publisher_trust'] = float(publisher_trust)
    features['prov_publisher_identity_score'] = float(publisher_trust * 0.8)

    dense_vector = [features.get(f, 0.0) for f in FEATURE_NAMES]
    X = np.array([dense_vector])

    if model_bundle and model_bundle.get("model") is not None:
        clf = model_bundle["model"]
        scaler = model_bundle.get("scaler")
        use_scaled = model_bundle.get("use_scaled", False)
        if use_scaled and scaler:
            X = scaler.transform(X)
        probs = clf.predict_proba(X)[0]
        attack_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
    else:
        # Fallback scoring
        score_sum = (
            shell_metachars * 2.0 + path_traversal * 2.5 + prompt_injection * 2.0 +
            secret_findings * 2.0 + (10.0 if special_ip else 0.0) + (entropy - 4.0) * 1.5
        )
        attack_prob = float(1.0 / (1.0 + np.exp(-score_sum / 3.0)))

    risk_score = round(attack_prob * 100.0, 2)

    # Decision Tiering per Roadmap
    if risk_score < 20.0:
        tier = "ALLOW"
        tier_color = "#10b981" # Green
    elif risk_score < 45.0:
        tier = "MONITOR"
        tier_color = "#3b82f6" # Blue
    elif risk_score < 70.0:
        tier = "PROMPT"
        tier_color = "#f59e0b" # Yellow
    elif risk_score < 85.0:
        tier = "SANDBOX"
        tier_color = "#f97316" # Orange
    else:
        tier = "BLOCK"
        tier_color = "#ef4444" # Red

    # Model B — Attack Family Multi-Class Classifier
    family_clf = model_bundle.get("model_b_family") if model_bundle else None
    if family_clf is not None:
        fam_probs = family_clf.predict_proba(X)[0]
        fam_classes = model_bundle.get("family_classes", getattr(family_clf, "classes_", []))
        fam_dict = {str(c): round(float(p), 4) for c, p in zip(fam_classes, fam_probs)}
        top_family = max(fam_dict, key=fam_dict.get)
        top_family_conf = fam_dict[top_family]
    else:
        fam_dict = {"BENIGN": round(1.0 - attack_prob, 4), "UNKNOWN_ATTACK": round(attack_prob, 4)}
        top_family = "BENIGN" if attack_prob < 0.5 else "UNKNOWN_ATTACK"
        top_family_conf = round(float(attack_prob if attack_prob >= 0.5 else 1.0 - attack_prob), 4)

    # Model C — Behavioral Sequence Trajectory Model
    seq_clf = model_bundle.get("model_c_sequence") if model_bundle else None
    seq_features = model_bundle.get("seq_features") if model_bundle else None
    if seq_clf is not None and seq_features:
        seq_vector = np.array([[features.get(f, 0.0) for f in seq_features]])
        seq_probs = seq_clf.predict_proba(seq_vector)[0]
        seq_risk = round(float(seq_probs[1] if len(seq_probs) > 1 else seq_probs[0]) * 100.0, 2)
    else:
        seq_risk = round(attack_prob * 100.0, 2)

    # Model D — Novelty & Outlier Anomaly Detector
    novelty_clf = model_bundle.get("model_d_novelty") if model_bundle else None
    if novelty_clf is not None:
        raw_outlier = float(novelty_clf.decision_function(X)[0])
        is_novelty = bool(novelty_clf.predict(X)[0] == -1)
        novelty_score = round(float(np.clip((0.15 - raw_outlier) * 120.0, 0.0, 100.0)), 2)
    else:
        novelty_score = 0.0
        is_novelty = False

    latency = round((time.perf_counter() - start_t) * 1000.0, 3)

    # Contributing signals
    signals = []
    if shell_metachars > 0: signals.append(f"Shell Metacharacters ({int(shell_metachars)})")
    if path_traversal > 0: signals.append(f"Path Traversal Patterns ({int(path_traversal)})")
    if prompt_injection > 0: signals.append(f"Prompt Injection Signals ({int(prompt_injection)})")
    if secret_findings > 0: signals.append(f"Secret / Token Findings ({int(secret_findings)})")
    if special_ip: signals.append("Metadata / Loopback IP Access Attempt")
    if entropy > 5.5: signals.append(f"Elevated Shannon Entropy ({entropy:.2f} bits)")
    if seq_trans_read_network: signals.append("Cross-Capability Transition: Local Read -> Egress")
    if is_novelty: signals.append(f"Model D Zero-Day Novelty Anomaly ({novelty_score}/100)")
    if not signals: signals.append("Normal baseline behavior")

    family_badge_color = "#10b981" if top_family == "BENIGN" else "#ef4444"
    safe_tool_name = html.escape(str(tool_name or 'unnamed_tool'))

    output_html = f"""
    <div style="padding: 20px; border-radius: 12px; background: #0f172a; color: white; font-family: sans-serif;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
            <div>
                <span style="font-size: 13px; text-transform: uppercase; letter-spacing: 1px; color: #94a3b8;">Target Tool</span>
                <h2 style="margin: 4px 0 0 0; color: #f8fafc;">{safe_tool_name}</h2>
            </div>
            <div style="text-align: right;">
                <span style="font-size: 12px; color: #94a3b8;">Decision Tier</span>
                <div style="font-size: 20px; font-weight: 800; color: {tier_color}; background: {tier_color}22; padding: 6px 14px; border-radius: 8px; border: 1px solid {tier_color};">
                    {tier}
                </div>
            </div>
        </div>

        <div style="margin: 16px 0;">
            <div style="display: flex; justify-content: space-between; font-size: 14px; margin-bottom: 6px;">
                <span>Model A: Calibrated Action Risk</span>
                <span style="font-weight: bold; color: {tier_color};">{risk_score} / 100</span>
            </div>
            <div style="background: #334155; border-radius: 999px; height: 10px; overflow: hidden;">
                <div style="background: {tier_color}; width: {min(100.0, risk_score)}%; height: 100%; transition: width 0.3s ease;"></div>
            </div>
        </div>

        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 14px;">
            <div style="background: #1e293b; padding: 10px; border-radius: 8px;">
                <div style="font-size: 11px; color: #94a3b8;">Model B: Attack Family</div>
                <div style="font-size: 14px; font-weight: 700; color: {family_badge_color}; margin-top: 2px;">{top_family}</div>
                <div style="font-size: 11px; color: #64748b;">{top_family_conf*100:.1f}% conf</div>
            </div>
            <div style="background: #1e293b; padding: 10px; border-radius: 8px;">
                <div style="font-size: 11px; color: #94a3b8;">Model C: Sequence Trajectory</div>
                <div style="font-size: 14px; font-weight: 700; color: {'#ef4444' if seq_risk >= 70 else '#3b82f6'}; margin-top: 2px;">{seq_risk} / 100</div>
                <div style="font-size: 11px; color: #64748b;">Kill-chain risk</div>
            </div>
            <div style="background: #1e293b; padding: 10px; border-radius: 8px;">
                <div style="font-size: 11px; color: #94a3b8;">Model D: Novelty Score</div>
                <div style="font-size: 14px; font-weight: 700; color: {'#f59e0b' if is_novelty else '#10b981'}; margin-top: 2px;">{novelty_score} / 100</div>
                <div style="font-size: 11px; color: #64748b;">{'Outlier Detected' if is_novelty else 'Standard Distribution'}</div>
            </div>
        </div>

        <div style="margin-top: 14px; background: #1e293b; padding: 12px; border-radius: 8px;">
            <div style="font-size: 11px; font-weight: 600; text-transform: uppercase; color: #94a3b8; margin-bottom: 6px;">Primary Threat Indicators ({latency}ms)</div>
            <ul style="margin: 0; padding-left: 18px; color: #cbd5e1; font-size: 13px;">
                {''.join(f'<li>{s}</li>' for s in signals)}
            </ul>
        </div>
    </div>
    """

    api_json = {
        "toolName": tool_name,
        "recommendedAction": tier,
        "latencyMs": latency,
        "modelVersion": "v2.0.0",
        "modelA_actionRisk": {
            "riskScore": risk_score,
            "attackProbability": round(attack_prob, 4),
            "decisionTier": tier
        },
        "modelB_attackFamily": {
            "predictedFamily": top_family,
            "confidence": top_family_conf,
            "familyProbabilities": fam_dict
        },
        "modelC_sequenceTrajectory": {
            "trajectoryRiskScore": seq_risk,
            "isHighRiskKillChain": bool(seq_risk >= 70.0)
        },
        "modelD_noveltyOutlier": {
            "noveltyScore": novelty_score,
            "isZeroDayNovelty": is_novelty
        },
        "primarySignals": signals
    }

    return output_html, json.dumps(api_json, indent=2)

# Build Gradio UI
with gr.Blocks(title="MCP-Shield Security Intelligence") as demo:
    gr.Markdown("""
    # 🛡️ MCP-Shield: Multi-Model Security Intelligence
    ### Real-Time 4-Model Threat Evaluation: Tabular Risk, Attack Family, Sequence Trajectory & Novelty Anomaly
    Inspect and score incoming tool execution envelopes against the synchronized MCP-Shield ML suite.
    """)

    with gr.Row():
        with gr.Column(scale=1):
            tool_name = gr.Textbox(label="MCP Tool Name", value="bash_exec", placeholder="e.g. fs_read, execute_command")
            
            with gr.Accordion("Exploit & Injection Signals", open=True):
                shell_metachars = gr.Slider(0, 10, value=0, step=1, label="Shell Metacharacters (`&&`, `;`, `|`, `` ` ``)")
                path_traversal = gr.Slider(0, 10, value=0, step=1, label="Path Traversal Indicators (`../`, `..\\`)")
                prompt_injection = gr.Slider(0, 10, value=0, step=1, label="Prompt Injection Triggers")
                secret_findings = gr.Slider(0, 10, value=0, step=1, label="Exposed Secrets / API Keys")
                special_ip = gr.Checkbox(label="Cloud Metadata / Loopback IP Attempt (169.254.x / 127.x)", value=False)
            
            with gr.Accordion("Payload & Entropy Stats", open=False):
                entropy = gr.Slider(1.0, 8.0, value=4.1, step=0.1, label="Shannon Entropy (bits/byte)")
                payload_size_bytes = gr.Slider(10, 5000000, value=512, step=100, label="Payload Size (Bytes)")
                seq_velocity = gr.Slider(0.0, 300.0, value=12.0, step=5.0, label="Tool Call Velocity (ops/min)")
                publisher_trust = gr.Slider(0.0, 1.0, value=0.85, step=0.05, label="Publisher Trust Score")

            with gr.Accordion("Capabilities & Sequence Context", open=False):
                cap_process_spawn = gr.Checkbox(label="Spawns Subprocesses", value=False)
                cap_network_egress = gr.Checkbox(label="Network Egress Capability", value=False)
                cap_fs_read = gr.Checkbox(label="Filesystem Read Capability", value=False)
                seq_trans_read_network = gr.Checkbox(label="Behavioral Sequence: Read -> Egress", value=False)

            analyze_btn = gr.Button("Evaluate Multi-Model Security Suite", variant="primary")

        with gr.Column(scale=1):
            gr.Markdown("### Multi-Model Threat Evaluation")
            result_html = gr.HTML()
            with gr.Accordion("Programmatic JSON API Output", open=True):
                result_json = gr.Code(language="json", label="JSON Response")

    inputs = [
        tool_name, shell_metachars, path_traversal, prompt_injection,
        secret_findings, special_ip, entropy, payload_size_bytes,
        cap_process_spawn, cap_network_egress, cap_fs_read,
        seq_trans_read_network, seq_velocity, publisher_trust
    ]
    
    analyze_btn.click(
        fn=analyze_risk,
        inputs=inputs,
        outputs=[result_html, result_json]
    )

    demo.load(
        fn=analyze_risk,
        inputs=inputs,
        outputs=[result_html, result_json]
    )

if __name__ == "__main__":
    demo.launch(
        server_name="0.0.0.0",
        server_port=int(os.getenv("PORT", 7860)),
        theme=gr.themes.Soft(primary_hue="red")
    )
