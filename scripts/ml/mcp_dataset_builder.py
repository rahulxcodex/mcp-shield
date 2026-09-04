"""
MCP-Shield - Security Telemetry Dataset Generator & Feature Aligner
Aligns with MCP-Shield FeatureExtractor (42 Versioned Features) and ML Roadmap.
Generates balanced, realistic benchmark datasets with holdout splits.
"""

import os
import json
import numpy as np
import pandas as pd

np.random.seed(42)

FEATURE_NAMES = [
    # 2.1 Tool Features (14)
    'tool_schema_complexity',
    'tool_param_count',
    'tool_cap_fs_read',
    'tool_cap_fs_write',
    'tool_cap_process_spawn',
    'tool_cap_network_egress',
    'tool_cap_secret_access',
    'tool_cap_db_access',
    'tool_destructive_capability',
    'tool_capability_mismatch',
    'tool_schema_drift',
    'tool_publisher_trust',
    'tool_server_age_days',
    'tool_historical_incidents',

    # 2.2 Request Features (11)
    'req_payload_size_bytes',
    'req_entropy',
    'req_encoding_count',
    'req_url_count',
    'req_ip_literals',
    'req_special_ip_rep',
    'req_shell_metachars',
    'req_interpreter_transitions',
    'req_path_traversal_indicators',
    'req_secret_findings',
    'req_prompt_injection_signals',

    # 2.3 Behavioral Transition Features (10)
    'seq_unique_tools_last_5',
    'seq_unique_tools_last_10',
    'seq_trans_read_to_network',
    'seq_trans_read_encode_network',
    'seq_trans_db_to_export',
    'seq_trans_db_export_upload',
    'seq_trans_fs_archive_upload',
    'seq_trans_new_cap_external_dest',
    'seq_velocity_ops_per_min',
    'seq_unseen_tool_transition',

    # 2.4 Provenance Features (7)
    'prov_binary_hash_changed',
    'prov_dep_graph_changed',
    'prov_schema_fingerprint_changed',
    'prov_publisher_identity_score',
    'prov_first_seen_days',
    'prov_deployment_history_score',
    'prov_previous_violations'
]

ATTACK_FAMILIES = [
    'BENIGN',
    'PROMPT_INJECTION',
    'COMMAND_INJECTION',
    'PATH_TRAVERSAL',
    'SSRF_METADATA',
    'CREDENTIAL_THEFT',
    'DATA_EXFILTRATION',
    'TOOL_POISONING',
    'RESOURCE_ABUSE',
    'PRIVILEGE_ESCALATION'
]

def generate_benign_sample(server_id):
    """Generates realistic benign MCP telemetry."""
    tool_caps = np.random.choice(['fs_read', 'db_read', 'network_call', 'calc', 'git_read', 'search'])
    payload_size = int(np.random.lognormal(mean=5.5, sigma=1.2)) # ~250B to 2KB typical
    entropy = float(np.clip(np.random.normal(loc=4.1, scale=0.5), 1.5, 6.0))
    
    server_age = int(np.random.uniform(15, 750))
    pub_trust = float(np.clip(np.random.beta(a=8, b=2), 0.5, 1.0))
    first_seen = int(np.random.uniform(10, server_age))
    
    data = {
        # Tool Features
        'tool_schema_complexity': int(np.random.randint(1, 8)),
        'tool_param_count': int(np.random.randint(1, 6)),
        'tool_cap_fs_read': 1 if 'fs' in tool_caps else 0,
        'tool_cap_fs_write': 1 if np.random.rand() < 0.08 else 0,
        'tool_cap_process_spawn': 1 if np.random.rand() < 0.03 else 0,
        'tool_cap_network_egress': 1 if 'network' in tool_caps else 0,
        'tool_cap_secret_access': 0,
        'tool_cap_db_access': 1 if 'db' in tool_caps else 0,
        'tool_destructive_capability': 0,
        'tool_capability_mismatch': 0,
        'tool_schema_drift': 0,
        'tool_publisher_trust': pub_trust,
        'tool_server_age_days': server_age,
        'tool_historical_incidents': 0,

        # Request Features
        'req_payload_size_bytes': payload_size,
        'req_entropy': entropy,
        'req_encoding_count': 0 if np.random.rand() < 0.95 else 1,
        'req_url_count': int(np.random.choice([0, 1, 2], p=[0.75, 0.20, 0.05])),
        'req_ip_literals': 0,
        'req_special_ip_rep': 0,
        'req_shell_metachars': 0 if np.random.rand() < 0.98 else 1,
        'req_interpreter_transitions': 0,
        'req_path_traversal_indicators': 0,
        'req_secret_findings': 0,
        'req_prompt_injection_signals': 0,

        # Behavioral Sequence Features
        'seq_unique_tools_last_5': int(np.random.randint(1, 4)),
        'seq_unique_tools_last_10': int(np.random.randint(2, 6)),
        'seq_trans_read_to_network': 1 if np.random.rand() < 0.05 else 0,
        'seq_trans_read_encode_network': 0,
        'seq_trans_db_to_export': 0,
        'seq_trans_db_export_upload': 0,
        'seq_trans_fs_archive_upload': 0,
        'seq_trans_new_cap_external_dest': 0,
        'seq_velocity_ops_per_min': float(np.random.exponential(scale=12.0)),
        'seq_unseen_tool_transition': 0 if np.random.rand() < 0.96 else 1,

        # Provenance Features
        'prov_binary_hash_changed': 0,
        'prov_dep_graph_changed': 0,
        'prov_schema_fingerprint_changed': 0,
        'prov_publisher_identity_score': float(np.clip(pub_trust * 0.65 + np.random.normal(0.2, 0.1), 0.1, 1.0)),
        'prov_first_seen_days': first_seen,
        'prov_deployment_history_score': float(np.clip(np.random.beta(a=7, b=2), 0.4, 1.0)),
        'prov_previous_violations': 0,

        # Meta
        'server_id': server_id,
        'attack_family': 'BENIGN',
        'is_attack': 0
    }
    return data

def generate_attack_sample(server_id, family):
    """Generates attack telemetry tailored to specific threat families."""
    sample = generate_benign_sample(server_id)
    sample['attack_family'] = family
    sample['is_attack'] = 1
    sample['tool_historical_incidents'] = int(np.random.choice([0, 1, 2, 3], p=[0.5, 0.3, 0.15, 0.05]))

    if family == 'PROMPT_INJECTION':
        sample['req_prompt_injection_signals'] = int(np.random.randint(1, 5))
        sample['req_entropy'] = float(np.clip(np.random.normal(loc=5.4, scale=0.6), 4.2, 7.8))
        sample['req_payload_size_bytes'] = int(np.random.lognormal(mean=7.2, sigma=0.8)) # longer prompts
        sample['req_encoding_count'] = int(np.random.choice([0, 1, 2], p=[0.4, 0.4, 0.2]))
        sample['tool_capability_mismatch'] = 1 if np.random.rand() < 0.4 else 0

    elif family == 'COMMAND_INJECTION':
        sample['req_shell_metachars'] = int(np.random.randint(2, 8))
        sample['req_interpreter_transitions'] = int(np.random.choice([1, 2, 3], p=[0.6, 0.3, 0.1]))
        sample['tool_cap_process_spawn'] = 1
        sample['tool_destructive_capability'] = 1 if np.random.rand() < 0.6 else 0
        sample['seq_velocity_ops_per_min'] = float(np.random.uniform(40, 120))

    elif family == 'PATH_TRAVERSAL':
        sample['req_path_traversal_indicators'] = int(np.random.randint(2, 7))
        sample['tool_cap_fs_read'] = 1
        sample['req_entropy'] = float(np.random.uniform(3.8, 5.2))
        sample['tool_capability_mismatch'] = 1 if np.random.rand() < 0.35 else 0

    elif family == 'SSRF_METADATA':
        sample['req_special_ip_rep'] = 1  # 169.254.169.254 or loopback/link-local
        sample['req_ip_literals'] = int(np.random.randint(1, 4))
        sample['tool_cap_network_egress'] = 1
        sample['seq_trans_read_to_network'] = 1
        sample['seq_trans_new_cap_external_dest'] = 1

    elif family == 'CREDENTIAL_THEFT':
        sample['req_secret_findings'] = int(np.random.randint(1, 6))
        sample['tool_cap_secret_access'] = 1
        sample['tool_cap_fs_read'] = 1
        sample['seq_trans_read_encode_network'] = 1 if np.random.rand() < 0.5 else 0

    elif family == 'DATA_EXFILTRATION':
        sample['req_payload_size_bytes'] = int(np.random.lognormal(mean=11.0, sigma=1.1)) # 50KB to multi-MB
        sample['seq_trans_db_to_export'] = 1
        sample['seq_trans_db_export_upload'] = 1 if np.random.rand() < 0.8 else 0
        sample['seq_trans_fs_archive_upload'] = 1 if np.random.rand() < 0.7 else 0
        sample['tool_cap_network_egress'] = 1
        sample['req_entropy'] = float(np.random.uniform(5.8, 7.9)) # compressed or encrypted data

    elif family == 'TOOL_POISONING':
        sample['tool_schema_drift'] = 1
        sample['prov_schema_fingerprint_changed'] = 1
        sample['prov_binary_hash_changed'] = 1 if np.random.rand() < 0.7 else 0
        sample['tool_capability_mismatch'] = 1
        sample['tool_publisher_trust'] = float(np.random.uniform(0.15, 0.50))
        sample['prov_publisher_identity_score'] = float(np.random.uniform(0.05, 0.40))

    elif family == 'RESOURCE_ABUSE':
        sample['seq_velocity_ops_per_min'] = float(np.random.uniform(80, 450))
        sample['tool_destructive_capability'] = 1 if np.random.rand() < 0.4 else 0
        sample['tool_schema_complexity'] = int(np.random.randint(12, 35))

    elif family == 'PRIVILEGE_ESCALATION':
        sample['tool_cap_process_spawn'] = 1
        sample['req_shell_metachars'] = int(np.random.randint(1, 5))
        sample['prov_previous_violations'] = int(np.random.randint(1, 4))
        sample['seq_unseen_tool_transition'] = 1
        sample['tool_destructive_capability'] = 1 if np.random.rand() < 0.6 else 0

    return sample

def build_dataset(total_samples=10000, benign_ratio=0.65, output_dir='data/ml'):
    os.makedirs(output_dir, exist_ok=True)
    
    n_benign = int(total_samples * benign_ratio)
    n_attack = total_samples - n_benign
    
    # Establish server identities (some in train, some strictly held out in test)
    train_servers = [f"mcp-server-{i:03d}" for i in range(1, 41)]
    heldout_servers = [f"mcp-unseen-server-{i:03d}" for i in range(1, 11)]

    samples = []
    
    # Generate benign events
    for _ in range(n_benign):
        srv = np.random.choice(train_servers + heldout_servers)
        samples.append(generate_benign_sample(srv))
        
    # Generate attack events evenly across attack families
    attack_types = [f for f in ATTACK_FAMILIES if f != 'BENIGN']
    for _ in range(n_attack):
        fam = np.random.choice(attack_types)
        srv = np.random.choice(train_servers + heldout_servers)
        samples.append(generate_attack_sample(srv, fam))
        
    df = pd.DataFrame(samples)
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    
    # Save full dataset
    full_path = os.path.join(output_dir, 'mcp_security_telemetry.csv')
    df.to_csv(full_path, index=False)
    print(f"[Dataset] Generated {len(df)} records ({n_benign} benign, {n_attack} attacks)")
    print(f"[Dataset] Full CSV saved to: {full_path}")
    
    # Server-aware / Holdout Train-Validation-Test Split (70% train, 15% val, 15% test)
    # Ensure held-out test contains unseen servers as well as unseen attack variations
    is_test_server = df['server_id'].isin(heldout_servers[:5])
    test_heldout = df[is_test_server]
    remaining = df[~is_test_server]
    
    # Stratified split on remaining
    from sklearn.model_selection import train_test_split
    train_df, val_df = train_test_split(remaining, test_size=0.20, random_state=42, stratify=remaining['is_attack'])
    
    # Add heldout servers into test set to evaluate out-of-domain generalization
    test_df = pd.concat([test_heldout, val_df.sample(frac=0.3, random_state=42)]).reset_index(drop=True)
    val_df = val_df.drop(test_df.index, errors='ignore').reset_index(drop=True)
    
    train_path = os.path.join(output_dir, 'train.csv')
    val_path = os.path.join(output_dir, 'val.csv')
    test_path = os.path.join(output_dir, 'test.csv')
    
    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)
    
    # Save feature schema JSON
    schema_path = os.path.join(output_dir, 'feature_schema.json')
    with open(schema_path, 'w') as f:
        json.dump({
            "schemaVersion": "2.0.0",
            "featureCount": len(FEATURE_NAMES),
            "features": FEATURE_NAMES,
            "target": "is_attack",
            "attackFamilies": ATTACK_FAMILIES
        }, f, indent=2)
        
    print(f"[Splits] Train: {len(train_df)}, Val: {len(val_df)}, Test: {len(test_df)}")
    print(f"[Splits] Feature schema saved to: {schema_path}")
    return df, train_df, val_df, test_df

if __name__ == '__main__':
    build_dataset()
