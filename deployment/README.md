---
title: MCP Shield ML Risk Classifier
emoji: 🛡️
colorFrom: red
colorTo: blue
sdk: gradio
sdk_version: 4.44.0
app_file: app.py
pinned: false
---

# MCP-Shield ML Risk Classifier (Gradio on Hugging Face Spaces)

This space hosts the calibrated Tabular Risk Model for Model Context Protocol (MCP) tool execution.
It provides:
1. **Interactive Web Dashboard**: Adjust payload metrics, metacharacters, entropy, and tool capabilities to inspect risk scores and decision tiers (`ALLOW`, `MONITOR`, `PROMPT`, `SANDBOX`, `BLOCK`).
2. **Programmatic API**: Call predictions via Python or cURL using Gradio's automatic `/api/predict` endpoint.

---

## 1-Click Free Deployment Instructions (Hugging Face Spaces)

Hugging Face provides **free 2 vCPU / 16GB RAM instances** under the Gradio SDK with **zero cost forever**.

### Step 1: Create a Space on Hugging Face
1. Go to [huggingface.co/new-space](https://huggingface.co/new-space).
2. Enter Space Name: `mcp-shield-risk-classifier` (or your choice).
3. Select **Gradio** as the Space SDK (choose **Blank** template).
4. Leave hardware on the default **Free (2 vCPU, 16 GB RAM)**.
5. Click **Create Space**.

### Step 2: Upload Files
You can upload directly via the Hugging Face Web UI ("Files" -> "Add file" -> "Upload files") or via Git:

```bash
git clone https://huggingface.co/spaces/<your-username>/mcp-shield-risk-classifier
cd mcp-shield-risk-classifier

# Copy all deployment files and the trained model bundle
cp -r /path/to/mcp-shield/deployment/* .
mkdir -p models/export
cp /path/to/mcp-shield/models/export/mcp_shield_risk_model.joblib models/export/

git add .
git commit -m "Deploy MCP-Shield Gradio Risk Classifier"
git push
```

### Step 3: Verify Live Endpoint
Once pushed, Hugging Face will automatically install dependencies from `requirements.txt` and launch `app.py`.
Your space will be live at:
`https://huggingface.co/spaces/<your-username>/mcp-shield-risk-classifier`

---

## Programmatic API Usage

You can query this deployed space programmatically from any MCP-Shield proxy or Python script:

### Using Python (`gradio_client`):
```python
from gradio_client import Client

client = Client("https://<your-username>-mcp-shield-risk-classifier.hf.space/")
result = client.predict(
    tool_name="bash_exec",
    shell_metachars=3.0,
    path_traversal=0.0,
    prompt_injection=0.0,
    secret_findings=0.0,
    special_ip=False,
    entropy=5.6,
    payload_size_bytes=1024,
    cap_process_spawn=True,
    cap_network_egress=False,
    cap_fs_read=True,
    seq_trans_read_network=False,
    seq_velocity=45.0,
    publisher_trust=0.9
)
print(result) # returns [html_view, json_response]
```

### Using cURL:
```bash
curl -X POST "https://<your-username>-mcp-shield-risk-classifier.hf.space/api/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "data": [
      "bash_exec", 3, 0, 0, 0, false, 5.6, 1024, true, false, true, false, 45.0, 0.9
    ]
  }'
```
