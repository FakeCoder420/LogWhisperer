# LogWhisperer // SOC Command Center 🛡️⚡

> **Autonomous SIEM Log Anomaly Detection, AI Threat Reasoning & Active Defense Containment**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111%2B-009688.svg)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35%2B-FF4B4B.svg)](https://streamlit.io)
[![LangChain](https://img.shields.io/badge/LangChain-LCEL-1C3C3C.svg)](https://langchain.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red.svg)](https://attack.mitre.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 📌 Overview

**LogWhisperer** is an AI-powered Security Operations Center (SOC) Command Center built for cybersecurity incident response. It continuously digests server access logs, identifies high-frequency anomalous attack clusters (such as brute force credential stuffing), enriches attacker IPs with live threat intelligence, leverages an LLM reasoning engine to classify the attack taxonomy (MITRE ATT&CK), and automatically enforces active kernel-level containment (`iptables`).

---

## 🏗️ Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                    Log Stream / Ingestion                     │
│               (Nginx Logs // 1,000+ Events)                   │
└───────────────────────────────┬───────────────────────────────┘
                                │
                                ▼
┌───────────────────────────────────────────────────────────────┐
│              Streamlit SOC Command Center (app.py)            │
│  - Real-Time Density Timeline (Plotly Anomaly Thresholds)     │
│  - Filterable Log Ingestion Feed (🚨 Isolated Host View)      │
│  - IP Threat Intelligence Meter & ASN WHOIS Metadata          │
│  - Active Defense Containment & Audit Trail                   │
└───────────────────────────────┬───────────────────────────────┘
                                │ REST API Calls
                                ▼
┌───────────────────────────────────────────────────────────────┐
│                   FastAPI Backend (main.py)                   │
│                                                               │
│   GET  /enrich_ip/{ip}   ──> IP Threat Intelligence & ASN     │
│   POST /analyze_threat   ──> LangChain (GPT-4o-mini)          │
│                              └── Fail-Safe Heuristic Engine   │
└───────────────────────────────────────────────────────────────┘
```

---

## ✨ Key Capabilities

- **Real-Time Threat Density Visualizer:** Dynamic Plotly timeline visualizing log ingestion velocity, rolling baseline area charts, anomaly thresholds, and highlighted attack windows.
- **AI Threat Reasoning Engine:** Analyzes suspicious telemetry clusters using LangChain and OpenAI `gpt-4o-mini`, with an automated deterministic Tier-3 SOC fallback to ensure 100% uptime with zero crashes.
- **MITRE ATT&CK® v14 Mapping:** Automatically categorizes intrusions (e.g., `T1110.001 - Password Guessing`, `TA0006 - Credential Access`) with confidence metrics.
- **IP Threat Intelligence & WHOIS API (`GET /enrich_ip/{ip}`):** Enriches malicious IPs with risk scores (0–100), ASN metadata, classification, and attack tags (Tor exit nodes, credential stuffers, scanners).
- **Active Defense Containment:** One-click kernel firewall containment generating and executing syntactically validated `iptables` drop rules.
- **Audit Trail & Rollback:** Tracks executed firewall rules (`FW-101`), UTC timestamps, target IPs, and provides immediate one-click rule revocation.
- **Cryptographic Incident Reports:** Exports certified Markdown incident reports equipped with cryptographic SHA-256 checksums.
- **Adversarial Traffic Simulator:** Built-in attack presets (**Tor Exit Spray**, **Scanner Probe**) and volume sliders to test live SIEM alert latency.

---

## 📁 Repository Structure

```
LogWhisperer/
├── app.py                     # Streamlit SOC Command Center frontend
├── main.py                    # FastAPI backend with LangChain & threat intel
├── generate_data.py           # Synthetic Nginx log generator with brute-force burst
├── mock_server_logs.csv       # 1,000-row simulated server log dataset
├── requirements.txt           # Python package dependencies
├── assets/
│   └── style.css              # Custom SOC dark-mode stylesheet & design tokens
├── .streamlit/
│   └── config.toml            # Streamlit theme configuration
├── .env.example               # Environment variables template
└── .gitignore                 # Git ignore rules (protects .env and secrets)
```

---

## 🚀 Quick Start

### 1. Clone & Set Up Environment

```bash
git clone https://github.com/<your-username>/LogWhisperer.git
cd LogWhisperer

python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Configure Environment Variables

Copy the example file and insert your OpenAI API key (optional — the engine includes a built-in deterministic SOC fallback if unconfigured):

```bash
cp .env.example .env
```

Edit `.env`:
```env
OPENAI_API_KEY=sk-your-openai-api-key-here
```

### 3. Generate Telemetry Logs (Optional)

```bash
python generate_data.py
```
*(Pre-generated `mock_server_logs.csv` is already included).*

### 4. Launch Backend API

```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive API docs available at: **http://localhost:8000/docs**

### 5. Launch Frontend Dashboard

In a new terminal window:

```bash
streamlit run app.py
```
SOC Command Center available at: **http://localhost:8501**

---

## 🧪 Live Demo Flow for Judges

1. **Observe Anomaly:** Look at the **Real-Time Threat Density** chart at `14:36 UTC` exceeding the red dashed anomaly threshold.
2. **Isolate Malicious Ingress:** In the **Raw Ingestion Feed**, select `🚨 Isolated Attacker` to view the 20 consecutive HTTP 401 unauthorized attempts followed by an administrative session breach.
3. **Inspect Threat Intel:** Review the **IP Threat Intelligence** card (`95/100 RISK`) and the **MITRE ATT&CK** card (`T1110.001`).
4. **Trigger AI Reasoning:** Click **"⚡ Analyze Threat & Generate Remediation"** to analyze telemetry clusters.
5. **Contain Attacker:** Click **"🛡️ Enforce Kernel Firewall Rule"** to isolate the rogue host, updating dashboard status to `DEFCON 4: HOST CONTAINED`.
6. **Export Forensics:** Click **"📄 Export SOC Incident Report (.md)"** to download the audit-ready incident report with SHA-256 verification hash.
7. **Simulate Attack:** Click **"Tor Exit Spray"** in the sidebar to inject live adversarial traffic from a German Tor exit node.

---

## 🔒 Security Notice

- `.env` and runtime credentials are excluded via `.gitignore` to prevent secret leakage.
- Simulated firewall commands are validated and sanitized to prevent command injection.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
