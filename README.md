# AI-Powered SOC Platform

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi)
![Next.js](https://img.shields.io/badge/Next.js-14-black?style=flat-square&logo=next.js)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.x-yellow?style=flat-square&logo=elasticsearch)
![Tailwind](https://img.shields.io/badge/Tailwind-CSS-38B2AC?style=flat-square&logo=tailwind-css)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

**A production-grade Security Operations Center (SOC) platform that ingests Windows event logs, performs behavior-based and rule-based threat detection, maps threats to the MITRE ATT&CK framework, correlates events into attack chains, and delivers AI-driven actionable intelligence through a conversational security copilot.**

</div>

---

## Overview

This platform implements a full **SIEM + SOAR-lite pipeline** inspired by enterprise tools like Splunk, Microsoft Sentinel, and Microsoft Security Copilot — built entirely from scratch with industry-standard threat intelligence.

```
Windows Logs (Sysmon / Security Events)
              ↓
     NXLog (log shipper)
              ↓
  FastAPI Backend  ←  main.py
              ↓
     normalizer.py  →  models.py
              ↓
      detector.py  (rule engine + behavior engine)
              ↓
     mitre_mapper.py  (ATT&CK tactic + technique mapping)
              ↓
         db.py  →  Elasticsearch
              ↓
    graph_engine.py  (attack chains)
              ↓
      ai_engine.py  +  chat_engine.py
      (Actionable Intelligence Decision Engine)
              ↓
    Next.js Dashboard  (soc-dashboard)
    (Tactic · Technique · Structured Alerts UI)
```

---

## What's New — v2.0 Upgrades

| Capability | v1.0 (Before) | v2.0 (Now) |
|---|---|---|
| Detection | Rule-based alerts only | Rule-based + behavior anomaly detection |
| Threat Intelligence | None | MITRE ATT&CK tactic + technique mapping |
| AI Output | Explanation of incident | Actionable intelligence — priority, response steps, risk score |
| Dashboard | Basic alert list | Structured alerts with tactic, technique, severity, and chain view |
| Pipeline | Logs → Detection → AI → UI | Logs → Detection → Correlation → MITRE → AI → UI |

### 1. MITRE ATT&CK Integration (`mitre_mapper.py`)

Every alert is automatically mapped to the **MITRE ATT&CK framework** — the industry standard for adversary behavior classification.

| Alert Type | Tactic | Technique | Technique ID |
|---|---|---|---|
| brute_force | Credential Access | Brute Force | T1110 |
| privilege_escalation | Privilege Escalation | Valid Accounts | T1078 |
| execution | Execution | Command & Scripting Interpreter | T1059 |

Each alert now carries:
- `mitre_tactic` — the adversarial goal (e.g., Credential Access)
- `mitre_technique` — the method used (e.g., Brute Force)
- `mitre_technique_id` — the official ATT&CK ID (e.g., T1110)

### 2. Behavior-Based Detection (`detector.py` — upgraded)

In addition to static Event ID rules, the engine now includes **dynamic behavior analysis**:

**Execution Burst Anomaly** — detects when a host spawns an abnormally high number of processes in a short time window, consistent with script-based attacks, malware dropper activity, or lateral movement toolkits.

```
If process creation events from the same host exceed threshold T
within window W seconds → flag as execution_burst (High severity)
```

### 3. AI Decision Engine (`ai_engine.py` — upgraded)

Upgraded from a simple explainer to a full **intelligence decision engine**. For every analyzed chain it returns:

- **Threat Summary** — what is happening and why it matters
- **Risk Score** — 1–10 severity scoring with justification
- **Attack Stage** — where in the kill chain this falls
- **Recommended Response Actions** — specific, prioritized SOC playbook steps
- **Containment Priority** — Immediate / High / Medium / Monitor

### 4. Advanced Dashboard UI (`soc-dashboard/` — upgraded)

- Alert cards show: tactic badge, technique name, technique ID, severity, host, user, source IP, and timestamp
- Attack chain view shows the full multi-stage progression with MITRE context at each node
- AI panel displays structured decision engine output — risk score, response actions, containment priority
- SOC Copilot for natural language queries over live data

---

## Features

| Component | File | Description |
|---|---|---|
| Log Ingestion | `main.py` | FastAPI server — receives NXLog events via `POST /logs` |
| Normalization | `normalizer.py` | Parses raw Windows event JSON into a clean schema |
| Data Models | `models.py` | Pydantic models for logs, alerts, chains, and MITRE fields |
| Detection Engine | `detector.py` | Rule-based + behavior-based threat detection |
| MITRE Mapping | `mitre_mapper.py` | Maps every alert to ATT&CK tactic, technique, and ID |
| Database Layer | `db.py` | Elasticsearch client — index, query, aggregate |
| Attack Chain Correlation | `graph_engine.py` | Correlates related alerts into multi-stage attack sequences |
| AI Decision Engine | `ai_engine.py` | GPT-4 powered risk scoring, recommendations, containment priority |
| SOC Copilot | `chat_engine.py` | Conversational chat interface over live SOC data |
| Dashboard | `soc-dashboard/` | Next.js 14 + Tailwind — alerts, chains, MITRE view, AI panel, copilot |

---

## Detection Rules

### Static Rules (Event ID Based)

| Rule ID | Event ID | Trigger | Severity | MITRE Tactic | Technique ID |
|---|---|---|---|---|---|
| BF-IP-001 | 4625 | Multiple failed login attempts (brute force) | High | Credential Access | T1110 |
| PE-001 | 4672 | Special privileges assigned to new logon | Critical | Privilege Escalation | T1078 |
| SP-001 | 4688 | Suspicious process creation (cmd / powershell) | Medium | Execution | T1059 |

### Behavior Rules (Dynamic)

| Rule ID | Trigger | Severity | MITRE Tactic | Technique ID |
|---|---|---|---|---|
| EB-001 | Execution burst — high process creation rate per host | High | Execution | T1059 |

### Attack Chain Example

```
[4625 × N]  brute_force
            Tactic: Credential Access | T1110
      ↓
[4672]      privilege_escalation
            Tactic: Privilege Escalation | T1078
      ↓
[4688]      execution  (powershell.exe / cmd.exe)
            Tactic: Execution | T1059
```

**AI Decision Engine output for this chain:**

```json
{
  "threat_summary": "Full credential compromise and execution chain detected on DESKTOP-01",
  "risk_score": 9,
  "attack_stage": "Post-Exploitation",
  "containment_priority": "Immediate",
  "recommended_actions": [
    "Isolate DESKTOP-01 from the network immediately",
    "Reset credentials for affected user accounts",
    "Review PowerShell execution logs for payload indicators",
    "Scan adjacent hosts for lateral movement artifacts"
  ]
}
```

---

## Project Structure

```
AI-Powered-SOC-Platform/
│
├── soc-backend/
│   ├── main.py                  # FastAPI app — all API routes
│   ├── normalizer.py            # Raw log → structured schema
│   ├── models.py                # Pydantic models (includes MITRE fields)
│   ├── detector.py              # Rule-based + behavior-based detection engine
│   ├── mitre_mapper.py          # MITRE ATT&CK tactic + technique mapper
│   ├── graph_engine.py          # Alert correlation → attack chains
│   ├── ai_engine.py             # AI Decision Engine — risk, actions, priority
│   ├── chat_engine.py           # SOC Copilot chat logic
│   ├── db.py                    # Elasticsearch client wrapper
│   ├── requirements.txt         # Python dependencies
│   └── venv/                    # Virtual environment (not committed)
│
├── soc-dashboard/               # Next.js 14 frontend
│   ├── app/                     # App router pages
│   ├── components/              # Alert cards, chain view, AI panel, copilot
│   ├── lib/                     # Utility functions + API helpers
│   ├── next.config.js
│   ├── tailwind.config.ts
│   ├── tsconfig.json
│   └── package.json
│
├── nxlog/
│   └── nxlog.conf               # NXLog config — Windows Events → HTTP → backend
│
├── photos/                      # Dashboard screenshots and demo images
├── docker-compose.yml           # Elasticsearch + Backend + Frontend
├── .env.example                 # Environment variable template
└── LICENSE                      # MIT
```

---

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) + Docker Compose
- [NXLog Community Edition](https://nxlog.co/products/nxlog-community-edition) on the Windows target machine
- OpenAI API key

### 1. Clone the repository

```bash
git clone https://github.com/cyber-rishabh/AI-Powered-SOC-Platform.git
cd AI-Powered-SOC-Platform
```

### 2. Configure environment

```bash
cp .env.example .env
# Open .env and fill in OPENAI_API_KEY and other values
```

### 3. Start the full stack

```bash
docker-compose up -d
```

| Service | Port | Description |
|---|---|---|
| Elasticsearch | `9200` | Log + alert + chain storage |
| SOC Backend | `8000` | FastAPI — detection, MITRE mapping, AI, chat |
| SOC Dashboard | `3000` | Next.js frontend |

### 4. Configure NXLog (Windows machine)

Copy `nxlog/nxlog.conf` to your NXLog config directory and update the backend IP:

```
define BACKEND_HOST  <your-backend-ip>
define BACKEND_PORT  8000
```

Restart the NXLog service — logs will begin shipping immediately.

### 5. Open the dashboard

```
http://localhost:3000
```

---

## Running Locally (without Docker)

### Backend

```bash
cd soc-backend
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux / macOS
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd soc-dashboard
npm install
npm run dev
```

Open `http://localhost:3000`.

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/logs` | Receive raw logs from NXLog |
| `GET` | `/alerts` | Fetch all detected alerts (with MITRE fields) |
| `GET` | `/chains` | Fetch all correlated attack chains |
| `POST` | `/ai/analyze` | AI Decision Engine — risk score, actions, priority for a chain |
| `POST` | `/chat` | SOC Copilot — conversational query endpoint |

### Example — POST /logs

```json
{
  "EventID": 4625,
  "SubjectUserName": "attacker",
  "WorkstationName": "DESKTOP-01",
  "IpAddress": "192.168.1.50",
  "TimeCreated": "2024-01-15T10:23:00Z"
}
```

### Example — normalized alert output (v2.0)

```json
{
  "rule_id": "BF-IP-001",
  "severity": "high",
  "type": "brute_force",
  "user": "attacker",
  "host": "DESKTOP-01",
  "source_ip": "192.168.1.50",
  "timestamp": "2024-01-15T10:23:00Z",
  "mitre_tactic": "Credential Access",
  "mitre_technique": "Brute Force",
  "mitre_technique_id": "T1110"
}
```

### Example — AI Decision Engine output (v2.0)

```json
{
  "threat_summary": "Full credential compromise and execution chain detected",
  "risk_score": 9,
  "attack_stage": "Post-Exploitation",
  "containment_priority": "Immediate",
  "recommended_actions": [
    "Isolate affected host from the network",
    "Reset credentials for compromised accounts",
    "Review PowerShell execution logs",
    "Scan adjacent hosts for lateral movement"
  ]
}
```

---

## Elasticsearch Indices

| Index | Contents |
|---|---|
| `soc-logs` | All normalized ingested log events |
| `soc-alerts` | Triggered alerts — includes MITRE tactic, technique, and ID fields |
| `soc-chains` | Correlated multi-stage attack chains with AI decision engine output |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Log shipper | NXLog Community Edition |
| Backend API | FastAPI + Python 3.10+ |
| Data models | Pydantic v2 |
| Detection | Custom rules engine + behavior anomaly engine |
| Threat intelligence | MITRE ATT&CK framework (`mitre_mapper.py`) |
| Correlation | Python graph engine (`graph_engine.py`) |
| Storage | Elasticsearch 8.x |
| AI / LLM | OpenAI GPT-4 (Decision Engine) |
| Frontend | Next.js 14 + TypeScript + Tailwind CSS |
| Containerization | Docker Compose |

---

## Industry Equivalents

| This Project | Enterprise Tool |
|---|---|
| `detector.py` rules | Sigma Rules / Splunk SPL |
| `mitre_mapper.py` | MITRE ATT&CK Navigator |
| Log ingestion + storage | Splunk SIEM / IBM QRadar |
| Alert correlation | Microsoft Sentinel |
| `ai_engine.py` + `chat_engine.py` | Microsoft Security Copilot |
| Behavior detection | Darktrace / CrowdStrike Falcon |

---

## Roadmap

- [x] Rule-based detection engine
- [x] Multi-stage attack chain correlation
- [x] GPT-4 AI analysis
- [x] MITRE ATT&CK framework mapping
- [x] Behavior-based anomaly detection (execution burst)
- [x] AI Decision Engine — risk score + response actions
- [x] Advanced dashboard — tactic, technique, structured alerts
- [ ] ML-based anomaly detection (Isolation Forest / Autoencoder)
- [ ] Automated response playbooks (SOAR actions)
- [ ] Lateral movement detection across multiple hosts
- [ ] Slack / email alerting integration
- [ ] User and Entity Behavior Analytics (UEBA)
- [ ] Custom detection rule builder in the dashboard UI

---

## Screenshots

> See the `photos/` directory for full dashboard screenshots.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

<div align="center">
Built by <a href="https://github.com/cyber-rishabh">cyber-rishabh</a>
</div>
