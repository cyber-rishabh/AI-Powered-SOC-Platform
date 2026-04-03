# AI-Powered SOC Platform

<div align="center">

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688)
![Next.js](https://img.shields.io/badge/Next.js-14-black)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.x-yellow)
![Tailwind](https://img.shields.io/badge/TailwindCSS-3.x-38BDF8)
![Docker](https://img.shields.io/badge/docker-compose-2496ED)

**A production-style Security Operations Center (SOC) platform that ingests Windows event logs, detects multi-stage attacks, correlates events into attack chains, and delivers AI-driven incident analysis through a conversational security copilot.**

</div>

---

## Overview

This platform implements a full SIEM + SOAR-lite pipeline inspired by enterprise tools like Splunk, Microsoft Sentinel, and Microsoft Security Copilot — built entirely from scratch.

```
Windows Logs (Sysmon / Security Events)
              ↓
     NXLog (log shipper)
              ↓
  FastAPI Backend  ←  main.py
              ↓
     normalizer.py  →  models.py
              ↓
      detector.py  (rule engine)
              ↓
         db.py  →  Elasticsearch
              ↓
    graph_engine.py  (attack chains)
              ↓
      ai_engine.py  +  chat_engine.py
              ↓
    Next.js Dashboard  (soc-dashboard)
```

---

## Features

| Component | File | Description |
|---|---|---|
| **Log Ingestion** | `main.py` | FastAPI server — receives NXLog events via `POST /logs` |
| **Normalization** | `normalizer.py` | Parses raw Windows event JSON into a clean schema |
| **Data Models** | `models.py` | Pydantic models for logs, alerts, and chains |
| **Detection Engine** | `detector.py` | Rule-based threat detection on Windows Event IDs |
| **Database Layer** | `db.py` | Elasticsearch client — index, query, aggregate |
| **Attack Chain Correlation** | `graph_engine.py` | Correlates related alerts into multi-stage attack sequences |
| **AI Analysis** | `ai_engine.py` | GPT-4 powered incident explanation, severity, recommendations |
| **SOC Copilot** | `chat_engine.py` | Conversational chat interface over your live SOC data |
| **Dashboard** | `soc-dashboard/` | Next.js 14 + Tailwind — alerts, chains, AI panel, copilot |

---

## Detection Rules

| Rule ID | Event ID | Trigger | Severity |
|---|---|---|---|
| `BF-IP-001` | 4625 | Multiple failed login attempts (brute force) | High |
| `PE-001` | 4672 | Special privileges assigned to new logon | Critical |
| `SP-001` | 4688 | Suspicious process creation (cmd / powershell) | Medium |

### Attack Chain Example

A complete simulated attack produces this correlated chain:

```
[4625 × N]  brute_force
      ↓
[4672]  privilege_escalation
      ↓
[4688]  execution  (powershell.exe / cmd.exe)
```

---

## Project Structure

```
AI-Powered-SOC-Platform/
│
├── soc-backend/
│   ├── main.py                  # FastAPI app — all API routes
│   ├── normalizer.py            # Raw log → structured schema
│   ├── models.py                # Pydantic data models
│   ├── detector.py              # Detection rules engine
│   ├── graph_engine.py          # Alert correlation → attack chains
│   ├── ai_engine.py             # OpenAI integration + cache + rate limiting
│   ├── chat_engine.py           # SOC Copilot chat logic
│   ├── db.py                    # Elasticsearch client wrapper
│   ├── requirements.txt         # Python dependencies
│   └── venv/                    # Virtual environment (not committed)
│
├── soc-dashboard/               # Next.js 14 frontend
│   ├── app/                     # App router pages
│   ├── components/              # Reusable UI components
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

Services started:

| Service | Port | Description |
|---|---|---|
| Elasticsearch | `9200` | Log + alert + chain storage |
| SOC Backend | `8000` | FastAPI — detection, AI, chat |
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
| `GET` | `/alerts` | Fetch all detected alerts |
| `GET` | `/chains` | Fetch all correlated attack chains |
| `POST` | `/ai/analyze` | AI analysis of a specific attack chain |
| `POST` | `/chat` | SOC Copilot — conversational query endpoint |

### Example — POST /logs (raw Windows event)

```json
{
  "EventID": 4625,
  "SubjectUserName": "attacker",
  "WorkstationName": "DESKTOP-01",
  "IpAddress": "192.168.1.50",
  "TimeCreated": "2024-01-15T10:23:00Z"
}
```

### Example — normalized alert output

```json
{
  "rule_id": "BF-IP-001",
  "severity": "high",
  "type": "brute_force",
  "user": "attacker",
  "host": "DESKTOP-01",
  "source_ip": "192.168.1.50",
  "timestamp": "2024-01-15T10:23:00Z"
}
```

---

## Elasticsearch Indices

| Index | Contents |
|---|---|
| `soc-logs` | All normalized ingested log events |
| `soc-alerts` | Triggered detection rule alerts |
| `soc-chains` | Correlated multi-stage attack chains |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Log shipper | NXLog Community Edition |
| Backend API | FastAPI + Python 3.10+ |
| Data models | Pydantic v2 |
| Detection | Custom rules engine (`detector.py`) |
| Correlation | Python graph engine (`graph_engine.py`) |
| Storage | Elasticsearch 8.x |
| AI / LLM | OpenAI GPT-4 |
| Frontend | Next.js 14 + TypeScript + Tailwind CSS |
| Containerization | Docker Compose |

---

## Industry Equivalents

| This Project | Enterprise Tool |
|---|---|
| `detector.py` rules | Sigma Rules / Splunk SPL |
| Log ingestion + storage | Splunk SIEM / IBM QRadar |
| Alert correlation | Microsoft Sentinel |
| `ai_engine.py` + `chat_engine.py` | Microsoft Security Copilot |

---

## Roadmap

- [ ] MITRE ATT&CK framework mapping per alert
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
