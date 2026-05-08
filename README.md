# AI-Powered SOC Platform

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js-14-000000?style=flat-square&logo=next.js&logoColor=white)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.x-005571?style=flat-square&logo=elasticsearch&logoColor=white)
![Tailwind CSS](https://img.shields.io/badge/Tailwind-CSS-06B6D4?style=flat-square&logo=tailwindcss&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

A production-grade Security Operations Center platform implementing a full **SIEM + SOAR pipeline** — ingesting Windows Security and Sysmon telemetry, performing rule-based and behavior-based threat detection, mapping adversary behavior to the MITRE ATT&CK framework, correlating events into multi-stage attack chains, enriching alerts with live threat intelligence, executing automated SOAR playbooks, and delivering AI-assisted analysis through a structured SOC dashboard and conversational security copilot.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Platform Capabilities](#platform-capabilities)
- [Detection Engineering](#detection-engineering)
- [MITRE ATT&CK Integration](#mitre-attck-integration)
- [SOAR Automation Engine](#soar-automation-engine)
- [CTI Enrichment](#cti-enrichment)
- [AI Decision Engine & SOC Copilot](#ai-decision-engine--soc-copilot)
- [Attack Chain Correlation](#attack-chain-correlation)
- [Verified Attack Simulations](#verified-attack-simulations)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Running Locally](#running-locally-without-docker)
- [API Reference](#api-reference)
- [Elasticsearch Indices](#elasticsearch-indices)
- [Tech Stack](#tech-stack)
- [Industry Equivalents](#industry-equivalents)
- [Roadmap](#roadmap)
- [Screenshots](#screenshots)

---

## Overview

This platform is a ground-up implementation of an enterprise SOC pipeline, architecturally comparable to tools like **Splunk SIEM**, **Microsoft Sentinel**, and **Microsoft Security Copilot** — built entirely with open-source components and purpose-built detection engineering.

It covers the full incident lifecycle: telemetry ingestion → normalization → detection → MITRE mapping → CTI enrichment → alert deduplication → attack chain correlation → SOAR playbook execution → AI-assisted analysis → real-time dashboard visualization.

### v2.0 Feature Delta

| Capability | v1.0 | v2.0 |
|---|---|---|
| Detection | Rule-based (static Event IDs) | Rule-based + behavior anomaly + LOLBin detection |
| Threat Intelligence | None | MITRE ATT&CK tactic + technique mapping on every alert |
| CTI Enrichment | None | Abuse score, ISP attribution, country, threat pulses, campaign correlation |
| AI Output | Incident explanation | Risk score, attack stage, response actions, containment priority |
| SOAR | None | Automated playbook execution per rule ID |
| Alert Quality | Raw, unfiltered | Deduplicated with cooldown suppression |
| Dashboard | Basic alert list | Structured alerts with tactic, technique, SOAR actions, chain view, CTI panel |
| Pipeline | Logs → Detection → AI → UI | Logs → Detection → Dedup → MITRE → CTI → SOAR → Correlation → AI → UI |

---

## Architecture

```
Windows Security Events + Sysmon Telemetry
                    │
              NXLog (log shipper)
                    │
          ┌─────────▼─────────┐
          │   FastAPI Backend  │  ◄── main.py
          └─────────┬─────────┘
                    │
          ┌─────────▼─────────┐
          │   normalizer.py   │  Raw event → structured schema
          └─────────┬─────────┘
                    │
          ┌─────────▼─────────┐
          │    detector.py    │  Rule engine + behavior engine + LOLBin rules
          └─────────┬─────────┘
                    │
          ┌─────────▼─────────┐
          │  mitre_mapper.py  │  ATT&CK tactic + technique + ID enrichment
          └─────────┬─────────┘
                    │
          ┌─────────▼─────────┐
          │  dedup_engine.py  │  Alert deduplication + cooldown suppression
          └─────────┬─────────┘
                    │
          ┌─────────▼─────────┐
          │   soar_engine.py  │  Automated playbook execution per rule ID
          └─────────┬─────────┘
                    │
          ┌─────────▼─────────┐
          │   cti_enricher    │  Abuse score, ISP, country, threat pulses
          └─────────┬─────────┘
                    │
          ┌─────────▼─────────┐
          │      db.py        │  Elasticsearch — index, query, aggregate
          └─────────┬─────────┘
                    │
          ┌─────────▼─────────┐
          │  graph_engine.py  │  Attack chain correlation
          └─────────┬─────────┘
                    │
          ┌─────────▼─────────┐
          │   ai_engine.py    │  Gemini — risk score, response actions, priority
          │  chat_engine.py   │  SOC Copilot — conversational threat hunting
          └─────────┬─────────┘
                    │
          ┌─────────▼─────────┐
          │  Next.js Dashboard │  Alerts · Chains · MITRE · CTI · SOAR · Copilot
          └───────────────────┘
```

---

## Platform Capabilities

| Component | File | Description |
|---|---|---|
| Log Ingestion | `main.py` | FastAPI server — receives NXLog events via `POST /logs` |
| Normalization | `normalizer.py` | Parses raw Windows event JSON into a clean, typed schema |
| Data Models | `models.py` | Pydantic v2 models for logs, alerts, chains, MITRE fields, SOAR actions |
| Detection Engine | `detector.py` | Rule-based + behavior-based + LOLBin detection |
| MITRE Mapping | `mitre_mapper.py` | Maps every alert to ATT&CK tactic, technique, and technique ID |
| Deduplication | `dedup_engine.py` | Alert dedup with per-rule cooldown windows — suppresses alert floods |
| SOAR Engine | `soar_engine.py` | Automated playbook execution triggered per rule ID |
| CTI Enrichment | `cti_enricher.py` | Enriches source IPs with abuse score, ISP, country, threat pulses |
| Database Layer | `db.py` | Elasticsearch client — index, query, aggregate |
| Attack Chain Correlation | `graph_engine.py` | Correlates related alerts into multi-stage attack sequences |
| AI Decision Engine | `ai_engine.py` | Gemini-powered risk scoring, recommended actions, containment priority |
| SOC Copilot | `chat_engine.py` | Conversational interface for live threat hunting over SOC data |
| Dashboard | `soc-dashboard/` | Next.js 14 + Tailwind — alerts, chains, MITRE view, CTI panel, SOAR panel, copilot |

---

## Detection Engineering

### Static Rules — Event ID Based

| Rule ID | Event Source | Event ID | Trigger | Severity | MITRE Tactic | Technique ID |
|---|---|---|---|---|---|---|
| BF-IP-001 | Windows Security | 4625 | Multiple failed logins from same IP (brute force) | High | Credential Access | T1110 |
| BF-USR-001 | Windows Security | 4625 | Multiple failed logins against same user account | High | Credential Access | T1110 |
| PE-001 | Windows Security | 4672 | Special privileges assigned to new logon | Critical | Privilege Escalation | T1078 |
| SP-001 | Windows Security | 4688 | Suspicious process creation — cmd.exe / powershell.exe | Medium | Execution | T1059 |

### Behavior Rules — Dynamic Anomaly Detection

| Rule ID | Event Source | Trigger | Severity | MITRE Tactic | Technique ID |
|---|---|---|---|---|---|
| EB-001 | Windows Security | Execution burst — high process creation rate per host within sliding window | High | Execution | T1059 |

The execution burst rule uses an **in-memory sliding window** to track process creation events per host. When the count exceeds threshold `T` within window `W` seconds, an `execution_burst` alert fires — consistent with script-based attacks, malware dropper activity, and lateral movement toolkit execution.

### LOLBin Detection — Sysmon Event ID 1

The platform detects abuse of native Windows binaries (Living off the Land Binaries) via Sysmon process creation telemetry:

| Binary | Common Abuse |
|---|---|
| `mshta.exe` | HTA-based payload execution, VBScript/JScript dropper |
| `rundll32.exe` | DLL sideloading, in-memory payload execution |
| `powershell.exe` | Encoded command execution, download cradles, AMSI bypass |

Suspicious command-line arguments are evaluated at parse time. Matches generate structured alerts with full MITRE context attached.

### Alert Deduplication

A dedicated deduplication engine suppresses alert floods using per-rule cooldown windows. Repeated triggering of the same rule against the same host/user within the cooldown period generates a single deduplicated alert rather than unbounded alert volume — a critical requirement for operational SOC usability.

---

## MITRE ATT&CK Integration

Every alert generated by the detection engine is automatically enriched with the corresponding MITRE ATT&CK context:

| Field | Example |
|---|---|
| `mitre_tactic` | Credential Access |
| `mitre_technique` | Brute Force |
| `mitre_technique_id` | T1110 |

This mapping is performed in `mitre_mapper.py` at detection time and persisted alongside the alert in Elasticsearch. The dashboard renders tactic and technique as structured badge components for rapid analyst triage.

Full mapping table:

| Alert Type | Tactic | Technique | Technique ID |
|---|---|---|---|
| `brute_force` | Credential Access | Brute Force | T1110 |
| `privilege_escalation` | Privilege Escalation | Valid Accounts | T1078 |
| `execution` / `lolbin` | Execution | Command & Scripting Interpreter | T1059 |
| `execution_burst` | Execution | Command & Scripting Interpreter | T1059 |

---

## SOAR Automation Engine

The platform includes an automated Security Orchestration, Automation, and Response engine implemented in `soar_engine.py`. On alert generation, the engine looks up the triggering rule ID, selects the associated playbook, and executes each action in sequence. Action results are attached to the alert record and rendered on the dashboard.

### Playbook Registry

| Rule ID | Trigger | Automated Actions |
|---|---|---|
| BF-IP-001 | Brute force from IP | `block_ip` → `create_ticket` → `notify_soc` |
| BF-USR-001 | Brute force against user | `block_ip` → `create_ticket` → `notify_soc` |
| SP-001 | Suspicious process creation | `isolate_host` → `kill_process` → `notify_ir_team` |
| PE-001 | Privilege escalation | `disable_account` → `escalate_priority` → `notify_soc` |

Each action produces a structured result object that records the action name, execution status, and timestamp. The dashboard's SOAR panel surfaces these results per alert, giving analysts full visibility into what automated response steps have already been taken before manual investigation begins.

---

## CTI Enrichment

Source IP addresses in alerts are enriched with live threat intelligence context at ingestion time:

| Enrichment Field | Description |
|---|---|
| Abuse Confidence Score | Numeric confidence that the IP is malicious (0–100) |
| ISP Attribution | Internet service provider associated with the source IP |
| Country | Geolocation of the source IP |
| Threat Pulses | Known threat intelligence pulses linked to this IP |
| Suspicious Verdict | Boolean classification based on enrichment signals |
| Attack Campaign Correlation | Known campaign associations from threat intelligence feeds |

Enrichment data is stored alongside the alert in Elasticsearch and rendered in a dedicated CTI panel in the dashboard, enabling analysts to immediately assess whether a source IP has prior malicious history without pivoting to an external tool.

---

## AI Decision Engine & SOC Copilot

### Decision Engine (`ai_engine.py`)

For each correlated attack chain, the AI Decision Engine produces a structured intelligence report powered by the Gemini API. The engine is not a general-purpose explainer — it is prompted as a SOC decision engine and returns actionable operational output:

| Output Field | Description |
|---|---|
| `threat_summary` | Concise description of the active threat and why it is significant |
| `risk_score` | Integer severity score (1–10) with justification |
| `attack_stage` | Position in the kill chain (e.g., Post-Exploitation, Lateral Movement) |
| `containment_priority` | Operational urgency: Immediate / High / Medium / Monitor |
| `recommended_actions` | Prioritized SOC playbook steps for the specific chain |

Example output for a credential compromise + execution chain:

```json
{
  "threat_summary": "Full credential compromise and execution chain detected on DESKTOP-01. Brute force led to privilege escalation followed by PowerShell execution — consistent with post-compromise payload delivery.",
  "risk_score": 9,
  "attack_stage": "Post-Exploitation",
  "containment_priority": "Immediate",
  "recommended_actions": [
    "Isolate DESKTOP-01 from the network immediately",
    "Reset credentials for all affected user accounts",
    "Review PowerShell execution logs for encoded command indicators",
    "Scan adjacent hosts for lateral movement artifacts"
  ]
}
```

### SOC Copilot (`chat_engine.py`)

The SOC Copilot provides a conversational natural language interface over live SOC data. Analysts can query the platform in plain English without constructing queries manually.

Supported workflows:

- Live attack summaries across active alerts and chains
- Threat prioritization — which chains require immediate action
- Chain-level analysis — explain a specific attack sequence
- Remediation guidance for individual alert types
- Conversational threat hunting — investigate hypotheses against ingested data

---

## Attack Chain Correlation

The graph engine (`graph_engine.py`) correlates individually detected alerts into multi-stage attack sequences by tracking shared host, user, or source IP relationships across time windows. Each chain represents a coherent adversary action sequence mapped to the kill chain.

### Example Chain — Credential Compromise + Execution

```
[Event 4625 × N]  →  brute_force
                      Tactic: Credential Access | T1110
                      SOAR: block_ip, create_ticket, notify_soc
         │
         ▼
[Event 4672]      →  privilege_escalation
                      Tactic: Privilege Escalation | T1078
                      SOAR: disable_account, escalate_priority, notify_soc
         │
         ▼
[Event 4688]      →  execution (powershell.exe)
                      Tactic: Execution | T1059
                      SOAR: isolate_host, kill_process, notify_ir_team
```

The full chain is submitted to the AI Decision Engine for risk scoring and response recommendations. The dashboard's chain view renders each stage with its MITRE tactic, technique ID, severity, and SOAR action results.

---

## Verified Attack Simulations

The platform has been end-to-end tested against the following attack scenarios with verified detection, chain generation, and SOAR playbook execution:

| Simulation | Detection Fired | Chain Generated | SOAR Executed |
|---|---|---|---|
| Brute force (repeated Event 4625) | BF-IP-001, BF-USR-001 | Yes | block_ip, create_ticket, notify_soc |
| Privilege escalation (Event 4672) | PE-001 | Yes | disable_account, escalate_priority, notify_soc |
| PowerShell execution (Event 4688) | SP-001 | Yes | isolate_host, kill_process, notify_ir_team |
| LOLBin execution via Sysmon (mshta, rundll32) | LOLBin rules | Yes | notify_ir_team |
| Execution burst anomaly (high process rate) | EB-001 | Yes | — |
| Full kill chain (brute force → escalation → execution) | Multiple | Multi-stage chain | Full playbook sequence |

---

## Project Structure

```
AI-Powered-SOC-Platform/
│
├── soc-backend/
│   ├── main.py                  # FastAPI application — all API routes
│   ├── normalizer.py            # Raw Windows event → structured alert schema
│   ├── models.py                # Pydantic v2 models — logs, alerts, chains, MITRE, SOAR
│   ├── detector.py              # Rule-based + behavior-based + LOLBin detection engine
│   ├── mitre_mapper.py          # MITRE ATT&CK tactic, technique, and ID enrichment
│   ├── dedup_engine.py          # Alert deduplication + per-rule cooldown suppression
│   ├── soar_engine.py           # SOAR automation — playbook registry + execution engine
│   ├── cti_enricher.py          # CTI enrichment — abuse score, ISP, country, pulses
│   ├── graph_engine.py          # Alert correlation → multi-stage attack chain generation
│   ├── ai_engine.py             # Gemini-powered AI Decision Engine
│   ├── chat_engine.py           # SOC Copilot conversational threat hunting interface
│   ├── db.py                    # Elasticsearch client wrapper
│   ├── requirements.txt         # Python dependencies
│   └── venv/                    # Virtual environment (not committed)
│
├── soc-dashboard/               # Next.js 14 frontend
│   ├── app/                     # App router pages
│   ├── components/
│   │   ├── AlertsTable.tsx      # Alert cards with tactic badge, technique, SOAR actions
│   │   ├── ChainsPanel.tsx      # Multi-stage attack chain visualization
│   │   ├── CTIPanel.tsx         # Threat intelligence enrichment view
│   │   ├── AIPanel.tsx          # AI Decision Engine structured output
│   │   └── Copilot.tsx          # SOC Copilot chat interface
│   ├── lib/                     # API helpers and utility functions
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
└── LICENSE                      # MIT License
```

---

## Quick Start

### Prerequisites

- Docker and Docker Compose
- NXLog Community Edition installed on the target Windows machine
- Gemini API key

### 1. Clone the Repository

```bash
git clone https://github.com/cyber-rishabh/AI-Powered-SOC-Platform.git
cd AI-Powered-SOC-Platform
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env and set GEMINI_API_KEY and any other required values
```

### 3. Start the Full Stack

```bash
docker-compose up -d
```

| Service | Port | Description |
|---|---|---|
| Elasticsearch | 9200 | Log, alert, and chain storage |
| SOC Backend | 8000 | FastAPI — detection, MITRE, CTI, SOAR, AI, chat |
| SOC Dashboard | 3000 | Next.js frontend |

### 4. Configure NXLog (Windows Target)

Copy `nxlog/nxlog.conf` to your NXLog configuration directory and set the backend address:

```
define BACKEND_HOST  <your-backend-ip>
define BACKEND_PORT  8000
```

Restart the NXLog service. Events will begin shipping to the backend immediately.

### 5. Open the Dashboard

```
http://localhost:3000
```

---

## Running Locally (Without Docker)

### Backend

```bash
cd soc-backend
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

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

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/logs` | Receive raw Windows event logs from NXLog |
| `GET` | `/alerts` | Retrieve all detected alerts with MITRE and CTI fields |
| `GET` | `/chains` | Retrieve all correlated attack chains |
| `POST` | `/ai/analyze` | Submit a chain to the AI Decision Engine |
| `POST` | `/chat` | SOC Copilot conversational query endpoint |

### Example — `POST /logs`

```json
{
  "EventID": 4625,
  "SubjectUserName": "attacker",
  "WorkstationName": "DESKTOP-01",
  "IpAddress": "192.168.1.50",
  "TimeCreated": "2024-01-15T10:23:00Z"
}
```

### Example — Normalized Alert (v2.0)

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
  "mitre_technique_id": "T1110",
  "cti": {
    "abuse_confidence_score": 87,
    "isp": "DigitalOcean LLC",
    "country": "NL",
    "is_suspicious": true,
    "threat_pulses": ["Brute Force Botnet", "Known SSH Scanner"]
  },
  "soar_actions": [
    { "action": "block_ip", "status": "executed", "timestamp": "2024-01-15T10:23:01Z" },
    { "action": "create_ticket", "status": "executed", "timestamp": "2024-01-15T10:23:01Z" },
    { "action": "notify_soc", "status": "executed", "timestamp": "2024-01-15T10:23:02Z" }
  ]
}
```

### Example — AI Decision Engine Output (v2.0)

```json
{
  "threat_summary": "Full credential compromise and execution chain detected on DESKTOP-01",
  "risk_score": 9,
  "attack_stage": "Post-Exploitation",
  "containment_priority": "Immediate",
  "recommended_actions": [
    "Isolate DESKTOP-01 from the network immediately",
    "Reset credentials for all affected user accounts",
    "Review PowerShell execution logs for encoded command indicators",
    "Scan adjacent hosts for lateral movement artifacts"
  ]
}
```

---

## Elasticsearch Indices

| Index | Contents |
|---|---|
| `soc-logs` | All normalized, ingested log events |
| `soc-alerts` | Triggered alerts — includes MITRE tactic, technique, CTI enrichment, and SOAR action fields |
| `soc-chains` | Correlated multi-stage attack chains with AI Decision Engine output |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Log Shipper | NXLog Community Edition |
| Telemetry Source | Windows Security Events + Sysmon |
| Backend API | FastAPI + Python 3.10+ |
| Data Models | Pydantic v2 |
| Detection | Custom rule engine + behavior anomaly engine + LOLBin detection |
| Deduplication | Custom cooldown suppression engine |
| Threat Intelligence | MITRE ATT&CK framework (`mitre_mapper.py`) |
| CTI Enrichment | IP reputation and threat pulse enrichment (`cti_enricher.py`) |
| SOAR Automation | Custom playbook engine (`soar_engine.py`) |
| Correlation | Python graph engine (`graph_engine.py`) |
| Storage | Elasticsearch 8.x |
| AI / LLM | Google Gemini API |
| Frontend | Next.js 14 + TypeScript + Tailwind CSS |
| Containerization | Docker Compose |

---

## Industry Equivalents

| This Platform | Enterprise Tool |
|---|---|
| `detector.py` static rules | Sigma Rules / Splunk SPL detection rules |
| `detector.py` behavior rules | Darktrace / CrowdStrike Falcon anomaly detection |
| `mitre_mapper.py` | MITRE ATT&CK Navigator |
| `soar_engine.py` | Splunk SOAR / Palo Alto XSOAR |
| `cti_enricher.py` | Recorded Future / VirusTotal enrichment |
| Log ingestion + Elasticsearch | Splunk SIEM / IBM QRadar |
| `graph_engine.py` | Microsoft Sentinel alert correlation |
| `ai_engine.py` + `chat_engine.py` | Microsoft Security Copilot |
| `dedup_engine.py` | Splunk alert suppression / aggregation policies |

---

## Roadmap

### Implemented

- [x] Rule-based detection engine (static Event ID rules)
- [x] Behavior-based anomaly detection (execution burst, sliding window)
- [x] LOLBin detection via Sysmon Event ID 1
- [x] Multi-stage attack chain correlation
- [x] MITRE ATT&CK tactic + technique mapping
- [x] Alert deduplication + cooldown suppression
- [x] SOAR automation engine with per-rule playbooks
- [x] CTI enrichment — abuse score, ISP, country, threat pulses
- [x] AI Decision Engine — Gemini-powered risk scoring + response actions
- [x] SOC Copilot — conversational threat hunting interface
- [x] Advanced dashboard — tactic badges, technique IDs, SOAR panel, CTI panel, chain view

### Planned

- [ ] ML-based anomaly detection (Isolation Forest / Autoencoder)
- [ ] Lateral movement detection across multiple hosts
- [ ] User and Entity Behavior Analytics (UEBA)
- [ ] Automated response playbook execution via real integrations (firewall, EDR)
- [ ] Slack / email alerting integration
- [ ] Custom detection rule builder in dashboard UI
- [ ] Threat hunting query builder with Elasticsearch DSL

---

## Screenshots

See the `photos/` directory for full dashboard screenshots including:

- Structured alert table with MITRE tactic/technique badges, severity, CTI verdict, and SOAR action status
- Multi-stage attack chain view with kill chain progression and MITRE context at each node
- AI Decision Engine panel with risk score, attack stage, containment priority, and recommended actions
- SOC Copilot conversational interface with live data query output
- CTI enrichment panel with abuse score, ISP attribution, country, and threat pulse associations

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
