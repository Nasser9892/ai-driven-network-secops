# SOC Dashboard

Web interface for the AI-driven SecOps platform. Runs on a dedicated
`secops-dashboard` instance (t3.medium) to isolate the chat/UI workload from
Ollama + n8n on `secops-management`.

## Architecture

## Components

| Layer | Tech | Location |
|---|---|---|
| Frontend | React (Vite build) | `frontend/` |
| Backend | FastAPI + Uvicorn | `backend/main.py` |
| Database | SQLite | `backend/data.db` (3 tables: alerts, chat_history, audit_log) |
| Web server | nginx + self-signed TLS | port 443 |
| LLM | Ollama / Llama-3.1-8B | proxied to secops-management |
| Alert sync | Python daemon on secops-detection | `backend/sync_alerts_to_dashboard.py` |

## Services (systemd)

| Instance | Service | Purpose |
|---|---|---|
| secops-dashboard | `secops-dashboard-api` | FastAPI backend on :8000 |
| secops-detection | `secops-alert-sync` | Tails alerts.json → POST /ingest-alert |

## Alert Sync Flow

`live_detection.py` (detection) writes alerts to
`~/secops/logs/alerts.json` (one JSON object per line). `sync_alerts_to_dashboard.py`
tails new lines, maps fields (`mitre`→`mitre_technique`, `severity`→`risk_level`,
builds `evidence` from conn stats), and POSTs each to the dashboard's
`/ingest-alert`. State is tracked in `.sync_state` to avoid re-sending.

## Security

- All ingress restricted to admin IP (`dashboard_sg`), except port 8000 open to
  VPC CIDR `10.0.0.0/16` for the internal alert-sync POST.
- Ollama is reached over the private VPC IP only — never exposed publicly.
- Self-signed TLS for demo; production should use ACM + ALB.

## Known limitations
- Chat currently sends raw prompts to Llama with no system prompt or live
  network context (planned enhancement: inject recent alerts + SOC-assistant
  system prompt).
