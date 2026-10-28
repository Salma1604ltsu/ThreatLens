# ThreatLens
### Security Operations & Threat Investigation Platform

ThreatLens is an educational defensive security monitoring MVP that demonstrates event ingestion, simple rule-based detection, alert triage, and incident tracking through a FastAPI application and responsive dashboard.

> **Scope and safety:** This is a lab/portfolio prototype, not a production SIEM. It uses synthetic events and documentation-only example IP addresses. It does not inspect live traffic or prove a host is compromised. Authentication and authorization are not implemented. Run it locally in a trusted lab; do not expose it to the public internet.

## Features
- FastAPI REST API and interactive OpenAPI docs
- SQLite persistence for events, alerts, and incidents
- Transparent example rules for repeated failed logins, supplied port-scan indicators, and suspicious request indicators
- Alert status workflow and incident creation
- Responsive security dashboard with summary metrics
- Synthetic demonstration data and pytest tests
- Docker packaging and GitHub Actions test workflow

## Technology stack
Python 3.12, FastAPI, Pydantic, SQLite, HTML/CSS/JavaScript, pytest, Docker, GitHub Actions.

## Run locally
```bash
python -m venv .venv
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000 for the dashboard and http://127.0.0.1:8000/docs for API documentation. Click **Load demo data** to create synthetic events.

## API endpoints
| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Health check |
| GET | `/api/summary` | Dashboard counters |
| POST | `/api/events` | Store and evaluate one event |
| POST | `/api/demo/seed` | Add synthetic demo events |
| GET | `/api/alerts` | List alerts |
| PATCH | `/api/alerts/{id}?status=investigating` | Update alert status |
| POST | `/api/alerts/{id}/incidents` | Create an incident from an alert |
| GET | `/api/incidents` | List incidents |

## Run tests
```bash
pytest -q
```
The starter test suite checks the health endpoint, the example repeated-failed-login rule, and invalid alert-status handling.

## Detection limitations
- Repeated failed-login detection is a simple count-based demonstration, not a calibrated detector.
- Port-scan and suspicious-request alerts are generated only when an ingested event already carries the corresponding event type. The application does not scan networks or inspect packets.
- Example IP addresses are from documentation-reserved TEST-NET ranges.
- Authentication, role-based access control, production audit logging, robust retention controls, and deployment hardening are not implemented.

## Roadmap
- [ ] Add authentication and role-based access control
- [ ] Improve time-window aggregation and event normalization
- [ ] Map detections to MITRE ATT&CK with sourced references
- [ ] Add validated CSV/JSON log upload with size limits
- [ ] Add incident notes, evidence references, and closure reasons
- [ ] Expand detection tests and evaluate false positives on labelled data
- [ ] Add screenshots and a short demo video
- [ ] Harden deployment and secrets management before any real deployment

## Resume description
**ThreatLens | Security Operations & Threat Investigation Platform**  
Built a FastAPI-based security monitoring prototype that ingests synthetic events, applies explainable example detection rules, generates alerts, and supports incident tracking through a responsive dashboard. Added SQLite persistence, REST API documentation, automated tests, and Docker packaging.

Only claim features you have personally run and verified. ThreatLens is an educational MVP, not a production security product.
