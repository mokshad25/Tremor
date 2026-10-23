<p align="center">
  <h1 align="center">TREMOR</h1>
  <p align="center"><strong>Trend-aware Real-time Event Monitoring & Outlier Response</strong></p>
  <p align="center"><em>Feel the tremor before the quake.</em></p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.12-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-async-009688?logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/React-TypeScript-61DAFB?logo=react" alt="React">
  <img src="https://img.shields.io/badge/AWS-CloudWatch%20%7C%20SNS-FF9900?logo=amazonaws" alt="AWS">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
</p>

---

## What is TREMOR?

TREMOR is a production-grade **real-time log anomaly detector** with a live alert feed. It learns what "normal" looks like for each service, catches bursts, slow drifts, and silences early, and explains *why* with the offending log patterns.

### Five Differentiators

1. **🔍 Multi-signal detection** — Error rate, traffic silence, new/rare log patterns, latency shifts
2. **🧠 Root-cause hints** — `drain3` template mining shows *which* patterns drive anomalies
3. **📊 Alert lifecycle** — Dedup, cooldown, escalation, ack/silence, auto-resolution (not alert spam)
4. **📈 Evaluation harness** — Proves precision/recall/F1 vs naive baselines with reproducible scenarios
5. **🛡️ Explainability + baseline protection** — Every alert shows *why* it fired; baselines never absorb incidents

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/your-org/tremor.git && cd tremor

# 2. Create virtual environment
python -m venv .venv && .venv\Scripts\activate  # Windows
# python -m venv .venv && source .venv/bin/activate  # Linux/Mac

# 3. Install
pip install -e ".[dev]"

# 4. Configure
cp .env.example .env  # Edit as needed

# 5. Run
uvicorn app.main:create_app --factory --reload
```

### Docker (recommended)

```bash
cp .env.example .env
docker compose up --build
# App: http://localhost:8000
# Frontend: http://localhost:5173
# LocalStack: http://localhost:4566
```

---

## Infrastructure (AWS & Docker)

TREMOR is designed to run in Docker and integrate natively with AWS. 

### Local Development
To run locally with real AWS integration:
1. Ensure your AWS credentials are set in `.env` (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`).
2. Run `docker-compose up --build -d`.
3. The backend container automatically inherits your AWS credentials from `.env` and uses `boto3` to communicate with AWS.

### Production Deployment (Terraform)
We provide a complete Terraform module for production AWS infrastructure.
```bash
cd infra/terraform
terraform init
terraform apply -var="alert_email=you@example.com" -var="environment=prod"
```
**This provisions:**
- **SNS Topic & Subscription:** For email/SMS routing of `HIGH` and `CRITICAL` alerts.
- **CloudWatch Log Group (`/tremor/alerts`):** For structured JSON audit trails of all alerts.
- **IAM Role & Instance Profile:** Attach this profile to your EC2/ECS servers so TREMOR can authenticate without hardcoded keys.
- **CloudWatch Alarms:** Secondary safety nets for extreme error rates.

See the complete [Setup Guide](tremor_aws_docker_setup.md) (or artifact) for full details.

---

## Architecture

```
                 ┌────────────────────────── TREMOR (FastAPI) ──────────────────────────┐
                 │                                                                       │
 app.log ──────► │ Tailer ─► Parser ─► Template Miner ─► Window Engine ─► Baseline       │
                 │                                                   │                    │
                 │                  Detector Suite ◄─────────────────┘                    │
                 │   (error-rate · silence · new-pattern · latency)                       │
                 │                      │                                                 │
                 │          Alert Manager (dedup, severity, lifecycle)                     │
                 │       ┌──────────────┼──────────────┬──────────────┐                   │
                 │   SQLite/PG     WebSocket hub   CloudWatch     SNS                     │
                 └───────┼──────────────┼──────────────┼──────────────┼───────────────────┘
                         ▼              ▼              ▼              ▼
                    History API    React dashboard  Log group    Email/SMS
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

---

## Configuration

All settings are env-driven with sane defaults. See [`.env.example`](.env.example).

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_PATHS` | `./sample/app.log` | Comma-separated files to tail |
| `WINDOWS_S` | `10,60,300` | Window sizes in seconds |
| `WARMUP_TICKS` | `30` | Ticks (with >= `MIN_EVENTS` lines) that seed the baseline; no z-based alerts before |
| `Z_INFO / Z_WARN / Z_HIGH` | `3 / 5 / 8` | Severity z-score thresholds |
| `RATE_CEILING` | `0.5` | Hard critical ceiling |
| `CLEAR_Z / CLEAR_WINDOWS` | `2.0 / 10` | Resolve after 10 consecutive 1 s ticks below z 2 |
| `SILENCE_SECONDS` | `10` | No lines for this long opens a silence incident |
| `ALERT_COOLDOWN_S` | `60` | Re-open within this reuses the incident id |
| `DRY_RUN` | `false` | Skip real AWS calls |
| `DEMO_MODE` | `false` | Enable scenario injection |
| `DATABASE_URL` | `sqlite+aiosqlite:///./tremor.db` | Database connection |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `WS` | `/ws/alerts` | Live alert feed + metrics |
| `GET` | `/api/alerts` | Alert history (filterable) |
| `GET` | `/api/alerts/{id}` | Alert detail with timeline |
| `POST` | `/api/alerts/{id}/ack` | Acknowledge alert |
| `POST` | `/api/alerts/{id}/silence` | Silence for a duration |
| `GET` | `/api/metrics/current` | Current windows per service |
| `GET` | `/api/baseline` | Baseline state |
| `GET` | `/api/templates` | Top templates |
| `POST` | `/api/sim/inject` | Scenario injection (demo only) |
| `GET` | `/health` | Component health |
| `GET` | `/metrics` | Prometheus self-metrics |

---

## Evaluation Results

> Generated by `python -m eval.run --seed 42`

See [docs/EVAL.md](docs/EVAL.md) for full results.

_Results will be published after Phase 6._

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.12 |
| API | FastAPI + Uvicorn (fully async) |
| Config | pydantic-settings |
| Storage | SQLAlchemy 2.x async + SQLite/Postgres |
| AWS | boto3 + tenacity (retry/backoff) |
| Template Mining | drain3 |
| Stats | numpy |
| Logging | structlog (JSON) |
| Metrics | prometheus-client |
| Frontend | React + Vite + TypeScript |
| Tests | pytest, pytest-asyncio, hypothesis, moto |
| Quality | ruff, black, mypy --strict (core/) |
| Ops | Docker, docker-compose, GitHub Actions, Terraform |

---

## Development

```bash
# Run tests
pytest -v

# Lint
ruff check app/ tests/

# Format
black app/ tests/

# Type check (core/)
mypy app/core/ --strict

# Pre-commit hooks
pre-commit install
pre-commit run --all-files
```

---

## Project Structure

```
tremor/
├── app/
│   ├── main.py              # App factory, lifespan, routers
│   ├── config.py            # pydantic-settings
│   ├── clock.py             # Clock protocol (SystemClock, FakeClock)
│   ├── ingest/              # Tailer, parser, PII redaction
│   ├── core/                # Window engine, baseline, detectors, alerts
│   │   └── detectors/       # Error-rate, silence, new-pattern, latency
│   ├── sinks/               # CloudWatch, SNS, WebSocket, dry-run
│   ├── api/                 # REST routes, schemas, WS endpoint
│   └── db/                  # SQLAlchemy models, repository
├── simulator/               # Scenario-driven log generator
├── eval/                    # Evaluation harness
├── frontend/                # React + Vite + TypeScript
├── infra/terraform/         # AWS infrastructure
├── tests/                   # pytest suite
├── docs/                    # ARCHITECTURE, TRADEOFFS, EVAL
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## License

MIT

---

## Docs

- [Architecture](docs/ARCHITECTURE.md)
- [Detection Engine & Baselines](docs/DETECTION_ENGINE.md)
- [Tradeoffs & Decisions](docs/TRADEOFFS.md)
- [Evaluation Results](docs/EVAL.md)
