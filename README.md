<p align="center">
  <h1 align="center">TREMOR</h1>
  <p align="center"><strong>Trend-aware Real-time Event Monitoring & Outlier Response</strong></p>
  <p align="center"><em>Feel the tremor before the quake.</em></p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.12-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-async-009688?logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/Go-1.26-00ADD8?logo=go" alt="Go">
  <img src="https://img.shields.io/badge/React-TypeScript-61DAFB?logo=react" alt="React">
  <img src="https://img.shields.io/badge/AWS-CloudWatch%20%7C%20SNS-FF9900?logo=amazonaws" alt="AWS">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
</p>

---

## What is TREMOR?

TREMOR is a **real-time log anomaly detector** with a live alert feed. It learns what "normal" looks like for each service, catches bursts, slow drifts, and silences early, and explains *why* with the offending log patterns.

### Five Differentiators

1. **🔍 Multi-signal detection** — Error rate, traffic silence, new/rare log patterns, latency shifts
2. **🧠 Root-cause hints** — `drain3` template mining shows *which* patterns drive anomalies
3. **📊 Alert lifecycle** — Dedup, cooldown, escalation, ack/silence, auto-resolution (not alert spam)
4. **📈 Evaluation harness** — Proves precision/recall/F1 vs naive baselines with reproducible scenarios
5. **🛡️ Explainability + baseline protection** — Every alert shows *why* it fired; baselines never absorb incidents

### Two implementations in one repo

| Part | Path | What it is |
|------|------|-----------|
| **Python app** | `app/`, `frontend/`, `simulator/`, `eval/` | FastAPI backend that tails a log file, detects anomalies and streams alerts to a React dashboard. **Start here.** |
| **Go pipeline** | `go/` | High-throughput ingest service (HTTP + OpenTelemetry), PII redaction, write-ahead log, Prometheus/Grafana stack. See [go/README.md](go/README.md). |

---

## Prerequisites

| Tool | Version | Needed for |
|------|---------|-----------|
| Python | **3.12+** | Backend, simulator, eval, tests |
| Node.js | **22.13+** or **24** | React dashboard |
| Docker + Docker Compose v2 | any recent | Optional: container run, Go dashboard stack |
| Go | **1.26+** | Optional: Go pipeline in `go/` |

Check what you have:

```bash
python3 --version
node --version
docker compose version
go version
```

---

## Run TREMOR locally (recommended)

You will use **three terminals**: one for the backend, one to generate logs, one for the dashboard. All commands are run from the repository root unless a `cd` is shown.

> macOS/Linux commands are shown. On Windows, activate the virtual environment with `.venv\Scripts\activate` instead of `source .venv/bin/activate`; everything else is the same.

### 1. Clone the repository

```bash
git clone https://github.com/mokshad25/Tremor.git
cd Tremor
```

### 2. Create a virtual environment and install

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
```

### 3. Create your configuration

```bash
cp .env.example .env
```

The defaults work as-is: no AWS account is needed, and alerts go to the dashboard and the local SQLite database (`tremor.db`). Set `DRY_RUN=true` in `.env` if you want to guarantee no AWS calls are ever made. Never commit `.env`; it is git-ignored.

### 4. Terminal 1 — start the backend

```bash
source .venv/bin/activate
touch sample/app.log
uvicorn app.main:create_app --factory --reload
```

The API is now on **http://localhost:8000**. Check it from another terminal:

```bash
curl http://localhost:8000/health
```

You should see `"status":"healthy"`. Interactive API docs: http://localhost:8000/docs

### 5. Terminal 2 — generate logs

The backend tails `sample/app.log`. The simulator writes realistic multi-service logs into that file, with an incident injected part-way through:

```bash
source .venv/bin/activate
python -m simulator.gen_logs --scenario burst --speed 10
```

`--speed 10` plays 15 virtual minutes in about 90 seconds. The detector needs about 30 seconds of traffic to learn a baseline before it can alert. Available scenarios:

`steady`, `burst`, `drift`, `latency_spike`, `malformed_flood`, `new_pattern`, `noisy_normal`, `outage`, `rotation`, `silence`

Run another scenario at any time with the same command and a different `--scenario`.

### 6. Terminal 3 — start the dashboard

```bash
cd frontend
npm ci
npm run dev
```

Open **http://localhost:5173/dashboard**. The live chart, incident feed and alert drawer update over a WebSocket to the backend.

> The dashboard connects to `ws://localhost:8000/ws/alerts`, so the backend must be running on port **8000**.

### 7. Look at the results

```bash
curl http://localhost:8000/api/alerts
curl http://localhost:8000/api/metrics/current
curl http://localhost:8000/api/templates
```

After a `burst` run you should see `payment-gateway` `ERROR_RATE` alerts escalate (INFO → WARNING → HIGH) and then resolve.

### Stop everything

Press `Ctrl+C` in each terminal, then `deactivate` to leave the virtual environment.

---

## Run the backend with Docker

```bash
cp .env.example .env
docker compose up --build app
```

- Backend: http://localhost:8000 (check with `curl http://localhost:8000/health`)
- The container tails `./sample/app.log` from your machine, so generate logs from the host with the simulator (step 5 above), and run the dashboard with `npm run dev` (step 6).
- Stop with `Ctrl+C`, then `docker compose down` (add `-v` to also delete the stored alert database).

> Run `docker compose up --build app`, not a bare `docker compose up`: the `frontend` service in `docker-compose.yml` expects a `frontend/Dockerfile` that does not exist yet, so building it fails.

---

## Run the Go pipeline (optional)

```bash
cd go
make build
TREMOR_HMAC_KEY=$(openssl rand -hex 32) make run
```

This starts the ingest service:

| Port | Purpose |
|------|---------|
| `:8080` | `POST /ingest` (JSON events) |
| `:4318` / `:4317` | OpenTelemetry logs (OTLP/HTTP and gRPC) |
| `:2112` | Prometheus `/metrics` |
| `127.0.0.1:6060` | `/debug/vars` stats |

In another terminal, send an event and read the counters:

```bash
curl -s -XPOST localhost:8080/ingest -H 'Content-Type: application/json' \
  -d '{"events":[{"service":"auth-service","level":"warn","message":"Login failed user=alice"}]}'
curl -s 127.0.0.1:6060/debug/vars
```

The username is stored redacted (`usr_<hmac>`), never in plain text. More Go commands, from inside `go/`:

```bash
make check     # go vet, gofmt, race-enabled tests
make loadgen   # 20k events/s across 10 services for 30 s (server must be running)
go run ./cmd/eval             # replay the 10 labelled scenarios
go run ./cmd/eval -security   # attack simulator: detection rate and false alarms
```

**Ports already in use?** Override any address with an environment variable, for example:

```bash
TREMOR_HMAC_KEY=$(openssl rand -hex 32) TREMOR_LISTEN_ADDR=:18080 make run
```

(also `TREMOR_DEBUG_ADDR`, `TREMOR_METRICS_ADDR`, `TREMOR_OTLP_HTTP_ADDR`, `TREMOR_OTLP_GRPC_ADDR`).

**Grafana dashboard stack** (TREMOR + Prometheus + Grafana + demo load):

```bash
cd go/deploy
docker compose up -d
open http://localhost:3000/d/tremor     # Linux: xdg-open; use GRAFANA_PORT=3001 if 3000 is taken
docker compose down -v
```

Full details: [go/README.md](go/README.md).

---

## Tests and checks

The same checks run in CI on every push and pull request to `main`.

```bash
# Python (from the repo root, with the venv active)
pytest -v
ruff check app/ tests/ simulator/ eval/
black --check app/ tests/ simulator/ eval/
mypy app/core/ --strict

# Frontend
cd frontend
npm ci
npm run lint
npm run build
cd ..

# Go
cd go
make check
cd ..
```

Optional pre-commit hooks:

```bash
pre-commit install
pre-commit run --all-files
```

---

## Evaluation

Replay all labelled scenarios against TREMOR and two naive baselines (static threshold, rolling mean), and write the report to [docs/EVAL.md](docs/EVAL.md):

```bash
python -m eval.run --seed 42
```

Print a single scenario without writing the file:

```bash
python -m eval.run --seed 42 --scenario burst --no-write
```

Step through a burst tick by tick to see how severity escalates:

```bash
python -m scripts.burst_sim
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Address already in use` on port 8000 | Another app uses 8000. Stop it, or run `uvicorn ... --port 8001`, but note the dashboard expects 8000. Find the process with `lsof -i :8000`. |
| Dashboard shows zeros / no services | Logs aren't flowing. Keep the backend running and start the simulator (step 5); wait ~30 s for the baseline to warm up. |
| `python3.12: command not found` | Install Python 3.12+ (macOS: `brew install python@3.12`), or use any `python3` that reports 3.12 or newer. |
| `npm ci` fails | Check `node --version` is 22.13+ or 24. |
| Docker build fails on `frontend` | Use `docker compose up --build app` (see the Docker section). |

---

## Configuration

All settings are environment variables with sane defaults. See [`.env.example`](.env.example) for the full list.

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_PATHS` | `./sample/app.log` | Comma-separated files to tail |
| `TAIL_START` | `end` | `end` follows new lines; `beginning` replays the whole file |
| `WINDOWS_S` | `10,60,300` | Window sizes in seconds |
| `WARMUP_TICKS` | `30` | Ticks (with >= `MIN_EVENTS` lines) that seed the baseline; no z-based alerts before |
| `Z_INFO / Z_WARN / Z_HIGH` | `3 / 5 / 8` | Severity z-score thresholds |
| `RATE_CEILING` | `0.5` | Hard critical ceiling |
| `CLEAR_Z / CLEAR_WINDOWS` | `2.0 / 10` | Resolve after 10 consecutive 1 s ticks below z 2 |
| `SILENCE_SECONDS` | `10` | No lines for this long opens a silence incident |
| `ALERT_COOLDOWN_S` | `60` | Re-open within this reuses the incident id |
| `SNS_TOPIC_ARN` | _(empty)_ | Set to send HIGH/CRITICAL alerts to SNS |
| `AWS_ENDPOINT_URL` | _(empty)_ | `http://localhost:4566` for LocalStack |
| `DRY_RUN` | `false` | Skip real AWS calls |
| `DEMO_MODE` | `false` | Enable the demo-only endpoints |
| `DATABASE_URL` | `sqlite+aiosqlite:///./tremor.db` | Database connection |

AWS credentials are never stored in this repo. Locally, use your normal AWS CLI profile or environment variables; in production, use the IAM role created by the Terraform module below.

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
| `POST` | `/api/sim/inject` | Demo only (`DEMO_MODE=true`); currently a placeholder, use the simulator instead |
| `GET` | `/health` | Component health |
| `GET` | `/metrics` | Prometheus self-metrics |

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

## Production deployment (AWS, Terraform)

```bash
cd infra/terraform
terraform init
terraform apply -var="alert_email=you@example.com" -var="environment=prod"
```

This provisions:
- **SNS topic & subscription** for email/SMS routing of `HIGH` and `CRITICAL` alerts
- **CloudWatch log group (`/tremor/alerts`)** for structured JSON audit trails of all alerts
- **IAM role & instance profile** so TREMOR authenticates on EC2/ECS without hardcoded keys
- **CloudWatch alarms** as a secondary safety net for extreme error rates

Then set `SNS_TOPIC_ARN` (from the Terraform output) in the app's environment.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.12, Go 1.26 |
| API | FastAPI + Uvicorn (fully async) |
| Config | pydantic-settings |
| Storage | SQLAlchemy 2.x async + SQLite/Postgres |
| AWS | boto3 + tenacity (retry/backoff) |
| Template Mining | drain3 |
| Stats | numpy |
| Logging | structlog (JSON) |
| Metrics | prometheus-client |
| Frontend | React + Vite + TypeScript |
| Tests | pytest, pytest-asyncio, hypothesis, moto, go test |
| Quality | ruff, black, mypy --strict (core/), eslint |
| Ops | Docker, docker compose, GitHub Actions, Terraform, Prometheus, Grafana |

---

## Project Structure

```
Tremor/
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
├── scripts/                 # Dev utilities (burst_sim)
├── frontend/                # React + Vite + TypeScript dashboard
├── go/                      # Go ingest pipeline, bench, deploy stack
├── infra/terraform/         # AWS infrastructure
├── tests/                   # pytest suite
├── docs/                    # Architecture, detection, tradeoffs, eval
├── .env.example             # Configuration template (copy to .env)
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## Docs

- [Architecture](docs/ARCHITECTURE.md)
- [Detection Engine & Baselines](docs/DETECTION_ENGINE.md)
- [Detection API](docs/DETECTION_API.md)
- [Tradeoffs & Decisions](docs/TRADEOFFS.md)
- [Evaluation Results](docs/EVAL.md)
- [Go pipeline](go/README.md)

---

## License

MIT
