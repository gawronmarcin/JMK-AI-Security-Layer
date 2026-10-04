# JMK AI Security Layer (AICL) — Quickstart Guide

## Prerequisites

- **Option A (Docker - Recommended):** Docker Engine 24+ & Docker Compose v2+
- **Option B (Local Python):** Python 3.11+ and `pip`

---

## Option A: Running with Docker Compose

### 1. Launch Gateway & Services
Start the gateway alongside mock upstream LLM and tool backends:

```bash
docker compose up
```

*(Optional: To run with the full local AI hybrid profile including embeddings and local models, use: `docker compose --profile hybrid up`)*

### 2. Run Automated Tests
```bash
docker compose run --rm tests
```

---

## Option B: Running Locally (Python)

### 1. Setup Environment
Clone the repository and install the package with dependencies:

```bash
# Create and activate virtual environment
python -m venv .venv

# Windows (PowerShell):
.venv\Scripts\Activate.ps1

# Linux / macOS:
source .venv/bin/activate

# Install package and dependencies
pip install -e ".[test,dev]"
```

### 2. Configure Environment Variables
```bash
cp .env.example .env
```

### 3. Start Backends & Gateway

Run the following commands across separate terminals (or in background):

**Terminal 1 — Upstream LLM Mock:**
```bash
uvicorn tests.mocks.mock_llm:app --port 9001
```

**Terminal 2 — Tools Backend Mock:**
```bash
uvicorn tests.mocks.mock_tools:app --port 9002
```

**Terminal 3 — AICL Gateway:**
```bash
uvicorn aicl.app:create_app --factory --port 8080 --reload
```
*(Alternatively, you can run `make dev`)*

---

## Running Test Suites & Benchmarks

All test commands run completely offline and in-process without external network dependencies:

```bash
# Full test suite (793 tests + 234 data-driven YAML scenarios)
pytest -q
# or: make test

# View generated test report
cat reports/test_report.md

# Run autonomous mutation fuzzer
python -m tests.fuzz.run
# or: make fuzz
```

---

## Populating Dashboard with Demo Traffic

To generate a realistic mix of allowed, blocked, redacted, and budget-throttled traffic:

```bash
python scripts/demo_traffic.py
# or: make demo
```

---

## Access & Endpoints

- **Interactive Web Dashboard & Playground:**  
  **`http://localhost:8080/dashboard/`**  
  *(Default Admin Key: `dev-key-admin`)*
- **OpenAI-Compatible Chat Completions:**  
  `POST http://localhost:8080/v1/chat/completions`  
  *(Header: `Authorization: Bearer dev-key-support`)*
- **Tool Execution / MCP Invocation:**  
  `POST http://localhost:8080/v1/tools/invoke`
- **Artifact & Model File Scanning:**  
  `POST http://localhost:8080/v1/artifacts/scan`
- **Telemetry & Admin API:**  
  `GET http://localhost:8080/admin/telemetry`  
  `GET http://localhost:8080/admin/approvals`