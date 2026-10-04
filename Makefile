# Cele z ARCHITECTURE.md §10. Jedna komenda dla jury: `make test` (§11.8).
ifeq ($(OS),Windows_NT)
    PY      ?= python
    VENV    ?= .venv
    BIN     := $(VENV)/Scripts
else
    PY      ?= python3
    VENV    ?= .venv
    BIN     := $(VENV)/bin
endif

PYTEST  := $(BIN)/pytest

.PHONY: install test test-live test-fast check-semantic fuzz report mocks dev demo selftest agent lint clean

$(BIN)/pip:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -q --upgrade pip
	$(BIN)/pip install -q -e ".[test,dev]"

install: $(BIN)/pip

test: install                       ## pełny suite: bez Ollamy, bez internetu
	$(PYTEST) -q

OLLAMA_URL  ?= http://localhost:11434
JUDGE_MODEL ?= qwen2.5:1.5b

test-live: install                  ## + testy z prawdziwym Ollamą (make test-live JUDGE_MODEL=qwen2.5:3b)
	AICL_LIVE=1 AICL_OLLAMA_URL=$(OLLAMA_URL) AICL_JUDGE_MODEL=$(JUDGE_MODEL) 	AICL_LIVE_OLLAMA_URL=$(OLLAMA_URL) AICL_LIVE_JUDGE_MODEL=$(JUDGE_MODEL) $(PYTEST) -q --live

check-semantic: install             ## Ollama + klasyfikator: dostępność, latencja, kaskada (docs/SEMANTIC_SETUP.md)
	$(BIN)/python scripts/check_semantic.py $(ARGS)

test-fast: install                  ## tylko to, co nie wymaga gatewaya (mocki, schematy YAML)
	$(PYTEST) -q -m "not gateway"

fuzz: install                       ## fuzzer mutacyjny -> reports/fuzz_*.json
	$(BIN)/python -m tests.fuzz.run

report:                             ## pokaż ostatni raport
	@cat reports/test_report.md 2>/dev/null || echo "brak raportu — uruchom make test"

mocks: install                      ## mocki jako osobne procesy (LLM 9001, narzędzia 9002, serwer MCP 9003)
	$(BIN)/uvicorn tests.mocks.mock_llm:app --port 9001 & \
	$(BIN)/uvicorn tests.mocks.mock_tools:app --port 9002 & \
	$(BIN)/uvicorn tests.mocks.mock_mcp:app --port 9003 & \
	wait

dev: install                        ## gateway lokalnie z auto-reloadem (wymaga aicl/ od R1)
	set -a; [ -f .env ] && . ./.env; set +a; \
	$(BIN)/uvicorn aicl.app:create_app --factory --reload --port 8080

demo: install                       ## ruch demonstracyjny dla dashboardu i prezentacji
	$(BIN)/python scripts/demo_traffic.py $(ARGS)

selftest: install                   ## self-test działającego gatewaya na BIEŻĄCEJ polityce (ARGS="--url ...")
	$(BIN)/python scripts/selftest.py $(ARGS)

agent: install                      ## prawdziwy agent (model z Ollamy) przez gateway: benign / taint / indirect
	$(BIN)/python scripts/agent_demo.py $(ARGS)

lint: install
	$(BIN)/ruff check aicl tests

clean:
	rm -rf reports/*.json reports/*.md .pytest_cache
