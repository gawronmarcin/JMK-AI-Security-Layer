# Cele z ARCHITECTURE.md §10. Jedna komenda dla jury: `make test` (§11.8).
PY      ?= python3
VENV    ?= .venv
BIN     := $(VENV)/bin
PYTEST  := $(BIN)/pytest

.PHONY: install test test-live test-fast check-semantic fuzz report mocks dev lint clean

$(BIN)/activate:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -q --upgrade pip
	$(BIN)/pip install -q -e ".[test,dev]"

install: $(BIN)/activate

test: install                       ## pełny suite: bez Ollamy, bez internetu
	$(PYTEST) -q

test-live: install                  ## + testy z prawdziwym Ollamą
	AICL_LIVE=1 $(PYTEST) -q --live

check-semantic: install             ## Ollama + klasyfikator: dostępność, latencja, kaskada (docs/SEMANTIC_SETUP.md)
	$(BIN)/python scripts/check_semantic.py $(ARGS)

test-fast: install                  ## tylko to, co nie wymaga gatewaya (mocki, schematy YAML)
	$(PYTEST) -q -m "not gateway"

fuzz: install                       ## fuzzer mutacyjny -> reports/fuzz_*.json
	$(BIN)/python -m tests.fuzz.run

report:                             ## pokaż ostatni raport
	@cat reports/test_report.md 2>/dev/null || echo "brak raportu — uruchom make test"

mocks: install                      ## mocki jako osobne procesy dla R1/R2/R3 (porty 9001/9002)
	$(BIN)/uvicorn tests.mocks.mock_llm:app --port 9001 & \
	$(BIN)/uvicorn tests.mocks.mock_tools:app --port 9002 & \
	wait

dev: install                        ## gateway lokalnie z auto-reloadem (wymaga aicl/ od R1)
	set -a; [ -f .env ] && . ./.env; set +a; \
	$(BIN)/uvicorn aicl.app:create_app --factory --reload --port 8080

lint: install
	$(BIN)/ruff check tests

clean:
	rm -rf reports/*.json reports/*.md .pytest_cache
