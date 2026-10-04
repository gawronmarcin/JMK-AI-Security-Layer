# Podział poprawek na 3 równoległe zespoły LLM

Źródło: przegląd projektu z 2026-10-04 (testy na żywo + przegląd kodu). Każdy brief jest samodzielny.

| Grupa | Brief | Temat |
|---|---|---|
| A | [GROUP_A_coverage_identity.md](GROUP_A_coverage_identity.md) | Pokrycie ruchu (pola, których bramka nie skanuje) + tożsamość/sesje/delegacja |
| B | [GROUP_B_detection_quality.md](GROUP_B_detection_quality.md) | Jakość detekcji: dekodowanie, warstwy AI (fałszywe alarmy), komunikaty blokad |
| C | [GROUP_C_budget_governance_platform.md](GROUP_C_budget_governance_platform.md) | Budżety, martwe opcje polityki, zdalny feed, audyt/telemetria, artefakty, uruchomienie |

## Własność plików (każda grupa edytuje TYLKO swoje)

| Plik / obszar | A | B | C |
|---|---|---|---|
| `aicl/flows/chat.py` | ✅ | | |
| `aicl/flows/tool_invoke.py` | ✅ | | |
| `aicl/flows/common.py` | ✅ `authenticate`, `RequestRecord.__post_init__/authenticate`, `_size_decision` | | ✅ tylko `account_usage` i `RequestRecord.fail` (nagłówek Retry-After) |
| `aicl/controls/pii_secrets.py` | ✅ tylko stałe `_INPUT_ORIGINS/_OUTPUT_ORIGINS` | tylko import (read-only) | |
| `aicl/controls/delegation.py` | ✅ | | |
| `aicl/normalize.py` | | ✅ | |
| `aicl/controls/prompt_patterns.py`, `sig.py`, `bastion.py`, `injection_semantic.py`, `injection_embedding.py` | | ✅ | |
| `aicl/semantic/*` | | ✅ | |
| `aicl/engine.py` | | ✅ (jeśli konieczne) | |
| `feeds/attacks.yaml`, `feeds/injection_examples.yaml`, `scripts/stack_cases.yaml` | | ✅ | |
| `aicl/controls/budget.py`, `aicl/state/*` | | | ✅ |
| `aicl/controls/artifact.py`, `aicl/flows/artifact_scan.py` | | | ✅ |
| `aicl/policy/schema.py`, `aicl/policy/loader.py`, `aicl/feeds.py`, `aicl/audit.py`, `aicl/app.py` | | | ✅ |
| `aicl/admin/telemetry.py` | | | ✅ (`_EventCache`) |
| `policies/default.yaml` | ❌ | ✅ sekcje `injection_*`, `semantic` | ✅ sekcje `budgets`, `taint`, `audit`, `signature_feeds` |
| `policies/hybrid.yaml` (nowy) | | | ✅ |
| `docker/*`, `docker-compose.yml`, `Makefile`, `.env.example` | | | ✅ |
| Nowe testy | `tests/core/test_group_a_*.py`, `tests/cases/group_a_*.yaml` | `..._group_b_...` | `..._group_c_...` |

Plików spoza swojej kolumny nie wolno zmieniać. Jeśli coś tam trzeba poprawić, opisz to w raporcie końcowym, zamiast edytować.

## Kolejność scalania
Każda grupa pracuje lokalnie na swoim komputerze. Gotowe zmiany przenieście do jednego repo w dowolny sposób (commit i push albo patch).

1. Grupy można scalać w dowolnej kolejności. Konflikty mogą się pojawić tylko w `policies/default.yaml` i `aicl/flows/common.py`. Obie grupy edytują tam różne fragmenty, więc git powinien scalić je automatycznie.
2. Po scaleniu B i C: zsynchronizuj sekcje `injection_*` i `semantic` w `policies/hybrid.yaml` (grupa C) ze zmianami grupy B w `default.yaml`.
3. Na końcu uruchom pełne `python -m pytest -q` i `ruff check aicl tests`, potem zaktualizuj liczby w README (liczba przypadków, p50/p95).

Punkt odniesienia przed zmianami: `692 passed, 3 skipped`, raport YAML `220/220`.
