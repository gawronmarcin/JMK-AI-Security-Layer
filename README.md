# JMK AI Security Layer (AICL)

**Kompleksowa warstwa kontroli i bezpieczeństwa (Security Gateway) dla agentów AI, aplikacji LLM i narzędzi MCP.**

Projekt stworzony na wyzwanie HackYeah *"AI Control Layer"*. Działa jako transparentny proxy pośredniczący pomiędzy aplikacjami/agentami a modelami językowymi (LLM), narzędziami (Tools/MCP) i bazami wiedzy (RAG/Memory).

---

## 🌟 Główne Wyróżniki (Differentiators)

1. **Wieloetapowa kaskada obrony hybrydowej (Multi-Tier Defense-in-Depth)**:
   - **Tier 1 (Deterministyczny, < 0.1 ms)**: Błyskawiczna normalizacja Unicode (NFKC), dekodery obfuskacji, silnik reguł regex (`C-INJ-PAT`) oraz baza sygnatur ataków IOC (`C-SIG` z `feeds/attacks.yaml`).
   - **Tier 2 (Wielojęzyczne Embeddingi, dziesiątki ms)**: Kontrola `C-INJ-EMB` oparta na wielojęzycznym modelu embeddingów (`bge-m3` przez Ollamę) i korpusie 150 ataków oraz 135 zapytań benign w **17 językach** (`feeds/injection_examples.yaml`). Porównanie wektorowe z marginesem względem trudnych przykładów benign chroni przed fałszywymi alarmami, wyłapując parafrazy omijające reguły tekstowe.
   - **Tier 3 (Klasyfikator ML ONNX, ~5–15 ms)**: Kontrola `C-INJ-BASTION` wykorzystująca model *ProtectAI / DeBERTa-v3* uruchamiany bezpośrednio w procesie przez ONNX Runtime (licencja **Apache-2.0**, brak ciężkiego narzutu PyTorcha).
   - **Tier 4 (Lokalny Sędzia Semantyczny LLM, Ollama)**: Kontrola `C-INJ-SEM` z modelem *Qwen 2.5:1.5b* (domyślnie, licencja Apache-2.0; `qwen2.5:3b` jest dokładniejszy, ale ma licencję badawczą *qwen-research*). Budzony selektywnie w tzw. strefie niepewności (*grey zone*) wyznaczonej przez Tier 2/3 oraz dla niezaufanych treści zewnętrznych. Zwraca ustrukturyzowany werdykt JSON z uzasadnieniem.
2. **Śledzenie zatrucia sesji (Taint Tracking)**:
   - Wyniki z niezaufanych narzędzi (np. `fetch_url`, zewnętrzne pliki, retrieval) natychmiast oznaczają sesję flagą `tainted`.
   - Kontrola `C-TAINT` blokuje wykonanie operacji o wysokich uprawnieniach (`high`, `critical`) w zatrutej sesji, neutralizując pośrednie wstrzyknięcia (*Indirect Prompt Injection*).
3. **Hot-Reloading polityk w locie (Atomic Swap)**:
   - Całość reguł definiowana jest w jednym scentralizowanym pliku YAML (`policies/default.yaml`).
   - Zmiany są wykrywane w czasie rzeczywistym (~1 s) i aplikowane atomowo bez przerywania aktywnych połączeń. Błędny plik jest odrzucany z zachowaniem ostatniej poprawnej konfiguracji.
4. **Statyczna inspekcja artefaktów bez deserializacji**:
   - Bezpieczna analiza wag modeli i plików pickle (`pickletools.genops`) – zero ryzyka wykonania kodu (`pickle.load`) przy skanowaniu.
5. **Autonomiczny Fuzzer Mutacyjny**:
   - Wbudowane narzędzie atakujące (`tests/fuzz/`) testujące 14 strategii mutacyjnych (Base64, Hex, Leetspeak, Homoglyph, Zero-Width, HTML/Markdown smuggling, wielojęzyczność) osiągające **0.0% bypass rate**.
6. **Lokalny Dashboard czasu rzeczywistego & Playground**:
   - Statyczny panel (Vanilla JS + Chart.js, zero zewnętrznych CDN) serwowany bezpośrednio z bramki. Obsługuje strumieniowanie zdarzeń SSE, podgląd telemetrii, eksport audytu JSONL, kolejkę Human-in-the-Loop, podgląd polityk (*Policy Preview*) oraz interaktywny **Playground** do testowania promptów ad-hoc z gotowymi presetami ataków hybrydowych.

---

## 🏗 Architektura Przepływu Żądań

Każde żądanie przechodzi przez 5-etapowy potok:

```
Klient / Agent / Aplikacja
       │
       ▼
┌──────────────────────────── AICL Gateway (FastAPI / ASGI) ──────────────────────────┐
│ 1. Ingress   : Autoryzacja API key (C-AUTH) ──► Model allowlist ──► Limity rozmiaru │
│ 2. Input     : Normalizacja (NFKC) ──► Regex/Feedy ──► Embeddingi ──► Klasyfikator/AI│
│ 3. Forward   : Przekazanie do upstream LLM lub backendu narzędzia                    │
│ 4. Output    : Skan wyjścia (Canary, PII/Sekrety, Code Exec) ──► Redakcja/Blokada    │
│ 5. Post      : Rozliczenie budżetów (tokeny, koszt, czas) ──► Log audytowy JSONL     │
└─────────────────────────────────────────────────────────────────────────────────────┘
       │                              │                              │
       ▼                              ▼                              ▼
  Upstream LLM                   Backends Narzędzi              Lokalny Ollama
(OpenAI-compat/mock)             (REST / MCP Tools)        (Sędzia LLM / Embeddingi)
```

---

## 🛡 Katalog Zagrożeń i Kontroli

Bramka pokrywa **20 zagrożeń** (TH-01..TH-20) zmapowanych na **OWASP Top 10 for LLM (2025)**, **OWASP Top 10 for Agentic Applications (2026)** oraz **MITRE ATLAS**:

| ID | Zagrożenie | Kontrole AICL | OWASP LLM | OWASP Agentic | MITRE ATLAS |
|---|---|---|---|---|---|
| **TH-01** | Direct Prompt Injection | `C-INJ-PAT`, `C-INJ-EMB`, `C-INJ-BASTION`, `C-INJ-SEM` | LLM01:2025 | ASI01 | AML.T0051.000, AML.T0054 |
| **TH-02** | Indirect Prompt Injection | `C-INJ-PAT`, `C-INJ-EMB`, `C-INJ-BASTION`, `C-INJ-SEM` | LLM01:2025 | ASI01, ASI06 | AML.T0051.001, AML.T0070 |
| **TH-03** | Inbound PII Exposure | `C-PII-IN` | LLM02:2025 | — | — |
| **TH-04** | Secrets & Credentials Leakage | `C-SECRET-IN`, `C-SECRET-OUT` | LLM02:2025 | ASI03 | AML.T0057, AML.T0098 |
| **TH-05** | Outbound PII Leakage | `C-PII-OUT` | LLM02:2025 | — | AML.T0057 |
| **TH-06** | Disallowed Model Selection | `C-MODEL-ALLOW` | LLM03:2025 | — | — |
| **TH-07** | Excessive Agency / Tool Misuse | `C-TOOL-ACL` | LLM06:2025 | ASI02 | AML.T0053 |
| **TH-08** | Impersonation & Missing Auth | `C-AUTH` | — | ASI03 | AML.T0012, AML.T0073 |
| **TH-09** | Delegation & Privilege Escalation | `C-DELEG` | LLM06:2025 | ASI03, ASI07 | — |
| **TH-10** | Unauthorized Memory/RAG Access | `C-MEM-ACL` | LLM08:2025 | ASI03 | AML.T0085.000 |
| **TH-11** | Token Overuse | `C-BUDGET` | LLM10:2025 | — | AML.T0034, AML.T0029 |
| **TH-12** | Cost / Compute Overuse | `C-BUDGET` | LLM10:2025 | — | AML.T0034, AML.T0029 |
| **TH-13** | Runaway Tool Loops | `C-LOOP` | LLM10:2025 | ASI08 | AML.T0034.002 |
| **TH-14** | Unsafe Deserialization (Pickle) | `C-ARTIFACT` | LLM03:2025 | ASI04, ASI05 | AML.T0011.000 |
| **TH-15** | Malicious Code Execution | `C-CODE-EXEC` | LLM05:2025 | ASI05 | AML.T0050, AML.T0102 |
| **TH-16** | Supply Chain Compromise | `C-SUPPLY` | LLM03:2025 | ASI04 | AML.T0010, AML.T0058 |
| **TH-17** | Known Attack Signatures | `C-SIG` | LLM01:2025 | ASI01, ASI04 | AML.T0051 |
| **TH-18** | Canary / Prompt Leakage | `C-CANARY` | LLM07:2025 | — | AML.T0056 |
| **TH-19** | Tainted Session Privileged Action | `C-TAINT` | LLM01:2025 | ASI01, ASI02 | AML.T0051.001, AML.T0086 |
| **TH-20** | Oversized Payload / DoS | `C-SIZE` | LLM10:2025 | — | AML.T0029 |

---

## 🎯 Wyniki Benchmarków i Skuteczność Kaskady

Pomiary przeprowadzone na zbiorze kontrolnym ataków held-out (`scripts/stack_cases.yaml`, teksty niewystępujące w korpusie treningowym ani regułach regex):

- **Wykrywanie ataków pełnej kaskady**: **45 / 47 ataków zablokowanych (95.7%)** w profilu `balanced`.
- **Wskaźnik fałszywych alarmów (FPR)**: **0 / 24 (0.0%)** – ani jedno zwykłe zapytanie biznesowe nie zostało zablokowane.
- **Wielojęzyczność**: Pełne pokrycie ataków w językach EN, PL, UK, ZH, DE, FR, ES, IT, JA i innych dzięki modelowi wektorowemu `bge-m3`.
- **Zestaw testów deterministycznych YAML**: **212 / 212 przypadków (100% zaliczenia)** w `reports/test_report.md`.
- **Kryterium pokrycia 3/3/2 (3 negatywne, 3 pozytywne, 2 brzegowe)**: Spełnione w 100% kontrolek.
- **Narzut bramki na ścieżce szybkiej (Fast Path)**: **p50 = 0.44 ms**, **p95 = 1.84 ms**.

### Weryfikacja kaskady semantycznej i AI:
Szczegółowa instrukcja uruchomienia lokalnej Ollamy i pobrania wag modeli znajduje się w dokumencie [docs/SEMANTIC_SETUP.md](docs/SEMANTIC_SETUP.md).

```bash
# Weryfikacja modeli i rozgrzanie sędziego:
python scripts/check_semantic.py --skip-classifier

# Uruchomienie testu całej kaskady na żywej bramce:
python scripts/stack_test.py
```

---

## 🧑‍💻 Human-in-the-Loop (HITL) Approval Flow

Dla operacji o podwyższonym ryzyku (np. wywołanie uprzywilejowanego narzędzia w sesji skażonej nieufnymi danymi `C-TAINT` lub operacji wymagających zatwierdzenia przez operatora):
1. **Wykrycie i wstrzymanie**: Bramka zwraca `HTTP 403 aicl_approval_required` wraz z unikalnym identyfikatorem `approval_id` (np. `appr_...`).
2. **Kolejka administracyjna**: Żądanie trafia do rejestru oczekujących zatwierdzeń, dostępnego przez Admin API:
   - `GET /admin/approvals` – lista wniosków (filtry: `pending`, `approved`, `rejected`, `all`)
   - `GET /admin/approvals/{approval_id}` – szczegóły wniosku
   - `POST /admin/approvals/{approval_id}/approve` – zatwierdzenie przez operatora
   - `POST /admin/approvals/{approval_id}/reject` – odrzucenie przez operatora
3. **Ponowienie z tokenem**: Klient ponawia żądanie przekazując nagłówek `X-AICL-Approval-Id: <approval_id>`. Po weryfikacji zgody bramka bezpiecznie przepuszcza wykonanie (`HTTP 200`).
4. **Interfejs Dashboardu**: Sekcja **Approvals** w panelu webowym umożliwia podgląd kolejki na żywo oraz zatwierdzanie/odrzucanie jednym kliknięciem.

---

## 🔄 Policy Preview & Replay (`POST /admin/policy/preview`)

Przed wdrożeniem nowej wersji polityki na środowisko produkcyjne operator może przetestować kandydujący plik YAML na podstawie ostatnich żądań z logu audytowego:
- **Endpoint**: `POST /admin/policy/preview?last_n=50` (przyjmuje treść YAML lub JSON `{"policy": "...", "last_n": 50}`).
- **Wynik**: Raport różnicowy (*diff*) wskazujący, które żądania zmieniłyby swój status (np. `allow` ➔ `block` lub `block` ➔ `require_approval`), wraz z uzasadnieniem kontroli oraz informacją o zakresie replayu.
- **Interfejs UI**: W zakładce **Policy** w panelu webowym przycisk **„Preview impact (Replay traffic)”** natychmiast generuje tabelę zmian dla wklejonego dokumentu YAML.

---

## 🚀 Szybki Start (Quickstart)

### 1. Wymagania
- Python 3.11+ lub Docker & Docker Compose
- Wirtualne środowisko z zależnościami:
  ```bash
  make install
  ```

### 2. Uruchomienie testów
```bash
make test          # Pełny suite testów automatycznych (in-process, bez zewnętrznych usług)
make test-live     # Weryfikacja z działającym lokalnie modelem Ollama
make fuzz          # Uruchomienie fuzera mutacyjnego
make lint          # Weryfikacja jakości kodu (ruff)
```

### 3. Uruchomienie z Docker Compose

```bash
# Uruchomienie bramki z mockami LLM i narzędzi:
docker compose up

# Uruchomienie pełnego stosu hybrydowego (bramka + Ollama z bge-m3 i qwen2.5):
docker compose --profile hybrid up

# Uruchomienie pełnego suite testów w kontenerze:
docker compose run --rm tests

# Uruchomienie z profilem Bastion (zewnętrzny mikroserwis klasyfikatora):
docker compose --profile bastion up

# Uruchomienie niezależnego serwera sygnatur (zdalny feed z ETag i HMAC):
python scripts/feed_server.py --port 8088 --feed feeds/attacks.yaml
```

Bramka uruchomi się na porcie `:8080`, mock LLM na `:9001`, a mock narzędzi na `:9002`.

Dashboard administracyjny dostępny jest pod adresem:
👉 **`http://localhost:8080/dashboard/`** (klucz deweloperski: `dev-key-admin`).

### 4. Uruchomienie lokalne (Dev)
```bash
cp .env.example .env
make dev
```

---

## 📁 Struktura Projektu

```text
├── aicl/                   # Główny kod bramki bezpieczeństwa
│   ├── app.py              # Fabryka aplikacji FastAPI i routing
│   ├── engine.py           # Silnik ewaluacji potoku i łączenia decyzji
│   ├── models.py           # Kontrakty danych (RequestContext, Decision, Match)
│   ├── controls/           # Moduły kontroli bezpieczeństwa (21 kontroli)
│   ├── flows/              # Obsługa przepływów (chat, tools/invoke, artifacts/scan)
│   ├── policy/             # Walidator, loader, preview i kompilator polityki YAML
│   ├── admin/              # Endpointy telemetryczne i administracyjne (w tym Approvals)
│   └── dashboard/          # Panel operatora (HTML, JS, CSS, Chart.js, Playground)
├── policies/               # Pliki polityk bezpieczeństwa (default.yaml)
├── feeds/                  # Zewnętrzne feedy sygnatur (attacks.yaml, injection_examples.yaml)
├── catalog/                # Katalog zagrożeń z mapowaniem OWASP/ATLAS (threats.yaml)
├── tests/                  # Zestaw testów automatycznych
│   ├── cases/              # Przypadki testowe sterowane danymi YAML (*.yaml)
│   ├── harness/            # Runner testów, walidacja schematu, generowanie raportu
│   ├── mocks/              # In-process mocki LLM i narzędzi
│   └── fuzz/               # Fuzzer mutacyjny ataków
├── scripts/                # Skrypty kalibracji, pomiarów i testów kaskady AI
└── reports/                # Wygenerowane raporty testowe i wydajnościowe
```
