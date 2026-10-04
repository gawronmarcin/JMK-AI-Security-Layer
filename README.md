# JMK AI Security Layer (AICL)

**Kompleksowa warstwa kontroli i bezpieczeństwa (Security Gateway) dla agentów AI, aplikacji LLM i narzędzi MCP.**

Projekt stworzony na wyzwanie HackYeah *"AI Control Layer"*. Działa jako transparentny proxy pośredniczący pomiędzy aplikacjami/agentami a modelami językowymi (LLM), narzędziami (Tools/MCP) i bazami wiedzy (RAG/Memory).

---

## 🌟 Główne Wyróżniki (Differentiators)

1. **Wieloetapowa kaskada obrony (Tiered Defense)**:
   - **Tier 1**: Błyskawiczne, deterministyczne reguły regex i sygnatury z zewnętrznego feedu (`< 0.1 ms`).
   - **Tier 2**: Klasyfikator ML (np. *ProtectAI / DeBERTa-v3* lub embeddingi wektorowe, Apache-2.0).
   - **Tier 3**: Lokalny sędzia semantyczny LLM (*Ollama / Llama 3.2:3b*) uruchamiany w tzw. szarej strefie (*grey zone*).
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
6. **Lokalny Dashboard czasu rzeczywistego**:
   - Statyczny panel (Vanilla JS + Chart.js, zero zewnętrznych CDN) serwowany z bramki. Obsługuje strumieniowanie zdarzeń SSE, podgląd telemetrii, eksport audytu JSONL oraz interaktywny **Playground** do testowania promptów na żywo.

---

## 🏗 Architektura Przepływu Żądań

Każde żądanie przechodzi przez 5-etapowy potok:

```
Klient / Agent / Aplikacja
       │
       ▼
┌──────────────────────────── AICL Gateway (FastAPI / ASGI) ──────────────────────────┐
│ 1. Ingress   : Autoryzacja API key ──► Model allowlist ──► Limity rozmiaru (DoS)     │
│ 2. Input     : Normalizacja (NFKC, de-obfuskacja) ──► Regex/Feedy ──► Klasyfikator/AI│
│ 3. Forward   : Przekazanie do upstream LLM lub backendu narzędzia                    │
│ 4. Output    : Skan wyjścia (Canary, PII/Sekrety, Code Exec) ──► Redakcja/Blokada    │
│ 5. Post      : Rozliczenie budżetów (tokeny, koszt, czas) ──► Log audytowy JSONL     │
└─────────────────────────────────────────────────────────────────────────────────────┘
       │                              │                              │
       ▼                              ▼                              ▼
  Upstream LLM                   Backends Narzędzi              Lokalny Ollama
(OpenAI-compat/mock)             (REST / MCP Tools)            (Sędzia semantyczny)
```

---

## 🛡 Katalog Zagrożeń i Kontroli

Bramka pokrywa **20 zagrożeń** zmapowanych na **OWASP Top 10 for LLM (2025)**, **OWASP Top 10 for Agentic Applications (2026)** oraz **MITRE ATLAS**:

| ID | Zagrożenie | Kontrola AICL | OWASP LLM | OWASP Agentic | MITRE ATLAS |
|---|---|---|---|---|---|
| **TH-01** | Direct Prompt Injection | `C-INJ-PAT`, `C-INJ-BASTION`, `C-INJ-SEM` | LLM01:2025 | ASI01 | AML.T0051.000, AML.T0054 |
| **TH-02** | Indirect Prompt Injection | `C-INJ-PAT`, `C-TAINT` | LLM01:2025 | ASI01, ASI06 | AML.T0051.001, AML.T0070 |
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
| **TH-19** | Tainted Session Privileged Action| `C-TAINT` | LLM01:2025 | ASI01, ASI02 | AML.T0051.001, AML.T0086 |
| **TH-20** | Oversized Payload / DoS | `C-SIZE` | LLM10:2025 | — | AML.T0029 |

---

## 🧑‍💻 Human-in-the-Loop (HITL) Approval Flow

Dla operacji o podwyższonym ryzyku (np. wywołanie uprzywilejowanego narzędzia w sesji skażonej nieufnymi danymi `C-TAINT`, lub operacji wymagających zatwierdzenia przez operatora):
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
- **Wynik**: Raport różnicowy (*diff*) wskazujący, które żądania zmieniłyby swój status (np. `allow` ➔ `block` lub `block` ➔ `require_approval`), wraz z uzasadnieniem kontroli.
- **Interfejs UI**: W zakładce **Policy** w panelu webowym przycisk **„Preview impact (Replay traffic)”** natychmiast generuje tabelę zmian dla wklejonego dokumentu YAML.

---

## 📊 Metryki i Wyniki Testów

Pełny raport wygenerowany przez zestaw 212 przypadków testowych YAML (`reports/test_report.md`):

- **Zaliczone przypadki testowe**: **212 / 212 (100%)**
- **Detection Rate (DR)**: **100%**
- **False Positive Rate (FPR)**: **0%**
- **Narzut bramki**: **p50 = 0.44 ms**, **p95 = 1.84 ms**
- **Spełnienie kryterium pokrycia 3/3/2 (3 negatywne, 3 pozytywne, 2 brzegowe)**: **100% kontroli**
- **Wyniki fuzera mutacyjnego**: **Bypass rate = 0.0% (0 / 26)**

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
make test          # Pełny suite (in-process, bez potrzeby internetu i Ollamy)
make test-live     # Weryfikacja z działającym lokalnie modelem Ollama
make fuzz          # Uruchomienie fuzera mutacyjnego
make lint          # Weryfikacja jakości kodu (ruff)
```

### 3. Uruchomienie z Docker Compose
```bash
docker compose up
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
│   ├── controls/           # Moduły kontroli bezpieczeństwa (19 kontroli)
│   ├── flows/              # Obsługa przepływów (chat, tools/invoke, artifacts/scan)
│   ├── policy/             # Walidator, loader i kompilator polityki YAML
│   ├── admin/              # Endpointy telemetryczne i administracyjne
│   └── dashboard/          # Panel operatora (HTML, JS, CSS, Chart.js)
├── policies/               # Pliki polityk bezpieczeństwa (default.yaml)
├── feeds/                  # Zewnętrzne feedy sygnatur (attacks.yaml)
├── catalog/                # Katalog zagrożeń z mapowaniem OWASP/ATLAS (threats.yaml)
├── tests/                  # Zestaw testów automatycznych
│   ├── cases/              # Przypadki testowe sterowane danymi YAML (*.yaml)
│   ├── harness/            # Runner testów, walidacja schematu, generowanie raportu
│   ├── mocks/              # In-process mocki LLM i narzędzi
│   └── fuzz/               # Fuzzer mutacyjny ataków
└── reports/                # Wygenerowane raporty testowe i wydajnościowe
```
