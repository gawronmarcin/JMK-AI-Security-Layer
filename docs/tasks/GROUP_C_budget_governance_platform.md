# Grupa C: budżety, governance polityki, zdalny feed, audyt, artefakty, uruchomienie

Pracujesz nad projektem **AICL**: bramką bezpieczeństwa (FastAPI) między agentami AI a LLM-ami i narzędziami. Projekt bierze udział w konkursie HackYeah „AI Control Layer”. Jury będzie **edytować plik polityki na żywo** (zmieniać limity, wyłączać kontrolki) i obserwować skutek. Każda opcja w polityce musi więc albo działać, albo zostać odrzucona przez walidację. Brief konkursu wymaga też budżetów (tokeny, koszt, czas obliczeń), sygnatur ataków „dostarczanych z zewnętrznie zarządzanego systemu” oraz telemetrii wydajności.

Dwie inne grupy pracują równolegle na innych komputerach nad innymi plikami (patrz [00_PODZIAL.md](00_PODZIAL.md)). Żeby zmiany dało się potem scalić bez konfliktów, edytuj **tylko pliki z sekcji „Twoje pliki”**.

## Środowisko
Pracuj lokalnie w repozytorium. Zależności: `pip install -e ".[test,dev,redis]"`. Testy: `python -m pytest -q`. Punkt odniesienia przed zmianami: 692 passed, 3 skipped.

Do testów na żywo: bramka `uvicorn aicl.app:create_app --factory --port 8080`, mocki `uvicorn tests.mocks.mock_llm:app --port 9001` i `uvicorn tests.mocks.mock_tools:app --port 9002`, zmienne środowiskowe z `.env.example`. Do testów Redis jest `tests/core/fake_redis.py`.

## Twoje pliki
- `aicl/controls/budget.py`, `aicl/state/*` (`base.py`, `memory.py`, `redis_store.py`)
- `aicl/flows/common.py`: **tylko** `account_usage()` i `RequestRecord.fail()`. Resztę pliku edytuje grupa A.
- `aicl/models.py`: tylko dodanie opcjonalnych pól (z wartością domyślną) do `Decision`
- `aicl/policy/schema.py`, `aicl/policy/loader.py`, `aicl/feeds.py`, `aicl/runtime.py`, `aicl/audit.py`, `aicl/app.py`
- `aicl/admin/telemetry.py`: klasa `_EventCache` i endpoint eksportu audytu
- `aicl/controls/artifact.py`, `aicl/flows/artifact_scan.py`
- `policies/default.yaml`: **tylko** sekcje `budgets`, `taint`, `audit`, `signature_feeds`. Nowy plik `policies/hybrid.yaml`.
- `docker/Dockerfile`, `docker-compose.yml`, `Makefile`, `.env.example`, `README.md` (tylko sekcje „Szybki Start” i Docker), nowe `scripts/feed_server.py`
- nowe testy: `tests/core/test_group_c_*.py`, `tests/cases/group_c_*.yaml`

Nie edytuj `aicl/flows/chat.py`, `aicl/flows/tool_invoke.py`, kontrolek injection i PII, `aicl/normalize.py`, `aicl/semantic/*` ani feedów `feeds/*.yaml` (poza testowymi kopiami w katalogach tymczasowych).

## Zasady
- Styl kodu jak w otoczeniu: komentarze po angielsku.
- Każda poprawka dostaje test negatywny i pozytywny. Testy stanu w dwóch wariantach: `InMemoryStore` i Redis (fake), wzorem `tests/core/test_shared_state.py`.
- Zmiany w schemacie polityki muszą zachować poprawność `policies/default.yaml` i wszystkich polityk testowych (`tests/core/policy_files.py`, `tests/harness/policy_utils.py`).
- Na koniec: `python -m pytest -q` musi być zielone, a `ruff check aicl tests` czyste.

---

## C1. Budżet: atomowa rezerwacja przed wywołaniem i rozliczenie po (WYSOKI)

**Problem.**
- `controls/budget.py:~76-130` tylko **odczytuje** liczniki na etapie ingress. Zużycie dopisuje dopiero `account_usage()` (`flows/common.py:~403-421`) po odpowiedzi upstreamu. Nie ma szacunku ani rezerwacji.
- Na żywo przy limicie 5000 tokenów pierwsze żądanie przeszło i licznik skończył na 6940.
- 60 równoległych żądań przy limicie 20/min dostało 200 (wyścig check-then-act).
- Okno minutowe jest stałe, więc da się wysłać podwójną serię na granicy minuty.
- Odpowiedź 429 nie ma `Retry-After`.

**Do zrobienia.**
1. **Nowe API stanu** w `state/base.py`, z implementacją w `memory.py` (z `asyncio.Lock`) i `redis_store.py` (atomowo: skrypt Lua albo `WATCH/MULTI`):
   - `check_and_reserve(identity, window, request_id, *, tokens, cost_usd, limits) -> ReserveResult`: w jednej atomowej operacji sprawdza `aktualne + rezerwacje + szacunek` względem limitów (tokeny, koszt, compute, req/min). Jeśli limit nie jest przekroczony, dolicza szacunek i inkrementuje licznik żądań w oknie minutowym. Zwraca, który limit został przekroczony, oraz czas do resetu okna.
   - `settle(request_id, *, prompt_tokens, completion_tokens, cost_usd, compute_seconds)`: zamienia rezerwację na faktyczne zużycie (dolicza różnicę). Rezerwacja bez rozliczenia wygasa po TTL (np. 600 s).
2. **Szacunek w `budget.py`.** Tokeny promptu to suma `len(text)//4` segmentów dostępnych w `ctx` na etapie ingress (sprawdź, co tam jest). Tokeny odpowiedzi to `max_tokens` / `max_completion_tokens` z żądania, jeśli są dostępne w `ctx`; w przeciwnym razie nowe pole budżetu `default_completion_reserve` (domyślnie 512). Koszt liczony z `models[].price_per_1k_tokens`. **Nie edytuj flows A** (chat.py, tool_invoke.py). Jeśli czegoś brakuje w `ctx`, użyj wartości domyślnych i opisz to w raporcie.
3. **`account_usage()`** woła `settle(rec.request_id, ...)` (już jest w `finally` we flows). Nie dubluj liczenia `requests` (są doliczane przy rezerwacji). Ścieżki bez rezerwacji (rola bez budżetu, wyłączona kontrolka) działają jak dotąd.
4. **Limit minutowy:** okno przesuwne (sliding window, np. dwa koszyki ważone albo sorted set w Redis) zamiast stałego.
5. **`Retry-After`:** dodaj do `Decision` opcjonalne pole `retry_after_s: float | None = None`, ustawiane przez C-BUDGET. W `RequestRecord.fail()` dla `ErrorType.budget_exceeded` ustaw nagłówek `Retry-After` (sekundy, zaokrąglone w górę).

**Akceptacja.**
- Limit 5000 tokenów i żądanie, którego szacunek przekracza pozostały budżet: 429 **przed** wywołaniem upstreamu (`upstream_called: false`).
- 60 równoległych żądań (`asyncio.gather`) przy `max_requests_per_minute: 20`: dokładnie 20 × 200 i 40 × 429, na obu backendach stanu.
- 429 ma `Retry-After`.
- `/admin/metrics/budgets` pokazuje rzeczywiste zużycie po rozliczeniu.
- Istniejące `tests/cases/budgets.yaml` i `tests/test_budgets.py` są zielone.

## C2. Opcje polityki, które nic nie robią (ŚREDNI, jury je zmieni)

Każdą z poniższych opcji **zaimplementuj** albo **usuń ze schematu**, tak żeby walidacja ją odrzucała z czytelnym komunikatem. Pole `extra="forbid"` już działa dla `_Strict`.

| Opcja | Stan | Decyzja |
|---|---|---|
| `budgets.*.on_exceed: throttle \| downgrade_model` (`schema.py:94`) | brak implementacji | usuń obie wartości; zostaw `block`. Zaktualizuj komentarz w `default.yaml`. (Implementacja `downgrade_model` wymaga zmian w `chat.py`, czyli w grupie A; zostaw to na później.) |
| `taint.session_ttl_seconds` (`schema.py:146`) | `app.py` tworzy `InMemoryStore()` / `RedisStore` z domyślnym 3600 | **zaimplementuj**: przekaż wartość z polityki do konstruktorów stanu w `app.py` (`_shared_state`) i aktualizuj ją przy przeładowaniu polityki |
| `audit.content: masked \| none` (`schema.py:173`) | ignorowane | **zaimplementuj**: `none` oznacza, że w zdarzeniach audytu nie ma żadnych fragmentów treści (`matches[].masked`, podglądy argumentów i zgód); zostają tylko typy i ID |
| `audit.replay_capture` (`schema.py:174`) | sprawdź `grep -rn replay_capture aicl` | jeśli nieużywane: usuń ze schematu i z `default.yaml` |
| `signature_feeds[].url`, `refresh_seconds` | `feeds.py:225`: „remote (url) feeds are not supported yet” | **zaimplementuj** w C3 |
| `budgets.*.max_delegation_depth` | ignorowane | **nie ruszaj**; grupa A podłącza to w `delegation.py` |

**Literówki w ID kontrolek.** Dziś błędne `id:` w `controls:` przechodzi walidację i pojawia się tylko jako `missing_controls` w audycie. Walidacja polityki ma zwracać błąd „unknown control id 'C-INJ-PATT' (known: …)”, gdy ID nie jest w rejestrze (`aicl/registry.py`). Sprawdź, czy testy z niestandardowym zestawem kontrolek (`create_app(controls=...)`) nadal działają; tam walidacja powinna brać znany zestaw z przekazanych kontrolek.

**Akceptacja.** Dla każdej usuniętej opcji: test, że polityka z nią jest odrzucana, a przy hot-reload zostaje poprzednia wersja i powstaje zdarzenie `policy.rejected`. Dla każdej zaimplementowanej: test zachowania.

## C3. Zdalny feed sygnatur „z zewnętrznie zarządzanego systemu” (WYSOKI, wymóg briefu)

**Problem.** Feed jest tylko plikiem lokalnym. Pole `url` jest w schemacie, ale `feeds.py:225` rzuca „not supported yet”. Brief wprost mówi o sygnaturach „fed from some externally managed system”.

**Do zrobienia.**
- W `feeds.py` dla `FeedRef` z `url`: pobieranie przez `httpx` co `refresh_seconds` w pętli przeładowania (`runtime.py`). Wymagania:
  - nagłówki `If-None-Match` / `ETag` (odpowiedź 304 nic nie zmienia),
  - timeout,
  - limit rozmiaru (np. 5 MB),
  - dozwolone tylko `https://` albo `http://` do `localhost/127.0.0.1`,
  - opcjonalna weryfikacja HMAC-SHA256 z kluczem z env (`signing_key_env`, podpis w nagłówku `X-AICL-Feed-Signature`).
- Treść przechodzi przez istniejące `parse_feed()`. Przy błędzie lub niedostępności działa `on_unavailable: keep_last_good` (już w schemacie). Każda zmiana wersji to zdarzenie audytu `feed.reloaded`, a każdy błąd to `feed.rejected` (sprawdź istniejące typy zdarzeń).
- `scripts/feed_server.py`: minimalny serwer (FastAPI albo `http.server`) wystawiający `feeds/attacks.yaml` z ETagiem, do demo na żywo przed jury.
- Dodaj do `default.yaml` zakomentowany przykład feedu zdalnego.
- `/healthz` i `/admin/policy/` mają pokazywać źródło feedu (plik czy URL) i czas ostatniego pobrania.

**Akceptacja.** Test z `httpx.MockTransport`:
- nowa wersja feedu → nowa sygnatura blokuje,
- 304 → bez zmian,
- 500 albo niepoprawny YAML → stara wersja zostaje i powstaje zdarzenie,
- zły podpis HMAC → odrzucenie.

## C4. Telemetria i log audytu: przyrostowo i z rotacją (ŚREDNI, wydajność)

**Problem.** `admin/telemetry.py:~88-108` (`_EventCache.all`) przy **każdej** zmianie pliku (czyli po każdym żądaniu) parsuje cały `audit.jsonl` od nowa, ~2,3 KB na zdarzenie. Log nie ma rotacji. Na pokazie, przy ruchu demo, dashboard będzie coraz wolniejszy.

**Do zrobienia.**
- `_EventCache`: pamiętaj offset. Gdy plik urósł, parsuj tylko dopisane bajty (uważaj na niedokończoną ostatnią linię). Gdy plik się skurczył lub został podmieniony (rotacja), czytaj od zera. Ogranicz pamięć: np. ostatnie 100 000 zdarzeń albo zakres czasu dashboardu (7 dni).
- `audit.py`: rotacja po rozmiarze. Nowe pola polityki `audit.max_file_bytes` (domyślnie 50 MB) i `audit.keep_files` (domyślnie 5): `audit.jsonl` → `audit.jsonl.1` → … Zapis nadal w tle.
- `/admin/export/audit.jsonl`: parametr `include_rotated=true`, który dokleja pliki rotowane (strumieniowo, bez ładowania całości do pamięci).

**Akceptacja.** Test: 5000 zdarzeń, potem 1 nowe; drugie `all()` parsuje tylko 1 linię (zmierz albo zmockuj). Test rotacji i eksportu z `include_rotated`. Endpointy `/admin/metrics/*` dają te same wyniki co przed zmianą (porównaj na tych samych danych).

## C5. Skaner artefaktów: sklejone pickle i event loop (ŚREDNI)

**Problem.**
- `controls/artifact.py:~140`: `pickletools.genops` kończy na pierwszym `STOP`. Plik `pickle.dumps({"ok":1}) + pickle.dumps(EvilReduce())` daje tylko ostrzeżenie `pickle_format`; w balanced to `flag`, więc plik jest przepuszczany, chociaż `pickle.load` w pętli wykona `os.system`.
- Skan (do 100 MB) działa synchronicznie na event loopie.

**Do zrobienia.**
- Po `STOP` kontynuuj parsowanie od następnego bajtu, aż do końca danych. Globale ze wszystkich strumieni idą do tej samej oceny. Śmieci po ostatnim `STOP`, które nie parsują się jako pickle, to nowe ostrzeżenie `trailing_data`; w strict blokada przez `block_on_warn`.
- To samo dla pickli wewnątrz archiwów (`.pt`/zip).
- Ciężką część skanu w `evaluate()` (l. ~405) uruchamiaj przez `anyio.to_thread.run_sync`.

**Akceptacja.**
- Plik z dwoma picklami (benign + `os.system`) daje 403 `C-ARTIFACT` z ID sygnatury.
- Benign pickle i safetensors bez zmian.
- Podczas skanu 50 MB inny request (`/healthz`) odpowiada w mniej niż 100 ms.

Przykład złośliwego pickla w testach generuj przez `__reduce__` (samo `pickle.dumps` niczego nie wykonuje). **Nigdy nie wywołuj `pickle.load`.**

## C6. Uruchomienie hybrydy i ergonomia dla jury (ŚREDNI)

**Problem.**
- `policies/default.yaml` ma `backend: none` dla embeddingów i klasyfikatora, a sędziego ustawionego na `qwen2.5:1.5b` (lokalnie niepobrany). Jury uruchamiające repo nie zobaczy hybrydowej obrony, a sędzia przejdzie w fail-open.
- `docker compose --profile ollama up` nie przełącza bramki na Ollamę (potrzebny `AICL_OLLAMA_URL_OVERRIDE`) i nie pobiera modeli.
- `Makefile` używa `.venv/bin`, więc nie działa na Windows.
- Compose używa kluczy z `.env.example`, publikuje porty na wszystkich interfejsach, a kontener działa jako root.

**Do zrobienia.**
1. **`policies/hybrid.yaml`** (śledzony w git): kopia `default.yaml` z `injection_embedding.backend: ollama` (`timeout_ms: 6000`), `injection_bastion.backend: protectai`, sędzia `qwen2.5:1.5b` (`timeout_ms: 12000`). Nagłówek pliku ma wyjaśniać użycie (`AICL_POLICY=policies/hybrid.yaml`). Dodaj test, że `hybrid.yaml` przechodzi walidację (bez uruchamiania modeli). **Uwaga:** grupa B zmienia sekcje `injection_*` i `semantic` w `default.yaml`; osoba scalająca zsynchronizuje je potem w `hybrid.yaml`.
2. **docker-compose:** nowy profil `hybrid` (albo rozszerzony `ollama`) z usługą `ollama-init` jednorazowo pobierającą `bge-m3` i `qwen2.5:1.5b`. Bramka w tym profilu ma `AICL_OLLAMA_URL=http://ollama:11434`, `AICL_POLICY=policies/hybrid.yaml` i obraz z extras `protectai`. Jedna komenda w README.
3. **Hardening:** porty `127.0.0.1:8080:8080` itd.; w `Dockerfile` użytkownik nieuprzywilejowany (UID 10001), `HF_HOME` w jego katalogu i odpowiednio przeniesiony wolumen cache; zapis do `/app/data` dla tego użytkownika. W `app.py` przy starcie WARNING w logu (i zdarzenie audytu `config.warning`), jeśli któryś klucz tożsamości zaczyna się od `dev-key-`.
4. **`Makefile`:** `ifeq ($(OS),Windows_NT)` → `BIN := $(VENV)/Scripts`, `PY ?= python`; w przeciwnym razie zostaje jak jest. Sprawdź `make test` w Git Bash.
5. **`README.md`** (tylko sekcje „Szybki Start” i Docker): jak uruchomić hybrydę lokalnie i w Dockerze; jak zademonstrować zdalny feed (`scripts/feed_server.py`). Liczb w sekcji wyników nie zmieniaj; zaktualizuje je osoba scalająca.

**Akceptacja.** `docker compose config` jest poprawny dla wszystkich profili. Jeśli Docker jest dostępny, `docker compose --profile hybrid up` daje `/healthz` z `embedding.ready: true`, `classifier.ready: true` i `judge.ready: true`. Jeśli Dockera nie ma, napisz to w raporcie.

---

## Raport końcowy (w ostatniej wiadomości)
- lista zmian per zadanie (C1-C6) ze ścieżkami `plik:linia`,
- wynik `python -m pytest -q` i `ruff`,
- zmiany schematu polityki (dodane i usunięte pola), żeby osoba scalająca mogła je sprawdzić z grupami A i B,
- czego nie udało się zweryfikować (np. Docker).
