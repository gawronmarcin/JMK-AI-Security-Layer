# AICL — dashboard administracyjny (R5)

Statyczny dashboard (HTML + CSS + vanilla JS, moduły ES) dla bramki **AI Control Layer**. Nie wymaga kroku
budowania ani dostępu do internetu: Chart.js 4.5.1 jest dołączony lokalnie w `vendor/`, czcionki są systemowe,
nie ma CDN‑ów ani telemetrii. Dashboard korzysta wyłącznie z `/healthz` i `/admin/*` (ARCHITECTURE §5.1) oraz
opcjonalnie ze statycznych raportów testów i fuzzera.

## Uruchomienie

### Z bramką FastAPI (docelowo)

```python
from fastapi.staticfiles import StaticFiles

app.mount("/dashboard", StaticFiles(directory="aicl/dashboard", html=True), name="dashboard")
# opcjonalnie, jeśli runner testów zapisuje raporty w ./reports:
app.mount("/reports", StaticFiles(directory="reports"), name="reports")
```

Otwórz `http://<host>:<port>/dashboard/`, wpisz klucz admina (rola `admin`, §6.2) i zaloguj się.
Klucz jest przechowywany tylko w pamięci strony (zamknięcie funkcji w `auth.js`): nie trafia do `localStorage`,
`sessionStorage`, ciasteczek, adresu URL, logów ani komunikatów błędów. Po przeładowaniu strony trzeba zalogować się ponownie.

Tryb lokalny bez autoryzacji (`AICL_ADMIN_OPEN=1`) wybiera się ręcznie w oknie logowania
(„More options → Connect without key”). Dashboard nigdy nie zakłada go sam: jeśli bramka zwróci 401, pokazuje
komunikat „admin auth is not disabled”.

### Lokalny serwer deweloperski (atrapa API, tylko biblioteka standardowa Pythona)

```bash
python tests/dashboard/mock_admin_server.py --port 8080 --key dev-key-123 --live   # ciągle dopisuje zdarzenia
python tests/dashboard/mock_admin_server.py --open                                 # bez klucza
python tests/dashboard/mock_admin_server.py --scenario edge                        # XSS, nieznane typy, null-e
python tests/dashboard/mock_admin_server.py --scenario empty                       # puste odpowiedzi
python tests/dashboard/mock_admin_server.py --scenario large                       # ~20 000 zdarzeń
python tests/dashboard/mock_admin_server.py --fail summary=500,latency=429,budgets=timeout,controls=403
```

Atrapa serwuje `/dashboard/`, wszystkie endpointy `/admin/*`, `/healthz` oraz `/reports/test_report.json` i
`/reports/fuzz_latest.json`. Jeśli nie podasz `--key`, wygeneruje klucz i wypisze go jeden raz na stderr.
Nagłówka `Authorization` nie loguje.

### Tryb DEMO DATA

`/dashboard/?demo=1` albo przycisk „Open demo data” w oknie logowania. Tryb demo:

- trzeba go włączyć jawnie; nigdy nie uruchamia się sam po błędzie API (sprawdza to test e2e),
- przez cały czas pokazuje pasek **DEMO DATA** i przycisk „Exit demo”, a eksport ma przyrostek `-DEMO`,
- używa osobnego adaptera (`demo/demo-adapter.js`, ładowanego dynamicznie przez `import()`), więc nie miesza się z produkcyjnym `api.js`,
- działa na deterministycznych danych z `demo/` (seed `20261003`), bez wartości losowanych w przeglądarce.
  Znaczniki czasu są przesuwane tak, aby punkt zakotwiczenia fikstur odpowiadał chwili „teraz”,
- nie pozwala na `validate` ani `reload`, bo te akcje wymagają działającej bramki.

Fikstury generuje się ponownie poleceniem `python tests/dashboard/generate_demo_fixtures.py`. Wynik jest bajtowo identyczny przy tym samym seedzie.

## Pliki

| Plik | Rola |
|---|---|
| `index.html` | szkielet, CSP (`script-src 'self'; style-src 'self'`), konfiguracja JSON `#aicl-config`, okno logowania |
| `styles.css` | motyw ciemny SOC, siatka 12 kolumn, układ responsywny, focus, `prefers-reduced-motion`, `forced-colors` |
| `app.js` | bootstrap, routing (`#/view?filtry`), status bramki, logowanie i 401, eksport, nawigacja mobilna |
| `api.js` | **jedyny** moduł wołający bramkę: `fetch`, `AbortController`, timeouty, jedno żądanie w locie na klucz, mapowanie błędów (`ApiError.kind`), `Retry-After` |
| `auth.js` | przechowywanie klucza w pamięci i redakcja klucza w tekstach |
| `normalize.js` | cienka warstwa normalizacji odpowiedzi (aliasy pól, `null`/brak, nieznane typy) |
| `derive.js` | agregacje z załadowanych zdarzeń (kubełki czasu, liczniki, percentyle) |
| `state.js` | jeden kontrolowany store i synchronizacja z hashem URL (tylko filtry jawne) |
| `refresh.js` | harmonogram odświeżania: tylko widoczna karta, brak duplikatów, wykładniczy backoff, stan „stale” |
| `resources.js` | definicje zasobów i przyrostowy loader zdarzeń (`since` + deduplikacja) |
| `charts.js` | wrappery Chart.js: aktualizacja w miejscu (bez niszczenia wykresów), linia celu, tekst w środku donuta |
| `components.js` | panele ze stanami, KPI, tabele, szuflada, dialogi, toasty, pułapka focusu |
| `utils.js` | formatowanie `Intl`, czas, `el()` (wyłącznie tekst), `sanitizeForDisplay` |
| `views/*.js` | Overview, Threats, Controls, Budgets, Performance, Tests, Audit events, Policy |
| `demo/` | adapter DEMO i deterministyczne fikstury |
| `vendor/chart.umd.min.js` | Chart.js 4.5.1 (MIT, licencja w `vendor/chart.js.LICENSE.md`) |
| `tests/dashboard/` | testy jednostkowe (Node), e2e (Playwright), atrapa API, generator fikstur |

## Obsługiwane endpointy

| Endpoint | Użycie | Interwał |
|---|---|---|
| `GET /healthz` | status bramki, `policy_version`, `feed_version` | 5 s |
| `GET /admin/metrics/summary` | KPI, porównanie z poprzednim okresem, rankingi, szereg czasowy | 5 s |
| `GET /admin/metrics/latency` | p50/p95/p99 dla `total_overhead`, `upstream` i każdej kontroli; sędzia semantyczny | 5 s |
| `GET /admin/metrics/budgets` | zużycie i limity per tożsamość | 5 s |
| `GET /admin/events?limit=&since=` | strumień zdarzeń (przyrostowo `since=<ostatni ts>`); historia przeładowań z 7 dni | wg selektora (domyślnie 5 s) |
| `GET /admin/controls` | tabela kontroli, poziomy, pokrycie testami, opcjonalny katalog zagrożeń | 15 s |
| `GET /admin/policy` | aktywna polityka (bez sekretów) i wersje | 15 s |
| `POST /admin/policy/validate` | body YAML (`Content-Type: application/yaml`); tylko walidacja | na żądanie |
| `POST /admin/policy/reload` | wymuszenie przeładowania po potwierdzeniu | na żądanie |
| `GET /admin/export/audit.jsonl` | eksport z nagłówkiem `Authorization`, pobierany jako blob | na żądanie |
| `GET /reports/test_report.json`, `GET /reports/fuzz_latest.json` | raport testów (§11.6) i fuzzera (§11.7); 404 oznacza „unavailable”, a nie awarię | 60 s |

Ścieżki raportów, bazowy URL API, timeout i limity zdarzeń ustawia się w `#aicl-config` w `index.html`.
Odpytywane są tylko zasoby potrzebne bieżącemu widokowi i paskowi górnemu.

## Założenia dotyczące payloadów

Kontrakt CONTRACT (§8, zdarzenie audytu) jest używany bez zmian nazw pól. Endpointy `/admin/*` są w ARCHITECTURE
oznaczone jako GUIDANCE, dlatego `normalize.js` przyjmuje kilka wariantów. Poniżej kształt **zalecany** (generuje
go atrapa) i akceptowane aliasy:

- **summary**: `requests_total`, `by_action{allow,flag,redact,require_approval,block}` (lub płaskie `blocks`,
  `redactions`, …), `cost_usd`, `window{from,to}`, `previous{…te same pola…}` (bez tego KPI pokazują
  „no comparison data”, a zmiana nie jest liczona), `by_control`, `by_threat`, `by_identity`, `by_owasp`,
  `by_severity`, `by_endpoint` (obiekt `{klucz: liczba}` albo lista `[{key,count}]`), `semantic{judged,skipped}`,
  `timeseries{bucket_seconds, points[{ts, allow, flag, …}]}`.
- **latency**: `total_overhead`, `upstream` i `semantic_judge` jako `{p50,p95,p99,count}` (także `*_ms`),
  `per_control{ID:{p50,p95,p99,count}}` albo lista z `id`.
- **budgets**: `identities[{identity, role, budget, window, window_started_at?, resets_at?, on_exceed, usage{tokens,
  cost_usd, compute_seconds, requests_per_minute, tool_calls_per_session}, limits{max_tokens, max_cost_usd,
  max_compute_seconds, max_requests_per_minute, max_tool_calls_per_session}}]`. Limit `null` lub pominięty oznacza
  **Unlimited** (§6.5). `0` to prawdziwy limit.
- **controls**: `controls[{id, key, name, enabled, mode?, stages, priority, tier, type, threat_ids, on_error,
  levels{strict,balanced,permissive:{action,…progi}}, current?, tests{total,negative,positive,edge,by_threat}}]`,
  `active_profile`, opcjonalnie `threats[{id,title,owasp[],atlas[]}]`.
- **policy**: `policy_version`, `feed_version`, `loaded_at`, `last_reload_result`, `last_reload_error`,
  `policy{version, meta{name,description}, active_profile, mode, evaluation, on_error_default, identities, controls,
  signature_feeds}`.
- **validate**: `{valid|ok, errors[{loc|path, msg|message}]}` albo FastAPI 422 `detail[{loc,msg}]`.
  Ścieżka pola jest pokazywana jako `loc` połączone kropkami.
- **events**: tablica zdarzeń §8 albo `{events:[…]}`. Zdarzenia bez `event_id` dostają stabilny hash.
  Nieznane `type` i `final_action` są pokazywane jako „unknown” z neutralnym kolorem, a nie odrzucane.
- **raport testów**: `generated_at`, `status`, `totals{total,passed,failed,skipped}`,
  `overall{negatives,negatives_blocked,positives,positives_blocked}`, `per_control{ID:{…}}`, `coverage[{control_id,
  threat_id,kind}]`, `failures[…]`, `overhead{p50,p95}`. **Fuzzer**: `per_control`, `per_strategy`
  `{attempts,bypasses}`.

Gdy brakuje źródła danych, wykres korzysta z załadowanych zdarzeń i ma o tym podpis (np. „Derived from 1 234 loaded
audit events”). Dashboard nie generuje losowych wartości i nie liczy zmian bez danych z poprzedniego okresu.

## Brakujące dane po stronie backendu (propozycje dla R1/R5)

1. `/admin/metrics/summary` nie ma w §5.1 ani okna, ani **poprzedniego okresu**. Bez `previous` nie da się pokazać zmian KPI.
2. Brak parametru zakresu (`from`/`to`, `bucket`) w `/admin/metrics/*`. Liczniki obejmują okno serwera, a wykresy krótkich zakresów są liczone ze zdarzeń.
3. `/admin/events` nie ma filtrów `type`, `severity`, `endpoint`, `threat` ani `until` i nie paginuje kursorem. Historia `policy.*` i `feed.reloaded` skanuje najnowsze `eventsLimit` zdarzeń z 7 dni i informuje o obcięciu.
4. Brak źródła katalogu zagrożeń z referencjami OWASP/ATLAS w `/admin/*`. Proponowane pole to `threats` w `/admin/controls` (z `catalog/threats.yaml`).
5. Brak `resets_at` / `window_started_at` w budżetach. Bez nich czas resetu jest „unknown”.
6. Brak `last_reload_at/result/error` w `/admin/policy`. Bez nich ostatnie przeładowanie jest wyprowadzane ze zdarzeń audytu.
7. Raporty testów i fuzzera nie mają endpointu `/admin/*`. Dashboard czyta pliki statyczne spod `/reports/…` (do skonfigurowania).
8. W §8 nie ma `severity` na poziomie zdarzenia ani `endpoint` dla zdarzeń systemowych. Dashboard bierze najwyższe `severity` z decyzji działających.
9. Brak `POST /admin/policy/preview` (stretch). Dashboard go nie wywołuje.

## Testy

```bash
node --test tests/dashboard/                     # 14 testów jednostkowych (formatowanie, sanitizacja, normalizacja, hash URL, api z mockiem fetch)
# e2e: uruchom 4 atrapy (polecenia w nagłówku pliku), potem:
python tests/dashboard/e2e_dashboard.py --shots /tmp/aicl-shots   # 54 kontrole Playwright + zrzuty ekranu
```

## Checklista akceptacji

| # | Kryterium | Jak sprawdzić | Status |
|---|---|---|---|
| 1 | Logowanie, zły klucz → komunikat, dobry → widoki | e2e „wrong key → 401”, „gateway Online” | ✅ automat |
| 2 | 401 w trakcie sesji czyści klucz i pokazuje logowanie | e2e (route 401) i brak `Authorization` po 401 | ✅ automat |
| 3 | 403 → „lacks the admin role”; 429 → backoff z `Retry-After`; 5xx → błąd panelu i retry | atrapa `--fail …`, test jednostkowy mapowania | ✅ automat |
| 4 | Puste odpowiedzi → stany „No data” | atrapa `--scenario empty`, e2e | ✅ automat |
| 5 | Częściowa awaria izoluje panele, status „Degraded” | atrapa `--fail`, e2e | ✅ automat |
| 6 | Duża liczba zdarzeń (limit, paginacja, `maxEventsInMemory`, komunikat o obcięciu) | atrapa `--scenario large` (~20 000 zdarzeń) | ✅ sprawdzone ręcznie w Playwright |
| 7 | Brakujące pola, `null`, nieznany `type`/`action` | atrapa `--scenario edge`, testy jednostkowe | ✅ automat |
| 8 | Limit `null` → „Unlimited”, nigdy 0 | test jednostkowy, widok Budgets | ✅ automat |
| 9 | Mobile 390 px bez poziomego przewijania strony; menu otwiera się i zamyka Escape | e2e | ✅ automat |
| 10 | Klawiatura: skip link, focus widoczny, wiersze tabel Enter, Escape, pułapka focusu | e2e (szuflada, skip link) | ✅ automat |
| 11 | Token nie trafia do storage, cookies, URL ani DOM | e2e | ✅ automat |
| 12 | XSS: `reason`, `masked`, `error`, ID renderowane jako tekst; surowe `value`/`raw` i klucze nie są pokazywane | e2e edge | ✅ automat |
| 13 | Wykresy aktualizowane w miejscu przy odświeżaniu (bez migotania, ukryte serie pozostają ukryte) | `--live`, ukryć serię w legendzie i obserwować | ☐ ręcznie |
| 14 | Cross-filtering (KPI, słupki, donut, heatmapa, chipy) → Audit events z filtrem w hashu | e2e (KPI → `action=block`) | ✅ automat |
| 15 | Eksport audit JSONL z autoryzacją | e2e (download) | ✅ automat |
| 16 | Badge DEMO DATA zawsze widoczny w trybie demo; demo nie startuje po błędzie | e2e | ✅ automat |
| 17 | Brak błędów konsoli i naruszeń CSP | e2e | ✅ automat |
| 18 | Odpytywanie zatrzymuje się na ukrytej karcie i wznawia po powrocie | przełączyć kartę, obserwować log atrapy | ☐ ręcznie |
| 19 | Kontrast WCAG AA, znaczenie przekazywane nie tylko kolorem (ikony, kształty punktów, wzory) | przegląd wizualny | ☐ ręcznie |
