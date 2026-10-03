// Unit tests for the dashboard's pure modules. Run: node --test tests/dashboard/
import test from 'node:test';
import assert from 'node:assert/strict';

const D = '../../aicl/dashboard/';
const U = await import(D + 'utils.js');
const N = await import(D + 'normalize.js');
const S = await import(D + 'state.js');
const { auth } = await import(D + 'auth.js');
const { createApi, ApiError } = await import(D + 'api.js');

test('fmtRate shows the denominator', () => {
  assert.match(U.fmtRate(46, 50), /^92(\.0)?\s?% \(46\/50\)$/);
  assert.equal(U.fmtRate(0, 0), 'n/a (0/0)');
  assert.match(U.fmtRate(null, null, 0.5), /sample size n\/a/);
  assert.equal(U.fmtRate(null, null, null), U.DASH);
});

test('fmtMs switches to seconds, percent has ≤1 decimal', () => {
  assert.match(U.fmtMs(4.2), /ms$/);
  assert.match(U.fmtMs(1500), /^1[.,]5(0)? s$/);
  assert.equal(U.fmtMs(null), U.DASH);
  assert.ok(!/\d[.,]\d\d/.test(U.fmtPct(0.12345)));
});

test('computeChange never invents a comparison', () => {
  assert.equal(U.computeChange(10, null), null);
  assert.equal(U.computeChange(undefined, 3), null);
  assert.deepEqual(U.computeChange(12, 10), { delta: 2, ratio: 0.2 });
  assert.equal(U.computeChange(5, 0).ratio, null);
});

test('sanitizeForDisplay strips credentials and raw match values', () => {
  const out = U.sanitizeForDisplay({
    api_key: 'sk-1', Authorization: 'Bearer abcdefghijkl', note: 'header Bearer abcdefghijklmnop end',
    decisions: [{ matches: [{ kind: 'email', masked: 'j***@x.pl', value: 'jan@x.pl', raw: 'jan@x.pl' }] }],
  });
  assert.equal(out.api_key, '[removed]');
  assert.equal(out.Authorization, '[removed]');
  assert.ok(!out.note.includes('abcdefghijklmnop'));
  assert.deepEqual(out.decisions[0].matches[0], { kind: 'email', masked: 'j***@x.pl' });
  assert.ok(!JSON.stringify(out).includes('jan@x.pl'));
});

test('topN groups the tail into Other', () => {
  const entries = Array.from({ length: 15 }, (_, i) => ({ key: `k${i}`, value: 15 - i }));
  const top = U.topN(entries, 10);
  assert.equal(top.length, 10);
  assert.equal(top.at(-1).key, 'Other');
  assert.equal(top.at(-1).members.length, 6);
  const total = top.reduce((a, e) => a + e.value, 0);
  assert.equal(total, 120, 'Other keeps the sum intact');
});

test('budgets: null/omitted limit is Unlimited, never zero; 0 is a real limit', () => {
  const [b] = N.normalizeBudgets({ identities: [{ identity: 'a', usage: { tokens: 50, cost_usd: 1 }, limits: { max_tokens: null, max_cost_usd: 0 } }] });
  const tokens = b.resources.find((r) => r.kind === 'tokens');
  const cost = b.resources.find((r) => r.kind === 'cost');
  const compute = b.resources.find((r) => r.kind === 'compute');
  assert.equal(tokens.unlimited, true);
  assert.equal(tokens.level, 'unlimited');
  assert.equal(compute.unlimited, true);
  assert.equal(cost.unlimited, false);
  assert.equal(cost.level, 'exceeded');
  assert.equal(b.exceeded, true);
});

test('budgetLevel thresholds <70 / 70–89 / 90–99 / ≥100', () => {
  assert.equal(N.budgetLevel(0.69), 'normal');
  assert.equal(N.budgetLevel(0.7), 'warning');
  assert.equal(N.budgetLevel(0.9), 'high');
  assert.equal(N.budgetLevel(1), 'exceeded');
  assert.equal(N.budgetLevel(null), 'unlimited');
});

test('events: unknown action/type and garbage are tolerated', () => {
  const list = N.normalizeEvents([
    { ts: '2026-10-04T10:00:00Z', type: 'model.swapped', final_action: 'quarantine' },
    { type: 'request', decisions: null, latency_ms: null, usage: null },
    'not-an-object', null, 42,
  ]);
  assert.equal(list.length, 2);
  assert.equal(list[0].type, 'model.swapped');
  assert.ok(typeof list[0].finalAction === 'string');
  assert.equal(list[1].finalAction, 'unknown');
  assert.equal(list[1].latency.totalOverhead, null);
  // stable synthetic id for events without event_id
  assert.equal(N.normalizeEvents([{ type: 'x', a: 1 }])[0].id, N.normalizeEvents([{ type: 'x', a: 1 }])[0].id);
});

test('normalizers accept empty payloads', () => {
  for (const fn of [N.normalizeSummary, N.normalizeLatency, N.normalizeBudgets, N.normalizeControls, N.normalizePolicy, N.normalizeHealth, N.normalizeTestReport, N.normalizeFuzzReport]) {
    for (const p of [null, {}, [], '']) assert.doesNotThrow(() => fn(p), `${fn.name}(${JSON.stringify(p)})`);
  }
});

test('validation maps FastAPI 422 detail to path + message', () => {
  const v = N.normalizeValidation({ detail: [{ loc: ['body', 'controls', 'x', 'threshold'], msg: 'Input should be ≤ 1', type: 'x' }] });
  assert.equal(v.ok, false);
  assert.ok(v.errors[0].path.includes('threshold'));
  assert.equal(v.errors[0].message, 'Input should be ≤ 1');
});

test('parseJsonl counts bad lines', () => {
  const r = N.parseJsonl('{"a":1}\nnot json\n\n{"b":2}\n');
  assert.equal(r.events.length, 2);
  assert.equal(r.bad, 1);
});

test('hash round-trip carries only non-secret filters', () => {
  const h = S.buildHash('events', { ...S.defaultFilters(), action: 'block', identity: 'support-agent-01', token: 'secret' });
  assert.ok(!h.includes('secret'));
  const p = S.parseHash(h);
  assert.equal(p.view, 'events');
  assert.equal(p.filters.action, 'block');
  assert.equal(p.filters.identity, 'support-agent-01');
  assert.equal(S.parseHash('#/nope?admin_key=x').view, 'overview');
  assert.equal(S.parseHash('#/nope?admin_key=x').filters.admin_key, undefined);
});

// ---------------------------------------------------------------- api error mapping (mocked fetch)
function mockFetch(handler) {
  globalThis.fetch = async (url, opts) => handler(url, opts);
}
const json = (status, body, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });

test('api sends Bearer, maps statuses and redacts the key', async () => {
  const key = 'very-secret-admin-key-123';
  auth.setKey(key);
  let seen = null;
  let unauthorized = 0;
  const api = createApi({ timeoutMs: 200, onUnauthorized: () => { unauthorized += 1; } });
  mockFetch((url, opts) => { seen = opts.headers; return json(200, { ok: 1 }); });
  await api.summary();
  assert.equal(seen.Authorization, `Bearer ${key}`);

  const cases = [[401, 'unauthorized'], [403, 'forbidden'], [404, 'not_found'], [429, 'rate_limited'], [422, 'bad_request'], [500, 'server'], [503, 'server']];
  for (const [status, kind] of cases) {
    mockFetch(() => json(status, { detail: `echo ${key}` }, status === 429 ? { 'Retry-After': '7' } : {}));
    const err = await api.latency().catch((e) => e);
    assert.ok(err instanceof ApiError);
    assert.equal(err.kind, kind, `status ${status}`);
    assert.ok(!err.message.includes(key), 'key must never appear in error text');
    if (status === 429) assert.equal(err.retryAfterMs, 7000);
  }
  assert.equal(unauthorized, 1);

  mockFetch(() => { throw new TypeError('fetch failed'); });
  assert.equal((await api.budgets().catch((e) => e)).kind, 'network');

  mockFetch((_u, opts) => new Promise((_res, rej) => opts.signal.addEventListener('abort', () => rej(new DOMException('aborted', 'AbortError')))));
  assert.equal((await api.controls().catch((e) => e)).kind, 'timeout');

  mockFetch(() => new Response('<html>', { status: 200 }));
  assert.equal((await api.policy().catch((e) => e)).kind, 'parse');
  auth.clear();
});

test('api: a newer call aborts the older in-flight call for the same key', async () => {
  auth.useOpenMode();
  const api = createApi({ timeoutMs: 1000 });
  let n = 0;
  mockFetch((_u, opts) => new Promise((res, rej) => {
    n += 1;
    const me = n;
    opts.signal.addEventListener('abort', () => rej(new DOMException('aborted', 'AbortError')));
    setTimeout(() => res(json(200, { me })), 30);
  }));
  const first = api.summary().catch((e) => e);
  const second = api.summary();
  assert.equal((await first).kind, 'aborted');
  assert.deepEqual(await second, { me: 2 });
  assert.deepEqual(auth.headers(), {}, 'open mode sends no Authorization header');
  auth.clear();
});
