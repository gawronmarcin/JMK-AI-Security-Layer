// AICL dashboard — resource definitions: what to fetch, how to normalise it and how often.
// Works with any adapter that implements the api.js interface (real gateway or explicit demo).

import {
  normalizeBudgets, normalizeControls, normalizeEvents, normalizeFuzzReport, normalizeHealth,
  normalizeLatency, normalizePolicy, normalizeSummary, normalizeTestReport, controlsThreatCatalog,
} from './normalize.js';
import { resolveRange } from './utils.js';

export const POLICY_EVENT_TYPES = ['policy.reloaded', 'policy.rejected', 'feed.reloaded'];

/** Incremental audit-event loader: full fetch for a new/wider range, then `since=<latest>` merges. */
function createEventsLoader(api, cfg) {
  const cache = new Map();
  let coveredFrom = null;
  let latest = null;
  let truncated = false;

  return async function loadEvents(state) {
    const { from } = resolveRange(state.filters);
    const full = coveredFrom === null || from < coveredFrom || latest === null;
    const since = full ? from : new Date(latest.getTime() - 2000); // small overlap; dedup by id
    const raw = await api.events({ limit: cfg.eventsLimit, since: since.toISOString() });
    const list = normalizeEvents(raw);
    if (full) { cache.clear(); truncated = false; coveredFrom = from; }
    if (list.length >= cfg.eventsLimit) truncated = true;
    for (const e of list) {
      cache.set(e.id, e);
      if (e.ts && (!latest || e.ts > latest)) latest = e.ts;
    }
    let events = [...cache.values()].sort((a, b) => (b.ts?.getTime() || 0) - (a.ts?.getTime() || 0));
    if (events.length > cfg.maxEventsInMemory) {
      for (const e of events.slice(cfg.maxEventsInMemory)) cache.delete(e.id);
      events = events.slice(0, cfg.maxEventsInMemory);
      truncated = true;
    }
    return { events, truncated, limit: cfg.eventsLimit, coveredFrom, received: list.length };
  };
}

export function createResources(api, cfg) {
  const loadEvents = createEventsLoader(api, cfg);
  const report = (key, path, norm) => async () => {
    if (!path) { const e = new Error('Not configured'); e.kind = 'not_found'; throw e; }
    return norm(await api.report(key, path));
  };
  return {
    health: { load: async () => normalizeHealth(await api.health()), minIntervalMs: 5000, abort: () => api.abort('health') },
    policy: { load: async () => normalizePolicy(await api.policy()), minIntervalMs: 15000, abort: () => api.abort('policy') },
    summary: { load: async () => normalizeSummary(await api.summary()), minIntervalMs: 5000, abort: () => api.abort('summary') },
    latency: { load: async () => normalizeLatency(await api.latency()), minIntervalMs: 5000, abort: () => api.abort('latency') },
    budgets: { load: async () => normalizeBudgets(await api.budgets()), minIntervalMs: 5000, abort: () => api.abort('budgets') },
    controls: {
      load: async () => { const raw = await api.controls(); return { list: normalizeControls(raw), catalog: controlsThreatCatalog(raw) }; },
      minIntervalMs: 15000,
      abort: () => api.abort('controls'),
    },
    events: { load: loadEvents, minIntervalMs: 0, abort: () => api.abort('events') },
    // Policy/feed reload history over 7 days. /admin/events has no `type` filter (§5.1), so the
    // newest `eventsLimit` events are scanned and filtered here; truncation is reported.
    policyHistory: {
      load: async () => {
        const since = new Date(Date.now() - 7 * 86400e3);
        const list = normalizeEvents(await api.events({ limit: cfg.eventsLimit, since: since.toISOString(), key: 'events:policy' }));
        const events = list.filter((e) => POLICY_EVENT_TYPES.includes(e.type)).sort((a, b) => (b.ts?.getTime() || 0) - (a.ts?.getTime() || 0));
        return { events, scanned: list.length, truncated: list.length >= cfg.eventsLimit, since };
      },
      minIntervalMs: 30000,
      abort: () => api.abort('events:policy'),
    },
    testReport: { load: report('tests', cfg.reports?.tests, normalizeTestReport), minIntervalMs: 60000, optional: true, abort: () => api.abort('report:tests') },
    fuzzReport: { load: report('fuzz', cfg.reports?.fuzz, normalizeFuzzReport), minIntervalMs: 60000, optional: true, abort: () => api.abort('report:fuzz') },
  };
}

/** Action configured for the active profile (explicit `current`/`action` from the API wins). */
export function controlAction(c, profile) {
  return c.currentAction || (profile && c.levels[profile] ? c.levels[profile].action : null);
}

export function controlLevel(c, profile) {
  return (profile && c.levels[profile]) || null;
}

/** Merged threat catalog (controls API, summary, test report — whichever provides one). */
export function threatCatalog(state) {
  const m = new Map();
  for (const src of [state.resources.summary?.data?.threatCatalog, state.resources.testReport?.data?.threatCatalog, state.resources.controls?.data?.catalog]) {
    if (src) for (const [k, v] of src) m.set(k, { ...(m.get(k) || {}), ...v });
  }
  return m;
}

export function activeProfile(state) {
  return state.resources.policy?.data?.activeProfile || state.resources.health?.data?.profile || null;
}
