// AICL dashboard — aggregations computed from *loaded* audit events.
// Used only where /admin/metrics/* does not provide the breakdown; every panel that uses
// these values says so ("derived from N loaded events"), so they are never mistaken for
// gateway-wide counters.

import { ACTIONS, bucketSizeFor, percentile, severityRank } from './utils.js';

export function inRange(events, from, to) {
  const f = from ? from.getTime() : -Infinity;
  const t = to ? to.getTime() : Infinity;
  return events.filter((e) => e.ts && e.ts.getTime() >= f && e.ts.getTime() <= t);
}

export const requestEvents = (events) => events.filter((e) => e.type === 'request');

/** Per-action counts per time bucket. Unknown actions are kept in `other`. */
export function bucketActions(events, from, to, bucketMs = null) {
  const span = Math.max(1, to - from);
  const size = bucketMs || bucketSizeFor(span);
  const start = Math.floor(from.getTime() / size) * size;
  const n = Math.max(1, Math.ceil((to.getTime() - start) / size));
  const buckets = Array.from({ length: n }, (_, i) => {
    const row = { t: new Date(start + i * size), end: new Date(start + (i + 1) * size), other: 0, total: 0 };
    for (const a of ACTIONS) row[a] = 0;
    return row;
  });
  for (const e of events) {
    if (!e.ts) continue;
    const i = Math.floor((e.ts.getTime() - start) / size);
    if (i < 0 || i >= n) continue;
    const a = ACTIONS.includes(e.finalAction) ? e.finalAction : 'other';
    buckets[i][a] += 1;
    buckets[i].total += 1;
  }
  return { buckets, bucketMs: size };
}

/** Re-buckets a backend timeseries into the dashboard's buckets (sums counts). */
export function rebucketSeries(points, from, to, bucketMs = null) {
  const size = bucketMs || bucketSizeFor(Math.max(1, to - from));
  const start = Math.floor(from.getTime() / size) * size;
  const n = Math.max(1, Math.ceil((to.getTime() - start) / size));
  const buckets = Array.from({ length: n }, (_, i) => {
    const row = { t: new Date(start + i * size), end: new Date(start + (i + 1) * size), other: 0, total: 0 };
    for (const a of ACTIONS) row[a] = 0;
    return row;
  });
  for (const p of points) {
    const i = Math.floor((p.t.getTime() - start) / size);
    if (i < 0 || i >= n) continue;
    for (const a of ACTIONS) { buckets[i][a] += p[a] || 0; buckets[i].total += p[a] || 0; }
  }
  return { buckets, bucketMs: size };
}

export function countBy(events, keyFn) {
  const m = new Map();
  for (const e of events) {
    const keys = keyFn(e);
    for (const k of Array.isArray(keys) ? keys : [keys]) {
      if (k === null || k === undefined || k === '') continue;
      m.set(k, (m.get(k) || 0) + 1);
    }
  }
  return [...m.entries()].map(([key, value]) => ({ key, value })).sort((a, b) => b.value - a.value);
}

export function actionTotals(events) {
  const out = { allow: 0, flag: 0, redact: 0, require_approval: 0, block: 0, other: 0 };
  for (const e of events) out[ACTIONS.includes(e.finalAction) ? e.finalAction : 'other'] += 1;
  return out;
}

/** Highest severity per threat among acting decisions. */
export function threatSeverity(events) {
  const m = new Map();
  for (const e of events) for (const d of e.decisions) {
    if (d.skipped || (d.action === 'allow' && !d.shadowSuppressed)) continue;
    for (const t of d.threatIds) {
      const cur = m.get(t) || {};
      const sev = d.severity || 'unknown';
      cur[sev] = (cur[sev] || 0) + 1;
      m.set(t, cur);
    }
  }
  return m;
}

/** Semantic judge routing: requests where C-INJ-SEM actually ran vs. requests it skipped / never saw. */
export function semanticUsage(events, judgeId = 'C-INJ-SEM') {
  let judged = 0;
  let skipped = 0;
  let total = 0;
  for (const e of requestEvents(events)) {
    total += 1;
    const d = e.decisions.find((x) => x.controlId === judgeId);
    if (d && !d.skipped) judged += 1; else skipped += 1;
  }
  return { judged, skipped, total, source: 'events' };
}

/** Per-control latency percentiles from `latency_ms.per_control` of loaded events. */
export function controlLatencyFromEvents(events) {
  const m = new Map();
  for (const e of events) for (const [id, v] of Object.entries(e.latency.perControl || {})) {
    if (!m.has(id)) m.set(id, []);
    m.get(id).push(v);
  }
  return [...m.entries()].map(([id, vals]) => {
    vals.sort((a, b) => a - b);
    return { id, p50: percentile(vals, 50), p95: percentile(vals, 95), p99: percentile(vals, 99), count: vals.length };
  });
}

export function overheadFromEvents(events) {
  const vals = events.map((e) => e.latency.totalOverhead).filter((v) => v !== null).sort((a, b) => a - b);
  if (!vals.length) return null;
  return { p50: percentile(vals, 50), p95: percentile(vals, 95), p99: percentile(vals, 99), count: vals.length };
}

/** Client-side filter matching every Audit events filter. */
export function filterEvents(events, f) {
  const q = (f.q || '').trim().toLowerCase();
  return events.filter((e) => {
    if (f.action && e.finalAction !== f.action && !(f.action === 'unknown' && !['allow', 'flag', 'redact', 'require_approval', 'block'].includes(e.finalAction))) return false;
    if (f.type && e.type !== f.type) return false;
    if (f.severity && e.severity !== f.severity) return false;
    if (f.identity && e.identity !== f.identity) return false;
    if (f.endpoint && e.endpoint !== f.endpoint) return false;
    if (f.control && !e.controlIds.includes(f.control)) return false;
    if (f.threat && !e.threatIds.includes(f.threat)) return false;
    if (f.policyVersion && e.policyVersion !== f.policyVersion) return false;
    if (q && !((e.requestId || '').toLowerCase().includes(q) || (e.sessionId || '').toLowerCase().includes(q) || (e.eventId || '').toLowerCase().includes(q))) return false;
    return true;
  });
}

export function maxSeverity(list) {
  let best = null;
  for (const s of list) if (severityRank(s) > severityRank(best)) best = s;
  return best;
}

/** Interventions per control over time (for the control detail drawer). */
export function controlTrend(events, controlId, from, to) {
  const subset = events.filter((e) => e.controlIds.includes(controlId));
  return bucketActions(subset, from, to);
}
