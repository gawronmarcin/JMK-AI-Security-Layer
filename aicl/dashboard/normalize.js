// AICL dashboard — thin normalisation layer between raw admin payloads and the UI.
// ARCHITECTURE.md fixes the audit event (§8) and the policy envelope (§6) but leaves the exact
// /admin/* response shapes to R1/R5. Every normaliser therefore accepts the documented snake_case
// form plus a few obvious variants (wrapped arrays, maps vs. lists, camelCase) and never throws
// on missing fields, nulls, empty arrays or unknown enum values.

import { ACTIONS, asArray, asStr, isNum, isObj, pick, severityRank, toDate, toNum } from './utils.js';

// ---------------------------------------------------------------- generic helpers

const ID_KEYS = ['id', 'key', 'name', 'control_id', 'controlId', 'threat_id', 'threatId', 'identity', 'category', 'label'];
const COUNT_KEYS = ['count', 'value', 'n', 'total', 'events', 'requests', 'interventions', 'hits'];

/** Accepts {k: n}, {k: {count}} or [{id, count}] and returns [{key, value}] (value is a finite number). */
export function toEntries(v) {
  const out = [];
  if (Array.isArray(v)) {
    for (const item of v) {
      if (!isObj(item)) continue;
      const key = asStr(pick(...ID_KEYS.map((k) => item[k])));
      const value = toNum(pick(...COUNT_KEYS.map((k) => item[k])));
      if (key !== null && value !== null) out.push({ key, value, extra: item });
    }
  } else if (isObj(v)) {
    for (const [key, raw] of Object.entries(v)) {
      const value = isObj(raw) ? toNum(pick(...COUNT_KEYS.map((k) => raw[k]))) : toNum(raw);
      if (value !== null) out.push({ key, value, extra: isObj(raw) ? raw : null });
    }
  }
  return out;
}

/** Unwraps {items|events|data|results: [...]} or returns the array itself. */
export function unwrapList(payload, ...keys) {
  if (Array.isArray(payload)) return payload;
  if (!isObj(payload)) return [];
  for (const k of [...keys, 'items', 'data', 'results']) if (Array.isArray(payload[k])) return payload[k];
  return [];
}

function strList(v) {
  if (Array.isArray(v)) return v.map((x) => (isObj(x) ? asStr(pick(x.id, x.threat_id, x.name)) : asStr(x))).filter(Boolean);
  if (typeof v === 'string' && v) return [v];
  return [];
}

function normAction(a) {
  if (typeof a !== 'string' || !a) return null;
  return a.trim().toLowerCase();
}

// ---------------------------------------------------------------- /healthz

export function normalizeHealth(p) {
  const body = isObj(p) ? p : {};
  const status = String(pick(body.status, body.state, p === null ? 'ok' : undefined, 'unknown')).toLowerCase();
  const ok = ['ok', 'healthy', 'up', 'pass', 'alive', 'ready'].includes(status) || body.ok === true;
  return {
    status,
    ok,
    policyVersion: asStr(pick(body.policy_version, body.policyVersion)),
    feedVersion: asStr(pick(body.feed_version, body.feedVersion)),
    profile: asStr(pick(body.active_profile, body.profile)),
    mode: asStr(body.mode),
    uptimeSeconds: toNum(pick(body.uptime_seconds, body.uptime)),
  };
}

// ---------------------------------------------------------------- /admin/metrics/summary

function actionCounts(obj) {
  const src = isObj(obj) ? obj : {};
  const out = { allow: null, flag: null, redact: null, require_approval: null, block: null };
  const byAction = isObj(src.by_action) ? src.by_action : isObj(src.byAction) ? src.byAction : isObj(src.actions) ? src.actions : null;
  if (byAction) for (const e of toEntries(byAction)) out[normAction(e.key)] = e.value;
  // flat counter aliases (documented in §5.1 as "requests, blocks, redactions")
  out.block = pick(out.block, toNum(pick(src.blocks, src.blocked, src.block)));
  out.redact = pick(out.redact, toNum(pick(src.redactions, src.redacted, src.redact)));
  out.flag = pick(out.flag, toNum(pick(src.flags, src.flagged, src.flag)));
  out.require_approval = pick(out.require_approval, toNum(pick(src.approvals_required, src.approval_required, src.require_approval)));
  out.allow = pick(out.allow, toNum(pick(src.allowed, src.allows, src.allow)));
  return out;
}

function totalRequests(src, counts) {
  const explicit = toNum(pick(src.requests_total, src.total_requests, src.requests, src.total, src.request_count));
  if (explicit !== null) return explicit;
  const known = ACTIONS.map((a) => counts[a]).filter((v) => v !== null);
  return known.length ? known.reduce((s, v) => s + v, 0) : null;
}

function normalizeTimeseries(raw) {
  const pts = Array.isArray(raw) ? raw : isObj(raw) ? asArray(pick(raw.points, raw.buckets, raw.series, raw.data)) : [];
  const bucketMs = isObj(raw) ? (toNum(raw.bucket_seconds) !== null ? raw.bucket_seconds * 1000 : toNum(pick(raw.bucket_ms, raw.bucketMs))) : null;
  const points = [];
  for (const p of pts) {
    if (!isObj(p)) continue;
    const t = toDate(pick(p.ts, p.t, p.time, p.bucket, p.start, p.timestamp));
    if (!t) continue;
    const counts = actionCounts(p);
    const row = { t };
    for (const a of ACTIONS) row[a] = counts[a] || 0;
    points.push(row);
  }
  points.sort((a, b) => a.t - b.t);
  return points.length ? { points, bucketMs } : null;
}

export function normalizeSummary(p) {
  const src = isObj(p) ? (isObj(p.summary) ? p.summary : p) : {};
  const counts = actionCounts(src);
  const total = totalRequests(src, counts);
  const prevRaw = pick(src.previous, src.previous_period, src.comparison);
  let previous = null;
  if (isObj(prevRaw)) {
    const pc = actionCounts(prevRaw);
    previous = { total: totalRequests(prevRaw, pc), ...pc, costUsd: toNum(pick(prevRaw.cost_usd, prevRaw.costUsd)), p95OverheadMs: toNum(prevRaw.p95_overhead_ms) };
  }
  const sem = pick(src.semantic, src.semantic_judge, src.judge);
  let semantic = null;
  if (isObj(sem)) {
    const judged = toNum(pick(sem.judged, sem.invoked, sem.calls, sem.runs));
    const skipped = toNum(pick(sem.skipped, sem.cheap_path, sem.not_judged));
    semantic = judged === null && skipped === null ? null : { judged, skipped, source: 'summary' };
  }
  const win = isObj(src.window) ? { from: toDate(src.window.from || src.window.start), to: toDate(src.window.to || src.window.end) } : null;
  return {
    total,
    counts,
    previous,
    byControl: toEntries(pick(src.by_control, src.byControl, src.controls)),
    byThreat: toEntries(pick(src.by_threat, src.byThreat, src.threats)),
    byIdentity: toEntries(pick(src.by_identity, src.byIdentity, src.identities)),
    byOwasp: toEntries(pick(src.by_owasp, src.by_owasp_category, src.byOwasp)),
    bySeverity: toEntries(pick(src.by_severity, src.bySeverity)),
    byEndpoint: toEntries(pick(src.by_endpoint, src.byEndpoint)),
    timeseries: normalizeTimeseries(pick(src.timeseries, src.time_series, src.over_time, src.series)),
    costUsd: toNum(pick(src.cost_usd, src.costUsd, src.estimated_cost_usd, isObj(src.usage) ? src.usage.cost_usd : undefined)),
    semantic,
    window: win && (win.from || win.to) ? win : null,
    since: toDate(pick(src.since, src.started_at, src.metrics_since)),
    threatCatalog: normalizeThreatCatalog(pick(src.threat_catalog, src.threats_catalog, src.catalog)),
  };
}

// ---------------------------------------------------------------- threat catalog (optional)

export function normalizeThreatCatalog(raw) {
  const list = Array.isArray(raw) ? raw : isObj(raw) ? (Array.isArray(raw.threats) ? raw.threats : Object.entries(raw).map(([id, v]) => ({ id, ...(isObj(v) ? v : {}) }))) : [];
  const out = new Map();
  for (const t of list) {
    if (!isObj(t)) continue;
    const id = asStr(pick(t.id, t.threat_id));
    if (!id) continue;
    out.set(id, {
      id,
      title: asStr(pick(t.title, t.name, t.description)),
      owasp: strList(pick(t.owasp, t.owasp_llm, t.owasp_refs)),
      owaspAgentic: strList(pick(t.owasp_agentic)),
      atlas: strList(pick(t.atlas, t.mitre_atlas, t.atlas_refs)),
    });
  }
  return out;
}

// ---------------------------------------------------------------- /admin/metrics/latency

function pctBlock(v) {
  if (!isObj(v)) return null;
  const r = {
    p50: toNum(pick(v.p50, v.p50_ms, v.median, v.p50Ms)),
    p95: toNum(pick(v.p95, v.p95_ms, v.p95Ms)),
    p99: toNum(pick(v.p99, v.p99_ms, v.p99Ms)),
    mean: toNum(pick(v.mean, v.avg, v.mean_ms)),
    max: toNum(pick(v.max, v.max_ms)),
    count: toNum(pick(v.count, v.n, v.samples, v.calls)),
  };
  return r.p50 === null && r.p95 === null && r.p99 === null ? null : r;
}

export function normalizeLatency(p) {
  const src = isObj(p) ? (isObj(p.latency) ? p.latency : p) : {};
  const per = pick(src.per_control, src.perControl, src.controls);
  const perControl = [];
  if (Array.isArray(per)) {
    for (const item of per) {
      const b = pctBlock(item);
      const id = asStr(pick(item?.control_id, item?.id, item?.controlId));
      if (b && id) perControl.push({ id, ...b });
    }
  } else if (isObj(per)) {
    for (const [id, v] of Object.entries(per)) {
      const b = pctBlock(v);
      if (b) perControl.push({ id, ...b });
    }
  }
  const sem = pick(src.semantic_judge, src.semantic, src.judge);
  let semantic = pctBlock(sem);
  if (!semantic) {
    const fromCtl = perControl.find((c) => c.id === 'C-INJ-SEM');
    if (fromCtl) semantic = { ...fromCtl, source: 'per_control C-INJ-SEM' };
  }
  let routing = null;
  const r = isObj(sem) ? sem : isObj(src.routing) ? src.routing : null;
  if (r) {
    const judged = toNum(pick(r.judged, r.invoked, r.calls));
    const skipped = toNum(pick(r.skipped, r.cheap_path));
    if (judged !== null || skipped !== null) routing = { judged, skipped, source: 'latency' };
  }
  return {
    total: pctBlock(pick(src.total_overhead, src.totalOverhead, src.overhead, src.total)),
    upstream: pctBlock(pick(src.upstream, src.upstream_latency)),
    perControl,
    semantic,
    routing,
    targetP95Ms: 20, // ARCHITECTURE §12 — a target, never a measurement
  };
}

// ---------------------------------------------------------------- /admin/metrics/budgets

export const BUDGET_RESOURCES = [
  { kind: 'tokens', label: 'Tokens', unit: 'tokens', used: ['tokens', 'tokens_used', 'total_tokens'], limit: ['max_tokens', 'tokens_limit', 'token_limit'] },
  { kind: 'cost', label: 'Cost', unit: 'USD', used: ['cost_usd', 'cost', 'cost_used_usd'], limit: ['max_cost_usd', 'cost_limit_usd', 'cost_limit'] },
  { kind: 'compute', label: 'Compute', unit: 's', used: ['compute_seconds', 'compute_s', 'compute_used_seconds'], limit: ['max_compute_seconds', 'compute_limit_seconds', 'compute_limit'] },
  { kind: 'rpm', label: 'Requests / min', unit: 'req/min', used: ['requests_per_minute', 'rpm', 'requests_last_minute'], limit: ['max_requests_per_minute', 'rpm_limit'] },
  { kind: 'tool_calls', label: 'Tool calls / session', unit: 'calls', used: ['tool_calls_per_session', 'tool_calls', 'max_session_tool_calls', 'session_tool_calls'], limit: ['max_tool_calls_per_session', 'tool_calls_limit'] },
];

function firstKey(obj, keys) {
  if (!isObj(obj)) return { found: false, value: undefined };
  for (const k of keys) if (Object.prototype.hasOwnProperty.call(obj, k)) return { found: true, value: obj[k] };
  return { found: false, value: undefined };
}

export function budgetLevel(pct) {
  if (pct === null) return 'unlimited';
  if (pct >= 1) return 'exceeded';
  if (pct >= 0.9) return 'high';
  if (pct >= 0.7) return 'warning';
  return 'normal';
}

export function normalizeBudgetEntry(item, idHint) {
  if (!isObj(item)) return null;
  const identity = asStr(pick(item.identity, item.id, item.identity_id, idHint));
  if (!identity) return null;
  const usage = pick(item.usage, item.used, item.current) || item;
  const limits = pick(item.limits, item.limit, item.budget_limits) || item;
  const resourcesRaw = isObj(item.resources) ? item.resources : null;
  const resources = BUDGET_RESOURCES.map((def) => {
    let used;
    let limit;
    let limitKnown;
    if (resourcesRaw && isObj(resourcesRaw[def.kind])) {
      const r = resourcesRaw[def.kind];
      used = toNum(pick(r.used, r.value, r.usage));
      limit = toNum(r.limit);
      limitKnown = Object.prototype.hasOwnProperty.call(r, 'limit');
    } else {
      used = toNum(firstKey(usage, def.used).value);
      const l = firstKey(limits, def.limit);
      limit = toNum(l.value);
      limitKnown = l.found;
    }
    // null/omitted limit = no limit (ARCHITECTURE §6.5). A limit of 0 is a real limit.
    const unlimited = limit === null;
    const pct = unlimited || used === null ? null : limit === 0 ? (used > 0 ? Infinity : 0) : used / limit;
    return { ...def, used, limit, unlimited, limitKnown, pct, level: unlimited ? 'unlimited' : budgetLevel(pct ?? 0) };
  });
  const maxPct = Math.max(-1, ...resources.map((r) => (r.pct === null ? -1 : r.pct)));
  return {
    identity,
    role: asStr(item.role),
    budget: asStr(pick(item.budget, item.budget_name, item.budget_id)),
    window: asStr(pick(item.window, isObj(limits) ? limits.window : undefined)),
    windowStartedAt: toDate(pick(item.window_started_at, item.window_start)),
    resetsAt: toDate(pick(item.resets_at, item.reset_at, item.window_resets_at, item.window_end)),
    onExceed: asStr(pick(item.on_exceed, isObj(limits) ? limits.on_exceed : undefined)),
    exceeded: item.exceeded === true || resources.some((r) => r.level === 'exceeded'),
    resources,
    maxPct: maxPct < 0 ? null : maxPct,
  };
}

const WINDOW_MS = { minute: 60e3, hour: 3600e3, day: 86400e3 };

/** Reset time: explicit from backend, or window start + window length; otherwise unknown (null). */
export function budgetResetAt(b) {
  if (b.resetsAt) return b.resetsAt;
  if (b.windowStartedAt && WINDOW_MS[b.window]) return new Date(b.windowStartedAt.getTime() + WINDOW_MS[b.window]);
  return null;
}

export function normalizeBudgets(p) {
  let list = unwrapList(p, 'identities', 'budgets');
  if (!list.length && isObj(p)) {
    const map = pick(p.by_identity, p.byIdentity, p.identities);
    if (isObj(map)) list = Object.entries(map).map(([id, v]) => ({ identity: id, ...(isObj(v) ? v : {}) }));
  }
  return list.map((it) => normalizeBudgetEntry(it)).filter(Boolean);
}

// ---------------------------------------------------------------- audit events (§8 contract)

function normalizeMatch(m) {
  if (!isObj(m)) return null;
  // Only the masked excerpt is ever kept. Any other value-bearing field is dropped here.
  return {
    kind: asStr(m.kind) || 'unknown',
    segmentIdx: toNum(m.segment_idx),
    masked: typeof m.masked === 'string' ? m.masked : null,
    inDecoded: m.in_decoded === true,
  };
}

function normalizeDecision(d) {
  if (!isObj(d)) return null;
  return {
    controlId: asStr(pick(d.control_id, d.controlId)) || 'unknown',
    threatIds: strList(pick(d.threat_ids, d.threatIds)),
    action: normAction(d.action) || 'unknown',
    severity: asStr(d.severity)?.toLowerCase() || null,
    score: toNum(d.score),
    reason: typeof d.reason === 'string' ? d.reason : null,
    matches: asArray(d.matches).map(normalizeMatch).filter(Boolean),
    latencyMs: toNum(d.latency_ms),
    skipped: d.skipped === true,
    shadowSuppressed: d.shadow_suppressed === true,
  };
}

/** Stable FNV-1a hash, used as id for events without `event_id` (so incremental merges dedupe). */
function stableHash(obj) {
  let str;
  try { str = JSON.stringify(obj); } catch { str = ''; }
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193); }
  return (h >>> 0).toString(36);
}

export function normalizeEvent(e) {
  if (!isObj(e)) return null;
  const decisions = asArray(e.decisions).map(normalizeDecision).filter(Boolean);
  const lat = isObj(e.latency_ms) ? e.latency_ms : isObj(e.latency) ? e.latency : {};
  const perControl = {};
  if (isObj(lat.per_control)) for (const [k, v] of Object.entries(lat.per_control)) { const n = toNum(v); if (n !== null) perControl[k] = n; }
  const usage = isObj(e.usage) ? e.usage : {};
  const acting = decisions.filter((d) => !d.skipped && (d.action !== 'allow' || d.shadowSuppressed));
  const controlIds = [...new Set(acting.map((d) => d.controlId))];
  const threatIds = [...new Set([...acting.flatMap((d) => d.threatIds), ...strList(e.threat_ids)])];
  let severity = asStr(e.severity)?.toLowerCase() || null;
  for (const d of acting) if (severityRank(d.severity) > severityRank(severity)) severity = d.severity;
  const ts = toDate(pick(e.ts, e.timestamp, e.time));
  const type = asStr(e.type) || 'unknown';
  const finalAction = normAction(e.final_action) || (type === 'request' ? 'unknown' : null);
  const id = asStr(e.event_id) || `h_${stableHash(e)}`;
  return {
    id,
    ts,
    eventId: asStr(e.event_id),
    requestId: asStr(e.request_id),
    sessionId: asStr(e.session_id),
    type,
    endpoint: asStr(e.endpoint),
    identity: asStr(e.identity),
    role: asStr(e.role),
    profile: asStr(e.profile),
    policyVersion: asStr(e.policy_version),
    feedVersion: asStr(e.feed_version),
    model: asStr(e.model),
    finalAction,
    wouldHaveAction: normAction(e.would_have_action),
    shadow: e.shadow === true,
    upstreamCalled: typeof e.upstream_called === 'boolean' ? e.upstream_called : null,
    decisions,
    controlIds,
    allControlIds: [...new Set(decisions.map((d) => d.controlId))],
    threatIds,
    severity,
    latency: { totalOverhead: toNum(lat.total_overhead), upstream: toNum(lat.upstream), perControl },
    usage: {
      promptTokens: toNum(usage.prompt_tokens),
      completionTokens: toNum(usage.completion_tokens),
      costUsd: toNum(usage.cost_usd),
      computeSeconds: toNum(usage.compute_seconds),
    },
    error: e.error === null || e.error === undefined ? null : typeof e.error === 'string' ? e.error : e.error,
    reason: typeof e.reason === 'string' ? e.reason : typeof e.message === 'string' ? e.message : null,
    raw: e, // sanitised before display (utils.sanitizeForDisplay)
  };
}

export function normalizeEvents(p) {
  const list = unwrapList(p, 'events');
  return list.map(normalizeEvent).filter(Boolean);
}

/** Parses a JSONL text (export / demo fixture) line by line; bad lines are counted, not fatal. */
export function parseJsonl(text) {
  const events = [];
  let bad = 0;
  for (const line of String(text || '').split(/\r?\n/)) {
    if (!line.trim()) continue;
    try { events.push(JSON.parse(line)); } catch { bad += 1; }
  }
  return { events, bad };
}

// ---------------------------------------------------------------- /admin/controls

function normalizeLevel(l) {
  if (!isObj(l)) return null;
  const { action, threshold, min_severity: minSeverity, ...rest } = l;
  return { action: normAction(action), threshold: toNum(threshold), minSeverity: asStr(minSeverity), params: rest };
}

function normalizeTests(t, item) {
  if (isNum(t)) return { total: t, negative: null, positive: null, edge: null };
  const src = isObj(t) ? t : isObj(item.coverage) ? item.coverage : null;
  const flat = toNum(pick(item.test_count, item.tests_count, item.n_tests));
  if (!src) return flat === null ? null : { total: flat, negative: null, positive: null, edge: null };
  const negative = toNum(pick(src.negative, src.negatives));
  const positive = toNum(pick(src.positive, src.positives));
  const edge = toNum(pick(src.edge, src.edges));
  const total = toNum(pick(src.total, src.tests, src.count)) ?? ([negative, positive, edge].some((v) => v !== null) ? (negative || 0) + (positive || 0) + (edge || 0) : flat);
  const perThreat = isObj(src.by_threat) ? Object.fromEntries(toEntries(src.by_threat).map((e) => [e.key, e.value])) : null;
  return { total, negative, positive, edge, perThreat };
}

export function normalizeControls(p, activeProfile = null) {
  let list = unwrapList(p, 'controls');
  if (!list.length && isObj(p) && isObj(p.controls)) list = Object.entries(p.controls).map(([key, v]) => ({ key, ...(isObj(v) ? v : {}) }));
  else if (!list.length && isObj(p) && !Array.isArray(p) && Object.values(p).every(isObj)) list = Object.entries(p).map(([key, v]) => ({ key, ...v }));
  const profile = asStr(pick(isObj(p) ? p.active_profile : undefined, activeProfile));
  return list.filter(isObj).map((c) => {
    const levels = {};
    if (isObj(c.levels)) for (const [name, l] of Object.entries(c.levels)) { const n = normalizeLevel(l); if (n) levels[name] = n; }
    const cur = isObj(c.current) ? normalizeLevel(c.current) : null;
    const prof = asStr(pick(c.profile, profile));
    const lvl = cur || (prof && levels[prof]) || null;
    const priorityRaw = pick(c.priority, c.order);
    const tierRaw = asStr(pick(c.tier, c.prio, typeof priorityRaw === 'string' && /^P\d$/i.test(priorityRaw) ? priorityRaw : undefined));
    return {
      id: asStr(pick(c.id, c.control_id)) || asStr(c.key) || 'unknown',
      key: asStr(c.key),
      name: asStr(pick(c.name, c.title, c.key)),
      description: asStr(c.description),
      enabled: typeof c.enabled === 'boolean' ? c.enabled : null,
      mode: asStr(c.mode) || null,
      effectiveMode: asStr(pick(c.effective_mode, c.mode)) || null,
      onError: asStr(c.on_error),
      stages: strList(c.stages),
      priority: toNum(priorityRaw),
      tier: tierRaw ? tierRaw.toUpperCase() : null,
      type: asStr(pick(c.type, c.kind)),
      threatIds: strList(pick(c.threat_ids, c.threatIds, c.threats)),
      levels,
      profile: prof,
      currentAction: normAction(pick(c.action, c.current_action, lvl?.action)),
      threshold: toNum(pick(c.threshold, lvl?.threshold)),
      minSeverity: asStr(pick(c.min_severity, lvl?.minSeverity)),
      tests: normalizeTests(pick(c.tests, c.test_coverage), c),
      interventions: toNum(pick(c.interventions, c.intervention_count, c.hits)),
      lastRun: toDate(pick(c.last_run, c.last_run_at, c.last_evaluated_at, c.last_hit)),
    };
  });
}

export function controlsThreatCatalog(p) {
  if (!isObj(p)) return new Map();
  return normalizeThreatCatalog(pick(p.threats, p.threat_catalog));
}

// ---------------------------------------------------------------- /admin/policy

export function normalizePolicy(p) {
  const body = isObj(p) ? p : {};
  const pol = isObj(body.policy) ? body.policy : body;
  const versionCandidate = pick(body.policy_version, body.version_hash, body.hash, pol.policy_version);
  const v = body.version;
  const policyVersion = asStr(pick(versionCandidate, typeof v === 'string' && !/^\d+$/.test(v) ? v : undefined));
  const feeds = asArray(pol.signature_feeds).filter(isObj).map((f) => ({ name: asStr(f.name), path: asStr(pick(f.path, f.url)), refreshSeconds: toNum(f.refresh_seconds), onUnavailable: asStr(f.on_unavailable), version: asStr(f.feed_version || f.version) }));
  const lastReload = isObj(body.last_reload) ? body.last_reload : null;
  return {
    name: asStr(pick(isObj(pol.meta) ? pol.meta.name : undefined, pol.name, body.name)),
    description: asStr(isObj(pol.meta) ? pol.meta.description : undefined),
    schemaVersion: asStr(pol.version !== undefined && /^\d+$/.test(String(pol.version)) ? pol.version : undefined),
    policyVersion,
    feedVersion: asStr(pick(body.feed_version, pol.feed_version, feeds.find((f) => f.version)?.version)),
    activeProfile: asStr(pol.active_profile),
    mode: asStr(pol.mode),
    evaluation: asStr(pol.evaluation),
    onErrorDefault: asStr(pol.on_error_default),
    loadedAt: toDate(pick(body.loaded_at, body.last_reload_at, lastReload?.ts, lastReload?.at)),
    lastReloadResult: asStr(pick(body.last_reload_result, lastReload?.result, lastReload?.status)),
    lastReloadError: asStr(pick(body.last_reload_error, lastReload?.error)),
    feeds,
    controlsCount: isObj(pol.controls) ? Object.keys(pol.controls).length : null,
    identitiesCount: Array.isArray(pol.identities) ? pol.identities.length : null,
    raw: body,
  };
}

/** Validation response → {ok, errors:[{path, message}]}. Handles AICL style and FastAPI 422 `detail`. */
export function normalizeValidation(p) {
  const body = isObj(p) ? p : {};
  const rawErrors = asArray(pick(body.errors, Array.isArray(body.detail) ? body.detail : undefined, isObj(body.error) ? body.error.errors : undefined));
  const errors = rawErrors.map((e) => {
    if (typeof e === 'string') return { path: '', message: e };
    if (!isObj(e)) return null;
    const loc = pick(e.loc, e.path, e.field, e.location);
    const path = Array.isArray(loc) ? loc.join('.') : asStr(loc) || '';
    return { path, message: asStr(pick(e.msg, e.message, e.error)) || 'invalid' };
  }).filter(Boolean);
  if (!errors.length && isObj(body.error) && body.error.message) errors.push({ path: '', message: String(body.error.message) });
  const explicitFail = body.ok === false || body.valid === false || ['error', 'invalid', 'rejected'].includes(String(body.status || '').toLowerCase());
  const ok = !errors.length && !explicitFail;
  return { ok, errors, version: asStr(pick(body.policy_version, body.version_hash)) };
}

// ---------------------------------------------------------------- test & fuzz reports (§11.6)

function rateBlock(src, numKeys, denKeys, rateKeys) {
  if (!isObj(src)) return { num: null, den: null, rate: null };
  const num = toNum(pick(...numKeys.map((k) => src[k])));
  const den = toNum(pick(...denKeys.map((k) => src[k])));
  const rate = toNum(pick(...rateKeys.map((k) => src[k])));
  return { num, den, rate: rate ?? (num !== null && den ? num / den : null) };
}

const DET = [['negatives_blocked', 'negatives_stopped', 'detected', 'tp'], ['negatives', 'negative_total', 'n_negative'], ['detection_rate']];
const FPR = [['positives_blocked', 'false_positives', 'fp'], ['positives', 'positive_total', 'n_positive'], ['false_positive_rate', 'fp_rate']];

export function normalizeTestReport(p) {
  if (!isObj(p)) return null;
  const totals = isObj(p.totals) ? p.totals : isObj(p.summary) ? p.summary : p;
  const overall = isObj(p.overall) ? p.overall : totals;
  const perRaw = pick(p.per_control, p.controls, p.by_control);
  const perControl = [];
  const iter = Array.isArray(perRaw) ? perRaw.map((c) => [asStr(pick(c?.control_id, c?.id)), c]) : isObj(perRaw) ? Object.entries(perRaw) : [];
  for (const [id, c] of iter) {
    if (!id || !isObj(c)) continue;
    perControl.push({
      id,
      detection: rateBlock(c, ...DET),
      falsePositive: rateBlock(c, ...FPR),
      passed: toNum(c.passed),
      failed: toNum(c.failed),
      p50: toNum(pick(c.latency_p50_ms, c.p50_ms, c.p50)),
      p95: toNum(pick(c.latency_p95_ms, c.p95_ms, c.p95)),
    });
  }
  const covRaw = pick(p.coverage, p.coverage_matrix, p.matrix);
  const coverage = [];
  for (const row of asArray(covRaw)) {
    if (!isObj(row)) continue;
    const controls = strList(pick(row.control_id, row.controls, row.control));
    const threats = strList(pick(row.threat_id, row.threats, row.threat));
    const kind = asStr(row.kind);
    const count = toNum(pick(row.tests, row.count)) ?? 1;
    for (const c of controls) for (const t of threats) coverage.push({ controlId: c, threatId: t, kind, count, testId: asStr(pick(row.test_id, row.id)) });
  }
  const failures = asArray(pick(p.failures, p.failed_cases, p.failed)).filter(isObj).map((f) => ({
    id: asStr(pick(f.id, f.case_id, f.test_id)) || 'unknown',
    title: asStr(f.title),
    controls: strList(pick(f.controls, f.control_ids, f.control_id)),
    threats: strList(pick(f.threats, f.threat_ids)),
    kind: asStr(f.kind),
    expected: f.expected === undefined ? null : f.expected,
    actual: f.actual === undefined ? null : f.actual,
    message: asStr(pick(f.message, f.error, f.reason)),
  }));
  const overhead = isObj(p.overhead) ? p.overhead : isObj(p.total_overhead) ? p.total_overhead : {};
  const status = asStr(pick(p.status, p.result, p.outcome));
  const total = toNum(pick(totals.total, totals.tests, totals.count));
  const passed = toNum(totals.passed);
  const failed = toNum(totals.failed);
  const skipped = toNum(totals.skipped);
  return {
    generatedAt: toDate(pick(p.generated_at, p.timestamp, p.ts, p.finished_at, p.started_at)),
    durationSeconds: toNum(pick(p.duration_seconds, p.duration_s)),
    status: status ? status.toLowerCase() : failed === null ? null : failed > 0 ? 'failed' : 'passed',
    total: total ?? ([passed, failed, skipped].some((v) => v !== null) ? (passed || 0) + (failed || 0) + (skipped || 0) : null),
    passed, failed, skipped,
    detection: rateBlock(overall, ...DET),
    falsePositive: rateBlock(overall, ...FPR),
    overheadP50: toNum(pick(overhead.p50, overhead.p50_ms, p.overhead_p50_ms)),
    overheadP95: toNum(pick(overhead.p95, overhead.p95_ms, p.overhead_p95_ms)),
    perControl,
    coverage,
    failures,
    policyVersion: asStr(p.policy_version),
    threatCatalog: normalizeThreatCatalog(pick(p.threats, p.threat_catalog)),
  };
}

export function normalizeFuzzReport(p) {
  if (!isObj(p)) return null;
  const block = (raw, idKeys) => {
    const iter = Array.isArray(raw) ? raw.map((x) => [asStr(pick(...idKeys.map((k) => x?.[k]))), x]) : isObj(raw) ? Object.entries(raw) : [];
    return iter.filter(([id, v]) => id && isObj(v)).map(([id, v]) => {
      const attempts = toNum(pick(v.attempts, v.variants, v.total, v.n));
      const bypasses = toNum(pick(v.bypasses, v.bypassed, v.survived));
      const rate = toNum(v.bypass_rate) ?? (attempts ? (bypasses ?? 0) / attempts : null);
      return { id, attempts, bypasses, rate };
    });
  };
  return {
    generatedAt: toDate(pick(p.generated_at, p.timestamp, p.ts)),
    perControl: block(pick(p.per_control, p.by_control), ['control_id', 'id']),
    perStrategy: block(pick(p.per_strategy, p.by_strategy, p.strategies), ['strategy', 'id', 'name']),
    total: rateBlock(isObj(p.overall) ? p.overall : p, ['bypasses', 'bypassed'], ['attempts', 'variants', 'total'], ['bypass_rate']),
    label: asStr(pick(p.label, p.run, p.name)),
  };
}
