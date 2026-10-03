// AICL dashboard — pure helpers: formatting, DOM building (text only), time, sanitising.
// No module here touches the network or global state.

export const ACTIONS = ['allow', 'flag', 'redact', 'require_approval', 'block'];
export const SEVERITIES = ['low', 'medium', 'high', 'critical'];
export const ENDPOINTS = ['chat', 'tool_invoke', 'mcp', 'artifact_scan'];

/** Single source of truth for action colours, icons and labels (charts + badges). */
export const ACTION_META = {
  allow: { color: '#3DDC97', icon: '✓', label: 'Allow', pointStyle: 'circle', dash: [] },
  flag: { color: '#FFB547', icon: '⚑', label: 'Flag', pointStyle: 'triangle', dash: [6, 3] },
  redact: { color: '#A78BFA', icon: '▒', label: 'Redact', pointStyle: 'rect', dash: [2, 2] },
  require_approval: { color: '#FF8A3D', icon: '⏸', label: 'Approval required', pointStyle: 'rectRot', dash: [8, 3, 2, 3] },
  block: { color: '#FF5D67', icon: '✕', label: 'Block', pointStyle: 'crossRot', dash: [] },
};
export const UNKNOWN_META = { color: '#667085', icon: '?', label: 'Unknown', pointStyle: 'star', dash: [1, 2] };

export const SEVERITY_META = {
  low: { color: '#667085', icon: '▁', rank: 1 },
  medium: { color: '#FFB547', icon: '▃', rank: 2 },
  high: { color: '#FF8A3D', icon: '▅', rank: 3 },
  critical: { color: '#FF5D67', icon: '█', rank: 4 },
};

export const COLORS = {
  bg: '#0B0F14', panel: '#111821', raised: '#17212B', border: '#263241',
  text: '#E7EDF5', muted: '#91A0B2', info: '#4EA1FF', neutral: '#667085',
  success: '#3DDC97', warning: '#FFB547', error: '#FF5D67', redact: '#A78BFA', orange: '#FF8A3D',
};

export function actionMeta(action) {
  return ACTION_META[action] || { ...UNKNOWN_META, label: action ? String(action) : 'Unknown' };
}

export function severityRank(sev) {
  return SEVERITY_META[sev]?.rank || 0;
}

// ---------------------------------------------------------------- type guards

export const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
export const isNum = (v) => typeof v === 'number' && Number.isFinite(v);
export const asArray = (v) => (Array.isArray(v) ? v : []);
export const asStr = (v) => (v === null || v === undefined ? null : String(v));

/** Returns a finite number or null (accepts numeric strings). */
export function toNum(v) {
  if (isNum(v)) return v;
  if (typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v))) return Number(v);
  return null;
}

/** First defined (not null/undefined) value among the candidates. */
export function pick(...vals) {
  for (const v of vals) if (v !== undefined && v !== null) return v;
  return undefined;
}

// ---------------------------------------------------------------- formatting

const LOCALE = undefined; // user's locale
const nf0 = new Intl.NumberFormat(LOCALE, { maximumFractionDigits: 0 });
const nf1 = new Intl.NumberFormat(LOCALE, { maximumFractionDigits: 1 });
const nf2 = new Intl.NumberFormat(LOCALE, { maximumFractionDigits: 2 });
const pct1 = new Intl.NumberFormat(LOCALE, { style: 'percent', maximumFractionDigits: 1 });
const dtf = new Intl.DateTimeFormat(LOCALE, {
  year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
});
const dtfShort = new Intl.DateTimeFormat(LOCALE, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const dtfUtc = new Intl.DateTimeFormat(LOCALE, {
  year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
  timeZone: 'UTC', timeZoneName: 'short',
});

export const DASH = '—';

export function fmtInt(v) {
  const n = toNum(v);
  return n === null ? DASH : nf0.format(n);
}

export function fmtNum(v, digits = 1) {
  const n = toNum(v);
  if (n === null) return DASH;
  return (digits === 2 ? nf2 : digits === 0 ? nf0 : nf1).format(n);
}

/** Ratio (0..1) → "12.3%". */
export function fmtPct(ratio) {
  const n = toNum(ratio);
  return n === null ? DASH : pct1.format(n);
}

/** "92% (46/50)" when the sample size is known, otherwise just the rate. */
export function fmtRate(num, den, ratio) {
  const n = toNum(num);
  const d = toNum(den);
  if (n !== null && d !== null) {
    if (d === 0) return `n/a (0/0)`;
    return `${pct1.format(n / d)} (${nf0.format(n)}/${nf0.format(d)})`;
  }
  const r = toNum(ratio);
  return r === null ? DASH : `${pct1.format(r)} (sample size n/a)`;
}

/** Milliseconds: "<1000 ms" as ms, otherwise seconds. */
export function fmtMs(v) {
  const n = toNum(v);
  if (n === null) return DASH;
  if (Math.abs(n) >= 1000) return `${nf2.format(n / 1000)} s`;
  if (Math.abs(n) < 10) return `${nf2.format(n)} ms`;
  return `${nf1.format(n)} ms`;
}

export function fmtSeconds(v) {
  const n = toNum(v);
  if (n === null) return DASH;
  if (n >= 3600) return `${nf1.format(n / 3600)} h`;
  if (n >= 120) return `${nf1.format(n / 60)} min`;
  return `${nf1.format(n)} s`;
}

/** USD with precision adapted to the magnitude (micro-costs stay readable). */
export function fmtUsd(v) {
  const n = toNum(v);
  if (n === null) return DASH;
  const abs = Math.abs(n);
  const digits = abs === 0 ? 2 : abs < 0.01 ? 6 : abs < 1 ? 4 : 2;
  return new Intl.NumberFormat(LOCALE, {
    style: 'currency', currency: 'USD', minimumFractionDigits: Math.min(2, digits), maximumFractionDigits: digits,
  }).format(n);
}

export function fmtDate(d) {
  const dt = toDate(d);
  return dt ? dtf.format(dt) : DASH;
}
export function fmtTime(d) {
  const dt = toDate(d);
  return dt ? dtfShort.format(dt) : DASH;
}
export function fmtUtc(d) {
  const dt = toDate(d);
  return dt ? dtfUtc.format(dt) : DASH;
}

export function fmtRelative(d, now = Date.now()) {
  const dt = toDate(d);
  if (!dt) return DASH;
  const s = Math.round((now - dt.getTime()) / 1000);
  if (s < 5) return 'just now';
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

/** Signed change between current and previous value; null when no comparison exists. */
export function computeChange(current, previous) {
  const c = toNum(current);
  const p = toNum(previous);
  if (c === null || p === null) return null;
  const delta = c - p;
  const ratio = p === 0 ? null : delta / p;
  return { delta, ratio };
}

// ---------------------------------------------------------------- time

export function toDate(v) {
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v;
  if (typeof v === 'number' && Number.isFinite(v)) {
    // seconds vs milliseconds heuristic: < 1e11 means epoch seconds
    return new Date(v < 1e11 ? v * 1000 : v);
  }
  if (typeof v === 'string' && v) {
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  return null;
}

export const RANGES = {
  '15m': { label: '15 min', ms: 15 * 60e3 },
  '1h': { label: '1 h', ms: 60 * 60e3 },
  '6h': { label: '6 h', ms: 6 * 3600e3 },
  '24h': { label: '24 h', ms: 24 * 3600e3 },
  '7d': { label: '7 d', ms: 7 * 86400e3 },
};

const BUCKET_STEPS = [10e3, 30e3, 60e3, 2 * 60e3, 5 * 60e3, 10 * 60e3, 15 * 60e3, 30 * 60e3, 3600e3, 2 * 3600e3, 3 * 3600e3, 6 * 3600e3, 12 * 3600e3, 86400e3];

/** Picks a bucket size so the series has at most ~maxPoints buckets. */
export function bucketSizeFor(spanMs, maxPoints = 96) {
  for (const step of BUCKET_STEPS) if (spanMs / step <= maxPoints) return step;
  return BUCKET_STEPS[BUCKET_STEPS.length - 1];
}

/** Resolves the time-range filter to absolute {from, to} Dates. */
export function resolveRange(filters, now = Date.now()) {
  if (filters.range === 'custom') {
    const from = toDate(filters.from);
    const to = toDate(filters.to) || new Date(now);
    if (from && from < to) return { from, to };
  }
  const r = RANGES[filters.range] || RANGES['1h'];
  return { from: new Date(now - r.ms), to: new Date(now) };
}

export function fmtBucket(ms) {
  if (ms < 60e3) return `${ms / 1e3} s`;
  if (ms < 3600e3) return `${ms / 60e3} min`;
  if (ms < 86400e3) return `${ms / 3600e3} h`;
  return `${ms / 86400e3} d`;
}

// ---------------------------------------------------------------- stats

export function percentile(sortedValues, p) {
  if (!sortedValues.length) return null;
  const idx = Math.min(sortedValues.length - 1, Math.max(0, Math.ceil((p / 100) * sortedValues.length) - 1));
  return sortedValues[idx];
}

/** Top-N entries by value, remaining ones aggregated as "Other". */
export function topN(entries, n = 10, otherLabel = 'Other') {
  const sorted = [...entries].sort((a, b) => b.value - a.value);
  if (sorted.length <= n) return sorted;
  const head = sorted.slice(0, n - 1);
  const rest = sorted.slice(n - 1);
  head.push({ key: otherLabel, value: rest.reduce((s, e) => s + e.value, 0), other: true, members: rest.map((e) => e.key) });
  return head;
}

// ---------------------------------------------------------------- DOM (text only — never innerHTML)

/**
 * Creates an element. Children may be nodes, strings (rendered via text nodes) or arrays.
 * Attributes: `class`, `text`, `dataset`, `on<Event>` handlers, aria-*, and plain attributes.
 */
export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = String(v);
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else if (k === 'style') setStyle(node, v); // CSSOM, so a strict CSP (no inline styles) still works
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'hidden' || k === 'disabled' || k === 'checked' || k === 'selected') node[k] = Boolean(v);
    else if (k === 'value') node.value = v;
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  append(node, children);
  return node;
}

function setStyle(node, css) {
  for (const decl of String(css).split(';')) {
    const i = decl.indexOf(':');
    if (i > 0) node.style.setProperty(decl.slice(0, i).trim(), decl.slice(i + 1).trim());
  }
}

export function append(node, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    node.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

export function clear(node) {
  while (node && node.firstChild) node.removeChild(node.firstChild);
  return node;
}

export function replaceChildren(node, ...children) {
  clear(node);
  return append(node, children);
}

export function svgIcon(pathD, label) {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', '18');
  svg.setAttribute('height', '18');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.8');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  if (label) { svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', label); } else svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS(ns, 'path');
  path.setAttribute('d', pathD);
  svg.appendChild(path);
  return svg;
}

export function debounce(fn, ms = 200) {
  let t = null;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

// ---------------------------------------------------------------- sanitising for display / copy

const CREDENTIAL_KEY = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[-_]?key|apikey|api_key_env|access[-_]?token|refresh[-_]?token|id[-_]?token|token|bearer|secret|client[-_]?secret|password|passwd|pwd|credentials?|private[-_]?key|admin[-_]?key|session[-_]?token|capability(_token)?|hmac|signature_secret)$/i;
const RAW_CONTENT_KEY = /^(raw|raw_value|value|original|plaintext|unmasked|text|content|prompt|body)$/i;
const BEARER_VALUE = /\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi;

/**
 * Deep-copies an object for display/copy, removing credential-bearing keys.
 * Inside `matches` only whitelisted fields survive (the masked excerpt is the only allowed
 * representation of a match — raw values are never shown even if a backend leaks them).
 */
export function sanitizeForDisplay(value, depth = 0, parentKey = '') {
  if (depth > 12) return '[truncated]';
  if (Array.isArray(value)) return value.map((v) => sanitizeForDisplay(v, depth + 1, parentKey));
  if (isObj(value)) {
    const out = {};
    const inMatches = parentKey === 'matches';
    for (const [k, v] of Object.entries(value)) {
      if (CREDENTIAL_KEY.test(k)) { out[k] = '[removed]'; continue; }
      if (inMatches && !['kind', 'segment_idx', 'start', 'end', 'masked', 'in_decoded'].includes(k)) continue;
      if (inMatches && RAW_CONTENT_KEY.test(k)) continue;
      out[k] = sanitizeForDisplay(v, depth + 1, k);
    }
    return out;
  }
  if (typeof value === 'string') return value.replace(BEARER_VALUE, '$1 [removed]');
  return value;
}

/** Text for any backend-provided value; always safe to put in textContent. */
export function safeText(v, fallback = DASH) {
  if (v === null || v === undefined || v === '') return fallback;
  if (typeof v === 'string') return v.replace(BEARER_VALUE, '$1 [removed]');
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  try { return JSON.stringify(sanitizeForDisplay(v)); } catch { return fallback; }
}

export async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch { /* fall through */ }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch { ok = false; }
  ta.remove();
  return ok;
}

export function uniqueSorted(values) {
  return [...new Set(values.filter((v) => v !== null && v !== undefined && v !== ''))].sort((a, b) => String(a).localeCompare(String(b), undefined, { numeric: true }));
}
