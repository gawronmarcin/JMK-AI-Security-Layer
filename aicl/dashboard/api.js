// AICL dashboard — the only module that talks to the gateway.
// Every admin call goes through `request()`: same-origin fetch, Bearer header from `auth`,
// AbortController-based timeout, one in-flight request per key (a newer call aborts the
// older one) and a single error taxonomy (ApiError.kind).

import { auth } from './auth.js';

export class ApiError extends Error {
  constructor(kind, message, { status = null, endpoint = '', retryAfterMs = null, details = null } = {}) {
    super(message);
    this.name = 'ApiError';
    this.kind = kind; // unauthorized | forbidden | not_found | rate_limited | bad_request | server | timeout | network | aborted | parse
    this.status = status;
    this.endpoint = endpoint;
    this.retryAfterMs = retryAfterMs;
    this.details = details;
  }
}

const KIND_BY_STATUS = (s) => {
  if (s === 401) return 'unauthorized';
  if (s === 403) return 'forbidden';
  if (s === 404) return 'not_found';
  if (s === 429) return 'rate_limited';
  if (s === 400 || s === 409 || s === 413 || s === 415 || s === 422) return 'bad_request';
  if (s >= 500) return 'server';
  return 'server';
};

const HUMAN = {
  unauthorized: 'Admin key rejected (401). Sign in again.',
  forbidden: 'Access denied (403). The key is valid but lacks the admin role.',
  not_found: 'Endpoint not available on this gateway (404).',
  rate_limited: 'Rate limited by the gateway (429). Backing off.',
  bad_request: 'Request rejected by the gateway.',
  server: 'Gateway error.',
  timeout: 'Request timed out.',
  network: 'Gateway unreachable (network error).',
  aborted: 'Request cancelled.',
  parse: 'Unexpected response format.',
};

function parseRetryAfter(value) {
  if (!value) return null;
  const secs = Number(value);
  if (Number.isFinite(secs)) return Math.max(0, secs * 1000);
  const at = Date.parse(value);
  return Number.isNaN(at) ? null : Math.max(0, at - Date.now());
}

/** Extracts a short, text-only message from an AICL / FastAPI error body. */
function errorMessageFrom(body) {
  if (!body || typeof body !== 'object') return null;
  if (body.error && typeof body.error === 'object') return body.error.message || body.error.type || null;
  if (typeof body.detail === 'string') return body.detail;
  if (typeof body.message === 'string') return body.message;
  return null;
}

export function createApi({ baseUrl = '', timeoutMs = 10000, onUnauthorized = () => {} } = {}) {
  const inflight = new Map(); // key -> AbortController

  async function request(key, path, { method = 'GET', query = null, body = null, contentType = null, customHeaders = null, accept = 'application/json', raw = false, meta = false, timeout = timeoutMs, auth: useAuth = true } = {}) {
    const prev = inflight.get(key);
    if (prev) prev.abort('superseded');
    const ctrl = new AbortController();
    inflight.set(key, ctrl);
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; ctrl.abort('timeout'); }, timeout);

    let url = baseUrl + path;
    if (query) {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== null && v !== '') qs.set(k, String(v));
      const s = qs.toString();
      if (s) url += (url.includes('?') ? '&' : '?') + s;
    }
    const headers = { Accept: accept, ...(useAuth ? auth.headers() : {}), ...(customHeaders || {}) };
    if (contentType) headers['Content-Type'] = contentType;

    try {
      let res;
      try {
        res = await fetch(url, { method, headers, body, signal: ctrl.signal, cache: 'no-store', credentials: 'same-origin', redirect: 'error' });
      } catch {
        if (ctrl.signal.aborted) {
          throw new ApiError(timedOut ? 'timeout' : 'aborted', timedOut ? `${HUMAN.timeout} (${Math.round(timeout / 1000)} s)` : HUMAN.aborted, { endpoint: path });
        }
        throw new ApiError('network', HUMAN.network, { endpoint: path });
      }

      if (!res.ok) {
        const kind = KIND_BY_STATUS(res.status);
        let parsed = null;
        try { parsed = await res.clone().json(); } catch { parsed = null; }
        const backendMsg = errorMessageFrom(parsed);
        const msg = auth.redact(`${HUMAN[kind]}${backendMsg && kind !== 'unauthorized' ? ` ${String(backendMsg).slice(0, 300)}` : ''} [HTTP ${res.status}]`);
        const err = new ApiError(kind, msg, { status: res.status, endpoint: path, retryAfterMs: parseRetryAfter(res.headers.get('Retry-After')), details: parsed });
        err.headers = res.headers;
        err.requestId = res.headers.get('x-aicl-request-id');
        err.action = res.headers.get('x-aicl-action');
        err.overheadMs = res.headers.get('x-aicl-overhead-ms');
        if (kind === 'unauthorized' && useAuth) onUnauthorized(err);
        throw err;
      }

      if (raw) return { blob: await res.blob(), headers: res.headers };
      if (res.status === 204) return null;
      const text = await res.text();
      let parsed = null;
      if (text.trim()) {
        try {
          parsed = JSON.parse(text);
        } catch {
          if (accept.includes('json')) throw new ApiError('parse', HUMAN.parse, { status: res.status, endpoint: path });
          parsed = text;
        }
      }

      if (meta) {
        return {
          status: res.status,
          headers: res.headers,
          data: parsed,
          requestId: res.headers.get('x-aicl-request-id'),
          action: res.headers.get('x-aicl-action'),
          overheadMs: res.headers.get('x-aicl-overhead-ms'),
          policyVersion: res.headers.get('x-aicl-policy-version'),
        };
      }
      return parsed;
    } finally {
      clearTimeout(timer);
      if (inflight.get(key) === ctrl) inflight.delete(key);
    }
  }

  return {
    request,
    isInflight: (key) => inflight.has(key),
    abort(key) { inflight.get(key)?.abort('cancelled'); },
    abortAll() { for (const c of inflight.values()) c.abort('cancelled'); inflight.clear(); },

    health: () => request('health', '/healthz', { auth: true }),
    summary: () => request('summary', '/admin/metrics/summary'),
    latency: () => request('latency', '/admin/metrics/latency'),
    budgets: () => request('budgets', '/admin/metrics/budgets'),
    controls: () => request('controls', '/admin/controls'),
    policy: () => request('policy', '/admin/policy'),
    /** Server-side filters documented in ARCHITECTURE §5.1: limit, since, action, control, identity. */
    events: ({ limit, since, action, control, identity, key = 'events' } = {}) =>
      request(key, '/admin/events', { query: { limit, since, action, control, identity } }),
    validatePolicy: (yamlText) =>
      request('policy.validate', '/admin/policy/validate', { method: 'POST', body: yamlText, contentType: 'application/yaml', timeout: 20000 }),
    previewPolicy: (yamlText, lastN = 50) =>
      request('policy.preview', `/admin/policy/preview?last_n=${lastN}`, { method: 'POST', body: yamlText, contentType: 'application/yaml', timeout: 30000 }),
    listApprovals: (status = 'all') =>
      request('approvals', `/admin/approvals?status=${status}`),
    approveRequest: (approvalId) =>
      request(`approve:${approvalId}`, `/admin/approvals/${approvalId}/approve`, { method: 'POST' }),
    rejectRequest: (approvalId) =>
      request(`reject:${approvalId}`, `/admin/approvals/${approvalId}/reject`, { method: 'POST' }),
    reloadPolicy: () => request('policy.reload', '/admin/policy/reload', { method: 'POST', timeout: 20000 }),
    exportAudit: () => request('export', '/admin/export/audit.jsonl', { raw: true, accept: 'application/x-ndjson, application/jsonl, text/plain, */*', timeout: 120000 }),
    chat: ({ model, prompt, identity = null, timeout = 30000 } = {}) => {
      const customHeaders = {};
      if (identity) customHeaders['X-AICL-Agent'] = identity;
      const body = JSON.stringify({
        model,
        messages: [{ role: 'user', content: prompt }],
      });
      return request('playground.chat', '/v1/chat', {
        method: 'POST',
        body,
        contentType: 'application/json',
        customHeaders,
        meta: true,
        timeout,
      });
    },
    /** Optional static/API reports (test suite, fuzzer). 404 is reported as `not_found`, not as an outage. */
    report: (key, path) => request(`report:${key}`, path),
  };
}
