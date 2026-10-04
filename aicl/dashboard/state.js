// AICL dashboard — the single controlled application state + URL-hash sync.
// The admin key is deliberately NOT part of this state (see auth.js), so nothing here can
// ever leak it into the URL or a copied view.

export const VIEWS = ['overview', 'playground', 'threats', 'controls', 'budgets', 'performance', 'tests', 'events', 'policy', 'approvals'];

export const EVENT_FILTER_KEYS = ['action', 'type', 'severity', 'identity', 'endpoint', 'control', 'threat', 'policyVersion', 'q'];
const HASH_KEYS = ['range', 'from', 'to', ...EVENT_FILTER_KEYS];

export function defaultFilters() {
  return { range: '1h', from: null, to: null, action: '', type: '', severity: '', identity: '', endpoint: '', control: '', threat: '', policyVersion: '', q: '' };
}

export function createStore() {
  const state = {
    view: 'overview',
    filters: defaultFilters(),
    ui: { seriesMode: 'abs', refreshMs: 5000, budgetKind: '', sidebarOpen: false },
    resources: {}, // name -> { status, data, error, updatedAt, failures, version }
    demo: false,
    auth: { status: 'signed_out', message: '' }, // signed_out | signed_in | open
    lastRefreshAt: null,
  };
  const listeners = new Set();
  let scheduled = false;

  function notify() {
    if (scheduled) return;
    scheduled = true;
    queueMicrotask(() => {
      scheduled = false;
      for (const fn of listeners) fn(state);
    });
  }

  return {
    get: () => state,
    subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); },
    setView(view) { if (VIEWS.includes(view) && state.view !== view) { state.view = view; notify(); } },
    setFilters(patch) { Object.assign(state.filters, patch); notify(); },
    resetEventFilters() { for (const k of EVENT_FILTER_KEYS) state.filters[k] = ''; notify(); },
    setUi(patch) { Object.assign(state.ui, patch); notify(); },
    setAuth(patch) { Object.assign(state.auth, patch); notify(); },
    setDemo(v) { state.demo = Boolean(v); notify(); },
    resource(name) {
      if (!state.resources[name]) state.resources[name] = { status: 'idle', data: null, error: null, updatedAt: null, failures: 0, version: 0 };
      return state.resources[name];
    },
    patchResource(name, patch) {
      const r = this.resource(name);
      Object.assign(r, patch);
      r.version += 1;
      if (patch.updatedAt) state.lastRefreshAt = patch.updatedAt;
      notify();
    },
    clearResources() { state.resources = {}; state.lastRefreshAt = null; notify(); },
    notify,
  };
}

/** "#/events?action=block&range=1h" → { view, filters } (unknown keys ignored). */
export function parseHash(hash) {
  const h = String(hash || '').replace(/^#\/?/, '');
  const [path, qs = ''] = h.split('?');
  const view = VIEWS.includes(path) ? path : 'overview';
  const params = new URLSearchParams(qs);
  const filters = {};
  for (const k of HASH_KEYS) if (params.has(k)) filters[k] = params.get(k).slice(0, 200);
  return { view, filters };
}

export function buildHash(view, filters) {
  const params = new URLSearchParams();
  const defaults = defaultFilters();
  for (const k of HASH_KEYS) {
    const v = filters[k];
    if (v === null || v === undefined || v === '' || v === defaults[k]) continue;
    params.set(k, v instanceof Date ? v.toISOString() : String(v));
  }
  const qs = params.toString();
  return `#/${view}${qs ? `?${qs}` : ''}`;
}
