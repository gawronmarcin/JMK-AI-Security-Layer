// AICL dashboard — central refresh scheduler.
// - polls only while the tab is visible; refreshes immediately when it becomes visible again
// - never runs two copies of the same resource request (in-flight guard)
// - manual refresh aborts the stale request (AbortController in api.js) and starts a new one
// - bounded exponential backoff per resource after failures (honours Retry-After on 429)
// - a failing resource never stops the others (partial failure)

const MAX_BACKOFF_MS = 60000;
const TICK_MS = 1000;

/**
 * @param {object} o
 * @param {ReturnType<import('./state.js').createStore>} o.store
 * @param {Record<string, {load: Function, minIntervalMs?: number, optional?: boolean}>} o.resources
 * @param {() => string[]} o.activeResources  names needed by the topbar + current view
 * @param {() => boolean} o.canRun             false while signed out
 * @param {(name: string, err: Error) => void} [o.onError]
 */
export function createScheduler({ store, resources: resourcesOrFn, activeResources, canRun, onError = () => {} }) {
  const res = typeof resourcesOrFn === 'function' ? resourcesOrFn : () => resourcesOrFn;
  const nextAt = new Map();
  const running = new Map(); // name -> promise
  let timer = null;
  let started = false;

  function intervalFor(name) {
    const base = store.get().ui.refreshMs;
    if (!base) return Infinity; // auto-refresh off: only manual / navigation refreshes
    return Math.max(base, res()[name].minIntervalMs || 0);
  }

  function backoffFor(failures, err) {
    if (err && err.retryAfterMs) return Math.min(MAX_BACKOFF_MS, Math.max(err.retryAfterMs, 1000));
    const base = Math.max(2000, Math.min(store.get().ui.refreshMs || 5000, 10000));
    return Math.min(MAX_BACKOFF_MS, base * 2 ** Math.max(0, failures - 1));
  }

  async function run(name, { force = false } = {}) {
    const def = res()[name];
    if (!def) return;
    if (running.has(name)) {
      if (!force) return running.get(name);
      def.abort?.(); // supersede: api.js aborts the previous controller for the same key
    }
    const r = store.resource(name);
    store.patchResource(name, { status: r.status === 'idle' ? 'loading' : r.status, refreshing: true });
    const p = (async () => {
      try {
        const data = await def.load(store.get());
        store.patchResource(name, { status: 'ok', data, error: null, updatedAt: new Date(), failures: 0, refreshing: false });
        nextAt.set(name, Date.now() + intervalFor(name));
      } catch (err) {
        if (err && err.kind === 'aborted') {
          store.patchResource(name, { refreshing: false });
          return;
        }
        const failures = (store.resource(name).failures || 0) + 1;
        // optional resources (static reports) that do not exist are "unavailable", not failing
        const unavailable = def.optional && err && err.kind === 'not_found';
        store.patchResource(name, { status: unavailable ? 'unavailable' : 'error', error: err, failures: unavailable ? 0 : failures, refreshing: false });
        nextAt.set(name, Date.now() + (unavailable ? Math.max(60000, intervalFor(name)) : backoffFor(failures, err)));
        if (!unavailable) onError(name, err);
      } finally {
        running.delete(name);
      }
    })();
    running.set(name, p);
    return p;
  }

  function tick() {
    timer = null;
    if (!document.hidden && canRun()) {
      const now = Date.now();
      for (const name of activeResources()) {
        if (!res()[name] || running.has(name)) continue;
        const due = nextAt.has(name) ? nextAt.get(name) : 0;
        if (now >= due) run(name);
      }
    }
    schedule();
  }

  function schedule() {
    if (!started || timer !== null || document.hidden) return;
    timer = setTimeout(tick, TICK_MS);
  }

  function onVisibility() {
    if (document.hidden) {
      clearTimeout(timer);
      timer = null;
    } else {
      refreshNow(); // immediately catch up after the tab was hidden
      schedule();
    }
  }

  function refreshNow(names = null, { force = true } = {}) {
    if (!canRun()) return Promise.resolve();
    const list = names || activeResources();
    return Promise.all(list.filter((n) => res()[n]).map((n) => run(n, { force })));
  }

  /** Refresh resources of a newly shown view only if never loaded or older than their interval. */
  function ensureFresh(names) {
    if (!canRun()) return;
    const now = Date.now();
    for (const n of names) {
      const r = store.resource(n);
      const age = r.updatedAt ? now - r.updatedAt.getTime() : Infinity;
      const interval = intervalFor(n);
      if (!running.has(n) && (age >= Math.min(interval, 30000) || r.status === 'idle')) run(n);
    }
  }

  return {
    start() {
      if (started) return;
      started = true;
      document.addEventListener('visibilitychange', onVisibility);
      schedule();
    },
    stop() {
      started = false;
      clearTimeout(timer);
      timer = null;
      document.removeEventListener('visibilitychange', onVisibility);
    },
    reset() { nextAt.clear(); },
    /** Interval changed: re-plan next polls relative to now. */
    replan() {
      const now = Date.now();
      for (const n of Object.keys(res())) if (store.resource(n).updatedAt) nextAt.set(n, now + intervalFor(n));
    },
    refreshNow,
    ensureFresh,
    run,
    isRunning: (n) => running.has(n),
  };
}

/** Data is stale when the last success is older than max(3 × interval, 30 s), or the last attempt failed. */
export function isStale(resource, refreshMs, now = Date.now()) {
  if (!resource || !resource.updatedAt) return false;
  if (resource.status === 'error') return true;
  const limit = Math.max((refreshMs || 30000) * 3, 30000);
  return now - resource.updatedAt.getTime() > limit;
}
