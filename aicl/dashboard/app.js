// AICL dashboard — bootstrap: config, auth flow, routing, topbar, refresh scheduler, views.

import { createApi } from './api.js';
import { auth } from './auth.js';
import { destroyChart, setupChartDefaults, chartsAvailable } from './charts.js';
import { createDrawer, openDialog, toast } from './components.js';
import { createResources } from './resources.js';
import { createScheduler, isStale } from './refresh.js';
import { EVENT_FILTER_KEYS, VIEWS, buildHash, createStore, defaultFilters, parseHash } from './state.js';
import { clear, el, fmtRelative, fmtTime } from './utils.js';
import { createBudgets } from './views/budgets.js';
import { createControls } from './views/controls.js';
import { createEvents, eventDetails } from './views/events.js';
import { createOverview } from './views/overview.js';
import { createPerformance } from './views/performance.js';
import { createPolicy } from './views/policy.js';
import { createTests } from './views/tests.js';
import { createThreats } from './views/threats.js';

const TOPBAR_RES = ['health', 'policy'];

function readConfig() {
  const defaults = { apiBase: '', timeoutMs: 10000, eventsLimit: 2000, maxEventsInMemory: 10000, defaultRefreshMs: 5000, reports: { tests: null, fuzz: null } };
  try {
    const node = document.getElementById('aicl-config');
    const parsed = node ? JSON.parse(node.textContent) : {};
    return { ...defaults, ...parsed, reports: { ...defaults.reports, ...(parsed.reports || {}) } };
  } catch {
    return defaults;
  }
}

function main() {
  const config = readConfig();
  const store = createStore();
  store.setUi({ refreshMs: [0, 2000, 5000, 10000, 30000].includes(config.defaultRefreshMs) ? config.defaultRefreshMs : 5000 });
  if (chartsAvailable()) setupChartDefaults();
  else toast('Chart.js (vendor/chart.umd.min.js) failed to load — charts fall back to data tables.', 'error', 0);

  const api = createApi({ baseUrl: config.apiBase, timeoutMs: config.timeoutMs, onUnauthorized: () => handleUnauthorized() });
  let adapter = api;
  let resources = createResources(adapter, config);
  let running = false;

  const drawer = createDrawer(document.getElementById('drawer'));
  const views = {};
  const viewsRoot = document.getElementById('views');

  const scheduler = createScheduler({
    store,
    resources: () => resources,
    activeResources: () => [...new Set([...TOPBAR_RES, ...(views[store.get().view]?.resources || [])])],
    canRun: () => running,
  });

  // ------------------------------------------------------------- navigation & filters

  function syncHash(push = false) {
    const s = store.get();
    const h = buildHash(s.view, s.filters);
    if (location.hash !== h) history[push ? 'pushState' : 'replaceState'](null, '', `${location.pathname}${location.search}${h}`);
  }

  function go(view, { push = true } = {}) {
    if (!VIEWS.includes(view)) return;
    drawer.close();
    store.setView(view);
    syncHash(push);
    closeNav();
    scheduler.ensureFresh(views[view]?.resources || []);
    const main = document.getElementById('main');
    main.focus({ preventScroll: true });
    window.scrollTo({ top: 0, behavior: 'instant' in window ? 'instant' : 'auto' });
  }

  function setFilters(patch) {
    const before = store.get().filters;
    const rangeChanged = ['range', 'from', 'to'].some((k) => k in patch && patch[k] !== before[k]);
    store.setFilters(patch);
    syncHash(false);
    if (rangeChanged) scheduler.run('events', { force: true });
  }

  function filterEvents(patch) {
    const cleared = Object.fromEntries(EVENT_FILTER_KEYS.map((k) => [k, '']));
    const cur = store.get().filters;
    setFilters({ ...cleared, range: cur.range, from: cur.from, to: cur.to, ...patch });
    go('events');
  }

  const ctx = {
    store, config, drawer,
    get api() { return adapter; },
    setFilters, filterEvents,
    refresh: (names) => scheduler.refreshNow(names),
    isStale: (r) => isStale(r, store.get().ui.refreshMs),
    setRefresh: (ms) => { store.setUi({ refreshMs: ms }); document.getElementById('refresh-interval').value = String(ms); scheduler.replan(); },
    openEvent: (e) => drawer.open({ title: `Event ${e.requestId || e.eventId || e.type}`, content: eventDetails(ctx, e) }),
    openControl: (id) => { go('controls'); renderNow(); views.controls.openDetails(id); },
    destroyChart,
    exportAudit,
  };

  for (const make of [createOverview, createThreats, createControls, createBudgets, createPerformance, createTests, createEvents, createPolicy]) {
    const v = make(ctx);
    v.root.hidden = true;
    views[v.id] = v;
    viewsRoot.appendChild(v.root);
  }

  // ------------------------------------------------------------- rendering

  const gwEl = document.getElementById('st-gateway');
  /** Required (non-optional) resources of the topbar + current view. */
  const activeNames = (s) => [...new Set([...TOPBAR_RES, ...(views[s.view]?.resources || [])])].filter((n) => !resources[n]?.optional);
  function gatewayStatus(s) {
    const h = s.resources.health;
    const required = activeNames(s).map((n) => s.resources[n]).filter(Boolean);
    if (!h || h.status === 'idle' || (h.status === 'loading' && !h.data)) return { kind: 'unknown', label: 'Checking…' };
    if (h.status === 'error' && ['network', 'timeout', 'server'].includes(h.error?.kind)) return { kind: 'offline', label: 'Offline', title: h.error?.message };
    const failing = required.filter((r) => r.status === 'error');
    if ((h.data && !h.data.ok) || failing.length) return { kind: 'degraded', label: 'Degraded', title: h.data && !h.data.ok ? `healthz status: ${h.data.status}` : `${failing.length} admin endpoint(s) failing` };
    return { kind: 'online', label: 'Online', title: 'healthz OK and all admin endpoints responding' };
  }

  function renderTopbar(s) {
    const st = gatewayStatus(s);
    const icon = { online: '●', degraded: '▲', offline: '✕', unknown: '○' }[st.kind];
    clear(gwEl).appendChild(el('span', { class: `gw-pill gw-${st.kind}`, title: st.title || '' }, el('span', { 'aria-hidden': 'true', text: icon }), el('span', { text: ` ${st.label}` })));
    const p = s.resources.policy?.data;
    const h = s.resources.health?.data;
    const evs = s.resources.events?.data?.events || [];
    const lastFeed = evs.find((e) => e.feedVersion)?.feedVersion;
    document.getElementById('st-profile').textContent = p?.activeProfile || h?.profile || '—';
    const mode = p?.mode || h?.mode;
    const modeEl = document.getElementById('st-mode');
    clear(modeEl).appendChild(el('span', { class: `badge ${mode === 'shadow' ? 'badge-shadow' : mode ? 'badge-enforce' : ''}` }, el('span', { 'aria-hidden': 'true', text: mode === 'shadow' ? '◌ ' : mode ? '◆ ' : '' }), el('span', { text: mode || '—' })));
    document.getElementById('st-policy').textContent = p?.policyVersion || h?.policyVersion || '—';
    document.getElementById('st-feed').textContent = p?.feedVersion || h?.feedVersion || lastFeed || '—';
    const anyStale = Object.values(s.resources).some((r) => ctx.isStale(r));
    const refreshed = document.getElementById('st-refreshed');
    refreshed.textContent = s.lastRefreshAt ? `${fmtTime(s.lastRefreshAt)} (${fmtRelative(s.lastRefreshAt)})${anyStale ? ' · stale' : ''}` : '—';
    refreshed.classList.toggle('text-warn', anyStale);
    document.getElementById('refresh-now').classList.toggle('spinning', Object.values(s.resources).some((r) => r.refreshing));

    // total failure banner: every active resource failed and nothing to show
    const banner = document.getElementById('global-banner');
    const names = activeNames(s);
    const rs = names.map((n) => s.resources[n]).filter(Boolean);
    const total = running && rs.length === names.length && rs.every((r) => r.status === 'error' && !r.data);
    banner.hidden = !total;
    if (total) {
      clear(banner).append(el('strong', { text: 'Gateway unreachable. ' }), el('span', { text: `All admin endpoints are failing (${rs[0].error?.message || 'error'}). Retrying with exponential backoff.` }), el('button', { type: 'button', class: 'btn btn-sm', text: 'Retry now', onClick: () => scheduler.refreshNow() }));
    }
  }

  let lastView = null;
  function renderNow() {
    const s = store.get();
    renderTopbar(s);
    for (const [id, v] of Object.entries(views)) v.root.hidden = id !== s.view;
    for (const a of document.querySelectorAll('#nav-list a')) {
      if (a.dataset.view === s.view) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    }
    if (lastView !== s.view) { document.title = `${views[s.view].title} — JMK AI Control Layer`; lastView = s.view; }
    try { views[s.view].render(s); } catch (err) {
      // never let one broken payload take the whole UI down; surface it instead
      toast(`Rendering ${views[s.view].title} failed: ${err && err.message ? err.message : err}`, 'error');
    }
  }
  store.subscribe(renderNow);
  setInterval(() => store.notify(), 5000); // relative times + stale badges

  // ------------------------------------------------------------- auth flow

  const dlg = document.getElementById('login-dialog');
  const keyInput = document.getElementById('admin-key');
  const errEl = document.getElementById('login-error');
  let releaseDialog = null;

  function showLogin(message = '') {
    running = false;
    errEl.hidden = !message;
    errEl.textContent = message;
    keyInput.value = '';
    signOutBtn.textContent = 'Sign in';
    if (!releaseDialog) releaseDialog = openDialog(dlg, { onEscape: hideLogin, initialFocus: keyInput });
    keyInput.focus();
  }
  function hideLogin() { releaseDialog?.(); releaseDialog = null; }
  const signOutBtn = document.getElementById('sign-out');

  function startSession() {
    hideLogin();
    signOutBtn.textContent = store.get().demo ? 'Exit demo' : 'Sign out';
    resources = createResources(adapter, config);
    store.clearResources();
    scheduler.reset();
    running = true;
    scheduler.start();
    scheduler.refreshNow();
  }

  function handleUnauthorized() {
    if (!running && !auth.hasCredentials()) return;
    auth.clear();
    running = false;
    api.abortAll();
    store.clearResources();
    drawer.close();
    showLogin('The gateway rejected the admin credentials (401). Sign in again.');
  }

  /** Probe one admin endpoint: only 401/403 block sign-in, other failures surface per panel. */
  async function probe() {
    try { await api.policy(); return null; } catch (err) {
      if (err.kind === 'unauthorized') return auth.isOpenMode() ? 'The gateway requires an admin key (401) — admin auth is not disabled.' : 'Admin key rejected (401).';
      if (err.kind === 'forbidden') return 'This key is valid but its identity lacks the admin role (403).';
      return null;
    }
  }

  async function signIn(mode) {
    const submit = document.getElementById('login-submit');
    submit.disabled = true;
    errEl.hidden = true;
    if (mode === 'key') {
      const k = keyInput.value;
      keyInput.value = '';
      if (!k.trim()) { errEl.textContent = 'Enter the admin key.'; errEl.hidden = false; submit.disabled = false; keyInput.focus(); return; }
      auth.setKey(k);
    } else auth.useOpenMode();
    const problem = await probe();
    submit.disabled = false;
    if (problem) { auth.clear(); errEl.textContent = problem; errEl.hidden = false; keyInput.focus(); return; }
    store.setAuth({ status: mode === 'key' ? 'signed_in' : 'open' });
    adapter = api;
    startSession();
    toast(mode === 'key' ? 'Signed in. The key is held in page memory only.' : 'Connected without admin key (local open mode).', 'success');
  }

  document.getElementById('login-form').addEventListener('submit', (e) => { e.preventDefault(); signIn('key'); });
  document.getElementById('login-open').addEventListener('click', () => signIn('open'));
  document.getElementById('login-demo').addEventListener('click', () => {
    const url = new URL(location.href);
    url.searchParams.set('demo', '1');
    location.href = url.toString();
  });
  signOutBtn.addEventListener('click', () => {
    if (store.get().demo) { exitDemo(); return; }
    if (!running) { showLogin(); return; }
    auth.clear();
    running = false;
    api.abortAll();
    store.clearResources();
    drawer.close();
    showLogin('Signed out. The key was removed from memory.');
  });

  // ------------------------------------------------------------- demo mode (explicit only)

  function exitDemo() {
    const url = new URL(location.href);
    url.searchParams.delete('demo');
    location.href = url.toString();
  }
  async function startDemo() {
    const { createDemoAdapter } = await import('./demo/demo-adapter.js');
    adapter = createDemoAdapter({ base: './demo/' });
    store.setDemo(true);
    store.setAuth({ status: 'demo' });
    document.body.classList.add('is-demo');
    document.getElementById('demo-ribbon').hidden = false;
    startSession();
  }
  document.getElementById('demo-exit').addEventListener('click', exitDemo);

  // ------------------------------------------------------------- export

  async function exportAudit(btn) {
    btn.disabled = true;
    const label = btn.textContent;
    btn.textContent = 'Exporting…';
    try {
      const { blob } = await adapter.exportAudit();
      const url = URL.createObjectURL(blob);
      const a = el('a', { href: url, download: `aicl-audit-${new Date().toISOString().replace(/[:.]/g, '-')}${store.get().demo ? '-DEMO' : ''}.jsonl` });
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
      toast(`Audit export downloaded (${Math.round(blob.size / 1024)} KB).`, 'success');
    } catch (err) {
      toast(`Export failed: ${err.message}`, 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = label;
    }
  }

  // ------------------------------------------------------------- chrome: refresh, nav, hash

  const intervalSel = document.getElementById('refresh-interval');
  intervalSel.value = String(store.get().ui.refreshMs);
  intervalSel.addEventListener('change', () => ctx.setRefresh(Number(intervalSel.value)));
  document.getElementById('refresh-now').addEventListener('click', () => scheduler.refreshNow());

  const sidebar = document.getElementById('sidebar');
  const menuBtn = document.getElementById('menu-toggle');
  const navBackdrop = document.getElementById('nav-backdrop');
  function openNav() { document.body.classList.add('nav-open'); menuBtn.setAttribute('aria-expanded', 'true'); navBackdrop.hidden = false; sidebar.querySelector('a')?.focus(); }
  function closeNav() { if (!document.body.classList.contains('nav-open')) return; document.body.classList.remove('nav-open'); menuBtn.setAttribute('aria-expanded', 'false'); navBackdrop.hidden = true; }
  menuBtn.addEventListener('click', () => (document.body.classList.contains('nav-open') ? closeNav() : openNav()));
  navBackdrop.addEventListener('click', closeNav);
  sidebar.addEventListener('keydown', (e) => { if (e.key === 'Escape' && document.body.classList.contains('nav-open')) { closeNav(); menuBtn.focus(); } });
  for (const a of document.querySelectorAll('#nav-list a')) a.addEventListener('click', (e) => { e.preventDefault(); go(a.dataset.view); });

  function applyHash() {
    const { view, filters } = parseHash(location.hash);
    store.setFilters({ ...defaultFilters(), ...filters });
    store.setView(view);
    scheduler.ensureFresh(views[view]?.resources || []);
  }
  window.addEventListener('hashchange', applyHash);
  window.addEventListener('popstate', applyHash);
  applyHash();
  syncHash(false);
  renderNow();

  if (new URLSearchParams(location.search).get('demo') === '1') startDemo().catch((e) => toast(`Demo data failed to load: ${e.message}`, 'error', 0));
  else showLogin();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', main);
else main();
