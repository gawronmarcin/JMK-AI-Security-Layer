// Controls — read-only table of every control with filters and a details drawer
// (strict/balanced/permissive config, intervention trend, latency, recent events).

import { alpha, chartBox, timeAxisOptions, upsertChart, vbarOptions } from '../charts.js';
import { actionBadge, boolBadge, chip, createPanel, createTable, dataTableAlt, defList, modeBadge, mono, severityBadge, timeCell } from '../components.js';
import { controlLatencyFromEvents, controlTrend, countBy, inRange } from '../derive.js';
import { activeProfile, controlAction } from '../resources.js';
import { ACTIONS, ACTION_META, COLORS, debounce, el, fmtInt, fmtMs, fmtNum, fmtTime, resolveRange, uniqueSorted } from '../utils.js';
import { grid, signature, stateFor, viewHeader } from './common.js';

const RES = ['controls', 'summary', 'latency', 'events', 'testReport', 'policy'];
const PROFILES = ['strict', 'balanced', 'permissive'];

function priorityBucket(c) {
  if (c.tier) return c.tier;
  if (c.priority === null) return 'unknown';
  if (c.priority < 100) return 'deterministic (<100)';
  if (c.priority < 500) return 'mid (100–499)';
  return 'semantic (≥500)';
}

export function createControls(ctx) {
  let lastSig = '';
  const f = { enabled: '', mode: '', stage: '', action: '', threat: '', priority: '', q: '' };
  let rowsCache = [];

  const mk = (label, key, opts) => {
    const s = el('select', { 'aria-label': label, onChange: (e) => { f[key] = e.target.value; lastSig = ''; ctx.store.notify(); } }, el('option', { value: '', text: `${label}: all` }));
    s.dataset.key = key;
    for (const o of opts || []) s.appendChild(el('option', { value: o, text: o }));
    return s;
  };
  const selEnabled = mk('Enabled', 'enabled', ['enabled', 'disabled']);
  const selMode = mk('Mode', 'mode', ['enforce', 'shadow']);
  const selStage = mk('Stage', 'stage');
  const selAction = mk('Action', 'action');
  const selThreat = mk('Threat', 'threat');
  const selPrio = mk('Priority', 'priority');
  const search = el('input', { type: 'search', placeholder: 'Search ID or name', 'aria-label': 'Search controls by ID or name', onInput: debounce((e) => { f.q = e.target.value; lastSig = ''; ctx.store.notify(); }, 150) });
  const countEl = el('span', { class: 'muted', 'aria-live': 'polite' });
  const toolbar = el('div', { class: 'toolbar', role: 'toolbar', 'aria-label': 'Control filters' }, search, selEnabled, selMode, selStage, selAction, selThreat, selPrio,
    el('button', { type: 'button', class: 'btn btn-sm', text: 'Reset', onClick: () => { Object.keys(f).forEach((k) => { f[k] = ''; }); for (const s of toolbar.querySelectorAll('select')) s.value = ''; search.value = ''; lastSig = ''; ctx.store.notify(); } }),
    countEl);

  const panel = createPanel({ title: 'Security controls', desc: 'All controls from /admin/controls. Action and thresholds are those of the active profile. Interventions = non-allow decisions; latency from /admin/metrics/latency. Select a row for details. Editing is not possible here: change policies/*.yaml, validate, then reload.', span: 12 });
  const table = createTable({
    caption: 'Security controls',
    pageSize: 50,
    onRowClick: (r) => openDetails(r.c),
    columns: [
      { key: 'id', label: 'Control ID', header: true, sort: (r) => r.c.id, render: (r) => mono(r.c.id) },
      { key: 'name', label: 'Name', sort: (r) => r.c.name || '', render: (r) => r.c.name },
      { key: 'enabled', label: 'Enabled', sort: (r) => (r.c.enabled ? 1 : 0), render: (r) => boolBadge(r.c.enabled, 'on', 'off') },
      { key: 'mode', label: 'Mode', sort: (r) => r.mode, render: (r) => modeBadge(r.c.mode || r.globalMode) },
      { key: 'stages', label: 'Stages', render: (r) => (r.c.stages.length ? el('span', { class: 'mono small', text: r.c.stages.join(', ') }) : null) },
      { key: 'action', label: 'Action (profile)', sort: (r) => r.action || '', render: (r) => actionBadge(r.action) },
      { key: 'thr', label: 'Threshold / min sev.', render: (r) => (r.c.threshold !== null ? mono(fmtNum(r.c.threshold, 2)) : r.c.minSeverity ? severityBadge(r.c.minSeverity) : null) },
      { key: 'threats', label: 'Threats', render: (r) => el('span', { class: 'chips' }, r.c.threatIds.map((t) => chip(t, (v) => ctx.filterEvents({ threat: v })))) },
      { key: 'int', label: 'Interventions', className: 'num', sort: (r) => r.interventions ?? -1, render: (r) => (r.interventions === null ? null : fmtInt(r.interventions)) },
      { key: 'p50', label: 'p50', className: 'num', sort: (r) => r.lat?.p50 ?? -1, render: (r) => (r.lat ? fmtMs(r.lat.p50) : null) },
      { key: 'p95', label: 'p95', className: 'num', sort: (r) => r.lat?.p95 ?? -1, render: (r) => (r.lat ? fmtMs(r.lat.p95) : null) },
      { key: 'tests', label: 'Tests', className: 'num', sort: (r) => r.c.tests?.total ?? -1, render: (r) => (r.c.tests?.total === null || r.c.tests?.total === undefined ? null : fmtInt(r.c.tests.total)) },
      { key: 'last', label: 'Last run', sort: (r) => r.lastRun?.getTime() ?? 0, render: (r) => timeCell(r.lastRun) },
    ],
    initialSort: { key: 'int', dir: 'desc' },
    rowKey: (r) => r.c.id,
    rowClass: (r) => (r.c.enabled === false ? 'row-dim' : ''),
  });
  panel.content.appendChild(table.root);

  const root = el('section', { class: 'view', 'aria-labelledby': 'v-controls' },
    viewHeader('Controls', 'What every control does under the active profile, how often it intervenes and what it costs.'),
    toolbar, grid(panel));
  root.querySelector('h1').id = 'v-controls';

  function buildRows(state) {
    const list = state.resources.controls?.data?.list || [];
    const profile = activeProfile(state);
    const globalMode = state.resources.policy?.data?.mode || null;
    const sum = state.resources.summary?.data;
    const byCtl = new Map((sum?.byControl || []).map((e) => [e.key, e.value]));
    const evs = state.resources.events?.data?.events || [];
    const evCounts = byCtl.size ? null : new Map(countBy(evs, (e) => e.controlIds).map((e) => [e.key, e.value]));
    const latList = state.resources.latency?.data?.perControl?.length ? state.resources.latency.data.perControl : controlLatencyFromEvents(evs);
    const lat = new Map(latList.map((l) => [l.id, l]));
    const reportAt = state.resources.testReport?.data?.generatedAt || null;
    const lastHit = new Map();
    for (const e of evs) for (const id of e.allControlIds) if (e.ts && (!lastHit.has(id) || e.ts > lastHit.get(id))) lastHit.set(id, e.ts);
    return list.map((c) => ({
      c,
      globalMode,
      mode: c.mode || globalMode || '',
      action: controlAction(c, profile),
      interventions: c.interventions ?? byCtl.get(c.id) ?? evCounts?.get(c.id) ?? (byCtl.size ? 0 : null),
      lat: lat.get(c.id) || null,
      lastRun: c.lastRun || lastHit.get(c.id) || null,
      reportAt,
    }));
  }

  function fillOptions(sel, values) {
    const cur = sel.value;
    const have = [...sel.options].slice(1).map((o) => o.value).join('|');
    if (have === values.join('|')) return;
    while (sel.options.length > 1) sel.remove(1);
    for (const v of values) sel.appendChild(el('option', { value: v, text: v }));
    sel.value = values.includes(cur) ? cur : '';
  }

  function applyFilters(rows) {
    const q = f.q.trim().toLowerCase();
    return rows.filter((r) => {
      if (f.enabled && (f.enabled === 'enabled') !== (r.c.enabled === true)) return false;
      if (f.mode && (r.mode || 'enforce') !== f.mode) return false;
      if (f.stage && !r.c.stages.includes(f.stage)) return false;
      if (f.action && r.action !== f.action) return false;
      if (f.threat && !r.c.threatIds.includes(f.threat)) return false;
      if (f.priority && priorityBucket(r.c) !== f.priority) return false;
      if (q && !(`${r.c.id} ${r.c.name || ''} ${r.c.key || ''}`.toLowerCase().includes(q))) return false;
      return true;
    });
  }

  // ------------------------------------------------------------- details drawer

  function openDetails(c) {
    const state = ctx.store.get();
    const profile = activeProfile(state);
    const row = rowsCache.find((r) => r.c.id === c.id) || buildRows(state).find((r) => r.c.id === c.id);
    const levelsTable = el('table', { class: 'table table-compact' },
      el('caption', { class: 'sr-only', text: 'Configuration per strictness profile' }),
      el('thead', {}, el('tr', {}, ['Profile', 'Action', 'Threshold', 'Min severity', 'Other params'].map((h) => el('th', { scope: 'col', text: h })))),
      el('tbody', {}, uniqueSorted([...PROFILES, ...Object.keys(c.levels)]).sort((a, b) => PROFILES.indexOf(a) - PROFILES.indexOf(b)).map((p) => {
        const l = c.levels[p];
        return el('tr', { class: p === profile ? 'row-active' : '' },
          el('th', { scope: 'row' }, el('span', { text: p }), p === profile ? el('span', { class: 'badge badge-yes small', text: 'active' }) : null),
          el('td', {}, l ? actionBadge(l.action) : el('span', { class: 'muted', text: 'not configured' })),
          el('td', { class: 'mono', text: l && l.threshold !== null ? fmtNum(l.threshold, 2) : '—' }),
          el('td', {}, l && l.minSeverity ? severityBadge(l.minSeverity) : '—'),
          el('td', { class: 'mono small', text: l && Object.keys(l.params).length ? JSON.stringify(l.params) : '—' }));
      })));

    const { from, to } = resolveRange(state.filters);
    const evs = state.resources.events?.data?.events || [];
    const trend = controlTrend(inRange(evs, from, to), c.id, from, to);
    const trendBox = chartBox(`Interventions of ${c.id} over time`, { height: 180 });
    const latBox = chartBox(`Latency of ${c.id}`, { height: 160 });
    const recent = evs.filter((e) => e.allControlIds.includes(c.id)).slice(0, 12);
    const recentList = el('ol', { class: 'event-list compact' }, recent.length ? recent.map((e) => {
      const d = e.decisions.find((x) => x.controlId === c.id);
      return el('li', {}, el('button', { type: 'button', class: 'event-item', onClick: () => ctx.openEvent(e) },
        el('span', { class: 'muted', text: fmtTime(e.ts) }), actionBadge(d?.shadowSuppressed ? d.action : d?.action || e.finalAction, { would: d?.shadowSuppressed }), severityBadge(d?.severity), el('span', { class: 'mono ev-req', text: e.requestId || e.type })));
    }) : el('li', { class: 'muted', text: 'No loaded events reference this control.' }));

    const content = el('div', { class: 'drawer-sections' },
      el('p', { class: 'notice notice-info', text: 'Read-only. Policy is edited in policies/*.yaml and applied by hot reload or Policy → Reload after validation.' }),
      defList([
        ['Control ID', mono(c.id)], ['Policy key', c.key ? mono(c.key) : null], ['Name', c.name], ['Description', c.description],
        ['Enabled', boolBadge(c.enabled, 'enabled', 'disabled')], ['Mode', modeBadge(c.mode || row?.globalMode)], ['On error', c.onError],
        ['Stages', c.stages.join(', ') || null], ['Priority', c.priority !== null ? String(c.priority) : c.tier], ['Type', c.type],
        ['Threats', el('span', { class: 'chips' }, c.threatIds.map((t) => chip(t, (v) => { ctx.drawer.close(); ctx.filterEvents({ threat: v }); })))],
        ['Tests', c.tests ? `${fmtInt(c.tests.total)} total${c.tests.negative !== null ? ` · ${c.tests.negative} negative · ${c.tests.positive ?? '?'} positive · ${c.tests.edge ?? '?'} edge` : ''}` : null],
        ['Interventions', row?.interventions === null || row?.interventions === undefined ? null : fmtInt(row.interventions)],
        ['Last run', row?.lastRun ? row.lastRun.toLocaleString() : null],
      ]),
      el('h3', { text: 'Configuration per profile' }), el('div', { class: 'table-scroll' }, levelsTable),
      el('h3', { text: 'Interventions over time (selected range)' }), trendBox.box,
      el('h3', { text: 'Latency' }), latBox.box,
      el('p', { class: 'muted small', text: row?.lat ? `p50 ${fmtMs(row.lat.p50)} · p95 ${fmtMs(row.lat.p95)} · p99 ${fmtMs(row.lat.p99)} · samples ${fmtInt(row.lat.count)}` : 'No latency samples.' }),
      el('h3', { text: 'Recent events' }), recentList,
      el('button', { type: 'button', class: 'btn', text: `Open all audit events for ${c.id}`, onClick: () => { ctx.drawer.close(); ctx.filterEvents({ control: c.id }); } }));

    ctx.drawer.open({ title: `Control ${c.id}`, content, onClose: () => { ctx.destroyChart(trendBox.canvas); ctx.destroyChart(latBox.canvas); } });
    const keys = ACTIONS.filter((a) => a !== 'allow');
    upsertChart(trendBox.canvas, {
      type: 'bar', labels: trend.buckets.map((b) => fmtTime(b.t)), meta: trend.buckets,
      datasets: keys.map((a) => ({ id: a, label: ACTION_META[a].label, data: trend.buckets.map((b) => b[a]), backgroundColor: alpha(ACTION_META[a].color, 0.85), stack: 's' })),
      options: { ...timeAxisOptions({ stacked: true }), scales: { ...timeAxisOptions({ stacked: true }).scales, x: { stacked: true, ticks: { maxTicksLimit: 6, maxRotation: 0 } } } },
    });
    const l = row?.lat;
    upsertChart(latBox.canvas, {
      type: 'bar', labels: ['p50', 'p95', 'p99'],
      datasets: [{ id: 'l', label: 'Latency (ms)', data: l ? [l.p50, l.p95, l.p99] : [], backgroundColor: [COLORS.info, COLORS.warning, COLORS.error], maxBarThickness: 40 }],
      options: vbarOptions({ unit: 'ms', legend: false, yTitle: 'ms', tooltipExtra: () => (l?.count !== null && l?.count !== undefined ? `samples: ${fmtInt(l.count)}` : null) }),
    });
  }

  return {
    id: 'controls', title: 'Controls', resources: RES, root,
    openDetails: (id) => { const r = rowsCache.find((x) => x.c.id === id); if (r) openDetails(r.c); },
    render(state) {
      const sig = signature(state, RES, JSON.stringify(f));
      if (sig === lastSig) return;
      lastSig = sig;
      const list = state.resources.controls?.data?.list || [];
      rowsCache = buildRows(state);
      fillOptions(selStage, uniqueSorted(list.flatMap((c) => c.stages)));
      fillOptions(selAction, uniqueSorted(rowsCache.map((r) => r.action)));
      fillOptions(selThreat, uniqueSorted(list.flatMap((c) => c.threatIds)));
      fillOptions(selPrio, uniqueSorted(list.map(priorityBucket)));
      if (!stateFor(ctx, panel, ['controls'], { isEmpty: () => !list.length, emptyMessage: 'The gateway reports no controls.' })) return;
      const filtered = applyFilters(rowsCache);
      countEl.textContent = `${filtered.length} of ${rowsCache.length} controls`;
      table.setRows(filtered);
      panel.setSource(`/admin/controls · profile ${activeProfile(state) || 'unknown'} · interventions: ${state.resources.summary?.data?.byControl?.length ? '/admin/metrics/summary' : 'loaded audit events'} · latency: ${state.resources.latency?.data?.perControl?.length ? '/admin/metrics/latency' : 'loaded audit events'}`);
      panel.setAlt(dataTableAlt('Controls — plain data', ['Control', 'Enabled', 'Action', 'Interventions', 'p95 ms'], filtered.map((r) => [r.c.id, String(r.c.enabled), r.action || '—', r.interventions ?? '—', r.lat?.p95 ?? '—'])));
    },
  };
}
