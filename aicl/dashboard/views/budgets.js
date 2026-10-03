// Budgets — per-identity usage vs limits (tokens, cost, compute seconds, RPM, tool calls/session).
// Different units are never mixed on one axis: the chart shows % of limit only.

import { chartBox, clickHandler, upsertChart, vbarOptions } from '../charts.js';
import { actionBadge, chip, createPanel, createTable, dataTableAlt, progressBar, timeCell } from '../components.js';
import { BUDGET_RESOURCES, budgetResetAt } from '../normalize.js';
import { el, fmtInt, fmtPct, fmtSeconds, fmtUsd, clear } from '../utils.js';
import { eventsSourceText, grid, signature, stateFor, viewHeader } from './common.js';

const RES = ['budgets', 'events'];
const RES_COLORS = { tokens: '#4EA1FF', cost: '#FFB547', compute: '#A78BFA', rpm: '#3DDC97', tool_calls: '#FF8A3D' };

export function fmtBudgetValue(kind, v) {
  if (v === null || v === undefined) return '—';
  if (kind === 'cost') return fmtUsd(v);
  if (kind === 'compute') return fmtSeconds(v);
  return fmtInt(v);
}

function resourceText(r) {
  if (r.used === null && r.unlimited) return 'Unlimited (no usage reported)';
  if (r.unlimited) return `${fmtBudgetValue(r.kind, r.used)} ${r.kind === 'cost' || r.kind === 'compute' ? '' : r.unit} · Unlimited`;
  if (r.used === null) return `no usage reported / ${fmtBudgetValue(r.kind, r.limit)}`;
  return `${fmtBudgetValue(r.kind, r.used)} / ${fmtBudgetValue(r.kind, r.limit)}${r.kind === 'cost' || r.kind === 'compute' ? '' : ` ${r.unit}`} (${r.pct === Infinity ? '∞' : fmtPct(r.pct)})`;
}

export function createBudgets(ctx) {
  let lastSig = '';
  const kindSel = el('select', { 'aria-label': 'Resource type', onChange: (e) => ctx.store.setUi({ budgetKind: e.target.value }) },
    el('option', { value: '', text: 'All resources' }), BUDGET_RESOURCES.map((r) => el('option', { value: r.kind, text: r.label })));
  const toolbar = el('div', { class: 'toolbar', role: 'toolbar', 'aria-label': 'Budget filters' }, el('label', { class: 'field-inline' }, el('span', { text: 'Resource' }), kindSel),
    el('span', { class: 'muted small', text: 'Sorted by highest utilisation. Thresholds: <70% normal · 70–89% warning · 90–99% high · ≥100% exceeded. Missing/null limit = Unlimited.' }));

  const chartPanel = createPanel({ title: 'Utilisation by identity', desc: 'Usage as a percentage of each limit, so tokens, USD and seconds are never placed on one numeric axis. Unlimited resources are not plotted. Click a bar to filter audit events by identity.', unit: '% of limit', span: 12 });
  const chart = chartBox('Budget utilisation by identity', { height: 300 });
  chartPanel.content.appendChild(chart.box);

  const listPanel = createPanel({ title: 'Usage vs limits', desc: 'Current budget window per identity (budget name from the role, window minute/hour/day). Values come from /admin/metrics/budgets.', span: 12 });
  const cards = el('div', { class: 'budget-cards' });
  listPanel.content.appendChild(cards);

  const exPanel = createPanel({ title: 'budget.exceeded events', desc: 'Audit events of type budget.exceeded and requests stopped by C-BUDGET in the loaded window.', span: 12 });
  const exTable = createTable({
    caption: 'Budget exceeded events',
    pageSize: 15,
    onRowClick: (e) => ctx.openEvent(e),
    columns: [
      { key: 'ts', label: 'Time', sort: (e) => e.ts?.getTime() || 0, render: (e) => timeCell(e.ts) },
      { key: 'type', label: 'Type', render: (e) => el('span', { class: `mono${e.type === 'budget.exceeded' ? ' text-error' : ''}`, text: e.type }) },
      { key: 'identity', label: 'Identity', render: (e) => (e.identity ? chip(e.identity, (v) => ctx.filterEvents({ identity: v })) : null) },
      { key: 'action', label: 'Action', render: (e) => actionBadge(e.finalAction) },
      { key: 'reason', label: 'Reason', render: (e) => e.reason || e.decisions.find((d) => d.controlId === 'C-BUDGET')?.reason || null },
      { key: 'req', label: 'Request ID', render: (e) => el('span', { class: 'mono small', text: e.requestId || '' }) },
    ],
    initialSort: { key: 'ts', dir: 'desc' },
  });
  exPanel.content.appendChild(exTable.root);

  const root = el('section', { class: 'view', 'aria-labelledby': 'v-budgets' },
    viewHeader('Budgets', 'Are token, cost, compute or rate limits close to being exceeded?'),
    toolbar, grid(chartPanel, listPanel, exPanel));
  root.querySelector('h1').id = 'v-budgets';

  function render(state) {
    const all = state.resources.budgets?.data || [];
    const kind = state.ui.budgetKind;
    kindSel.value = kind;
    const kinds = BUDGET_RESOURCES.filter((r) => !kind || r.kind === kind);
    const score = (b) => Math.max(-1, ...b.resources.filter((r) => kinds.some((k) => k.kind === r.kind)).map((r) => (r.pct === null ? -1 : r.pct)));
    const sorted = [...all].sort((a, b) => score(b) - score(a));
    const exceededIds = new Set();
    const evs = state.resources.events?.data?.events || [];
    const exEvents = evs.filter((e) => e.type === 'budget.exceeded' || e.decisions.some((d) => d.controlId === 'C-BUDGET' && d.action !== 'allow' && !d.skipped));
    for (const e of exEvents) if (e.identity) exceededIds.add(e.identity);

    if (stateFor(ctx, chartPanel, ['budgets'], { isEmpty: () => !sorted.length, emptyMessage: 'No identities with budgets reported.' })) {
      const labels = sorted.map((b) => b.identity);
      upsertChart(chart.canvas, {
        type: 'bar',
        labels,
        meta: sorted,
        datasets: kinds.map((k) => ({
          id: k.kind,
          label: `${k.label} (% of limit)`,
          data: sorted.map((b) => { const r = b.resources.find((x) => x.kind === k.kind); return r && r.pct !== null && r.pct !== Infinity ? +(r.pct * 100).toFixed(2) : r && r.pct === Infinity ? 100 : null; }),
          backgroundColor: RES_COLORS[k.kind],
          borderRadius: 2,
          maxBarThickness: 18,
        })),
        options: vbarOptions({
          unit: 'pct', yTitle: '% of limit',
          onClick: clickHandler(({ meta }) => { if (meta) ctx.filterEvents({ identity: meta.identity }); }),
          tooltipExtra: (item) => {
            const b = item.chart.data.meta?.[item.dataIndex];
            const r = b?.resources.find((x) => x.kind === item.dataset.id);
            if (!r) return null;
            return [`${resourceText(r)}`, `unit: ${r.unit} · window: ${b.window || 'n/a'}${b.budget ? ` · budget: ${b.budget}` : ''}`];
          },
        }),
      });
      // keep the 100 % reference visible
      chart.canvas.setAttribute('aria-label', `Budget utilisation for ${labels.length} identities; highest: ${labels[0] || 'none'}`);
      chartPanel.setAlt(dataTableAlt('Budget utilisation — data table', ['Identity', ...kinds.map((k) => k.label)], sorted.map((b) => [b.identity, ...kinds.map((k) => resourceText(b.resources.find((x) => x.kind === k.kind)))])));
      chartPanel.setSource('/admin/metrics/budgets');
    }

    if (stateFor(ctx, listPanel, ['budgets'], { isEmpty: () => !sorted.length, emptyMessage: 'No identities with budgets reported.' })) {
      clear(cards);
      for (const b of sorted) {
        const reset = budgetResetAt(b);
        const flagged = b.exceeded || exceededIds.has(b.identity);
        const card = el('article', { class: `budget-card${flagged ? ' is-exceeded' : ''}`, 'aria-label': `Budget of ${b.identity}` },
          el('header', { class: 'budget-head' },
            el('button', { type: 'button', class: 'link mono', text: b.identity, title: 'Filter audit events by this identity', onClick: () => ctx.filterEvents({ identity: b.identity }) }),
            el('span', { class: 'muted small', text: [b.role, b.budget ? `budget ${b.budget}` : null, b.window ? `window: ${b.window}` : null].filter(Boolean).join(' · ') }),
            flagged ? el('span', { class: 'badge badge-exceeded' }, el('span', { 'aria-hidden': 'true', text: '✕' }), el('span', { text: 'budget.exceeded' })) : null),
          el('dl', { class: 'budget-rows' }, b.resources.filter((r) => kinds.some((k) => k.kind === r.kind)).map((r) => el('div', { class: 'budget-row' },
            el('dt', { text: r.label }),
            el('dd', {}, progressBar({ pct: r.unlimited ? null : r.pct === Infinity ? 1 : r.pct ?? 0, level: r.level, label: `${b.identity} ${r.label}`, valueText: resourceText(r) }), el('span', { class: 'budget-val mono small', text: resourceText(r) }))))),
          el('footer', { class: 'muted small', text: `${reset ? `Resets ${reset.toLocaleString()}` : 'Reset time not reported'}${b.onExceed ? ` · on exceed: ${b.onExceed}` : ''}` }));
        cards.appendChild(card);
      }
      listPanel.setSource('/admin/metrics/budgets — "Unlimited" = limit null or omitted in policy (§6.5)');
    }

    if (stateFor(ctx, exPanel, ['events'], { isEmpty: () => !exEvents.length, emptyMessage: 'No budget.exceeded events in the loaded window.' })) {
      exTable.setRows(exEvents);
      exPanel.setSource(eventsSourceText(state.resources.events, evs.length));
    }
  }

  return {
    id: 'budgets', title: 'Budgets', resources: RES, root,
    render(state) {
      const sig = signature(state, RES, state.ui.budgetKind);
      if (sig === lastSig) return;
      lastSig = sig;
      render(state);
    },
  };
}

