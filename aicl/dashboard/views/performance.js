// Performance — total AICL overhead vs the 20 ms p95 target, upstream latency (separately),
// per-control percentiles, semantic-judge latency and cheap-path ratio.

import { chartBox, clickHandler, hbarOptions, upsertChart, vbarOptions } from '../charts.js';
import { createKpi, createPanel, dataTableAlt } from '../components.js';
import { controlLatencyFromEvents, overheadFromEvents, semanticUsage } from '../derive.js';
import { COLORS, el, fmtInt, fmtMs, fmtPct } from '../utils.js';
import { eventsSourceText, grid, signature, stateFor, viewHeader } from './common.js';

const RES = ['latency', 'summary', 'events'];
const SERIES = [
  // one hue, three lightness steps: percentiles are not "good/bad" states, so no semantic colours
  { key: 'p50', label: 'p50', color: '#A9D2FF' },
  { key: 'p95', label: 'p95', color: '#4EA1FF' },
  { key: 'p99', label: 'p99', color: '#2F6FC4' },
];
const TARGET_MS = 20;
const JUDGE_ID = 'C-INJ-SEM';

function ctlOptions(args) {
  const o = hbarOptions({ unit: 'ms', xTitle: 'ms', ...args });
  o.plugins.targetLine = { value: TARGET_MS, axis: 'x', label: `Target ${TARGET_MS} ms`, color: COLORS.info };
  o.scales.x.suggestedMax = TARGET_MS * 1.1;
  return o;
}

function ovhOptions(maxVal) {
  const o = vbarOptions({ unit: 'ms', yTitle: 'ms', legend: true, tooltipExtra: (item) => (item.dataset.samples ? `samples: ${fmtInt(item.dataset.samples)}` : null) });
  o.plugins.targetLine = { value: TARGET_MS, label: `Target ${TARGET_MS} ms (p95 goal)`, color: COLORS.info };
  o.scales.y.suggestedMax = maxVal * 1.1;
  return o;
}

export function createPerformance(ctx) {
  let lastSig = '';
  const kpiDefs = [
    ['ovh50', 'Overhead p50', 'latency.total_overhead p50 — median time spent in AICL per request, excluding the upstream call.'],
    ['ovh95', 'Overhead p95', 'latency.total_overhead p95. Target ≤ 20 ms for a ~2 KB prompt (§12) — a target, not a measurement.'],
    ['ovh99', 'Overhead p99', 'latency.total_overhead p99.'],
    ['up95', 'Upstream p95', 'latency.upstream p95 — time spent waiting for the LLM / tool backend. Not part of AICL overhead.'],
    ['sem95', 'Semantic judge p95', 'p95 latency of the semantic judge (C-INJ-SEM) on requests where it actually ran.'],
    ['judge', 'Judge share', 'Share of requests routed to the semantic judge.'],
    ['cheap', 'Cheap-path ratio', 'Share of requests decided by deterministic controls only (judge skipped).'],
  ];
  const kpis = new Map();
  const kpiGrid = el('div', { class: 'kpi-grid', role: 'list' });
  for (const [id, label, tip] of kpiDefs) { const k = createKpi({ label, tip }); k.root.setAttribute('role', 'listitem'); kpis.set(id, k); kpiGrid.appendChild(k.root); }

  const ovhPanel = createPanel({ title: 'Total AICL overhead', desc: 'latency.total_overhead percentiles. The dashed line is the 20 ms p95 TARGET from ARCHITECTURE §12 — a goal, not a measured value.', unit: 'ms', span: 6 });
  const ovh = chartBox('Total AICL overhead percentiles with 20 ms target', { height: 260 });
  const ovhNote = el('p', { class: 'metric-line' });
  ovhPanel.content.append(ovh.box, ovhNote);

  const upPanel = createPanel({ title: 'Upstream latency', desc: 'latency.upstream percentiles — LLM / tool backend time. Shown separately because it is not AICL overhead and is usually orders of magnitude larger.', unit: 'ms', span: 6 });
  const up = chartBox('Upstream latency percentiles', { height: 260 });
  upPanel.content.appendChild(up.box);

  const ctlPanel = createPanel({ title: 'Latency by control', desc: 'latency.per_control p50 / p95 / p99 per control, sorted by p95 (descending). Click a legend entry to hide a series, click a bar to filter audit events by control. The tooltip shows the number of samples.', unit: 'ms', span: 12 });
  const sortSel = el('select', { 'aria-label': 'Sort controls by', onChange: () => { lastSig = ''; ctx.store.notify(); } }, ['p95', 'p99', 'p50', 'count'].map((k) => el('option', { value: k, text: `Sort: ${k}` })));
  const judgeBox = el('input', { type: 'checkbox', onChange: () => { lastSig = ''; ctx.store.notify(); } });
  const judgeLbl = el('label', { class: 'field-inline' }, judgeBox, 'Include semantic judge');
  ctlPanel.root.querySelector('.panel-head').appendChild(el('div', { class: 'panel-tools' }, judgeLbl, sortSel));
  const ctl = chartBox('Latency by control', { height: 420 });
  ctlPanel.content.appendChild(ctl.box);

  const root = el('section', { class: 'view', 'aria-labelledby': 'v-performance' },
    viewHeader('Performance', 'Which controls add the most latency, and is the deterministic path within target?'),
    kpiGrid, grid(ovhPanel, upPanel, ctlPanel));
  root.querySelector('h1').id = 'v-performance';

  function render(state) {
    const latRes = state.resources.latency;
    const lat = latRes?.data;
    const evs = (state.resources.events?.data?.events || []).filter((e) => e.type === 'request');
    const total = lat?.total || null;
    const upstream = lat?.upstream || null;
    const kState = !latRes || (latRes.status !== 'ok' && !lat) ? (latRes?.status === 'error' ? 'error' : 'loading') : 'ok';
    const s = (b, k) => (b ? b[k] : null);
    kpis.get('ovh50').update({ state: kState, value: fmtMs(s(total, 'p50')), sub: total?.count ? `${fmtInt(total.count)} samples` : '', color: COLORS.info });
    const p95 = s(total, 'p95');
    kpis.get('ovh95').update({ state: kState, value: fmtMs(p95), sub: p95 === null ? 'not reported' : p95 <= TARGET_MS ? `≤ ${TARGET_MS} ms target` : `> ${TARGET_MS} ms target`, color: p95 !== null && p95 > TARGET_MS ? COLORS.warning : COLORS.success });
    kpis.get('ovh99').update({ state: kState, value: fmtMs(s(total, 'p99')), sub: s(total, 'p99') !== null && s(total, 'p99') > TARGET_MS ? 'tail incl. semantic judge calls' : '', color: COLORS.info });
    kpis.get('up95').update({ state: kState, value: fmtMs(s(upstream, 'p95')), sub: upstream ? `p50 ${fmtMs(upstream.p50)}` : 'not reported', color: COLORS.neutral });
    const semLat = lat?.semantic || null;
    kpis.get('sem95').update({ state: kState, value: fmtMs(s(semLat, 'p95')), sub: semLat ? `p50 ${fmtMs(semLat.p50)}${semLat.count ? ` · ${fmtInt(semLat.count)} calls` : ''}` : 'not reported', color: COLORS.redact });
    let routing = state.resources.summary?.data?.semantic || lat?.routing || null;
    let routingSrc = routing ? `/admin/metrics/${routing.source}` : '';
    if (!routing || (routing.judged === null && routing.skipped === null)) { routing = semanticUsage(evs); routingSrc = 'loaded audit events'; }
    const tot = (routing.judged || 0) + (routing.skipped || 0);
    kpis.get('judge').update({ state: tot ? 'ok' : kState, value: tot ? fmtPct(routing.judged / tot) : '—', sub: tot ? `${fmtInt(routing.judged)} / ${fmtInt(tot)} · ${routingSrc}` : 'no requests', color: COLORS.redact });
    kpis.get('cheap').update({ state: tot ? 'ok' : kState, value: tot ? fmtPct(routing.skipped / tot) : '—', sub: tot ? `${fmtInt(routing.skipped)} / ${fmtInt(tot)}` : 'no requests', color: COLORS.info });

    // total overhead (fallback: loaded events, labelled)
    let ovhData = total;
    let ovhSrc = '/admin/metrics/latency total_overhead';
    let ovhDeps = ['latency'];
    if (!ovhData && latRes?.status === 'ok') { ovhData = overheadFromEvents(evs); ovhSrc = eventsSourceText(state.resources.events, evs.length); ovhDeps = ['latency', 'events']; }
    if (stateFor(ctx, ovhPanel, ovhDeps, { isEmpty: () => !ovhData, emptyMessage: 'No overhead samples yet.' })) {
      const maxVal = Math.max(TARGET_MS * 1.25, ovhData.p50 || 0, ovhData.p95 || 0, ovhData.p99 || 0);
      upsertChart(ovh.canvas, {
        type: 'bar',
        labels: ['p50', 'p95', 'p99'],
        datasets: [{ id: 'measured', label: 'Measured total overhead (ms)', data: [ovhData.p50, ovhData.p95, ovhData.p99], samples: ovhData.count, backgroundColor: SERIES.map((x) => x.color), borderRadius: 3, maxBarThickness: 60 }],
        options: ovhOptions(maxVal),
        live: { 'scales.y.suggestedMax': maxVal * 1.1 },
      });
      ovhNote.textContent = `Measured p95 ${fmtMs(ovhData.p95)} vs target ${TARGET_MS} ms → ${ovhData.p95 === null ? 'n/a' : ovhData.p95 <= TARGET_MS ? 'within target' : 'above target'}.`;
      ovhPanel.setSource(ovhSrc);
      ovhPanel.setAlt(dataTableAlt('Total overhead — data table', ['Percentile', 'Measured (ms)', 'Target'], [['p50', fmtMs(ovhData.p50), '—'], ['p95', fmtMs(ovhData.p95), `${TARGET_MS} ms (target)`], ['p99', fmtMs(ovhData.p99), '—']]));
    }

    if (stateFor(ctx, upPanel, ['latency'], { isEmpty: () => !upstream, emptyMessage: 'No upstream latency reported (e.g. only artifact scans, or the gateway does not expose it).' })) {
      upsertChart(up.canvas, {
        type: 'bar',
        labels: ['p50', 'p95', 'p99'],
        datasets: [{ id: 'up', label: 'Upstream latency (ms)', data: [upstream.p50, upstream.p95, upstream.p99], samples: upstream.count, backgroundColor: COLORS.neutral, borderRadius: 3, maxBarThickness: 60 }],
        options: vbarOptions({ unit: 'ms', yTitle: 'ms', tooltipExtra: (item) => (item.dataset.samples ? `samples: ${fmtInt(item.dataset.samples)}` : null) }),
      });
      upPanel.setSource('/admin/metrics/latency upstream');
      upPanel.setAlt(dataTableAlt('Upstream latency — data table', ['Percentile', 'ms'], [['p50', fmtMs(upstream.p50)], ['p95', fmtMs(upstream.p95)], ['p99', fmtMs(upstream.p99)]]));
    }

    let per = lat?.perControl || [];
    let perSrc = '/admin/metrics/latency per_control';
    if (!per.length && latRes?.status === 'ok') { per = controlLatencyFromEvents(evs); perSrc = eventsSourceText(state.resources.events, evs.length); }
    const sortKey = sortSel.value;
    const judge = per.find((c) => c.id === JUDGE_ID);
    const perShown = judgeBox.checked ? per : per.filter((c) => c.id !== JUDGE_ID);
    const sorted = [...perShown].sort((a, b) => (b[sortKey] ?? -1) - (a[sortKey] ?? -1));
    const shown = sorted.slice(0, 12);
    if (stateFor(ctx, ctlPanel, ['latency'], { isEmpty: () => !per.length, emptyMessage: 'No per-control latency samples.' })) {
      ctl.box.style.height = `${Math.max(220, shown.length * 34 + 80)}px`;
      upsertChart(ctl.canvas, {
        type: 'bar',
        labels: shown.map((c) => c.id),
        meta: shown,
        datasets: SERIES.map((sr) => ({ id: sr.key, label: `${sr.label} (ms)`, data: shown.map((c) => c[sr.key]), backgroundColor: sr.color, borderRadius: 2, maxBarThickness: 10 })),
        options: ctlOptions({ onClick: clickHandler(({ meta: c }) => { if (c) ctx.filterEvents({ control: c.id }); }), tooltipExtra: (item) => { const c = item.chart.data.meta?.[item.dataIndex]; return c?.count !== null && c?.count !== undefined ? `samples: ${fmtInt(c.count)}` : 'samples: n/a'; } }),
      });
      const notes = [];
      if (judge && !judgeBox.checked) notes.push(`Semantic judge (${JUDGE_ID}, p95 ${fmtMs(judge.p95)}) hidden so deterministic controls stay readable — tick "Include semantic judge" to show it.`);
      if (sorted.length > shown.length) notes.push(`Showing top ${shown.length} of ${sorted.length} controls by ${sortKey}; all controls are in the data table.`);
      ctlPanel.setNotice(notes.join(' '), 'info');
      ctlPanel.setSource(perSrc);
      const allSorted = [...per].sort((a, b) => (b[sortKey] ?? -1) - (a[sortKey] ?? -1));
      ctlPanel.setAlt(dataTableAlt(`Latency by control — data table (${allSorted.length})`, ['Control', 'p50', 'p95', 'p99', 'Calls / samples'], allSorted.map((c) => [c.id, fmtMs(c.p50), fmtMs(c.p95), fmtMs(c.p99), c.count === null ? '—' : fmtInt(c.count)])));
    }
  }

  return {
    id: 'performance', title: 'Performance', resources: RES, root,
    render(state) {
      const sig = signature(state, RES, `${sortSel.value}|${judgeBox.checked}`);
      if (sig === lastSig) return;
      lastSig = sig;
      render(state);
    },
  };
}
