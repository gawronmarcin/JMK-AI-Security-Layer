// Overview — posture KPIs, security actions over time, distribution, top controls/threats,
// semantic-judge routing and the latest critical events.

import { alpha, chartBox, clickHandler, doughnutOptions, timeAxisOptions, upsertChart } from '../charts.js';
import { actionBadge, createKpi, createPanel, dataTableAlt, severityBadge, timeCell } from '../components.js';
import { actionTotals, bucketActions, countBy, inRange, rebucketSeries, requestEvents, semanticUsage } from '../derive.js';
import { activeProfile } from '../resources.js';
import { ACTIONS, ACTION_META, COLORS, actionMeta, clear, computeChange, el, fmtBucket, fmtInt, fmtMs, fmtPct, fmtTime, fmtUsd, resolveRange, severityRank, bucketSizeFor } from '../utils.js';
import { createRangeToolbar, createRankingPanel, eventsSourceText, grid, signature, stateFor, viewHeader } from './common.js';

const RES = ['summary', 'latency', 'controls', 'events', 'budgets', 'policy'];

const KPIS = [
  { id: 'total', label: 'Total requests', tip: 'All requests that passed through AICL (chat, tool invoke, MCP, artifact scan) in the summary window reported by /admin/metrics/summary.' },
  { id: 'block', label: 'Blocked', action: 'block', tip: 'Requests whose final action was block: never forwarded upstream (HTTP 403 aicl_blocked) or response withheld.' },
  { id: 'redact', label: 'Redacted', action: 'redact', tip: 'Requests answered with HTTP 200 after AICL replaced matched spans with [REDACTED:<kind>].' },
  { id: 'flag', label: 'Flagged', action: 'flag', tip: 'Requests passed unchanged but logged as suspicious (final action flag).' },
  { id: 'require_approval', label: 'Approval required', action: 'require_approval', tip: 'Requests stopped pending human approval (HTTP 403 aicl_approval_required).' },
  { id: 'allow', label: 'Allowed', action: 'allow', tip: 'Requests where no control intervened (final action allow). Shadow-suppressed decisions count as allow.' },
  { id: 'blockRate', label: 'Block rate', tip: 'Blocked ÷ total requests in the summary window.' },
  { id: 'cost', label: 'Estimated cost', tip: 'Sum of usage.cost_usd = tokens × per-model prices from the policy. Local models cost 0 and are budgeted by compute seconds instead.' },
  { id: 'p95', label: 'p95 AICL overhead', tip: 'p95 of latency_ms.total_overhead — time spent inside AICL excluding the upstream call (/admin/metrics/latency). Target: ≤ 20 ms (a target, not a measurement).' },
  { id: 'controls', label: 'Active controls', tip: 'Controls with enabled: true out of all controls listed by /admin/controls.' },
];

export function createOverview(ctx) {
  const kpis = new Map();
  let lastSig = '';
  let seriesBuckets = [];

  // Applies to the "Security actions over time" chart only, so it lives in that panel's header.
  const modeToggle = el('div', { class: 'seg seg-sm', role: 'group', 'aria-label': 'Chart values: absolute or share of requests' },
    el('button', { type: 'button', class: 'seg-btn', 'data-mode': 'abs', 'aria-pressed': 'true', text: 'Absolute', onClick: () => ctx.store.setUi({ seriesMode: 'abs' }) }),
    el('button', { type: 'button', class: 'seg-btn', 'data-mode': 'pct', 'aria-pressed': 'false', text: 'Share %', onClick: () => ctx.store.setUi({ seriesMode: 'pct' }) }));
  const toolbar = createRangeToolbar(ctx);

  const kpiGrid = el('div', { class: 'kpi-grid', role: 'list' });
  for (const k of KPIS) {
    const card = createKpi({ label: k.label, tip: k.tip, onClick: k.action ? () => ctx.filterEvents({ action: k.action }) : null });
    card.root.setAttribute('role', 'listitem');
    kpis.set(k.id, card);
    kpiGrid.appendChild(card.root);
  }
  const kpiNote = el('p', { class: 'kpi-note muted' });

  // --- Security actions over time
  const timePanel = createPanel({ title: 'Security actions over time', desc: 'Final action of each request per time bucket. Absolute shows request counts; Share % shows each action as a share of the requests in that bucket (useful when traffic volume varies; noisy with few requests). Click a coloured segment to open the audit events of that action and bucket, or anywhere else in the column for all events of the bucket; click a legend entry to hide a series.', unit: 'requests', span: 8, headerExtra: modeToggle });
  const timeChart = chartBox('Security actions over time', { height: 320 });
  timePanel.content.appendChild(timeChart.box);

  // --- Action distribution donut
  const donutPanel = createPanel({ title: 'Action distribution', desc: 'Share of final actions in the selected range. The centre shows the total number of requests. Click a segment to filter audit events.', unit: 'requests', span: 4 });
  const donut = chartBox('Action distribution', { height: 320 });
  donutPanel.content.appendChild(donut.box);

  const topControls = createRankingPanel({ title: 'Top controls by interventions', desc: 'Number of decisions per control with an action other than allow (or shadow-suppressed). Click a bar to filter audit events by control.', seriesLabel: 'Interventions', color: COLORS.info, onPick: (id) => ctx.filterEvents({ control: id }) });
  const topThreats = createRankingPanel({ title: 'Top threats', desc: 'Detections per threat ID (catalog/threats.yaml). Click a bar to filter audit events by threat.', seriesLabel: 'Detections', color: COLORS.orange, onPick: (id) => ctx.filterEvents({ threat: id }) });

  const semPanel = createPanel({ title: 'Semantic judge vs cheap path', desc: 'Requests that reached the local semantic judge (C-INJ-SEM) versus requests decided by deterministic controls only. Target: judge only for the grey zone and untrusted segments (§12).', unit: 'requests', span: 4 });
  const sem = chartBox('Semantic judge usage', { height: 220 });
  const semText = el('p', { class: 'metric-line' });
  semPanel.content.append(sem.box, semText);

  const critPanel = createPanel({ title: 'Recent critical events', desc: 'Latest audit events with severity high or critical among acting decisions. Select a row for full details.', span: 8 });
  const critList = el('ol', { class: 'event-list' });
  critPanel.content.appendChild(critList);

  const root = el('section', { class: 'view', 'aria-labelledby': 'v-overview' },
    viewHeader('Overview', 'Is the gateway up and actively protecting traffic?'),
    toolbar.root,
    kpiGrid, kpiNote,
    grid(timePanel, donutPanel, topControls, topThreats, semPanel, critPanel));
  root.querySelector('h1').id = 'v-overview';

  // ------------------------------------------------------------- data selection

  function series(state) {
    const { from, to } = resolveRange(state.filters);
    const want = bucketSizeFor(to - from);
    const ts = state.resources.summary?.data?.timeseries;
    if (ts && ts.points.length && (ts.bucketMs || 0) <= want && ts.points[0].t <= from) {
      return { ...rebucketSeries(ts.points, from, to, want), source: `/admin/metrics/summary timeseries (re-bucketed to ${fmtBucket(want)})`, exact: true };
    }
    const evs = state.resources.events?.data?.events || [];
    const subset = requestEvents(inRange(evs, from, to));
    return { ...bucketActions(subset, from, to, want), source: eventsSourceText(state.resources.events, subset.length) + ` · bucket ${fmtBucket(want)}`, exact: false };
  }

  function renderKpis(state) {
    const s = state.resources.summary;
    const sum = s?.data;
    const loading = !s || (s.status === 'loading' && !sum) || s.status === 'idle';
    const failed = s && s.status === 'error' && !sum;
    const st = loading ? 'loading' : failed ? 'error' : 'ok';
    const prev = sum?.previous;
    const changeFor = (cur, p, fmt = fmtInt) => {
      const c = computeChange(cur, p);
      if (!c) return null;
      const sign = c.delta > 0 ? '▲ +' : c.delta < 0 ? '▼ ' : '■ ';
      return { text: `${sign}${fmt(c.delta)}${c.ratio !== null ? ` (${c.ratio > 0 ? '+' : ''}${fmtPct(c.ratio)})` : ''} vs previous`, dir: Math.sign(c.delta) };
    };
    const buckets = seriesBuckets;
    const total = sum?.total ?? null;
    kpis.get('total').update({ state: st, value: fmtInt(total), change: changeFor(total, prev?.total), spark: buckets.map((b) => b.total), color: COLORS.info, sub: failed ? s.error?.message : '' });
    for (const a of ACTIONS) {
      const v = sum?.counts?.[a] ?? null;
      kpis.get(a).update({ state: st, value: fmtInt(v), sub: total ? `${fmtPct((v || 0) / total)} of requests` : '', change: changeFor(v, prev?.[a]), spark: buckets.map((b) => b[a]), color: ACTION_META[a].color });
    }
    const br = total ? (sum.counts.block || 0) / total : null;
    const prevBr = prev && prev.total ? (prev.block || 0) / prev.total : null;
    kpis.get('blockRate').update({ state: st, value: fmtPct(br), sub: total ? `${fmtInt(sum.counts.block || 0)} / ${fmtInt(total)}` : '', change: br !== null && prevBr !== null ? { text: `${br >= prevBr ? '▲ +' : '▼ '}${fmtPct(br - prevBr)} pts vs previous`, dir: Math.sign(br - prevBr) } : null, color: COLORS.error });

    // cost: summary first; fall back to budgets usage (labelled)
    let cost = sum?.costUsd ?? null;
    let costSub = cost !== null ? 'from /admin/metrics/summary' : '';
    const b = state.resources.budgets?.data;
    if (cost === null && b && b.length) {
      const vals = b.map((x) => x.resources.find((r) => r.kind === 'cost')?.used).filter((v) => v !== null && v !== undefined);
      if (vals.length) { cost = vals.reduce((x, y) => x + y, 0); costSub = 'sum of current budget windows'; }
    }
    kpis.get('cost').update({ state: st === 'loading' && cost === null ? 'loading' : 'ok', value: fmtUsd(cost), sub: costSub || (cost === null ? 'not reported' : ''), change: changeFor(cost, prev?.costUsd, fmtUsd), color: COLORS.warning });

    const lat = state.resources.latency;
    const p95 = lat?.data?.total?.p95 ?? null;
    kpis.get('p95').update({
      state: !lat || (lat.status !== 'ok' && !lat.data) ? (lat?.status === 'error' ? 'error' : 'loading') : 'ok',
      value: fmtMs(p95),
      sub: p95 === null ? (lat?.status === 'error' ? lat.error?.message : 'not reported') : p95 <= 20 ? 'within 20 ms target' : 'above 20 ms target',
      color: p95 !== null && p95 > 20 ? COLORS.warning : COLORS.success,
    });

    const ctl = state.resources.controls;
    const list = ctl?.data?.list;
    const enabled = list ? list.filter((c) => c.enabled === true).length : null;
    kpis.get('controls').update({
      state: !ctl || (!list && ctl.status !== 'error') ? 'loading' : list ? 'ok' : 'error',
      value: list ? `${enabled} / ${list.length}` : '—',
      sub: list ? `${list.filter((c) => (c.mode || '') === 'shadow').length} in shadow · profile ${activeProfile(state) || '—'}` : ctl?.error?.message || '',
      color: COLORS.success,
    });
    const scope = sum?.window ? `Summary window: ${sum.window.from ? sum.window.from.toLocaleString() : '…'} → ${sum.window.to ? sum.window.to.toLocaleString() : 'now'}` : sum?.since ? `Summary counters since ${sum.since.toLocaleString()}` : 'Summary counters cover the window reported by the gateway (not the time range selector).';
    kpiNote.textContent = `${scope} Sparklines follow the selected time range.`;
  }

  function renderTime(state) {
    const evRes = state.resources.events;
    const sumRes = state.resources.summary;
    const useSummary = sumRes?.data?.timeseries;
    const deps = useSummary ? ['summary'] : ['events'];
    const s = series(state);
    seriesBuckets = s.buckets;
    const total = s.buckets.reduce((x, b) => x + b.total, 0);
    const okTime = stateFor(ctx, timePanel, deps, { isEmpty: () => total === 0, emptyMessage: 'No requests in the selected time range.' });
    const okDonut = stateFor(ctx, donutPanel, deps, { isEmpty: () => total === 0, emptyMessage: 'No requests in the selected time range — nothing to distribute.' });
    timePanel.setNotice(!useSummary && evRes?.data?.truncated ? `Only the latest ${fmtInt(evRes.data.limit)} events per request are loaded; older buckets may be incomplete.` : '', 'warn');
    timePanel.setSource(s.source);
    donutPanel.setSource(s.source);
    const pct = state.ui.seriesMode === 'pct';
    for (const b of modeToggle.querySelectorAll('button')) b.setAttribute('aria-pressed', String(b.dataset.mode === state.ui.seriesMode));
    const bucketsMeta = s.buckets.map((b) => ({ t: b.t, end: b.end }));
    const labels = s.buckets.map((b) => fmtTime(b.t));
    const other = s.buckets.some((b) => b.other > 0);
    const keys = other ? [...ACTIONS, 'other'] : ACTIONS;
    if (okTime) {
      const datasets = keys.map((a) => {
        const m = a === 'other' ? actionMeta('unknown') : ACTION_META[a];
        const raw = s.buckets.map((b) => b[a]);
        return {
          id: a,
          label: a === 'other' ? 'Unknown action' : m.label,
          data: pct ? s.buckets.map((b) => (b.total ? (b[a] / b.total) * 100 : 0)) : raw,
          rawCounts: raw,
          borderColor: m.color,
          backgroundColor: alpha(m.color, a === 'allow' ? 0.55 : 0.9),
          borderWidth: 1, // also gives the legend's stroke-only point styles (×) a visible line
          pointStyle: m.pointStyle,
          barPercentage: 1,
          categoryPercentage: 0.9,
          stack: 'a',
        };
      });
      const chart = upsertChart(timeChart.canvas, {
        type: 'bar', labels, meta: bucketsMeta, datasets,
        options: timeAxisOptions({
          stacked: true, percent: pct,
          onClick: clickHandler(({ meta: b, dataset }) => {
            if (!b) return;
            const patch = { range: 'custom', from: b.t.toISOString(), to: b.end.toISOString() };
            if (dataset && ACTIONS.includes(dataset.id)) patch.action = dataset.id;
            ctx.filterEvents(patch);
          }, 'nearest', { columnFallback: true }),
        }),
        live: { 'scales.y.max': pct ? 100 : undefined, 'scales.y.title.text': pct ? 'Share of requests (%)' : 'Requests' },
      });
      if (chart) {
        // the tooltip formatter reads the mode from the options closure → refresh it on toggle
        const fresh = timeAxisOptions({ stacked: true, percent: pct });
        chart.config.options.plugins.tooltip.callbacks.label = fresh.plugins.tooltip.callbacks.label;
        chart.config.options.scales.y.ticks.callback = fresh.scales.y.ticks.callback;
        chart.update('none');
      }
      timeChart.canvas.setAttribute('aria-label', `Security actions over time, ${s.buckets.length} buckets, ${fmtInt(total)} requests. Data table available below.`);
      timePanel.setAlt(dataTableAlt('Security actions over time — data table', ['Bucket start', ...keys.map((k) => (k === 'other' ? 'Unknown' : ACTION_META[k].label)), 'Total'], s.buckets.filter((b) => b.total > 0).map((b) => [b.t.toLocaleString(), ...keys.map((k) => fmtInt(b[k])), fmtInt(b.total)])));
    }
    if (okDonut) {
      const totals = actionTotals([]);
      for (const b of s.buckets) for (const k of keys) totals[k] = (totals[k] || 0) + b[k];
      const dk = keys.filter((k) => totals[k] > 0);
      upsertChart(donut.canvas, {
        type: 'doughnut',
        meta: dk,
        labels: dk.map((k) => (k === 'other' ? 'Unknown action' : ACTION_META[k].label)),
        datasets: [{ id: 'd', data: dk.map((k) => totals[k]), backgroundColor: dk.map((k) => (k === 'other' ? COLORS.neutral : ACTION_META[k].color)), borderColor: COLORS.panel, borderWidth: 2 }],
        options: doughnutOptions({ center: { text: fmtInt(total), sub: 'requests' }, onClick: clickHandler(({ meta: k }) => { if (ACTIONS.includes(k)) ctx.filterEvents({ action: k }); }) }),
        live: { 'plugins.centerText': { text: fmtInt(total), sub: 'requests' } },
      });
      donut.canvas.setAttribute('aria-label', `Action distribution: ${dk.map((k) => `${k} ${totals[k]}`).join(', ')}; total ${total}`);
      donutPanel.setAlt(dataTableAlt('Action distribution — data table', ['Action', 'Requests', 'Share'], dk.map((k) => [k, fmtInt(totals[k]), fmtPct(totals[k] / total)])));
    }
  }

  function renderRankings(state) {
    const { from, to } = resolveRange(state.filters);
    const sum = state.resources.summary?.data;
    const evs = inRange(state.resources.events?.data?.events || [], from, to);
    // gateway counters win; events-derived ranking only when the summary does not break it down
    const pickSource = (entries, derive, label) => (entries && entries.length
      ? { entries, deps: ['summary'], text: `/admin/metrics/summary ${label} (summary window)` }
      : { entries: derive(), deps: ['summary', 'events'], text: eventsSourceText(state.resources.events, evs.length) });
    const c = pickSource(sum?.byControl, () => countBy(evs, (e) => e.controlIds), 'by_control');
    if (stateFor(ctx, topControls.panel, c.deps, { isEmpty: () => !c.entries.some((e) => e.value > 0), emptyMessage: 'No control interventions recorded.' })) topControls.render(c.entries, { sourceText: c.text });
    const t = pickSource(sum?.byThreat, () => countBy(evs, (e) => e.threatIds), 'by_threat');
    if (stateFor(ctx, topThreats.panel, t.deps, { isEmpty: () => !t.entries.some((e) => e.value > 0), emptyMessage: 'No threats detected.' })) topThreats.render(t.entries, { sourceText: t.text });

    // semantic routing
    let r = sum?.semantic || state.resources.latency?.data?.routing || null;
    let deps = ['summary'];
    let srcText = r ? `/admin/metrics/${r.source}` : '';
    if (!r || (r.judged === null && r.skipped === null)) {
      r = semanticUsage(evs);
      deps = ['events'];
      srcText = eventsSourceText(state.resources.events, r.total);
    }
    const judged = r.judged || 0;
    const skipped = r.skipped || 0;
    const tot = judged + skipped;
    if (stateFor(ctx, semPanel, deps, { isEmpty: () => tot === 0, emptyMessage: 'No requests to classify.' })) {
      upsertChart(sem.canvas, {
        type: 'doughnut',
        labels: ['Semantic judge', 'Cheap deterministic path'],
        datasets: [{ id: 's', data: [judged, skipped], backgroundColor: [COLORS.redact, COLORS.info], borderColor: COLORS.panel, borderWidth: 2 }],
        options: doughnutOptions({ center: { text: fmtPct(tot ? skipped / tot : 0), sub: 'cheap path', size: 18 } }),
        live: { 'plugins.centerText': { text: fmtPct(tot ? skipped / tot : 0), sub: 'cheap path', size: 18 } },
      });
      semText.textContent = `Judge: ${fmtInt(judged)} (${fmtPct(judged / tot)}) · cheap path: ${fmtInt(skipped)} (${fmtPct(skipped / tot)}) of ${fmtInt(tot)} requests`;
      semPanel.setSource(srcText);
      semPanel.setAlt(dataTableAlt('Semantic routing — data table', ['Path', 'Requests', 'Share'], [['Semantic judge', fmtInt(judged), fmtPct(judged / tot)], ['Cheap path', fmtInt(skipped), fmtPct(skipped / tot)]]));
    }
  }

  function renderCritical(state) {
    const evs = state.resources.events?.data?.events || [];
    const crit = evs.filter((e) => severityRank(e.severity) >= 3).slice(0, 10);
    if (!stateFor(ctx, critPanel, ['events'], { isEmpty: () => !crit.length, emptyMessage: 'No high or critical events in the loaded window.' })) return;
    clear(critList);
    for (const e of crit) {
      const li = el('li', {}, el('button', { type: 'button', class: 'event-item', onClick: () => ctx.openEvent(e), 'aria-label': `Open event ${e.requestId || e.id}` },
        timeCell(e.ts), severityBadge(e.severity), actionBadge(e.finalAction),
        el('span', { class: 'mono ev-ctl', text: e.controlIds.join(', ') || e.type }),
        el('span', { class: 'ev-who', text: `${e.identity || '—'} · ${e.endpoint || '—'}` }),
        el('span', { class: 'mono muted ev-req', text: e.requestId || '' })));
      critList.appendChild(li);
    }
    critPanel.setSource(eventsSourceText(state.resources.events, evs.length));
  }

  return {
    id: 'overview',
    title: 'Overview',
    resources: RES,
    root,
    render(state) {
      const sig = signature(state, RES, state.ui.seriesMode);
      if (sig === lastSig) return;
      lastSig = sig;
      toolbar.update(state.filters);
      renderTime(state);
      renderKpis(state);
      renderRankings(state);
      renderCritical(state);
    },
  };
}
