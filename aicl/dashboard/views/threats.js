// Threats — ranking, severity, trend, endpoint split, threat → control → OWASP/ATLAS mapping
// and the threat × control coverage heatmap.

import { alpha, chartBox, clickHandler, timeAxisOptions, upsertChart, vbarOptions } from '../charts.js';
import { chip, createPanel, createTable, dataTableAlt } from '../components.js';
import { countBy, inRange, threatSeverity } from '../derive.js';
import { threatCatalog } from '../resources.js';
import { COLORS, ENDPOINTS, SEVERITIES, SEVERITY_META, bucketSizeFor, el, fmtBucket, fmtInt, fmtTime, resolveRange, uniqueSorted } from '../utils.js';
import { buildCoverage, createHeatmap, createRangeToolbar, createRankingPanel, eventsSourceText, grid, signature, stateFor, viewHeader } from './common.js';

const RES = ['summary', 'events', 'controls', 'testReport'];
const TREND_COLORS = ['#4EA1FF', '#FF8A3D', '#A78BFA', '#3DDC97', '#FFB547', '#FF5D67'];

export function createThreats(ctx) {
  let lastSig = '';
  const toolbar = createRangeToolbar(ctx);

  const ranking = createRankingPanel({ title: 'Threats by detections', desc: 'Detections per threat ID. Gateway counters (/admin/metrics/summary by_threat) when available, otherwise derived from loaded audit events. Click a bar to filter audit events.', seriesLabel: 'Detections', color: COLORS.orange, onPick: (id) => ctx.filterEvents({ threat: id }), limit: 12, height: 340 });

  const sevPanel = createPanel({ title: 'Severity breakdown', desc: 'Acting decisions in the selected range grouped by severity (low, medium, high, critical). Click a bar to filter audit events by severity.', unit: 'decisions', span: 6 });
  const sevChart = chartBox('Severity breakdown', { height: 340 });
  sevPanel.content.appendChild(sevChart.box);

  const trendPanel = createPanel({ title: 'Detections over time', desc: 'Events per time bucket that contain a detection of the top threats (up to 6). Click a point to open matching audit events.', unit: 'events', span: 8 });
  const trendChart = chartBox('Detections over time', { height: 280 });
  trendPanel.content.appendChild(trendChart.box);

  const epPanel = createPanel({ title: 'Detections by endpoint', desc: 'Events with at least one detection, split by gateway endpoint: chat, tool_invoke, mcp, artifact_scan. Click a bar to filter audit events.', unit: 'events', span: 4 });
  const epChart = chartBox('Detections by endpoint', { height: 260 });
  epPanel.content.appendChild(epChart.box);

  const mapPanel = createPanel({ title: 'Threat → controls → OWASP / ATLAS', desc: 'Which controls mitigate each threat (from /admin/controls threat_ids) and the external taxonomy references when the gateway exposes the threat catalog.', span: 12 });
  const mapTable = createTable({
    caption: 'Threat to control mapping',
    pageSize: 25,
    rowKey: (r) => r.id,
    columns: [
      { key: 'id', label: 'Threat', header: true, sort: (r) => r.id, render: (r) => chip(r.id, (v) => ctx.filterEvents({ threat: v })) },
      { key: 'title', label: 'Title', render: (r) => r.title },
      { key: 'controls', label: 'Controls', render: (r) => el('span', { class: 'chips' }, r.controls.map((c) => chip(c, (v) => ctx.filterEvents({ control: v })))) },
      { key: 'owasp', label: 'OWASP', render: (r) => (r.owasp.length ? r.owasp.join(', ') : null) },
      { key: 'atlas', label: 'ATLAS', render: (r) => (r.atlas.length ? el('span', { class: 'mono', text: r.atlas.join(', ') }) : null) },
      { key: 'count', label: 'Detections', className: 'num', sort: (r) => r.count, render: (r) => fmtInt(r.count) },
    ],
    initialSort: { key: 'count', dir: 'desc' },
  });
  mapPanel.content.appendChild(mapTable.root);

  const heatPanel = createPanel({ title: 'Coverage heatmap — threats × controls', desc: 'Number of test cases per (threat, control) pair. Full = ≥3 negative, ≥3 positive, ≥2 edge cases (§11.5; ≥8 tests when kinds are unknown), partial = at least one test, no coverage = mapped but untested. Click a cell to filter audit events.', unit: 'tests', span: 12 });
  const heat = createHeatmap({ rowLabel: 'Threat', colLabel: 'Control', onPick: ({ threatId, controlId }) => ctx.filterEvents({ threat: threatId, control: controlId }) });
  heatPanel.content.appendChild(heat.root);

  const root = el('section', { class: 'view', 'aria-labelledby': 'v-threats' },
    viewHeader('Threats', 'Which threats generate the most events, and are they covered by controls and tests?'),
    toolbar.root,
    grid(ranking, sevPanel, trendPanel, epPanel, mapPanel, heatPanel));
  root.querySelector('h1').id = 'v-threats';

  function render(state) {
    const { from, to } = resolveRange(state.filters);
    const evAll = state.resources.events?.data?.events || [];
    const evs = inRange(evAll, from, to).filter((e) => e.threatIds.length);
    const sum = state.resources.summary?.data;
    const srcEv = eventsSourceText(state.resources.events, evs.length);

    // ranking
    const useSum = sum?.byThreat?.length;
    const entries = useSum ? sum.byThreat : countBy(evs, (e) => e.threatIds);
    if (stateFor(ctx, ranking.panel, useSum ? ['summary'] : ['summary', 'events'], { isEmpty: () => !entries.some((e) => e.value > 0), emptyMessage: 'No threat detections recorded.' })) {
      ranking.render(entries, { sourceText: useSum ? '/admin/metrics/summary by_threat (summary window)' : srcEv });
    }

    // severity
    const sevMap = threatSeverity(evs);
    const sevTotals = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
    let unknownSev = 0;
    for (const m of sevMap.values()) for (const [s, n] of Object.entries(m)) { if (s in sevTotals) sevTotals[s] += n; else unknownSev += n; }
    const sumSev = sum?.bySeverity?.length ? Object.fromEntries(sum.bySeverity.map((e) => [e.key, e.value])) : null;
    const sevData = sumSev || sevTotals;
    const sevLabels = [...SEVERITIES, ...(unknownSev && !sumSev ? ['unknown'] : [])];
    if (stateFor(ctx, sevPanel, sumSev ? ['summary'] : ['events'], { isEmpty: () => sevLabels.every((s) => !(s === 'unknown' ? unknownSev : sevData[s])), emptyMessage: 'No acting decisions in the selected range.' })) {
      upsertChart(sevChart.canvas, {
        type: 'bar',
        meta: sevLabels,
        labels: sevLabels.map((s) => `${SEVERITY_META[s]?.icon || '?'} ${s}`),
        datasets: [{ id: 'sev', label: 'Decisions', data: sevLabels.map((s) => (s === 'unknown' ? unknownSev : sevData[s] || 0)), backgroundColor: sevLabels.map((s) => SEVERITY_META[s]?.color || COLORS.neutral), borderRadius: 3, maxBarThickness: 48 }],
        options: vbarOptions({ legend: false, yTitle: 'Decisions', onClick: clickHandler(({ meta: s }) => { if (SEVERITIES.includes(s)) ctx.filterEvents({ severity: s }); }) }),
      });
      sevPanel.setSource(sumSev ? '/admin/metrics/summary by_severity' : srcEv);
      sevPanel.setAlt(dataTableAlt('Severity — data table', ['Severity', 'Decisions'], sevLabels.map((s) => [s, fmtInt(s === 'unknown' ? unknownSev : sevData[s] || 0)])));
    }

    // trend for top threats
    const top = countBy(evs, (e) => e.threatIds).slice(0, 6).map((e) => e.key);
    const size = bucketSizeFor(to - from);
    const start = Math.floor(from.getTime() / size) * size;
    const n = Math.max(1, Math.ceil((to.getTime() - start) / size));
    const meta = Array.from({ length: n }, (_, i) => ({ t: new Date(start + i * size), end: new Date(start + (i + 1) * size) }));
    const counts = Object.fromEntries(top.map((t) => [t, new Array(n).fill(0)]));
    for (const e of evs) {
      const i = Math.floor((e.ts.getTime() - start) / size);
      if (i < 0 || i >= n) continue;
      for (const t of e.threatIds) if (counts[t]) counts[t][i] += 1;
    }
    if (stateFor(ctx, trendPanel, ['events'], { isEmpty: () => !top.length, emptyMessage: 'No detections in the selected range.' })) {
      upsertChart(trendChart.canvas, {
        type: 'line',
        labels: meta.map((m) => fmtTime(m.t)),
        meta,
        datasets: top.map((t, i) => ({ id: t, label: t, data: counts[t], borderColor: TREND_COLORS[i], backgroundColor: alpha(TREND_COLORS[i], 0.1), pointStyle: ['circle', 'triangle', 'rect', 'rectRot', 'crossRot', 'star'][i], pointRadius: n > 60 ? 0 : 2, borderDash: i % 2 ? [5, 3] : [], borderWidth: 1.6, tension: 0 })),
        options: timeAxisOptions({ onClick: clickHandler(({ meta: m, dataset }) => { if (m) ctx.filterEvents({ threat: dataset?.id || '', range: 'custom', from: m.t.toISOString(), to: m.end.toISOString() }); }, 'nearest', { columnFallback: true }) }),
      });
      trendPanel.setSource(`${srcEv} · bucket ${fmtBucket(size)}`);
      trendPanel.setAlt(dataTableAlt('Detections over time — data table', ['Bucket start', ...top], meta.map((m, i) => [m.t.toLocaleString(), ...top.map((t) => fmtInt(counts[t][i]))]).filter((r) => r.slice(1).some((v) => v !== '0'))));
    }

    // endpoints
    const sumEp = sum?.byEndpoint?.length ? sum.byEndpoint : null;
    const epCounts = sumEp ? Object.fromEntries(sumEp.map((e) => [e.key, e.value])) : Object.fromEntries(countBy(evs, (e) => e.endpoint || 'unknown').map((e) => [e.key, e.value]));
    const epLabels = uniqueSorted([...ENDPOINTS, ...Object.keys(epCounts)]);
    if (stateFor(ctx, epPanel, sumEp ? ['summary'] : ['events'], { isEmpty: () => !Object.values(epCounts).some((v) => v > 0), emptyMessage: 'No detections in the selected range.' })) {
      upsertChart(epChart.canvas, {
        type: 'bar',
        labels: epLabels,
        meta: epLabels,
        datasets: [{ id: 'ep', label: sumEp ? 'Requests' : 'Events with detections', data: epLabels.map((k) => epCounts[k] || 0), backgroundColor: COLORS.info, borderRadius: 3, maxBarThickness: 56 }],
        options: vbarOptions({ legend: false, yTitle: 'Events', onClick: clickHandler(({ meta: k }) => { if (k && k !== 'unknown') ctx.filterEvents({ endpoint: k }); }) }),
      });
      epPanel.setSource(sumEp ? '/admin/metrics/summary by_endpoint (all requests)' : srcEv);
      epPanel.setAlt(dataTableAlt('Endpoints — data table', ['Endpoint', 'Events'], epLabels.map((k) => [k, fmtInt(epCounts[k] || 0)])));
    }

    // mapping table + heatmap
    const controls = state.resources.controls?.data?.list || [];
    const cat = threatCatalog(state);
    const byThreat = new Map();
    for (const c of controls) for (const t of c.threatIds) { if (!byThreat.has(t)) byThreat.set(t, []); byThreat.get(t).push(c.id); }
    const detected = new Map(entries.map((e) => [e.key, e.value]));
    const threatIds = uniqueSorted([...byThreat.keys(), ...cat.keys(), ...detected.keys()]);
    const rows = threatIds.map((id) => ({ id, title: cat.get(id)?.title || null, controls: byThreat.get(id) || [], owasp: [...(cat.get(id)?.owasp || []), ...(cat.get(id)?.owaspAgentic || [])], atlas: cat.get(id)?.atlas || [], count: detected.get(id) || 0 }));
    if (stateFor(ctx, mapPanel, ['controls'], { isEmpty: () => !rows.length, emptyMessage: 'No threats referenced by controls.' })) {
      mapTable.setRows(rows);
      mapPanel.setNotice(cat.size ? '' : 'OWASP / ATLAS references not exposed by the gateway (catalog/threats.yaml is not served by /admin/*).', 'info');
      mapPanel.setSource('/admin/controls threat_ids' + (cat.size ? ' + threat catalog' : ''));
    }
    const report = state.resources.testReport?.data || null;
    const cells = buildCoverage(controls, report);
    const ctlIds = uniqueSorted(controls.map((c) => c.id).concat([...cells.values()].map((c) => c.controlId)));
    const thIds = uniqueSorted([...threatIds, ...[...cells.values()].map((c) => c.threatId)]);
    if (stateFor(ctx, heatPanel, ['controls'], { isEmpty: () => !ctlIds.length || !thIds.length, emptyMessage: 'No controls or threats to map.' })) {
      heat.render(thIds, ctlIds, (t, c) => cells.get(`${c}\u0000${t}`), { rowIsThreat: true, rowTitles: new Map(thIds.map((t) => [t, cat.get(t)?.title || ''])) });
      heatPanel.setSource(report?.coverage?.length ? 'Test report coverage matrix + /admin/controls' : '/admin/controls test counts (control-level when per-threat counts are absent)');
    }
  }

  return {
    id: 'threats', title: 'Threats', resources: RES, root,
    render(state) {
      const sig = signature(state, RES);
      if (sig === lastSig) return;
      lastSig = sig;
      toolbar.update(state.filters);
      render(state);
    },
  };
}
