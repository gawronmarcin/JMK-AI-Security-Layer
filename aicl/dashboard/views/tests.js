// Tests — last test-suite run (§11.6 metrics) and fuzzer bypass rates.
// Rates are always shown with their sample size, e.g. "92% (46/50)".

import { chartBox, clickHandler, doughnutOptions, hbarOptions, upsertChart } from '../charts.js';
import { chip, createKpi, createPanel, createTable, dataTableAlt } from '../components.js';
import { COLORS, el, fmtDate, fmtInt, fmtMs, fmtPct, fmtRate, safeText, uniqueSorted } from '../utils.js';
import { buildCoverage, createHeatmap, grid, signature, stateFor, viewHeader } from './common.js';

const RES = ['testReport', 'fuzzReport', 'controls'];
const UNAVAILABLE = 'No test report is exposed. Run `make test` and serve reports/test_report.json at the configured path (see aicl-config in index.html), or enable DEMO DATA.';

const rateText = (b) => fmtRate(b.num, b.den, b.rate);

export function createTests(ctx) {
  let lastSig = '';
  const kpiDefs = [
    ['ts', 'Last run', 'Timestamp of reports/test_report.json (generated_at).'],
    ['status', 'Status', 'Overall result of the last run.'],
    ['total', 'Tests', 'Total test cases in the last run (passed / failed / skipped).'],
    ['det', 'Detection rate', 'Negatives blocked ÷ negatives (§11.6). Shown with sample size.'],
    ['fpr', 'False-positive rate', 'Positives blocked ÷ positives (§11.6). Lower is better.'],
    ['ovh', 'Tested overhead p50 / p95', 'Total AICL overhead measured by the test runner (test_perf.py).'],
    ['cov', 'Coverage', 'Controls with at least one test, and threats with at least one tested control.'],
  ];
  const kpis = new Map();
  const kpiGrid = el('div', { class: 'kpi-grid', role: 'list' });
  for (const [id, label, tip] of kpiDefs) { const k = createKpi({ label, tip }); k.root.setAttribute('role', 'listitem'); kpis.set(id, k); kpiGrid.appendChild(k.root); }

  const donutPanel = createPanel({ title: 'Results', desc: 'Passed / failed / skipped test cases of the last run.', unit: 'tests', span: 4 });
  const donut = chartBox('Test results', { height: 260 });
  donutPanel.content.appendChild(donut.box);

  const detPanel = createPanel({ title: 'Detection rate per control', desc: 'Share of negative cases (attacks) stopped per control. Lowest first (up to 12). Tooltip shows negatives blocked / negatives.', unit: '%', span: 4 });
  const det = chartBox('Detection rate per control', { height: 260 });
  detPanel.content.appendChild(det.box);

  const fpPanel = createPanel({ title: 'False-positive rate per control', desc: 'Share of positive (benign) cases wrongly blocked per control. Tooltip shows positives blocked / positives.', unit: '%', span: 4 });
  const fp = chartBox('False-positive rate per control', { height: 260 });
  fpPanel.content.appendChild(fp.box);

  const heatPanel = createPanel({ title: 'Coverage heatmap — controls × threats', desc: 'Test cases per (control, threat) pair from the report coverage matrix (fallback: /admin/controls counts). Full = ≥3 negative, ≥3 positive, ≥2 edge (§11.5).', unit: 'tests', span: 12 });
  const heat = createHeatmap({ rowLabel: 'Control', colLabel: 'Threat', onPick: ({ threatId, controlId }) => ctx.filterEvents({ threat: threatId, control: controlId }) });
  heatPanel.content.appendChild(heat.root);

  const failPanel = createPanel({ title: 'Failed cases', desc: 'Test cases that did not meet their expectation in the last run.', span: 12 });
  const failTable = createTable({
    caption: 'Failed test cases',
    pageSize: 20,
    rowKey: (r) => r.id,
    columns: [
      { key: 'id', label: 'Case', header: true, sort: (r) => r.id, render: (r) => el('span', { class: 'mono', text: r.id }) },
      { key: 'title', label: 'Title', render: (r) => r.title },
      { key: 'kind', label: 'Kind', render: (r) => r.kind },
      { key: 'controls', label: 'Controls', render: (r) => el('span', { class: 'chips' }, r.controls.map((c) => chip(c, (v) => ctx.filterEvents({ control: v })))) },
      { key: 'threats', label: 'Threats', render: (r) => el('span', { class: 'chips' }, r.threats.map((t) => chip(t, (v) => ctx.filterEvents({ threat: v })))) },
      { key: 'exp', label: 'Expected', render: (r) => (r.expected === null ? null : el('code', { class: 'small', text: safeText(r.expected) })) },
      { key: 'act', label: 'Actual', render: (r) => (r.actual === null ? null : el('code', { class: 'small', text: safeText(r.actual) })) },
      { key: 'msg', label: 'Message', render: (r) => r.message },
    ],
  });
  failPanel.content.appendChild(failTable.root);

  const fzCtlPanel = createPanel({ title: 'Fuzzer — bypass rate per control', desc: 'Mutated attack variants that were NOT stopped, per control (lower is better). Tooltip: bypasses / variants.', unit: '%', span: 6 });
  const fzCtl = chartBox('Fuzzer bypass rate per control', { height: 280 });
  fzCtlPanel.content.appendChild(fzCtl.box);
  const fzStPanel = createPanel({ title: 'Fuzzer — bypass rate per mutation strategy', desc: 'Bypass rate per mutation strategy (base64, zero-width, homoglyphs, translations, …).', unit: '%', span: 6 });
  const fzSt = chartBox('Fuzzer bypass rate per strategy', { height: 280 });
  fzStPanel.content.appendChild(fzSt.box);

  const root = el('section', { class: 'view', 'aria-labelledby': 'v-tests' },
    viewHeader('Tests', 'Do the controls provably work? Detection, false positives, coverage and fuzzer bypasses.'),
    kpiGrid, grid(donutPanel, detPanel, fpPanel, heatPanel, failPanel, fzCtlPanel, fzStPanel));
  root.querySelector('h1').id = 'v-tests';

  function rateChart(canvas, items, getBlock, color, label, onPick, { order = 'desc', max = 100 } = {}) {
    // worst first: lowest detection, highest FP / bypass; ties by id for a stable order
    const dir = order === 'asc' ? 1 : -1;
    const rows = items.filter((c) => getBlock(c).rate !== null).sort((a, b) => dir * (getBlock(a).rate - getBlock(b).rate) || String(a.id).localeCompare(String(b.id))).slice(0, 12);
    upsertChart(canvas, {
      type: 'bar',
      labels: rows.map((c) => c.id),
      meta: rows,
      datasets: [{ id: 'r', label, data: rows.map((c) => +(getBlock(c).rate * 100).toFixed(2)), backgroundColor: color, borderRadius: 3, maxBarThickness: 18 }],
      options: (() => {
        const o = hbarOptions({ unit: 'pct', max: max ?? undefined, onClick: onPick ? clickHandler(({ meta }) => meta && onPick(meta.id)) : null, tooltipExtra: (item) => { const c = item.chart.data.meta?.[item.dataIndex]; return c ? rateText(getBlock(c)) : null; } });
        o.plugins.legend.display = false;
        return o;
      })(),
    });
    return rows;
  }

  function render(state) {
    const tr = state.resources.testReport;
    const r = tr?.data;
    const kState = !tr || tr.status === 'idle' || (tr.status === 'loading' && !r) ? 'loading' : r ? 'ok' : 'error';
    const unavailable = tr?.status === 'unavailable' && !r;
    const blank = { state: unavailable ? 'ok' : kState, value: '—', sub: unavailable ? 'report not available' : tr?.error?.message || '' };
    if (!r) for (const k of kpis.values()) k.update(blank);
    else {
      kpis.get('ts').update({ value: r.generatedAt ? fmtDate(r.generatedAt) : '—', sub: r.durationSeconds ? `duration ${r.durationSeconds.toFixed(1)} s` : r.policyVersion ? `policy ${r.policyVersion}` : '', color: COLORS.info });
      const ok = r.status === 'passed' || r.status === 'ok' || r.status === 'success';
      kpis.get('status').update({ value: r.status ? `${ok ? '✓' : '✕'} ${r.status}` : '—', sub: r.failed ? `${fmtInt(r.failed)} failing` : '', color: ok ? COLORS.success : COLORS.error });
      kpis.get('total').update({ value: fmtInt(r.total), sub: `${fmtInt(r.passed)} passed · ${fmtInt(r.failed)} failed · ${fmtInt(r.skipped)} skipped`, color: COLORS.info });
      kpis.get('det').update({ value: fmtPct(r.detection.rate), sub: rateText(r.detection), color: COLORS.success });
      kpis.get('fpr').update({ value: fmtPct(r.falsePositive.rate), sub: rateText(r.falsePositive), color: COLORS.warning });
      kpis.get('ovh').update({ value: `${fmtMs(r.overheadP50)} / ${fmtMs(r.overheadP95)}`, sub: r.overheadP95 === null ? '' : r.overheadP95 <= 20 ? 'p95 within 20 ms target' : 'p95 above 20 ms target', color: COLORS.info });
    }
    const controls = state.resources.controls?.data?.list || [];
    const cells = buildCoverage(controls, r);
    const covered = [...cells.values()].filter((c) => c.count > 0);
    const ctlIds = uniqueSorted([...controls.map((c) => c.id), ...[...cells.values()].map((c) => c.controlId)]);
    const thIds = uniqueSorted([...cells.values()].map((c) => c.threatId));
    if (r || controls.length) {
      const ctlCovered = new Set(covered.map((c) => c.controlId)).size;
      const thCovered = new Set(covered.map((c) => c.threatId)).size;
      kpis.get('cov').update({ value: `${ctlCovered}/${ctlIds.length} controls`, sub: `${thCovered}/${thIds.length} threats with tests`, color: COLORS.redact });
    }

    const opts = { unavailableMessage: UNAVAILABLE };
    if (stateFor(ctx, donutPanel, ['testReport'], { ...opts, isEmpty: () => !r.total })) {
      const data = [r.passed || 0, r.failed || 0, r.skipped || 0];
      upsertChart(donut.canvas, {
        type: 'doughnut',
        labels: ['✓ Passed', '✕ Failed', '– Skipped'],
        datasets: [{ id: 'res', data, backgroundColor: [COLORS.success, COLORS.error, COLORS.neutral], borderColor: COLORS.panel, borderWidth: 2 }],
        options: doughnutOptions({ center: { text: fmtInt(r.total), sub: 'tests' } }),
        live: { 'plugins.centerText': { text: fmtInt(r.total), sub: 'tests' } },
      });
      donutPanel.setSource('test report');
      donutPanel.setAlt(dataTableAlt('Results — data table', ['Result', 'Tests'], [['passed', fmtInt(r.passed)], ['failed', fmtInt(r.failed)], ['skipped', fmtInt(r.skipped)]]));
    }
    const perCtl = r?.perControl || [];
    if (stateFor(ctx, detPanel, ['testReport'], { ...opts, isEmpty: () => !perCtl.some((c) => c.detection.rate !== null), emptyMessage: 'The report has no per-control detection data.' })) {
      rateChart(det.canvas, perCtl, (c) => c.detection, COLORS.success, 'Detection rate', (id) => ctx.openControl(id), { order: 'asc' });
      detPanel.setAlt(dataTableAlt('Detection per control — data table', ['Control', 'Detection rate'], perCtl.map((c) => [c.id, rateText(c.detection)])));
      detPanel.setSource('test report per_control');
    }
    if (stateFor(ctx, fpPanel, ['testReport'], { ...opts, isEmpty: () => !perCtl.some((c) => c.falsePositive.rate !== null), emptyMessage: 'The report has no per-control false-positive data.' })) {
      rateChart(fp.canvas, perCtl, (c) => c.falsePositive, COLORS.warning, 'False-positive rate', (id) => ctx.openControl(id));
      fpPanel.setAlt(dataTableAlt('False positives per control — data table', ['Control', 'False-positive rate'], perCtl.map((c) => [c.id, rateText(c.falsePositive)])));
      fpPanel.setSource('test report per_control');
    }
    const heatDeps = r ? ['testReport'] : ['controls'];
    if (stateFor(ctx, heatPanel, heatDeps, { ...opts, isEmpty: () => !ctlIds.length || !thIds.length, emptyMessage: 'No coverage data.' })) {
      heat.render(ctlIds, thIds, (c, t) => cells.get(`${c}\u0000${t}`), { rowIsThreat: false });
      heatPanel.setSource(r?.coverage?.length ? 'test report coverage matrix' : '/admin/controls test counts');
    }
    if (stateFor(ctx, failPanel, ['testReport'], { ...opts, isEmpty: () => !r.failures.length, emptyMessage: r ? `No failed cases — ${fmtInt(r.passed)} passed.` : '' })) {
      failTable.setRows(r.failures);
      failPanel.setSource('test report failures');
    }

    const fz = state.resources.fuzzReport?.data;
    const fzOpts = { unavailableMessage: 'No fuzzer report exposed. Run `make fuzz` and serve the latest reports/fuzz_*.json at the configured path, or enable DEMO DATA.' };
    if (stateFor(ctx, fzCtlPanel, ['fuzzReport'], { ...fzOpts, isEmpty: () => !fz.perControl.length })) {
      rateChart(fzCtl.canvas, fz.perControl, (c) => ({ num: c.bypasses, den: c.attempts, rate: c.rate }), COLORS.error, 'Bypass rate', (id) => ctx.openControl(id), { max: null });
      fzCtlPanel.setSource(`fuzzer report${fz.generatedAt ? ` · ${fmtDate(fz.generatedAt)}` : ''}${fz.total.den ? ` · overall ${rateText(fz.total)}` : ''}`);
      fzCtlPanel.setAlt(dataTableAlt('Bypass per control — data table', ['Control', 'Bypass rate'], fz.perControl.map((c) => [c.id, fmtRate(c.bypasses, c.attempts, c.rate)])));
    }
    if (stateFor(ctx, fzStPanel, ['fuzzReport'], { ...fzOpts, isEmpty: () => !fz.perStrategy.length })) {
      rateChart(fzSt.canvas, fz.perStrategy, (c) => ({ num: c.bypasses, den: c.attempts, rate: c.rate }), COLORS.orange, 'Bypass rate', null, { max: null });
      fzStPanel.setSource('fuzzer report per_strategy');
      fzStPanel.setAlt(dataTableAlt('Bypass per strategy — data table', ['Strategy', 'Bypass rate'], fz.perStrategy.map((c) => [c.id, fmtRate(c.bypasses, c.attempts, c.rate)])));
    }
  }

  return {
    id: 'tests', title: 'Tests', resources: RES, root,
    render(state) {
      const sig = signature(state, RES);
      if (sig === lastSig) return;
      lastSig = sig;
      render(state);
    },
  };
}
