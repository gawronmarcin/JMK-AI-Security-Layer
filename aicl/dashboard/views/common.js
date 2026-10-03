// AICL dashboard — helpers shared by the views (toolbars, ranking charts, heatmap, source labels).

import { chartBox, clickHandler, hbarOptions, upsertChart } from '../charts.js';
import { applyResourceState, createPanel, dataTableAlt } from '../components.js';
import { COLORS, RANGES, el, fmtInt, resolveRange, toDate, topN, append, clear } from '../utils.js';

/** Signature of the inputs a view depends on — the view re-renders only when it changes. */
export function signature(state, names, extra = '') {
  return names.map((n) => `${n}:${state.resources[n]?.version ?? 0}`).join('|') + `|${JSON.stringify(state.filters)}|${extra}`;
}

/** Converts a Date to the value format of <input type="datetime-local"> in local time. */
function toLocalInput(d) {
  if (!d) return '';
  const off = d.getTimezoneOffset() * 60000;
  return new Date(d.getTime() - off).toISOString().slice(0, 16);
}

/** Sticky time-range toolbar (15 min … 7 d + custom). */
export function createRangeToolbar(ctx, { extra = null, label = 'Time range' } = {}) {
  const group = el('div', { class: 'seg', role: 'group', 'aria-label': label });
  const buttons = new Map();
  for (const [key, r] of Object.entries(RANGES)) {
    const b = el('button', { type: 'button', class: 'seg-btn', 'aria-pressed': 'false', text: r.label, onClick: () => ctx.setFilters({ range: key, from: null, to: null }) });
    buttons.set(key, b);
    group.appendChild(b);
  }
  const customBtn = el('button', { type: 'button', class: 'seg-btn', 'aria-pressed': 'false', 'aria-expanded': 'false', text: 'Custom' });
  group.appendChild(customBtn);
  const fromIn = el('input', { type: 'datetime-local', 'aria-label': 'From (local time)' });
  const toIn = el('input', { type: 'datetime-local', 'aria-label': 'To (local time)' });
  const apply = el('button', { type: 'button', class: 'btn btn-sm', text: 'Apply' });
  const custom = el('div', { class: 'custom-range', hidden: true }, el('label', { class: 'field-inline' }, el('span', { text: 'From' }), fromIn), el('label', { class: 'field-inline' }, el('span', { text: 'To' }), toIn), apply);
  const rangeText = el('span', { class: 'range-text muted', 'aria-live': 'polite' });
  customBtn.addEventListener('click', () => {
    custom.hidden = !custom.hidden;
    customBtn.setAttribute('aria-expanded', String(!custom.hidden));
    if (!custom.hidden) {
      const { from, to } = resolveRange(ctx.store.get().filters);
      fromIn.value = toLocalInput(from);
      toIn.value = toLocalInput(to);
      fromIn.focus();
    }
  });
  apply.addEventListener('click', () => {
    const from = toDate(fromIn.value);
    const to = toDate(toIn.value);
    if (!from || !to || from >= to) { rangeText.textContent = 'Invalid range: "From" must be before "To".'; return; }
    ctx.setFilters({ range: 'custom', from: from.toISOString(), to: to.toISOString() });
    custom.hidden = true;
    customBtn.setAttribute('aria-expanded', 'false');
  });
  const root = el('div', { class: 'toolbar', role: 'toolbar', 'aria-label': `${label} and filters` }, group, custom, rangeText, extra);

  function update(filters) {
    for (const [k, b] of buttons) b.setAttribute('aria-pressed', String(filters.range === k));
    customBtn.setAttribute('aria-pressed', String(filters.range === 'custom'));
    const { from, to } = resolveRange(filters);
    rangeText.textContent = filters.range === 'custom' ? `${from.toLocaleString()} → ${to.toLocaleString()}` : `Last ${RANGES[filters.range]?.label || ''}`;
  }
  return { root, update };
}

export function viewHeader(title, subtitle) {
  return el('div', { class: 'view-head' }, el('h1', { class: 'view-title', text: title }), subtitle ? el('p', { class: 'view-sub muted', text: subtitle }) : null);
}

export function grid(...panels) {
  return el('div', { class: 'grid' }, panels.map((p) => (p.root ? p.root : p)));
}

/**
 * Horizontal ranking chart panel ("Top controls", "Top threats", …). Click → onPick(key).
 * Shows at most `limit` bars; the rest is aggregated as "Other" and listed in the data table.
 */
export function createRankingPanel({ title, desc, unit = 'events', seriesLabel, color = COLORS.info, onPick, limit = 10, span = 6, height = 300 }) {
  const panel = createPanel({ title, desc, unit, span });
  const { box, canvas } = chartBox(title, { height });
  panel.content.appendChild(box);
  let keys = [];
  const options = hbarOptions({
    onClick: clickHandler(({ index }) => { const k = keys[index]; if (k && !k.other) onPick(k.key); }),
    tooltipExtra: (item) => (keys[item.dataIndex]?.other ? `Aggregated: ${keys[item.dataIndex].members.length} items (see data table)` : 'Click to filter audit events'),
  });
  options.plugins.legend.display = false;

  function render(entries, { sourceText = '' } = {}) {
    keys = topN(entries.filter((e) => e.value > 0), limit);
    upsertChart(canvas, {
      type: 'bar',
      labels: keys.map((k) => k.key),
      datasets: [{ id: 'v', label: seriesLabel, data: keys.map((k) => k.value), backgroundColor: keys.map((k) => (k.other ? COLORS.neutral : color)), borderRadius: 3, maxBarThickness: 22 }],
      options,
    });
    canvas.setAttribute('aria-label', `${title}: ${keys.slice(0, 5).map((k) => `${k.key} ${k.value}`).join(', ')}`);
    panel.setAlt(dataTableAlt(`${title} — data table (${entries.length} rows)`, ['Key', seriesLabel], [...entries].sort((a, b) => b.value - a.value).map((e) => [e.key, fmtInt(e.value)])));
    panel.setSource(sourceText);
  }
  return { panel, render, root: panel.root };
}

// ---------------------------------------------------------------- coverage heatmap (semantic HTML grid)

export const COVERAGE_LEVELS = {
  none: { label: 'No coverage', icon: '○', cls: 'cov-none' },
  partial: { label: 'Partial', icon: '◐', cls: 'cov-partial' },
  full: { label: 'Full', icon: '●', cls: 'cov-full' },
  unmapped: { label: 'Not mapped', icon: '·', cls: 'cov-unmapped' },
};

/**
 * Coverage level of a (control, threat) pair.
 * full    = ≥3 negative, ≥3 positive, ≥2 edge cases (ARCHITECTURE §11.5) or ≥8 tests when kinds are unknown
 * partial = at least one test
 * none    = mapped in policy/controls but no test
 */
export function coverageLevel(cell) {
  if (!cell || (!cell.mapped && !cell.count)) return 'unmapped';
  if (!cell.count) return 'none';
  const k = cell.kinds || {};
  const hasKinds = (k.negative || 0) + (k.positive || 0) + (k.edge || 0) > 0;
  if (hasKinds ? (k.negative >= 3 && k.positive >= 3 && k.edge >= 2) : cell.count >= 8) return 'full';
  return 'partial';
}

/** Builds pair → {mapped, count, kinds, source} from the controls list and the test report coverage. */
export function buildCoverage(controls, testReport) {
  const cells = new Map();
  const key = (c, t) => `${c}\u0000${t}`;
  const get = (c, t) => { const k = key(c, t); if (!cells.has(k)) cells.set(k, { controlId: c, threatId: t, mapped: false, count: 0, kinds: null, source: '' }); return cells.get(k); };
  for (const c of controls || []) {
    for (const t of c.threatIds) {
      const cell = get(c.id, t);
      cell.mapped = true;
      const per = c.tests?.perThreat?.[t];
      if (per !== undefined && per !== null) { cell.count = per; cell.source = '/admin/controls (per threat)'; }
      else if (c.tests && c.tests.total !== null) {
        cell.count = c.tests.total;
        cell.kinds = { negative: c.tests.negative, positive: c.tests.positive, edge: c.tests.edge };
        cell.source = '/admin/controls (control-level count)';
      }
    }
  }
  if (testReport && testReport.coverage.length) {
    const fromReport = new Map();
    for (const row of testReport.coverage) {
      const k = key(row.controlId, row.threatId);
      const agg = fromReport.get(k) || { count: 0, kinds: { negative: 0, positive: 0, edge: 0 } };
      agg.count += row.count;
      if (row.kind && agg.kinds[row.kind] !== undefined) agg.kinds[row.kind] += row.count;
      fromReport.set(k, agg);
      get(row.controlId, row.threatId);
    }
    for (const [k, agg] of fromReport) {
      const cell = cells.get(k);
      cell.count = agg.count;
      cell.kinds = agg.kinds;
      cell.source = 'test report coverage matrix';
    }
  }
  return cells;
}

export function createHeatmap({ rowLabel, colLabel, onPick }) {
  const root = el('div', { class: 'heatmap-wrap' });
  const legend = el('ul', { class: 'heat-legend', 'aria-label': 'Legend' },
    Object.values(COVERAGE_LEVELS).map((l) => el('li', {}, el('span', { class: `heat-swatch ${l.cls}`, 'aria-hidden': 'true', text: l.icon }), el('span', { text: l.label }))));
  const scroller = el('div', { class: 'table-scroll heat-scroll', tabindex: '0', role: 'region', 'aria-label': `Coverage matrix: ${rowLabel} by ${colLabel}` });
  append(root, [legend, scroller]);

  /** rows/cols: arrays of ids; cellFor(row, col) → cell | undefined; orientation decides tooltip wording. */
  function render(rows, cols, cellFor, { rowIsThreat = true, rowTitles = new Map() } = {}) {
    clear(scroller);
    const table = el('table', { class: 'heatmap' });
    table.appendChild(el('caption', { class: 'sr-only', text: `Test coverage, rows: ${rowLabel}, columns: ${colLabel}. Each cell shows the number of tests and the coverage level.` }));
    table.appendChild(el('thead', {}, el('tr', {}, el('th', { scope: 'col', class: 'heat-corner', text: `${rowLabel} \\ ${colLabel}` }), cols.map((c) => el('th', { scope: 'col', class: 'heat-col mono' }, el('span', { text: c }))))));
    const tb = el('tbody');
    for (const r of rows) {
      const tr = el('tr', {}, el('th', { scope: 'row', class: 'heat-row mono', title: rowTitles.get(r) || '' , text: r }));
      for (const c of cols) {
        const cell = cellFor(r, c);
        const lvl = coverageLevel(cell);
        const meta = COVERAGE_LEVELS[lvl];
        const threatId = rowIsThreat ? r : c;
        const controlId = rowIsThreat ? c : r;
        const tipText = `${threatId} × ${controlId}: ${meta.label}${cell && cell.count ? `, ${cell.count} test${cell.count === 1 ? '' : 's'}` : ''}${cell?.kinds && (cell.kinds.negative || cell.kinds.positive || cell.kinds.edge) ? ` (neg ${cell.kinds.negative ?? '?'}, pos ${cell.kinds.positive ?? '?'}, edge ${cell.kinds.edge ?? '?'})` : ''}${cell?.source ? ` — ${cell.source}` : ''}`;
        const td = el('td', { class: `heat-cell ${meta.cls}` });
        if (lvl === 'unmapped') td.appendChild(el('span', { 'aria-label': tipText, title: tipText, text: meta.icon }));
        else td.appendChild(el('button', { type: 'button', class: 'heat-btn', title: `${tipText}. Click to filter audit events.`, 'aria-label': tipText, onClick: () => onPick({ threatId, controlId }) },
          el('span', { 'aria-hidden': 'true', class: 'heat-icon', text: meta.icon }), el('span', { class: 'heat-num', text: cell.count ? String(cell.count) : '0' })));
        tr.appendChild(td);
      }
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    scroller.appendChild(table);
  }
  return { root, render };
}

/** Standard resource state helper bound to the context (stale detection + retry). */
export function stateFor(ctx, panel, names, opts = {}) {
  const st = ctx.store.get();
  return applyResourceState(panel, names.map((n) => st.resources[n]), { staleFn: (r) => ctx.isStale(r), onRetry: () => ctx.refresh(names), ...opts });
}

export function eventsSourceText(evRes, count) {
  const d = evRes?.data;
  if (!d) return '';
  return `Derived from ${fmtInt(count)} loaded audit events (/admin/events)${d.truncated ? ` — capped at ${fmtInt(d.limit)} per request, older events may be missing` : ''}`;
}
