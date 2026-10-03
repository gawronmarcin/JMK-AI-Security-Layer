// AICL dashboard — Chart.js wrappers. Charts are created once per canvas and afterwards
// updated in place (datasets matched by `id`), so auto-refresh never re-creates charts and
// series hidden via the legend stay hidden.

import { COLORS, el, fmtInt, fmtMs, fmtPct, fmtUtc, fmtTime } from './utils.js';

const registry = new Map(); // canvas -> Chart
const reducedMotion = () => window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

export function chartsAvailable() {
  return typeof window.Chart === 'function';
}

export function setupChartDefaults() {
  if (!chartsAvailable()) return;
  const C = window.Chart;
  C.defaults.color = COLORS.muted;
  C.defaults.borderColor = 'rgba(38,50,65,0.9)';
  C.defaults.font.family = 'ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';
  C.defaults.font.size = 12;
  // Set the duration on the existing object, never replace it: Chart.js builds each animation's
  // config only from the keys present in defaults.animation, so `{duration: 250}` drops `type`
  // and every colour transition (hover) gets no interpolator ("this._fn is not a function"),
  // which kills the shared animation loop and freezes all charts.
  if (reducedMotion()) C.defaults.animation = false;
  else C.defaults.animation.duration = 250;
  C.defaults.plugins.legend.labels.usePointStyle = true;
  C.defaults.plugins.legend.labels.boxHeight = 8;
  C.defaults.plugins.legend.labels.color = COLORS.text;
  C.defaults.plugins.tooltip.backgroundColor = COLORS.raised;
  C.defaults.plugins.tooltip.borderColor = COLORS.border;
  C.defaults.plugins.tooltip.borderWidth = 1;
  C.defaults.plugins.tooltip.titleColor = COLORS.text;
  C.defaults.plugins.tooltip.bodyColor = COLORS.text;
  C.defaults.plugins.tooltip.padding = 10;
  C.defaults.plugins.tooltip.usePointStyle = true;
  C.defaults.maintainAspectRatio = false;
  C.defaults.responsive = true;
  C.register(centerTextPlugin, targetLinePlugin);
}

/** Draws total + caption in the centre of a doughnut (options.plugins.centerText). */
const centerTextPlugin = {
  id: 'centerText',
  afterDraw(chart, _args, opts) {
    if (!opts || !opts.text) return;
    const { ctx, chartArea } = chart;
    const meta = chart.getDatasetMeta(0);
    const arc = meta && meta.data && meta.data[0];
    const x = arc ? arc.x : (chartArea.left + chartArea.right) / 2;
    const y = arc ? arc.y : (chartArea.top + chartArea.bottom) / 2;
    ctx.save();
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = COLORS.text;
    ctx.font = `600 ${opts.size || 22}px ${window.Chart.defaults.font.family}`;
    ctx.fillText(opts.text, x, y - 8);
    ctx.fillStyle = COLORS.muted;
    ctx.font = `12px ${window.Chart.defaults.font.family}`;
    ctx.fillText(opts.sub || '', x, y + 14);
    ctx.restore();
  },
};

/** Dashed reference line, explicitly labelled as a target (options.plugins.targetLine). */
const targetLinePlugin = {
  id: 'targetLine',
  afterDatasetsDraw(chart, _args, opts) {
    if (!opts || opts.value === undefined || opts.value === null) return;
    const horizontal = opts.axis === 'x';
    const scale = chart.scales[horizontal ? 'x' : 'y'];
    if (!scale) return;
    const pos = scale.getPixelForValue(opts.value);
    const { ctx, chartArea } = chart;
    if (horizontal ? pos < chartArea.left || pos > chartArea.right : pos < chartArea.top || pos > chartArea.bottom) return;
    ctx.save();
    ctx.strokeStyle = opts.color || COLORS.info;
    ctx.lineWidth = 1.5;
    ctx.setLineDash([6, 4]);
    ctx.beginPath();
    if (horizontal) { ctx.moveTo(pos, chartArea.top); ctx.lineTo(pos, chartArea.bottom); } else { ctx.moveTo(chartArea.left, pos); ctx.lineTo(chartArea.right, pos); }
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = opts.color || COLORS.info;
    ctx.font = `600 11px ${window.Chart.defaults.font.family}`;
    ctx.textBaseline = 'bottom';
    if (horizontal) { ctx.textAlign = 'left'; ctx.fillText(opts.label || 'Target', pos + 4, chartArea.top + 12); } else { ctx.textAlign = 'right'; ctx.fillText(opts.label || 'Target', chartArea.right - 4, pos - 3); }
    ctx.restore();
  },
};

/** Creates <div class="chart-box"><canvas role=img></div>. */
export function chartBox(label, { height = 280, cls = '' } = {}) {
  const canvas = el('canvas', { role: 'img', 'aria-label': label });
  const fallback = el('p', { class: 'muted', text: 'Chart rendering unavailable — see the data table below.' });
  canvas.appendChild(fallback);
  const box = el('div', { class: `chart-box ${cls}`.trim(), style: `height:${height}px` }, canvas);
  return { box, canvas };
}

/**
 * Create-or-update. `spec` = {type, labels, datasets:[{id, ...}], options}.
 * Options are applied only at creation, except keys listed in `spec.live` (e.g. plugins.centerText).
 */
export function upsertChart(canvas, spec) {
  if (!chartsAvailable()) return null;
  let chart = registry.get(canvas);
  if (!chart) {
    chart = new window.Chart(canvas, {
      type: spec.type,
      data: { labels: spec.labels, datasets: spec.datasets.map((d) => ({ ...d })), meta: spec.meta || null },
      options: spec.options || {},
    });
    registry.set(canvas, chart);
    return chart;
  }
  chart.data.labels = spec.labels;
  chart.data.meta = spec.meta || null;
  const byId = new Map(chart.data.datasets.map((d, i) => [d.id ?? i, d]));
  const next = spec.datasets.map((d, i) => {
    const cur = byId.get(d.id ?? i);
    if (cur) { Object.assign(cur, d); return cur; }
    return { ...d };
  });
  chart.data.datasets = next;
  // Write into the raw config options (never through Chart.js' resolver proxies).
  if (spec.live) for (const [path, value] of Object.entries(spec.live)) setPath(chart.config.options, path, value);
  chart.update('none');
  return chart;
}

function setPath(obj, path, value) {
  const parts = path.split('.');
  let o = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (!o[parts[i]] || typeof o[parts[i]] !== 'object') o[parts[i]] = {};
    o = o[parts[i]];
  }
  o[parts[parts.length - 1]] = value;
}

export function destroyChart(canvas) {
  const c = registry.get(canvas);
  if (c) { c.destroy(); registry.delete(canvas); }
}

/** Click helper → handler({datasetIndex, index, dataset, label}). Uses nearest element on the x axis. */
/**
 * Chart click → handler({datasetIndex, index, dataset, label, meta}).
 * `columnFallback`: a click that hits no element (empty space above a stacked bar, a thin
 * segment, the gap around a line point) still selects the whole column, with `dataset`
 * null. Time charts use it so a click works wherever the hover tooltip and pointer cursor
 * (index mode, intersect: false) suggest it does.
 */
export function clickHandler(handler, mode = 'nearest', { columnFallback = false } = {}) {
  return (evt, _els, chart) => {
    let hits = chart.getElementsAtEventForMode(evt, mode, { intersect: mode === 'nearest' }, true);
    let dataset = hits.length ? chart.data.datasets[hits[0].datasetIndex] : null;
    if (!hits.length && columnFallback) {
      hits = chart.getElementsAtEventForMode(evt, 'index', { intersect: false }, true);
      dataset = null;
    }
    if (!hits.length) return;
    const { datasetIndex, index } = hits[0];
    handler({ datasetIndex, index, chart, dataset, label: chart.data.labels[index], meta: chart.data.meta ? chart.data.meta[index] : undefined });
  };
}

export function hoverCursor(evt, els) {
  const t = evt.native && evt.native.target;
  if (t) t.style.cursor = els.length ? 'pointer' : 'default';
}

// ---------------------------------------------------------------- common option factories

const gridStyle = () => ({ color: 'rgba(38,50,65,0.6)' });

const rawValue = (item) => (item.dataset.rawCounts ? item.dataset.rawCounts[item.dataIndex] : item.parsed.y);

/** Put the tooltip beside the hovered column (right of it, left near the right edge) so it never
 *  covers the bars being inspected. */
const besideColumn = (ctx) => {
  const x = ctx.tooltipItems?.[0]?.element?.x;
  const area = ctx.chart.chartArea;
  if (x === undefined || !area) return undefined;
  return x > area.left + area.width * 0.6 ? 'right' : 'left';
};

export function timeAxisOptions({ stacked = false, percent = false, onClick = null, bucketMs = 60000, utcTitle = false } = {}) {
  return {
    interaction: { mode: 'index', intersect: false },
    onClick,
    onHover: onClick ? hoverCursor : undefined,
    scales: {
      x: { type: 'category', stacked, grid: gridStyle(), ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 8 } },
      y: {
        stacked, beginAtZero: true, grid: gridStyle(), min: 0, max: percent ? 100 : undefined,
        title: { display: true, text: percent ? 'Share of requests (%)' : 'Requests' },
        ticks: { precision: 0, callback: (v) => (percent ? `${v}%` : fmtInt(v)) },
      },
    },
    plugins: {
      legend: { position: 'bottom' },
      tooltip: {
        // compact: only series present in the bucket, one-line title, total in the footer
        position: 'nearest',
        xAlign: besideColumn,
        yAlign: 'center',
        caretPadding: 8,
        padding: 8,
        bodySpacing: 2,
        boxPadding: 3,
        filter: (item) => rawValue(item) > 0,
        callbacks: {
          title: (items) => {
            const d = items[0]?.chart?.data?.meta?.[items[0].dataIndex];
            if (!d) return items[0]?.label || '';
            return `${fmtTime(d.t)}–${fmtTime(d.end)}${utcTitle ? `  (UTC ${fmtUtc(d.t)})` : ''}`;
          },
          label: (item) => {
            const raw = rawValue(item);
            return percent ? ` ${item.dataset.label}: ${fmtPct(item.parsed.y / 100)} (${fmtInt(raw)})` : ` ${item.dataset.label}: ${fmtInt(raw)}`;
          },
          footer: (items) => {
            if (items.length < 2) return '';
            return `Total: ${fmtInt(items.reduce((s, i) => s + (Number(rawValue(i)) || 0), 0))}`;
          },
        },
      },
    },
  };
}

export function hbarOptions({ unit = 'count', onClick = null, stacked = false, xTitle = '', max = undefined, tooltipExtra = null } = {}) {
  const fmt = unit === 'ms' ? fmtMs : unit === 'pct' ? (v) => fmtPct(v / 100) : fmtInt;
  return {
    indexAxis: 'y',
    onClick,
    onHover: onClick ? hoverCursor : undefined,
    interaction: { mode: 'nearest', axis: 'y', intersect: false },
    scales: {
      x: { beginAtZero: true, min: 0, max, stacked, grid: gridStyle(), title: { display: Boolean(xTitle), text: xTitle }, ticks: { callback: (v) => fmt(v) } },
      y: { stacked, grid: { display: false }, ticks: { autoSkip: false, font: { family: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', size: 11 } } },
    },
    plugins: {
      legend: { position: 'bottom' },
      tooltip: {
        callbacks: {
          label: (item) => {
            const base = ` ${item.dataset.label}: ${fmt(item.parsed.x)}`;
            const extra = tooltipExtra ? tooltipExtra(item) : null;
            return extra ? [base, ...[].concat(extra)] : base;
          },
        },
      },
    },
  };
}

export function vbarOptions({ unit = 'count', onClick = null, stacked = false, yTitle = '', max = undefined, tooltipExtra = null, legend = true } = {}) {
  const fmt = unit === 'ms' ? fmtMs : unit === 'pct' ? (v) => fmtPct(v / 100) : fmtInt;
  return {
    onClick,
    onHover: onClick ? hoverCursor : undefined,
    interaction: { mode: 'nearest', axis: 'x', intersect: false },
    scales: {
      x: { stacked, grid: { display: false }, ticks: { autoSkip: false, maxRotation: 45 } },
      y: { beginAtZero: true, min: 0, max, stacked, grid: gridStyle(), title: { display: Boolean(yTitle), text: yTitle }, ticks: { callback: (v) => fmt(v) } },
    },
    plugins: {
      legend: { display: legend, position: 'bottom' },
      tooltip: {
        callbacks: {
          label: (item) => {
            const base = ` ${item.dataset.label}: ${fmt(item.parsed.y)}`;
            const extra = tooltipExtra ? tooltipExtra(item) : null;
            return extra ? [base, ...[].concat(extra)] : base;
          },
        },
      },
    },
  };
}

export function doughnutOptions({ onClick = null, center = null, tooltipLabel = null } = {}) {
  return {
    cutout: '68%',
    onClick,
    onHover: onClick ? hoverCursor : undefined,
    plugins: {
      legend: { position: 'bottom' },
      centerText: center,
      tooltip: {
        callbacks: {
          label: tooltipLabel || ((item) => {
            const total = item.dataset.data.reduce((s, v) => s + (v || 0), 0);
            return ` ${item.label}: ${fmtInt(item.parsed)} (${fmtPct(total ? item.parsed / total : 0)})`;
          }),
        },
      },
    },
  };
}

/** Diagonal-stripe pattern so series are distinguishable without colour (used sparingly). */
export function stripePattern(color) {
  const c = document.createElement('canvas');
  c.width = 8; c.height = 8;
  const ctx = c.getContext('2d');
  ctx.fillStyle = color;
  ctx.globalAlpha = 0.55;
  ctx.fillRect(0, 0, 8, 8);
  ctx.globalAlpha = 1;
  ctx.strokeStyle = 'rgba(11,15,20,0.75)';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(0, 8); ctx.lineTo(8, 0);
  ctx.stroke();
  return ctx.createPattern(c, 'repeat');
}

export function alpha(hex, a) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
}
