// AICL dashboard — reusable UI building blocks. Everything renders backend data through
// text nodes (utils.el → textContent); no component accepts HTML strings.

import { actionMeta, clear, el, fmtRelative, fmtDate, fmtUtc, SEVERITY_META, append, safeText } from './utils.js';

let uid = 0;
export const nextId = (p = 'id') => `${p}-${++uid}`;

// ---------------------------------------------------------------- badges & small atoms

export function actionBadge(action, { would = false } = {}) {
  if (!action) return el('span', { class: 'muted', text: '—' });
  const m = actionMeta(action);
  return el('span', { class: `badge badge-action act-${cssSafe(action)}${would ? ' would' : ''}`, style: `--c:${m.color}` },
    el('span', { class: 'badge-icon', 'aria-hidden': 'true', text: m.icon }),
    el('span', { text: would ? `would ${m.label.toLowerCase()}` : m.label }));
}

export function severityBadge(sev) {
  if (!sev) return el('span', { class: 'muted', text: '—' });
  const m = SEVERITY_META[sev] || { color: '#667085', icon: '?' };
  return el('span', { class: 'badge badge-sev', style: `--c:${m.color}` },
    el('span', { class: 'badge-icon', 'aria-hidden': 'true', text: m.icon }), el('span', { text: sev }));
}

export function boolBadge(v, yes = 'Yes', no = 'No') {
  if (v === null || v === undefined) return el('span', { class: 'muted', text: '—' });
  return el('span', { class: `badge ${v ? 'badge-yes' : 'badge-no'}` }, el('span', { class: 'badge-icon', 'aria-hidden': 'true', text: v ? '●' : '○' }), el('span', { text: v ? yes : no }));
}

export function modeBadge(mode) {
  if (!mode) return el('span', { class: 'muted', text: 'inherit' });
  const shadow = mode === 'shadow';
  return el('span', { class: `badge ${shadow ? 'badge-shadow' : 'badge-enforce'}` }, el('span', { class: 'badge-icon', 'aria-hidden': 'true', text: shadow ? '◌' : '◆' }), el('span', { text: mode }));
}

export const mono = (text, cls = '') => el('span', { class: `mono ${cls}`.trim(), text: safeText(text) });

export function chip(label, onClick, { title = null, mono: isMono = true } = {}) {
  return el('button', { type: 'button', class: `chip${isMono ? ' mono' : ''}`, title: title || `Filter audit events by ${label}`, onClick: (e) => { e.stopPropagation(); onClick(label); }, text: label });
}

export function timeCell(d) {
  if (!d) return el('span', { class: 'muted', text: '—' });
  return el('time', { datetime: d.toISOString(), title: fmtUtc(d), text: fmtDate(d) });
}

function cssSafe(s) {
  return String(s).replace(/[^a-z0-9_-]/gi, '_');
}

// ---------------------------------------------------------------- info tooltip

export function infoTip(text, label = 'About this metric') {
  const id = nextId('tip');
  const wrap = el('span', { class: 'tip-wrap' });
  const btn = el('button', { type: 'button', class: 'tip-btn', 'aria-label': label, 'aria-describedby': id, text: 'i' });
  const tip = el('span', { class: 'tip', role: 'tooltip', id, text });
  btn.addEventListener('keydown', (e) => { if (e.key === 'Escape') btn.blur(); });
  return append(wrap, [btn, tip]);
}

// ---------------------------------------------------------------- panel with states

/**
 * A titled panel with loading / empty / error / unavailable / stale states.
 * The content node is created once and only hidden while a non-success state is shown,
 * so charts inside are never destroyed by state changes.
 */
export function createPanel({ title, desc = '', unit = '', span = 12, source = '', headerExtra = null, cls = '', level = 2 }) {
  const id = nextId('panel');
  const titleEl = el(`h${level}`, { class: 'panel-title', id: `${id}-t`, text: title });
  const staleEl = el('span', { class: 'stale-badge', hidden: true, title: 'Data could not be refreshed recently', text: 'Stale' });
  const header = el('header', { class: 'panel-head' },
    el('div', { class: 'panel-title-row' }, titleEl, desc ? infoTip(desc, `About: ${title}`) : null, unit ? el('span', { class: 'unit-chip', text: unit }) : null, staleEl),
    headerExtra ? el('div', { class: 'panel-tools' }, headerExtra) : null);
  const descEl = desc ? el('p', { class: 'panel-desc', id: `${id}-d`, text: desc }) : null;
  const content = el('div', { class: 'panel-content' });
  const stateEl = el('div', { class: 'panel-state', role: 'status', 'aria-live': 'polite' });
  const notice = el('div', { class: 'panel-notice', hidden: true, role: 'status' });
  const footer = el('footer', { class: 'panel-foot' });
  const sourceEl = el('span', { class: 'panel-source', text: source });
  footer.appendChild(sourceEl);
  const altSlot = el('div', { class: 'panel-alt' });
  const root = el('section', { class: `panel span-${span} ${cls}`.trim(), 'aria-labelledby': `${id}-t`, 'aria-describedby': descEl ? `${id}-d` : null },
    header, descEl, notice, stateEl, content, altSlot, footer);
  let current = null;

  function setState(kind, { message = '', onRetry = null, stale = false, rows = 4 } = {}) {
    staleEl.hidden = !stale;
    root.classList.toggle('is-stale', Boolean(stale));
    const key = `${kind}|${message}|${Boolean(onRetry)}`;
    if (key === current) return;
    current = key;
    clear(stateEl);
    root.dataset.state = kind;
    if (kind === 'ok') {
      content.hidden = false;
      stateEl.hidden = true;
      root.removeAttribute('aria-busy');
      return;
    }
    stateEl.hidden = false;
    content.hidden = true;
    if (kind === 'loading') {
      root.setAttribute('aria-busy', 'true');
      stateEl.appendChild(el('span', { class: 'sr-only', text: `Loading ${title}…` }));
      for (let i = 0; i < rows; i++) stateEl.appendChild(el('div', { class: 'skeleton', style: `width:${92 - i * 13}%`, 'aria-hidden': 'true' }));
      return;
    }
    root.removeAttribute('aria-busy');
    const icon = kind === 'error' ? '!' : kind === 'empty' ? '∅' : '–';
    stateEl.appendChild(el('div', { class: `state-box state-${kind}` },
      el('span', { class: 'state-icon', 'aria-hidden': 'true', text: icon }),
      el('div', {},
        el('strong', { text: kind === 'error' ? 'Could not load data' : kind === 'empty' ? 'No data' : 'Not available' }),
        el('p', { text: message })),
      onRetry ? el('button', { type: 'button', class: 'btn btn-sm', onClick: onRetry, text: 'Retry' }) : null));
  }

  function setNotice(text, kind = 'info') {
    notice.hidden = !text;
    notice.className = `panel-notice notice-${kind}`;
    notice.textContent = text || '';
  }

  function setSource(text) { sourceEl.textContent = text; }

  function setAlt(node) { clear(altSlot); if (node) altSlot.appendChild(node); }

  return { root, content, setState, setNotice, setSource, setAlt, titleEl };
}

/**
 * Applies the standard resource→panel state mapping.
 * @returns {boolean} true when the caller should render data.
 */
export function applyResourceState(panel, resources, { isEmpty = () => false, emptyMessage = 'Nothing recorded for this selection.', onRetry = null, staleFn = () => false, unavailableMessage = null } = {}) {
  const list = Array.isArray(resources) ? resources : [resources];
  // `some`, not `find`: a not-yet-created resource is `undefined`, which `find` would return as falsy
  const missing = list.some((r) => !r || r.status === 'idle' || (r.status === 'loading' && r.data === null));
  if (missing) { panel.setState('loading'); return false; }
  const unavailable = list.find((r) => r.status === 'unavailable' && r.data === null);
  if (unavailable) { panel.setState('unavailable', { message: unavailableMessage || 'The gateway does not expose this data.' }); return false; }
  const failed = list.find((r) => r.status === 'error' && r.data === null);
  if (failed) { panel.setState('error', { message: failed.error?.message || 'Request failed.', onRetry }); return false; }
  const stale = list.some((r) => staleFn(r));
  const errWithData = list.find((r) => r.status === 'error' && r.data !== null);
  panel.setNotice(errWithData ? `Showing last good data — refresh failed: ${errWithData.error?.message || 'error'}` : '', 'warn');
  if (isEmpty()) { panel.setState('empty', { message: emptyMessage, stale }); return false; }
  panel.setState('ok', { stale });
  return true;
}

// ---------------------------------------------------------------- KPI card

export function createKpi({ label, tip, onClick = null, linkLabel = 'Events' }) {
  const valueEl = el('div', { class: 'kpi-value', text: '—' });
  const subEl = el('div', { class: 'kpi-sub' });
  const changeEl = el('div', { class: 'kpi-change muted', text: 'no comparison data' });
  const sparkEl = el('div', { class: 'kpi-spark', 'aria-hidden': 'true' });
  const link = onClick ? el('button', { type: 'button', class: 'kpi-link', onClick, 'aria-label': `${label}: open matching audit events`, text: `${linkLabel} ›` }) : null;
  const root = el('div', { class: 'kpi' },
    el('div', { class: 'kpi-head' }, el('span', { class: 'kpi-label', text: label }), infoTip(tip, `About: ${label}`), link),
    valueEl, subEl, el('div', { class: 'kpi-foot' }, changeEl, sparkEl));

  function update({ value = '—', sub = '', change = null, spark = null, state = 'ok', color = null }) {
    root.dataset.state = state;
    valueEl.textContent = state === 'loading' ? '' : value;
    valueEl.classList.toggle('kpi-value-long', String(value).length > 11);
    valueEl.title = String(value);
    valueEl.classList.toggle('skeleton-text', state === 'loading');
    if (color) root.style.setProperty('--accent', color);
    subEl.textContent = sub;
    if (change && change.text) {
      changeEl.textContent = change.text;
      changeEl.className = `kpi-change ${change.dir > 0 ? 'up' : change.dir < 0 ? 'down' : 'muted'}`;
    } else {
      changeEl.textContent = state === 'loading' ? '' : state === 'error' ? 'unavailable' : 'no comparison data';
      changeEl.className = 'kpi-change muted';
    }
    clear(sparkEl);
    if (spark && spark.length > 1) sparkEl.appendChild(sparkline(spark, color || '#4EA1FF'));
  }
  return { root, update };
}

export function sparkline(values, color) {
  const ns = 'http://www.w3.org/2000/svg';
  const w = 84;
  const h = 24;
  const max = Math.max(1, ...values);
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
  svg.setAttribute('width', String(w));
  svg.setAttribute('height', String(h));
  svg.setAttribute('aria-hidden', 'true');
  const pts = values.map((v, i) => `${((i / (values.length - 1)) * w).toFixed(1)},${(h - 2 - (v / max) * (h - 4)).toFixed(1)}`).join(' ');
  const line = document.createElementNS(ns, 'polyline');
  line.setAttribute('points', pts);
  line.setAttribute('fill', 'none');
  line.setAttribute('stroke', color);
  line.setAttribute('stroke-width', '1.5');
  svg.appendChild(line);
  return svg;
}

// ---------------------------------------------------------------- progress bar (budgets)

const LEVEL_LABEL = { normal: 'OK', warning: 'Warning', high: 'High', exceeded: 'Exceeded', unlimited: 'Unlimited' };
const LEVEL_ICON = { normal: '●', warning: '▲', high: '◆', exceeded: '✕', unlimited: '∞' };

export function progressBar({ pct, level, label, valueText }) {
  const shown = pct === null ? 0 : Math.min(100, Math.max(0, pct * 100));
  const bar = el('div', { class: `progress lvl-${level}`, role: pct === null ? null : 'progressbar', 'aria-label': label, 'aria-valuemin': pct === null ? null : '0', 'aria-valuemax': pct === null ? null : '100', 'aria-valuenow': pct === null ? null : String(Math.round(shown)), 'aria-valuetext': valueText },
    el('div', { class: 'progress-fill', style: `width:${shown}%` }));
  return el('div', { class: 'progress-wrap' }, bar, el('span', { class: `lvl-tag lvl-${level}` }, el('span', { 'aria-hidden': 'true', text: LEVEL_ICON[level] }), el('span', { text: LEVEL_LABEL[level] })));
}

// ---------------------------------------------------------------- data table

/**
 * Sortable, paginated table. Rows are plain objects; `columns[].render(row)` returns a node or string.
 * Only the visible page is rendered, so thousands of rows stay cheap.
 */
export function createTable({ columns, rowKey = (r) => r.id, onRowClick = null, caption = '', pageSize = 50, emptyText = 'No rows match the current filters.', initialSort = null, rowClass = null, nowrap = false }) {
  let rows = [];
  let page = 0;
  let sort = initialSort || null; // {key, dir}
  const table = el('table', { class: nowrap ? 'table table-nowrap' : 'table' });
  if (caption) table.appendChild(el('caption', { class: 'sr-only', text: caption }));
  const thead = el('thead');
  const headRow = el('tr');
  const headerCells = new Map();
  for (const col of columns) {
    const th = el('th', { scope: 'col', class: col.className || '' });
    if (col.sort) {
      const btn = el('button', { type: 'button', class: 'th-sort', onClick: () => toggleSort(col.key) }, el('span', { text: col.label }), el('span', { class: 'sort-ind', 'aria-hidden': 'true' }));
      th.appendChild(btn);
    } else th.textContent = col.label;
    headerCells.set(col.key, th);
    headRow.appendChild(th);
  }
  thead.appendChild(headRow);
  const tbody = el('tbody');
  table.append(thead, tbody);
  const info = el('span', { class: 'table-info', 'aria-live': 'polite' });
  const prev = el('button', { type: 'button', class: 'btn btn-sm', onClick: () => go(page - 1), text: '‹ Prev', 'aria-label': 'Previous page' });
  const next = el('button', { type: 'button', class: 'btn btn-sm', onClick: () => go(page + 1), text: 'Next ›', 'aria-label': 'Next page' });
  const pager = el('div', { class: 'pager' }, info, el('div', { class: 'pager-btns' }, prev, next));
  const root = el('div', { class: 'table-wrap' }, el('div', { class: 'table-scroll', tabindex: '0', role: 'region', 'aria-label': caption || 'Table' }, table), pager);

  function toggleSort(key) {
    sort = sort && sort.key === key ? { key, dir: sort.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'desc' };
    page = 0;
    render();
  }
  function go(p) { page = Math.max(0, Math.min(p, pages() - 1)); render(); }
  const pages = () => Math.max(1, Math.ceil(rows.length / pageSize));

  function sorted() {
    if (!sort) return rows;
    const col = columns.find((c) => c.key === sort.key);
    if (!col || !col.sort) return rows;
    const dir = sort.dir === 'asc' ? 1 : -1;
    return [...rows].sort((a, b) => {
      const va = col.sort(a);
      const vb = col.sort(b);
      if (va === vb) return 0;
      if (va === null || va === undefined) return 1;
      if (vb === null || vb === undefined) return -1;
      return (va < vb ? -1 : 1) * dir;
    });
  }

  function render() {
    for (const [key, th] of headerCells) {
      const active = sort && sort.key === key;
      th.setAttribute('aria-sort', active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none');
      const ind = th.querySelector('.sort-ind');
      if (ind) ind.textContent = active ? (sort.dir === 'asc' ? '▲' : '▼') : '';
    }
    clear(tbody);
    const all = sorted();
    if (page >= pages()) page = pages() - 1;
    const slice = all.slice(page * pageSize, (page + 1) * pageSize);
    if (!slice.length) {
      tbody.appendChild(el('tr', {}, el('td', { colspan: String(columns.length), class: 'table-empty', text: emptyText })));
    }
    const frag = document.createDocumentFragment();
    for (const r of slice) {
      const tr = el('tr', { class: rowClass ? rowClass(r) : '', dataset: { key: String(rowKey(r)) } });
      if (onRowClick) {
        tr.tabIndex = 0;
        tr.classList.add('row-link');
        tr.addEventListener('click', () => onRowClick(r, tr));
        tr.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onRowClick(r, tr); } });
      }
      for (const col of columns) {
        const v = col.render ? col.render(r) : r[col.key];
        const td = el(col.header ? 'th' : 'td', { class: col.className || '', scope: col.header ? 'row' : null });
        append(td, [v === null || v === undefined || v === '' ? el('span', { class: 'muted', text: '—' }) : v]);
        tr.appendChild(td);
      }
      frag.appendChild(tr);
    }
    tbody.appendChild(frag);
    const from = all.length ? page * pageSize + 1 : 0;
    info.textContent = `${from}–${Math.min(all.length, (page + 1) * pageSize)} of ${all.length.toLocaleString()}`;
    prev.disabled = page === 0;
    next.disabled = page >= pages() - 1;
    pager.hidden = all.length <= pageSize;
  }

  return {
    root,
    setRows(newRows, { resetPage = false } = {}) { rows = Array.isArray(newRows) ? newRows : []; if (resetPage) page = 0; render(); },
    get rows() { return rows; },
  };
}

// ---------------------------------------------------------------- text alternative for charts

export function dataTableAlt(summaryText, headers, rows, { maxRows = 200 } = {}) {
  const t = el('table', { class: 'table table-compact' });
  t.appendChild(el('thead', {}, el('tr', {}, headers.map((h) => el('th', { scope: 'col', text: h })))));
  const tb = el('tbody');
  for (const r of rows.slice(0, maxRows)) tb.appendChild(el('tr', {}, r.map((c, i) => el(i === 0 ? 'th' : 'td', { scope: i === 0 ? 'row' : null, text: safeText(c, '—') }))));
  if (rows.length > maxRows) tb.appendChild(el('tr', {}, el('td', { colspan: String(headers.length), class: 'muted', text: `… ${rows.length - maxRows} more rows` })));
  if (!rows.length) tb.appendChild(el('tr', {}, el('td', { colspan: String(headers.length), class: 'muted', text: 'No data' })));
  t.appendChild(tb);
  return el('details', { class: 'alt-data' }, el('summary', { text: summaryText || 'Show data as table' }), el('div', { class: 'table-scroll' }, t));
}

// ---------------------------------------------------------------- focus trap / drawer / dialogs / toasts

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])';

export function trapFocus(container, onEscape) {
  const handler = (e) => {
    if (e.key === 'Escape' && onEscape) { e.preventDefault(); e.stopPropagation(); onEscape(); return; }
    if (e.key !== 'Tab') return;
    const items = [...container.querySelectorAll(FOCUSABLE)].filter((n) => n.offsetParent !== null || n === document.activeElement);
    if (!items.length) { e.preventDefault(); return; }
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };
  container.addEventListener('keydown', handler);
  return () => container.removeEventListener('keydown', handler);
}

/** One drawer for the whole app (event details, control details). */
export function createDrawer(root) {
  const titleEl = root.querySelector('[data-drawer-title]');
  const body = root.querySelector('[data-drawer-body]');
  const closeBtn = root.querySelector('[data-drawer-close]');
  const backdrop = document.querySelector('[data-drawer-backdrop]');
  let release = null;
  let returnFocus = null;
  let onCloseCb = null;

  function close() {
    if (root.hidden) return;
    root.hidden = true;
    if (backdrop) backdrop.hidden = true;
    document.body.classList.remove('drawer-open');
    release?.();
    release = null;
    const cb = onCloseCb;
    onCloseCb = null;
    cb?.();
    if (returnFocus && document.contains(returnFocus)) returnFocus.focus();
  }
  closeBtn.addEventListener('click', close);
  backdrop?.addEventListener('click', close);

  return {
    open({ title, content, onClose = null }) {
      if (!root.hidden) { release?.(); onCloseCb?.(); }
      returnFocus = document.activeElement;
      titleEl.textContent = title;
      clear(body);
      append(body, [content]);
      onCloseCb = onClose;
      root.hidden = false;
      if (backdrop) backdrop.hidden = false;
      document.body.classList.add('drawer-open');
      release = trapFocus(root, close);
      body.scrollTop = 0;
      closeBtn.focus();
    },
    close,
    isOpen: () => !root.hidden,
    body,
  };
}

/** Modal built on <dialog>: native inertness + our own focus trap and Escape handling. */
export function openDialog(dialog, { onEscape = null, initialFocus = null } = {}) {
  if (!dialog.open) dialog.showModal();
  const release = trapFocus(dialog, onEscape);
  const cancel = (e) => { e.preventDefault(); onEscape?.(); };
  dialog.addEventListener('cancel', cancel);
  (initialFocus || dialog.querySelector(FOCUSABLE))?.focus();
  return () => { release(); dialog.removeEventListener('cancel', cancel); if (dialog.open) dialog.close(); };
}

export function confirmDialog({ title, message, confirmLabel = 'Confirm', danger = false }) {
  return new Promise((resolve) => {
    const d = el('dialog', { class: 'modal', 'aria-labelledby': 'confirm-title' });
    const cancelBtn = el('button', { type: 'button', class: 'btn', text: 'Cancel' });
    const okBtn = el('button', { type: 'button', class: `btn ${danger ? 'btn-danger' : 'btn-primary'}`, text: confirmLabel });
    append(d, [el('h2', { id: 'confirm-title', class: 'modal-title', text: title }), el('p', { class: 'modal-text', text: message }), el('div', { class: 'modal-actions' }, cancelBtn, okBtn)]);
    document.body.appendChild(d);
    const returnFocus = document.activeElement;
    const done = (v) => { close(); d.remove(); if (returnFocus) returnFocus.focus(); resolve(v); };
    const close = openDialog(d, { onEscape: () => done(false), initialFocus: cancelBtn });
    cancelBtn.addEventListener('click', () => done(false));
    okBtn.addEventListener('click', () => done(true));
  });
}

export function toast(message, kind = 'info', ms = 5000) {
  const region = document.getElementById('toasts');
  if (!region) return;
  const t = el('div', { class: `toast toast-${kind}`, role: kind === 'error' ? 'alert' : 'status' },
    el('span', { text: message }),
    el('button', { type: 'button', class: 'icon-btn', 'aria-label': 'Dismiss notification', text: '×', onClick: () => t.remove() }));
  region.appendChild(t);
  while (region.children.length > 4) region.firstChild.remove();
  if (ms) setTimeout(() => t.remove(), ms);
}

// ---------------------------------------------------------------- definition list

export function defList(pairs) {
  const dl = el('dl', { class: 'deflist' });
  for (const [k, v] of pairs) {
    if (v === undefined) continue;
    dl.append(el('dt', { text: k }), el('dd', {}, v === null || v === '' ? el('span', { class: 'muted', text: '—' }) : v instanceof Node ? v : String(v)));
  }
  return dl;
}

export function updatedLabel(date) {
  return date ? `Updated ${fmtRelative(date)}` : '';
}
