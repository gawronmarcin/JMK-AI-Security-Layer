// Audit events — live feed with filters (hash-synced), paginated table, details drawer and
// authorised JSONL export. All backend strings are rendered as text; matches show `masked` only.

import { actionBadge, boolBadge, chip, createPanel, createTable, defList, mono, severityBadge, timeCell, toast } from '../components.js';
import { filterEvents, inRange } from '../derive.js';
import { ACTIONS, SEVERITIES, ENDPOINTS, copyText, el, fmtInt, fmtMs, fmtNum, fmtUsd, fmtUtc, resolveRange, safeText, sanitizeForDisplay, uniqueSorted, debounce } from '../utils.js';
import { createRangeToolbar, grid, signature, stateFor, viewHeader } from './common.js';

const RES = ['events'];
const KNOWN_TYPES = ['request', 'policy.reloaded', 'policy.rejected', 'feed.reloaded', 'budget.exceeded'];

export function createEvents(ctx) {
  let lastSig = '';

  const selects = {};
  const mkSel = (key, label) => {
    const s = el('select', { 'aria-label': label, onChange: (e) => ctx.setFilters({ [key]: e.target.value }) }, el('option', { value: '', text: `${label}: all` }));
    selects[key] = s;
    return s;
  };
  const search = el('input', { type: 'search', placeholder: 'Request / session / event ID', 'aria-label': 'Search by request ID or session ID', class: 'mono-input', onInput: debounce((e) => ctx.setFilters({ q: e.target.value.trim() }), 250) });
  const refreshSel = el('select', { 'aria-label': 'Auto-refresh interval for the live feed', onChange: (e) => ctx.setRefresh(Number(e.target.value)) },
    [['0', 'Off'], ['2000', '2 s'], ['5000', '5 s'], ['10000', '10 s'], ['30000', '30 s']].map(([v, t]) => el('option', { value: v, text: `Live: ${t}` })));
  const exportBtn = el('button', { type: 'button', class: 'btn btn-sm', text: 'Export audit JSONL', onClick: () => ctx.exportAudit(exportBtn) });
  const resetBtn = el('button', { type: 'button', class: 'btn btn-sm', text: 'Clear filters', onClick: () => ctx.store.resetEventFilters() });
  const countEl = el('span', { class: 'muted small', 'aria-live': 'polite' });
  const filterRow = el('div', { class: 'filter-row' },
    search, mkSel('action', 'Action'), mkSel('type', 'Type'), mkSel('severity', 'Severity'), mkSel('identity', 'Identity'), mkSel('endpoint', 'Endpoint'),
    mkSel('control', 'Control'), mkSel('threat', 'Threat'), mkSel('policyVersion', 'Policy version'), resetBtn);
  const rangeBar = createRangeToolbar(ctx, { extra: el('div', { class: 'toolbar-right' }, refreshSel, exportBtn) });
  rangeBar.root.appendChild(filterRow);
  rangeBar.root.appendChild(countEl);

  const panel = createPanel({ title: 'Live event feed', desc: 'Audit events from /admin/events (newest first). Filters run on the loaded events; select a row (or press Enter) for full details.', span: 12 });
  const table = createTable({
    nowrap: true,
    caption: 'Audit events',
    pageSize: 50,
    onRowClick: (e) => ctx.openEvent(e),
    rowKey: (e) => e.id,
    initialSort: { key: 'ts', dir: 'desc' },
    rowClass: (e) => (e.finalAction === 'block' ? 'row-block' : ''),
    columns: [
      { key: 'ts', label: 'Timestamp', sort: (e) => e.ts?.getTime() || 0, render: (e) => timeCell(e.ts) },
      { key: 'type', label: 'Type', sort: (e) => e.type, render: (e) => el('span', { class: `mono small${KNOWN_TYPES.includes(e.type) ? '' : ' text-warn'}`, text: e.type, title: KNOWN_TYPES.includes(e.type) ? null : 'Unknown event type' }) },
      { key: 'action', label: 'Final action', sort: (e) => e.finalAction || '', render: (e) => (e.shadow && e.wouldHaveAction ? el('span', { class: 'stack' }, actionBadge(e.finalAction), actionBadge(e.wouldHaveAction, { would: true })) : actionBadge(e.finalAction)) },
      { key: 'sev', label: 'Severity', sort: (e) => SEVERITIES.indexOf(e.severity), render: (e) => severityBadge(e.severity) },
      { key: 'identity', label: 'Identity', sort: (e) => e.identity || '', render: (e) => (e.identity ? mono(e.identity, 'small') : null) },
      { key: 'role', label: 'Role', render: (e) => e.role },
      { key: 'endpoint', label: 'Endpoint', render: (e) => e.endpoint },
      { key: 'model', label: 'Model', render: (e) => (e.model ? mono(e.model, 'small') : null) },
      { key: 'controls', label: 'Control IDs', render: (e) => (e.controlIds.length ? el('span', { class: 'mono small', text: e.controlIds.join(', ') }) : null) },
      { key: 'threats', label: 'Threat IDs', render: (e) => (e.threatIds.length ? el('span', { class: 'mono small', text: e.threatIds.join(', ') }) : null) },
      { key: 'ovh', label: 'Overhead', className: 'num', sort: (e) => e.latency.totalOverhead ?? -1, render: (e) => (e.latency.totalOverhead === null ? null : fmtMs(e.latency.totalOverhead)) },
      { key: 'up', label: 'Upstream', render: (e) => boolBadge(e.upstreamCalled, 'called', 'not called') },
      { key: 'req', label: 'Request ID', render: (e) => (e.requestId ? mono(e.requestId, 'small') : null) },
    ],
  });
  panel.content.appendChild(table.root);

  const root = el('section', { class: 'view', 'aria-labelledby': 'v-events' },
    viewHeader('Audit events', 'What exactly happened in recent requests — masked excerpts only, never raw secrets or PII.'),
    rangeBar.root, grid(panel));
  root.querySelector('h1').id = 'v-events';

  function fill(sel, values, current) {
    const have = [...sel.options].slice(1).map((o) => o.value).join('|');
    const all = uniqueSorted([...values, current].filter(Boolean));
    if (have !== all.join('|')) {
      while (sel.options.length > 1) sel.remove(1);
      for (const v of all) sel.appendChild(el('option', { value: v, text: v }));
    }
    sel.value = current || '';
  }

  function render(state) {
    const f = state.filters;
    rangeBar.update(f);
    refreshSel.value = String(state.ui.refreshMs);
    if (document.activeElement !== search) search.value = f.q || '';
    const data = state.resources.events?.data;
    const all = data?.events || [];
    const { from, to } = resolveRange(f);
    const ranged = inRange(all, from, to);
    fill(selects.action, [...ACTIONS, ...all.map((e) => e.finalAction).filter((a) => a && !ACTIONS.includes(a))], f.action);
    fill(selects.type, [...KNOWN_TYPES, ...all.map((e) => e.type)], f.type);
    fill(selects.severity, SEVERITIES, f.severity);
    fill(selects.identity, all.map((e) => e.identity), f.identity);
    fill(selects.endpoint, [...ENDPOINTS, ...all.map((e) => e.endpoint)], f.endpoint);
    fill(selects.control, all.flatMap((e) => e.controlIds), f.control);
    fill(selects.threat, all.flatMap((e) => e.threatIds), f.threat);
    fill(selects.policyVersion, all.map((e) => e.policyVersion), f.policyVersion);
    const rows = filterEvents(ranged, f);
    const active = ['action', 'type', 'severity', 'identity', 'endpoint', 'control', 'threat', 'policyVersion', 'q'].filter((k) => f[k]).length;
    countEl.textContent = data ? `${fmtInt(rows.length)} matching · ${fmtInt(ranged.length)} in range · ${fmtInt(all.length)} loaded${active ? ` · ${active} filter${active > 1 ? 's' : ''} active` : ''}` : '';
    if (!stateFor(ctx, panel, ['events'], { isEmpty: () => !rows.length, emptyMessage: all.length ? 'No events match the current filters and time range.' : 'The gateway has not recorded any audit events yet.' })) return;
    table.setRows(rows);
    panel.setNotice(data.truncated ? `Only the latest ${fmtInt(data.limit)} events per request are loaded (in-memory cap ${fmtInt(ctx.config.maxEventsInMemory)}). Use the export for the full audit log.` : '', 'warn');
    panel.setSource(`/admin/events · ${fmtInt(data.received)} received in the last poll`);
  }

  return {
    id: 'events', title: 'Audit events', resources: RES, root,
    render(state) {
      const sig = signature(state, RES, String(state.ui.refreshMs));
      if (sig === lastSig) return;
      lastSig = sig;
      render(state);
    },
  };
}

// ---------------------------------------------------------------- event details (drawer)

export function eventDetails(ctx, e) {
  const decisions = el('div', { class: 'decisions' });
  if (!e.decisions.length) decisions.appendChild(el('p', { class: 'muted', text: 'No decisions recorded.' }));
  for (const d of e.decisions) {
    const matches = d.matches.length
      ? el('ul', { class: 'matches' }, d.matches.map((m) => el('li', {},
        el('span', { class: 'mono small', text: m.kind }),
        el('code', { class: 'masked', text: m.masked ?? '(no masked excerpt provided)' }),
        m.segmentIdx !== null ? el('span', { class: 'muted small', text: `segment ${m.segmentIdx}` }) : null,
        m.inDecoded ? el('span', { class: 'badge small', text: 'in decoded text' }) : null)))
      : null;
    decisions.appendChild(el('article', { class: `decision${d.skipped ? ' is-skipped' : ''}` },
      el('header', { class: 'decision-head' },
        chip(d.controlId, (v) => { ctx.drawer.close(); ctx.filterEvents({ control: v }); }),
        actionBadge(d.action, { would: d.shadowSuppressed }),
        severityBadge(d.severity),
        d.skipped ? el('span', { class: 'badge small', text: 'skipped' }) : null,
        d.shadowSuppressed ? el('span', { class: 'badge badge-shadow small', text: 'shadow-suppressed' }) : null,
        el('span', { class: 'muted small', text: d.latencyMs !== null ? fmtMs(d.latencyMs) : '' })),
      d.threatIds.length ? el('p', { class: 'chips' }, d.threatIds.map((t) => chip(t, (v) => { ctx.drawer.close(); ctx.filterEvents({ threat: v }); }))) : null,
      d.reason ? el('p', { class: 'reason', text: d.reason }) : null,
      d.score !== null ? el('p', { class: 'muted small', text: `score ${fmtNum(d.score, 2)}` }) : null,
      matches));
  }
  const per = Object.entries(e.latency.perControl);
  const sanitized = sanitizeForDisplay(e.raw);
  const json = JSON.stringify(sanitized, null, 2);
  const pre = el('pre', { class: 'json', tabindex: '0', 'aria-label': 'Event JSON (credentials removed)', text: json });
  const copyBtn = el('button', { type: 'button', class: 'btn btn-sm', text: 'Copy JSON', onClick: async () => { const ok = await copyText(json); toast(ok ? 'Event JSON copied (credentials removed).' : 'Copy failed — select the JSON manually.', ok ? 'success' : 'error'); } });
  const errText = e.error === null ? null : typeof e.error === 'string' ? e.error : safeText(e.error);

  return el('div', { class: 'drawer-sections' },
    el('section', {}, el('h3', { text: 'Summary' }), defList([
      ['Final action', e.shadow && e.wouldHaveAction ? el('span', { class: 'stack' }, actionBadge(e.finalAction), actionBadge(e.wouldHaveAction, { would: true })) : actionBadge(e.finalAction)],
      ['Severity', severityBadge(e.severity)],
      ['Type', mono(e.type)],
      ['Timestamp', e.ts ? `${e.ts.toLocaleString()} (${fmtUtc(e.ts)})` : null],
      ['Request ID', e.requestId ? mono(e.requestId) : null],
      ['Session ID', e.sessionId ? mono(e.sessionId) : null],
      ['Event ID', e.eventId ? mono(e.eventId) : null],
      ['Identity', e.identity ? mono(e.identity) : null], ['Role', e.role], ['Profile', e.profile],
      ['Endpoint', e.endpoint], ['Model', e.model ? mono(e.model) : null],
      ['Shadow', e.shadow ? 'yes' : 'no'], ['Upstream called', boolBadge(e.upstreamCalled)],
      ['Policy version', e.policyVersion ? mono(e.policyVersion) : null], ['Feed version', e.feedVersion ? mono(e.feedVersion) : null],
    ])),
    e.reason ? el('section', {}, el('h3', { text: 'Reason' }), el('p', { class: 'reason', text: e.reason })) : null,
    errText ? el('section', {}, el('h3', { text: 'Error' }), el('pre', { class: 'json error-text', text: errText })) : null,
    el('section', {}, el('h3', { text: `Decisions (${e.decisions.length})` }), decisions),
    el('section', {}, el('h3', { text: 'Latency' }), defList([
      ['Total AICL overhead', fmtMs(e.latency.totalOverhead)], ['Upstream', fmtMs(e.latency.upstream)],
      ...per.map(([k, v]) => [`per control · ${k}`, fmtMs(v)]),
    ])),
    el('section', {}, el('h3', { text: 'Usage' }), defList([
      ['Prompt tokens', fmtInt(e.usage.promptTokens)], ['Completion tokens', fmtInt(e.usage.completionTokens)],
      ['Cost', fmtUsd(e.usage.costUsd)], ['Compute seconds', e.usage.computeSeconds === null ? '—' : `${fmtNum(e.usage.computeSeconds, 2)} s`],
    ])),
    el('section', {}, el('div', { class: 'section-head' }, el('h3', { text: 'JSON' }), copyBtn), el('p', { class: 'muted small', text: 'Credential-like fields are removed; match objects keep only kind, offsets and the masked excerpt.' }), pre),
    el('div', { class: 'drawer-actions' },
      e.requestId ? el('button', { type: 'button', class: 'btn btn-sm', text: 'All events of this request', onClick: () => { ctx.drawer.close(); ctx.filterEvents({ q: e.requestId }); } }) : null,
      e.sessionId ? el('button', { type: 'button', class: 'btn btn-sm', text: 'All events of this session', onClick: () => { ctx.drawer.close(); ctx.filterEvents({ q: e.sessionId }); } }) : null));
}
