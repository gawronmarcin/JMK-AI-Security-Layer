// Policy — active policy summary, reload history, manual reload (with confirmation) and
// validation of a candidate YAML (never activates it).

import { ApiError } from '../api.js';
import { confirmDialog, createPanel, createTable, defList, mono, modeBadge, timeCell, toast } from '../components.js';
import { normalizeValidation } from '../normalize.js';
import { el, clear, fmtInt, fmtRelative } from '../utils.js';
import { grid, signature, stateFor, viewHeader } from './common.js';

const RES = ['policy', 'health', 'events', 'policyHistory'];
const POLICY_EVENTS = ['policy.reloaded', 'policy.rejected', 'feed.reloaded'];

export function createPolicy(ctx) {
  let lastSig = '';
  let reloadResult = null; // {ok, at, message}

  const summaryPanel = createPanel({ title: 'Active policy', desc: 'From /admin/policy (secrets stripped by the gateway). policy_version = sha256[:12] of the active file.', span: 6 });
  const summaryBody = el('div');
  summaryPanel.content.appendChild(summaryBody);

  const reloadBtn = el('button', { type: 'button', class: 'btn btn-primary', text: 'Reload policy from disk…' });
  const reloadOut = el('div', { class: 'reload-out', role: 'status', 'aria-live': 'polite' });
  const reloadPanel = createPanel({ title: 'Reload', desc: 'POST /admin/policy/reload forces a reload of policies/*.yaml (the file watcher normally does this within ~1 s). An invalid file keeps the old policy active and emits policy.rejected.', span: 6 });
  reloadPanel.content.append(el('p', { class: 'muted small', text: 'Use this after editing the policy file if hot reload did not pick it up. The dashboard never edits the policy file.' }), reloadBtn, reloadOut);

  const histPanel = createPanel({ title: 'Reload history', desc: 'policy.reloaded, policy.rejected and feed.reloaded audit events of the last 7 days (newest first).', span: 12 });
  const histTable = createTable({
    caption: 'Policy and feed reload events',
    pageSize: 15,
    onRowClick: (e) => ctx.openEvent(e),
    initialSort: { key: 'ts', dir: 'desc' },
    columns: [
      { key: 'ts', label: 'Time', sort: (e) => e.ts?.getTime() || 0, render: (e) => timeCell(e.ts) },
      { key: 'type', label: 'Event', render: (e) => el('span', { class: `badge ${e.type === 'policy.rejected' ? 'badge-exceeded' : 'badge-yes'}` }, el('span', { 'aria-hidden': 'true', text: e.type === 'policy.rejected' ? '✕' : '✓' }), el('span', { text: e.type })) },
      { key: 'pv', label: 'Policy version', render: (e) => (e.policyVersion ? mono(e.policyVersion) : null) },
      { key: 'fv', label: 'Feed version', render: (e) => (e.feedVersion ? mono(e.feedVersion) : null) },
      { key: 'reason', label: 'Message / error', render: (e) => e.reason || (e.error ? (typeof e.error === 'string' ? e.error : JSON.stringify(e.error)) : null) },
    ],
  });
  histPanel.content.appendChild(histTable.root);

  const ta = el('textarea', { class: 'yaml', rows: '14', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Candidate policy YAML', placeholder: 'Paste a candidate policy YAML here. Validate syntax or preview its impact against recent audit traffic.' });
  const validateBtn = el('button', { type: 'button', class: 'btn', text: 'Validate (does not apply)' });
  const previewBtn = el('button', { type: 'button', class: 'btn btn-primary', text: 'Preview impact (Replay traffic)' });
  const valOut = el('div', { class: 'val-out', role: 'status', 'aria-live': 'polite' });
  const valPanel = createPanel({ title: 'Validate & preview candidate policy', desc: 'POST /admin/policy/validate checks syntax. POST /admin/policy/preview replays recorded requests and reports what outcomes would change before applying.', span: 12 });
  valPanel.content.append(el('p', { class: 'notice notice-info', text: 'Do not paste real API keys: identities reference keys via api_key_env, never inline values.' }), ta, el('div', { class: 'row-actions' }, validateBtn, previewBtn, el('span', { class: 'muted small', text: 'Max 512 KB' })), valOut);

  const root = el('section', { class: 'view', 'aria-labelledby': 'v-policy' },
    viewHeader('Policy', 'Which policy is active and did the last policy / feed reload succeed?'),
    grid(summaryPanel, reloadPanel, histPanel, valPanel));
  root.querySelector('h1').id = 'v-policy';

  reloadBtn.addEventListener('click', async () => {
    const p = ctx.store.get().resources.policy?.data;
    const ok = await confirmDialog({ title: 'Reload policy?', message: `The gateway will re-read the policy file from disk and atomically swap it if valid. Current version: ${p?.policyVersion || 'unknown'}. Requests in flight finish with the old policy.`, confirmLabel: 'Reload now' });
    if (!ok) return;
    reloadBtn.disabled = true;
    clear(reloadOut).appendChild(el('p', { class: 'muted', text: 'Reloading…' }));
    try {
      const res = await ctx.api.reloadPolicy();
      const v = normalizeValidation(res);
      reloadResult = { ok: v.ok, at: new Date(), message: v.ok ? `Reload accepted${v.version ? ` — version ${v.version}` : ''}.` : v.errors.map((e) => `${e.path ? `${e.path}: ` : ''}${e.message}`).join('; '), errors: v.errors };
      toast(v.ok ? 'Policy reload accepted.' : 'Policy reload rejected — old policy stays active.', v.ok ? 'success' : 'error');
    } catch (err) {
      const v = err instanceof ApiError && err.details ? normalizeValidation(err.details) : { errors: [] };
      reloadResult = { ok: false, at: new Date(), message: err.message, errors: v.errors };
      toast(`Reload failed: ${err.message}`, 'error');
    } finally {
      reloadBtn.disabled = false;
      ctx.refresh(['policy', 'health', 'events', 'policyHistory']);
      renderReload();
    }
  });

  validateBtn.addEventListener('click', async () => {
    const yaml = ta.value;
    clear(valOut);
    if (!yaml.trim()) { valOut.appendChild(el('p', { class: 'form-error', text: 'Paste a YAML document first.' })); return; }
    if (yaml.length > 512 * 1024) { valOut.appendChild(el('p', { class: 'form-error', text: 'Candidate is larger than 512 KB.' })); return; }
    validateBtn.disabled = true;
    valOut.appendChild(el('p', { class: 'muted', text: 'Validating…' }));
    let v;
    try {
      v = normalizeValidation(await ctx.api.validatePolicy(yaml));
    } catch (err) {
      if (err instanceof ApiError && err.kind === 'bad_request' && err.details) v = normalizeValidation(err.details);
      else v = { ok: false, errors: [{ path: '', message: err.message }], transport: true };
      if (!v.errors.length) v.errors.push({ path: '', message: err.message });
    } finally {
      validateBtn.disabled = false;
    }
    clear(valOut);
    if (v.ok) {
      valOut.appendChild(el('p', { class: 'notice notice-ok' }, el('span', { 'aria-hidden': 'true', text: '✓ ' }), el('span', { text: `Valid. Not applied — edit the policy file and reload to activate.${v.version ? ` Candidate version ${v.version}.` : ''}` })));
    } else {
      valOut.appendChild(el('p', { class: 'notice notice-error' }, el('span', { 'aria-hidden': 'true', text: '✕ ' }), el('span', { text: `${v.errors.length} validation error${v.errors.length === 1 ? '' : 's'}. The active policy is unchanged.` })));
      valOut.appendChild(el('table', { class: 'table table-compact' },
        el('caption', { class: 'sr-only', text: 'Validation errors' }),
        el('thead', {}, el('tr', {}, el('th', { scope: 'col', text: 'Field path' }), el('th', { scope: 'col', text: 'Message' }))),
        el('tbody', {}, v.errors.map((e) => el('tr', {}, el('td', { class: 'mono', text: e.path || '(document)' }), el('td', { text: e.message }))))));
    }
  });

  previewBtn.addEventListener('click', async () => {
    const yaml = ta.value;
    clear(valOut);
    if (!yaml.trim()) { valOut.appendChild(el('p', { class: 'form-error', text: 'Paste a YAML document first.' })); return; }
    previewBtn.disabled = true;
    valOut.appendChild(el('p', { class: 'muted', text: 'Replaying recorded requests against candidate policy…' }));
    try {
      const res = await ctx.api.previewPolicy(yaml, 50);
      clear(valOut);
      const isDiff = (res.changed_count || 0) > 0;
      valOut.appendChild(el('p', { class: `notice ${isDiff ? 'notice-warn' : 'notice-ok'}` },
        el('span', { 'aria-hidden': 'true', text: isDiff ? '⚠ ' : '✓ ' }),
        el('span', { text: `Replayed ${res.total_replayed} requests: ${res.changed_count} outcome change(s) detected. Candidate v${res.candidate_version}.` })
      ));
      if (res.diff && res.diff.length > 0) {
        valOut.appendChild(el('table', { class: 'table table-compact' },
          el('caption', { class: 'sr-only', text: 'Replay changes' }),
          el('thead', {}, el('tr', {},
            el('th', { scope: 'col', text: 'Request ID' }),
            el('th', { scope: 'col', text: 'Endpoint' }),
            el('th', { scope: 'col', text: 'Original action' }),
            el('th', { scope: 'col', text: 'Candidate action' }),
            el('th', { scope: 'col', text: 'Reasons' })
          )),
          el('tbody', {}, res.diff.map((d) => el('tr', {},
            el('td', { class: 'mono', text: d.request_id }),
            el('td', { text: d.endpoint }),
            el('td', { text: d.original_action }),
            el('td', { class: 'bold', text: d.candidate_action }),
            el('td', { text: (d.reasons || []).join('; ') })
          )))
        ));
      }
    } catch (err) {
      clear(valOut);
      valOut.appendChild(el('p', { class: 'notice notice-error' }, el('span', { text: `Preview failed: ${err.message}` })));
    } finally {
      previewBtn.disabled = false;
    }
  });

  function renderReload() {
    clear(reloadOut);
    if (!reloadResult) return;
    reloadOut.appendChild(el('p', { class: `notice ${reloadResult.ok ? 'notice-ok' : 'notice-error'}` },
      el('span', { 'aria-hidden': 'true', text: reloadResult.ok ? '✓ ' : '✕ ' }),
      el('span', { text: `${reloadResult.at.toLocaleTimeString()}: ${reloadResult.message}` })));
  }

  function render(state) {
    const p = state.resources.policy?.data;
    const h = state.resources.health?.data;
    const evs = state.resources.events?.data?.events || [];
    const ph = state.resources.policyHistory?.data;
    const byId = new Map();
    for (const e of [...(ph?.events || []), ...evs.filter((x) => POLICY_EVENTS.includes(x.type))]) byId.set(e.id, e);
    const hist = [...byId.values()].sort((a, b) => (b.ts?.getTime() || 0) - (a.ts?.getTime() || 0));
    const lastPolicyEvt = hist.find((e) => e.type === 'policy.reloaded' || e.type === 'policy.rejected');
    const lastFeedEvt = hist.find((e) => e.type === 'feed.reloaded');
    if (stateFor(ctx, summaryPanel, ['policy'])) {
      clear(summaryBody).appendChild(defList([
        ['Policy name', p.name], ['Description', p.description],
        ['Policy version', p.policyVersion || h?.policyVersion ? mono(p.policyVersion || h.policyVersion) : null],
        ['Schema version', p.schemaVersion],
        ['Feed version', p.feedVersion || h?.feedVersion || lastFeedEvt?.feedVersion ? mono(p.feedVersion || h?.feedVersion || lastFeedEvt.feedVersion) : null],
        ['Active profile', p.activeProfile ? mono(p.activeProfile) : null],
        ['Mode', modeBadge(p.mode)],
        ['Evaluation', p.evaluation ? mono(p.evaluation) : null],
        ['On-error default', p.onErrorDefault ? mono(p.onErrorDefault) : null],
        ['Controls in policy', p.controlsCount === null ? null : String(p.controlsCount)],
        ['Identities', p.identitiesCount === null ? null : String(p.identitiesCount)],
        ['Signature feeds', p.feeds.length ? p.feeds.map((f) => `${f.name || '?'} (${f.path || '?'}, every ${f.refreshSeconds ?? '?'} s, ${f.onUnavailable || '—'})`).join('; ') : null],
        ['Last reload', p.loadedAt ? `${p.loadedAt.toLocaleString()} (${fmtRelative(p.loadedAt)})` : lastPolicyEvt?.ts ? `${lastPolicyEvt.ts.toLocaleString()} (from audit)` : 'not reported'],
        ['Last reload result', p.lastReloadResult ? (/ok|success|reloaded|applied/i.test(p.lastReloadResult) ? el('span', { class: 'text-ok', text: `✓ ${p.lastReloadResult}` }) : el('span', { class: 'text-error', text: `✕ ${p.lastReloadResult}` })) : lastPolicyEvt ? el('span', { class: lastPolicyEvt.type === 'policy.rejected' ? 'text-error' : 'text-ok', text: lastPolicyEvt.type === 'policy.rejected' ? `rejected — ${lastPolicyEvt.reason || safeErr(lastPolicyEvt.error)}` : 'reloaded' }) : 'not reported'],
        ['Last reload error', p.lastReloadError],
        ['Last feed reload', lastFeedEvt?.ts ? `${lastFeedEvt.ts.toLocaleString()} → ${lastFeedEvt.feedVersion || '?'}` : 'no feed.reloaded in the last 7 days'],
      ]));
      summaryPanel.setSource('/admin/policy');
    }
    reloadPanel.setState('ok');
    renderReload();
    if (stateFor(ctx, histPanel, ['policyHistory'], { isEmpty: () => !hist.length, emptyMessage: 'No policy.reloaded, policy.rejected or feed.reloaded events in the last 7 days of scanned events.' })) {
      histTable.setRows(hist);
      histPanel.setNotice(ph?.truncated ? `Scanned only the newest ${fmtInt(ph.scanned)} audit events of the last 7 days (no server-side type filter) — older reloads may be missing.` : '', 'warn');
      histPanel.setSource(`/admin/events since ${ph?.since ? ph.since.toLocaleString() : '7 d'} · ${ph ? fmtInt(ph.scanned) : '—'} events scanned, type filter applied in the dashboard`);
    }
    valPanel.setState('ok');
  }

  return {
    id: 'policy', title: 'Policy', resources: RES, root,
    render(state) {
      const sig = signature(state, RES);
      if (sig === lastSig) return;
      lastSig = sig;
      render(state);
    },
  };
}

function safeErr(err) {
  if (!err) return '';
  return typeof err === 'string' ? err : JSON.stringify(err);
}
