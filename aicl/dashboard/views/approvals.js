// Human-in-the-Loop (HITL) Approvals view.
// Manages requests paused by Action.require_approval (e.g. C-TAINT on high-privilege tools).

import { createPanel, createTable, mono, timeCell, toast } from '../components.js';
import { clear, el } from '../utils.js';
import { grid, viewHeader } from './common.js';

export function createApprovals(ctx) {
  let currentFilter = 'all';

  const summaryPanel = createPanel({
    title: 'HITL Approval Queue',
    desc: 'Pending high-risk requests awaiting human verification (HTTP 403 aicl_approval_required).',
    span: 12,
  });

  const cardsContainer = el('div', { class: 'grid grid-4 mb-2' });
  summaryPanel.content.appendChild(cardsContainer);

  const filterBar = el('div', { class: 'filter-bar mb-2' });
  const filterSelect = el('select', { class: 'select' },
    el('option', { value: 'all', text: 'All statuses' }),
    el('option', { value: 'pending', text: 'Pending only' }),
    el('option', { value: 'approved', text: 'Approved only' }),
    el('option', { value: 'rejected', text: 'Rejected only' })
  );
  filterBar.append(el('span', { class: 'muted mr-1', text: 'Filter: ' }), filterSelect);
  summaryPanel.content.appendChild(filterBar);

  filterSelect.addEventListener('change', () => {
    currentFilter = filterSelect.value;
    ctx.refresh(['approvals']);
  });

  const table = createTable({
    caption: 'HITL Approval Requests',
    pageSize: 15,
    columns: [
      {
        key: 'created_at',
        label: 'Created',
        render: (row) => timeCell(new Date(row.created_at)),
      },
      {
        key: 'approval_id',
        label: 'Approval ID',
        render: (row) => mono(row.approval_id),
      },
      {
        key: 'identity',
        label: 'Caller',
        render: (row) => el('span', { text: row.identity || row.session_id || '—' }),
      },
      {
        key: 'control_id',
        label: 'Control',
        render: (row) => el('span', { class: 'badge', text: row.control_id }),
      },
      {
        key: 'reason',
        label: 'Action / reason',
        // summary = the exact action this approval authorizes (single use, this caller only)
        render: (row) => el('div', {},
          row.summary ? el('div', { class: 'mono small', text: row.summary }) : null,
          el('div', { class: 'muted small', text: row.reason }),
          row.used_at ? el('div', { class: 'muted small', text: `used ${row.used_at}` }) : null),
      },
      {
        key: 'status',
        label: 'Status',
        render: (row) => {
          let badgeClass = 'badge';
          if (row.status === 'pending') badgeClass += ' badge-warn';
          else if (row.status === 'approved') badgeClass += ' badge-yes';
          else if (row.status === 'rejected') badgeClass += ' badge-exceeded';
          return el('span', { class: badgeClass, text: row.status.toUpperCase() });
        },
      },
      {
        key: 'actions',
        label: 'Actions',
        render: (row) => {
          if (row.status !== 'pending') {
            return el('span', { class: 'muted small', text: `By ${row.decided_by || 'admin'}` });
          }
          const approveBtn = el('button', {
            type: 'button',
            class: 'btn btn-sm btn-primary mr-1',
            text: '✓ Approve',
          });
          const rejectBtn = el('button', {
            type: 'button',
            class: 'btn btn-sm btn-danger',
            text: '✕ Reject',
          });

          approveBtn.addEventListener('click', async (ev) => {
            ev.stopPropagation();
            approveBtn.disabled = true;
            try {
              await ctx.api.approveRequest(row.approval_id);
              toast(`Approved request ${row.approval_id}`, 'success');
              ctx.refresh(['approvals']);
            } catch (err) {
              toast(`Approval failed: ${err.message}`, 'error');
              approveBtn.disabled = false;
            }
          });

          rejectBtn.addEventListener('click', async (ev) => {
            ev.stopPropagation();
            rejectBtn.disabled = true;
            try {
              await ctx.api.rejectRequest(row.approval_id);
              toast(`Rejected request ${row.approval_id}`, 'warn');
              ctx.refresh(['approvals']);
            } catch (err) {
              toast(`Rejection failed: ${err.message}`, 'error');
              rejectBtn.disabled = false;
            }
          });

          return el('div', { class: 'row-actions' }, approveBtn, rejectBtn);
        },
      },
    ],
  });

  summaryPanel.content.appendChild(table.root);

  const root = el(
    'section',
    { class: 'view', 'aria-labelledby': 'v-approvals' },
    viewHeader('Human-in-the-Loop', 'Manage and approve high-risk AI agent actions.'),
    grid(summaryPanel)
  );
  root.querySelector('h1').id = 'v-approvals';

  function render(state) {
    const rawItems = state.resources.approvals?.data || [];
    const pendingCount = rawItems.filter((i) => i.status === 'pending').length;
    const approvedCount = rawItems.filter((i) => i.status === 'approved').length;
    const rejectedCount = rawItems.filter((i) => i.status === 'rejected').length;

    // Update nav badge if element exists
    const navBadge = document.getElementById('nav-approvals-count');
    if (navBadge) {
      navBadge.textContent = String(pendingCount);
      navBadge.hidden = pendingCount === 0;
    }

    clear(cardsContainer).append(
      el('div', { class: 'card stat-card' },
        el('div', { class: 'stat-label', text: 'Pending review' }),
        el('div', { class: 'stat-val text-warn', text: String(pendingCount) })
      ),
      el('div', { class: 'card stat-card' },
        el('div', { class: 'stat-label', text: 'Approved' }),
        el('div', { class: 'stat-val text-success', text: String(approvedCount) })
      ),
      el('div', { class: 'card stat-card' },
        el('div', { class: 'stat-label', text: 'Rejected' }),
        el('div', { class: 'stat-val text-muted', text: String(rejectedCount) })
      ),
      el('div', { class: 'card stat-card' },
        el('div', { class: 'stat-label', text: 'Total requests' }),
        el('div', { class: 'stat-val', text: String(rawItems.length) })
      )
    );

    const filtered = currentFilter === 'all'
      ? rawItems
      : rawItems.filter((i) => i.status === currentFilter);

    table.setRows(filtered);
  }

  return {
    id: 'approvals',
    title: 'Approvals',
    resources: ['approvals'],
    root,
    render,
  };
}
