"""Policy preview & replay engine (ARCHITECTURE.md §1, §5.1, §6.8).

Replays recorded request events against a candidate compiled policy to show
what outcomes would change (e.g. allow -> block or block -> require_approval)
BEFORE the policy is activated on production.
"""

from __future__ import annotations

import logging
from typing import Any

from aicl.audit import iter_events
from aicl.models import Action, AuditEvent, strongest_action
from aicl.policy.schema import CompiledPolicy
from aicl.runtime import Runtime

log = logging.getLogger(__name__)


def get_replay_events(rt: Runtime, limit: int = 50) -> list[AuditEvent]:
    """Retrieve up to limit recent request audit events for replay."""
    # 1. Start from in-memory recent events
    events = [e for e in rt.audit.recent_events() if e.type == "request"]
    if len(events) >= limit:
        return events[-limit:]

    # 2. Backfill from audit log on disk if needed
    disk_events: list[AuditEvent] = []
    try:
        for e in iter_events(rt.audit.path):
            if e.type == "request":
                disk_events.append(e)
    except Exception:
        log.exception("failed reading audit log for replay")

    combined = {e.request_id: e for e in (disk_events + events) if e.request_id}
    sorted_events = sorted(combined.values(), key=lambda x: x.ts)
    return sorted_events[-limit:]


def preview_policy_change(
    rt: Runtime,
    candidate: CompiledPolicy,
    limit: int = 50,
) -> dict[str, Any]:
    """Replay recent requests against candidate policy and return diff of outcomes."""
    requests = get_replay_events(rt, limit=limit)
    diffs: list[dict[str, Any]] = []

    orig_counts: dict[str, int] = {}
    cand_counts: dict[str, int] = {}

    for req in requests:
        orig_action = req.final_action or Action.allow
        orig_counts[orig_action.value] = orig_counts.get(orig_action.value, 0) + 1

        # Evaluate candidate policy on the request
        cand_action, reasons = _evaluate_candidate(req, candidate)
        cand_counts[cand_action.value] = cand_counts.get(cand_action.value, 0) + 1

        if orig_action != cand_action:
            diffs.append(
                {
                    "request_id": req.request_id,
                    "endpoint": req.endpoint,
                    "identity": req.identity,
                    "role": req.role,
                    "original_action": orig_action.value,
                    "candidate_action": cand_action.value,
                    "reasons": reasons,
                }
            )

    return {
        "total_replayed": len(requests),
        "changed_count": len(diffs),
        "candidate_version": candidate.version,
        "active_version": rt.policy.version,
        "summary": {
            "by_original_action": orig_counts,
            "by_candidate_action": cand_counts,
        },
        "diff": diffs,
    }


def _evaluate_candidate(
    req: AuditEvent, candidate: CompiledPolicy
) -> tuple[Action, list[str]]:
    candidate_actions: list[Action] = []
    reasons: list[str] = []

    # 1. Identity & Profile resolution
    ident = candidate.identities.get(req.identity) if req.identity else None
    if req.identity and ident is None:
        candidate_actions.append(Action.block)
        reasons.append(f"identity '{req.identity}' is not defined in candidate policy")
        profile = candidate.raw.active_profile
    else:
        profile = candidate.profile_for(ident) if ident else candidate.raw.active_profile

    # 2. Model allowlist
    if req.model:
        if req.model not in candidate.models:
            candidate_actions.append(Action.block)
            reasons.append(f"model '{req.model}' is not in candidate model allowlist")

    # 3. Re-evaluate controls from original decisions
    for d in req.decisions:
        cfg = candidate.level_config(d.control_id, profile)
        if cfg is None:
            reasons.append(f"control {d.control_id} is disabled in candidate policy")
            continue

        if cfg.mode == "shadow":
            if d.action in (Action.block, Action.require_approval, Action.redact):
                reasons.append(
                    f"{d.control_id} switched to shadow mode in candidate policy (action {d.action.value} suppressed)"
                )
            continue

        # In enforce mode:
        configured_action = cfg.action
        if d.shadow_suppressed:
            candidate_actions.append(configured_action)
            reasons.append(
                f"{d.control_id} was shadow-suppressed previously, now enforced as {configured_action.value}"
            )
        elif d.action in (Action.block, Action.require_approval, Action.redact):
            candidate_actions.append(configured_action)
            if configured_action != d.action:
                reasons.append(
                    f"{d.control_id} action changed from {d.action.value} to {configured_action.value}"
                )

    # 4. Check taint spec if tool call was in tainted session
    if req.endpoint == "tool_invoke" and any(d.control_id == "C-TAINT" for d in req.decisions):
        taint_spec = candidate.raw.taint
        if taint_spec and taint_spec.enabled:
            taint_action = Action(taint_spec.action)
            candidate_actions.append(taint_action)

    final = strongest_action(candidate_actions) if candidate_actions else Action.allow
    return final, list(dict.fromkeys(reasons))
