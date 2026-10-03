"""Pipeline engine: runs the controls of one stage and merges their decisions (§4.2).

    run_stage(policy, ctx, stage) -> StageResult

1. Pick controls registered for the stage and enabled in the policy, order by priority.
2. Run each with the active profile's config; keep a running max of `risk` so later
   controls (the semantic judge) can see it. Exceptions follow the control's `on_error`.
3. Shadow mode: a non-allow decision is recorded as `shadow_suppressed` and counts as allow.
4. `first_block` stops at the first block / require_approval; `collect_all` runs everything.
5. Final action = highest precedence. Redaction is applied here, using match spans;
   a redact that cannot be applied by span (match found only in decoded text) becomes block.

The engine knows nothing about HTTP; flows call it once per stage.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass, field

from aicl import registry
from aicl.models import (
    ACTION_PRECEDENCE,
    Action,
    AuditDecision,
    Control,
    Decision,
    Match,
    RequestContext,
    Segment,
    Stage,
    strongest_action,
)
from aicl.normalize import build_segment
from aicl.policy.schema import CompiledPolicy, ControlLevelConfig

log = logging.getLogger(__name__)

_STOPPING = (Action.block, Action.require_approval)


@dataclass
class StageResult:
    stage: Stage
    action: Action  # final, after shadow suppression and escalation
    decisions: list[Decision]
    segments: list[Segment]  # redacted when action == redact, else unchanged
    risk: float  # max of ctx.risk and every decision's risk
    taints_session: bool
    would_have_action: Action | None = None  # stronger action suppressed by shadow mode
    blocking: Decision | None = None  # decision behind a block / require_approval
    errors: list[str] = field(default_factory=list)  # "C-X: ExceptionType"

    @property
    def stopped(self) -> bool:
        return self.action in _STOPPING

    def audit_decisions(self) -> list[AuditDecision]:
        return [AuditDecision.from_decision(d) for d in self.decisions]

    def latency_per_control(self) -> dict[str, float]:
        return {d.control_id: d.latency_ms for d in self.decisions}


def controls_for_stage(
    policy: CompiledPolicy, stage: Stage, controls: Mapping[str, Control] | None = None
) -> list[tuple[Control, str]]:
    """(control, control_id) pairs that run at `stage`, in execution order.

    A control runs only if it is both registered and enabled in the policy. The policy's
    `stages` list overrides the control's default stages.
    """
    controls = registry.all_controls() if controls is None else controls
    selected = []
    for cid, control in controls.items():
        spec = policy.control_spec(cid)
        if spec is None or not spec.enabled:
            continue
        stages = spec.stages if spec.stages is not None else control.stages
        if stage in stages:
            selected.append((control, cid))
    selected.sort(key=lambda pair: (pair[0].priority, pair[1]))
    return selected


def missing_controls(policy: CompiledPolicy, controls: Mapping[str, Control] | None = None) -> list[str]:
    """Control ids enabled in the policy without an implementation (reported, not fatal)."""
    controls = registry.all_controls() if controls is None else controls
    return sorted(cid for cid, spec in policy.controls.items() if spec.enabled and cid not in controls)


async def run_stage(
    policy: CompiledPolicy,
    ctx: RequestContext,
    stage: Stage,
    controls: Mapping[str, Control] | None = None,
) -> StageResult:
    if ctx.stage != stage:
        ctx = ctx.model_copy(update={"stage": stage})
    risk = ctx.risk
    decisions: list[Decision] = []
    errors: list[str] = []
    collect_all = policy.raw.evaluation == "collect_all"

    for control, cid in controls_for_stage(policy, stage, controls):
        cfg = policy.level_config(cid, ctx.profile)
        if cfg is None:  # enabled check above makes this unreachable; keep it defensive
            continue
        if ctx.risk != risk:
            ctx = ctx.model_copy(update={"risk": risk})

        decision = await _evaluate(control, cid, ctx, cfg, errors)

        if decision.risk is not None:
            risk = max(risk, decision.risk)
        if cfg.mode == "shadow" and decision.action != Action.allow and not decision.skipped:
            decision = decision.model_copy(update={"shadow_suppressed": True})
        decisions.append(decision)

        effective = not decision.shadow_suppressed and not decision.skipped
        if effective and decision.action in _STOPPING and not collect_all:
            break

    return _merge(stage, ctx, decisions, risk, errors)


async def _evaluate(
    control: Control, cid: str, ctx: RequestContext, cfg: ControlLevelConfig, errors: list[str]
) -> Decision:
    start = time.perf_counter()
    try:
        decision = await control.evaluate(ctx, cfg)
        if not isinstance(decision, Decision):
            raise TypeError(f"evaluate() returned {type(decision).__name__}, expected Decision")
        if decision.control_id != cid:
            decision = decision.model_copy(update={"control_id": cid})
    except Exception as exc:  # noqa: BLE001 - a control failure must never crash the request
        # Only the exception type is recorded: messages may contain request content.
        errors.append(f"{cid}: {type(exc).__name__}")
        log.warning("control %s failed with %s (on_error=%s)", cid, type(exc).__name__, cfg.on_error)
        decision = _error_decision(cid, cfg, type(exc).__name__)
    latency = (time.perf_counter() - start) * 1000
    return decision.model_copy(update={"latency_ms": round(latency, 3)})


def _error_decision(cid: str, cfg: ControlLevelConfig, exc_name: str) -> Decision:
    if cfg.on_error == "fail_open":
        return Decision(
            control_id=cid,
            threat_ids=cfg.threat_ids,
            action=Action.allow,
            skipped=True,
            reason=f"control error ({exc_name}), failing open",
        )
    return Decision(
        control_id=cid,
        threat_ids=cfg.threat_ids,
        action=Action.block,
        severity="high",
        reason=f"control error ({exc_name}), failing closed",
    )


def _merge(
    stage: Stage, ctx: RequestContext, decisions: list[Decision], risk: float, errors: list[str]
) -> StageResult:
    effective = [d for d in decisions if not d.shadow_suppressed and not d.skipped]
    final = strongest_action([d.action for d in effective])
    would_have = strongest_action([d.action for d in decisions if not d.skipped])
    segments = ctx.segments
    blocking: Decision | None = None

    if final == Action.redact:
        redactors = [d for d in effective if d.action == Action.redact]
        unredactable = next(
            (d for d in redactors if not d.matches or any(not _has_span(m, ctx.segments) for m in d.matches)),
            None,
        )
        if unredactable is not None:
            # Nothing to cut out by offset (no span, or found only in decoded text): fail closed.
            # An encoded secret/PII is itself a red flag.
            final = Action.block
            blocking = unredactable
        else:
            segments = redact_segments(ctx.segments, [m for d in redactors for m in d.matches])

    if final in _STOPPING and blocking is None:
        blocking = next(d for d in effective if d.action == final)

    return StageResult(
        stage=stage,
        action=final,
        decisions=decisions,
        segments=segments,
        risk=risk,
        taints_session=any(d.taints_session for d in effective),
        would_have_action=would_have if ACTION_PRECEDENCE[would_have] > ACTION_PRECEDENCE[final] else None,
        blocking=blocking,
        errors=errors,
    )


def _has_span(m: Match, segments: list[Segment]) -> bool:
    if m.in_decoded or m.segment_idx is None or m.start is None or m.end is None:
        return False
    seg = next((s for s in segments if s.idx == m.segment_idx), None)
    return seg is not None and 0 <= m.start < m.end <= len(seg.text)


def redact_segments(segments: list[Segment], matches: list[Match]) -> list[Segment]:
    """Replace every match span with [REDACTED:<kind>]; overlapping spans are merged."""
    spans: dict[int, list[tuple[int, int, str]]] = {}
    for m in matches:
        assert m.segment_idx is not None and m.start is not None and m.end is not None
        spans.setdefault(m.segment_idx, []).append((m.start, m.end, m.kind))

    out = []
    for seg in segments:
        if seg.idx not in spans:
            out.append(seg)
            continue
        merged: list[list] = []
        for start, end, kind in sorted(spans[seg.idx]):
            if merged and start < merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end, kind])
        parts, pos = [], 0
        for start, end, kind in merged:
            parts += [seg.text[pos:start], f"[REDACTED:{kind}]"]
            pos = end
        parts.append(seg.text[pos:])
        out.append(build_segment(seg.idx, "".join(parts), seg.origin, seg.trust, seg.meta))
    return out
