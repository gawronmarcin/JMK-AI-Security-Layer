"""C-BUDGET: Budget guard at ingress (R3, P0). Threats TH-11 (token), TH-12 (cost/compute).

Contract notes (ARCHITECTURE.md §5.5, §6.5, §7):
- Stage: ingress
- Priority: 10 (deterministic, evaluated before model calls)
- Checks current usage counters against limits configured for the role's budget:
    * max_requests_per_minute (minute window)
    * max_tokens (budget.window)
    * max_cost_usd (budget.window)
    * max_compute_seconds (budget.window)
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from aicl.models import Action, Decision, RequestContext, Stage
from aicl.registry import register_control
from aicl.state import StateStore, get_store

log = logging.getLogger(__name__)


def _cfg_val(cfg: Any, key: str, default: Any = None) -> Any:
    if isinstance(cfg, Mapping):
        return cfg.get(key, default)
    return getattr(cfg, key, default) if hasattr(cfg, key) else default


@register_control
class BudgetGuard:
    id = "C-BUDGET"
    stages = (Stage.ingress,)
    priority = 10

    def __init__(self, store: StateStore | None = None) -> None:
        self._store = store

    def _get_store(self) -> StateStore:
        return self._store if self._store is not None else get_store()

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        threat_ids = list(_cfg_val(cfg, "threat_ids", ["TH-11", "TH-12"]))
        action = Action(_cfg_val(cfg, "action", "block"))

        if not ctx.identity:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=Action.allow,
                reason="no identity to check budget for",
            )

        policy = getattr(cfg, "policy", None)
        if policy is None:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=Action.allow,
                reason="policy not attached",
            )

        budget = policy.budget_for(ctx.role)
        if budget is None:
            # Unlimited budget
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=Action.allow,
                reason=f"role {ctx.role!r} has no budget limits (unlimited)",
            )

        store = self._get_store()
        usage = await store.get_usage(ctx.identity, budget.window)

        # 1. Rate limit (RPM)
        if budget.max_requests_per_minute is not None:
            rpm_usage = await store.get_usage(ctx.identity, "minute")
            if rpm_usage.requests >= budget.max_requests_per_minute:
                return Decision(
                    control_id=self.id,
                    threat_ids=["TH-12"],
                    action=action,
                    severity="high",
                    reason=(
                        f"Rate limit exceeded for identity {ctx.identity!r}: "
                        f"{rpm_usage.requests} >= {budget.max_requests_per_minute} req/min"
                    ),
                )

        # 2. Token limit
        if budget.max_tokens is not None and usage.tokens >= budget.max_tokens:
            return Decision(
                control_id=self.id,
                threat_ids=["TH-11"],
                action=action,
                severity="high",
                reason=(
                    f"Token budget exceeded for identity {ctx.identity!r}: "
                    f"{usage.tokens} >= {budget.max_tokens} tokens ({budget.window})"
                ),
            )

        # 3. Cost limit
        if budget.max_cost_usd is not None and usage.cost_usd >= budget.max_cost_usd:
            return Decision(
                control_id=self.id,
                threat_ids=["TH-12"],
                action=action,
                severity="high",
                reason=(
                    f"Cost budget exceeded for identity {ctx.identity!r}: "
                    f"${usage.cost_usd:.4f} >= ${budget.max_cost_usd:.4f} ({budget.window})"
                ),
            )

        # 4. Compute seconds limit (wall-clock inference time on local models)
        if (
            budget.max_compute_seconds is not None
            and usage.compute_seconds >= budget.max_compute_seconds
        ):
            return Decision(
                control_id=self.id,
                threat_ids=["TH-12"],
                action=action,
                severity="high",
                reason=(
                    f"Compute time limit exceeded for identity {ctx.identity!r}: "
                    f"{usage.compute_seconds:.1f}s >= {budget.max_compute_seconds:.1f}s ({budget.window})"
                ),
            )

        return Decision(
            control_id=self.id,
            threat_ids=threat_ids,
            action=Action.allow,
            reason="usage is within budget limits",
        )
