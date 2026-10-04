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
from aicl.state.base import BudgetLimits

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

        # 1. Estimate prompt tokens from available segments at ingress stage
        prompt_tokens = sum(len(s.text) // 4 for s in ctx.segments)

        # 2. Estimate completion tokens
        req_max_tokens = None
        for seg in ctx.segments:
            if isinstance(seg.meta, dict):
                req_max_tokens = seg.meta.get("max_tokens") or seg.meta.get("max_completion_tokens")
                if req_max_tokens is not None:
                    break
        if req_max_tokens is None and isinstance(ctx.tool_args, dict):
            req_max_tokens = ctx.tool_args.get("max_tokens") or ctx.tool_args.get("max_completion_tokens")

        default_reserve = getattr(budget, "default_completion_reserve", 512) or 512
        usage = await store.get_usage(ctx.identity, budget.window)
        if req_max_tokens is not None:
            completion_tokens = int(req_max_tokens)
        else:
            remaining_tokens = (
                max(0, budget.max_tokens - usage.tokens - prompt_tokens)
                if budget.max_tokens is not None
                else default_reserve
            )
            completion_tokens = min(default_reserve, remaining_tokens)

        estimated_tokens = prompt_tokens + completion_tokens

        # 3. Estimate cost from model pricing
        model = policy.models.get(ctx.model) if ctx.model else None
        if model and model.price_per_1k_tokens:
            prices = model.price_per_1k_tokens
            prompt_cost = (prompt_tokens / 1000) * prices.input
            comp_cost = (completion_tokens / 1000) * prices.output
            if budget.max_cost_usd is not None and req_max_tokens is None:
                remaining_cost = max(0.0, budget.max_cost_usd - usage.cost_usd - prompt_cost)
                comp_cost = min(comp_cost, remaining_cost)
            estimated_cost = round(prompt_cost + comp_cost, 8)
        else:
            estimated_cost = 0.0

        # 4. Check and reserve atomically
        limits = BudgetLimits(
            max_requests_per_minute=budget.max_requests_per_minute,
            max_tokens=budget.max_tokens,
            max_cost_usd=budget.max_cost_usd,
            max_compute_seconds=budget.max_compute_seconds,
        )

        res = await store.check_and_reserve(
            ctx.identity,
            budget.window,
            ctx.request_id,
            tokens=estimated_tokens,
            cost_usd=estimated_cost,
            limits=limits,
        )

        if not res.allowed:
            if res.exceeded_limit == "rpm":
                return Decision(
                    control_id=self.id,
                    threat_ids=["TH-12"],
                    action=action,
                    severity="high",
                    reason=(
                        f"Rate limit exceeded for identity {ctx.identity!r}: "
                        f"{int(res.current_value)} >= {int(res.limit_value)} req/min"
                    ),
                    retry_after_s=res.retry_after_s,
                )
            if res.exceeded_limit == "tokens":
                return Decision(
                    control_id=self.id,
                    threat_ids=["TH-11"],
                    action=action,
                    severity="high",
                    reason=(
                        f"Token budget exceeded for identity {ctx.identity!r}: "
                        f"{int(res.current_value)} >= {int(res.limit_value)} tokens ({budget.window})"
                    ),
                    retry_after_s=res.retry_after_s,
                )
            if res.exceeded_limit == "cost":
                return Decision(
                    control_id=self.id,
                    threat_ids=["TH-12"],
                    action=action,
                    severity="high",
                    reason=(
                        f"Cost budget exceeded for identity {ctx.identity!r}: "
                        f"${res.current_value:.4f} >= ${res.limit_value:.4f} ({budget.window})"
                    ),
                    retry_after_s=res.retry_after_s,
                )
            if res.exceeded_limit == "compute":
                return Decision(
                    control_id=self.id,
                    threat_ids=["TH-12"],
                    action=action,
                    severity="high",
                    reason=(
                        f"Compute time limit exceeded for identity {ctx.identity!r}: "
                        f"{res.current_value:.1f}s >= {res.limit_value:.1f}s ({budget.window})"
                    ),
                    retry_after_s=res.retry_after_s,
                )
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=action,
                severity="high",
                reason=f"Budget exceeded for identity {ctx.identity!r}",
                retry_after_s=res.retry_after_s,
            )

        return Decision(
            control_id=self.id,
            threat_ids=threat_ids,
            action=Action.allow,
            reason="usage is within budget limits",
        )
