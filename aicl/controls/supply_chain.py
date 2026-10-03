"""C-SUPPLY: Model and package supply chain integrity control (R2, P1 stretch). Threat TH-16.

Contract notes (ARCHITECTURE.md §4.1, §6.8, §7):
- Stages: ingress, artifact, tool_call
- Priority: 45 (deterministic check)
- Purpose: Prevent downloading or using poisoned model repos or malicious packages.
- Checks artifact SHA256, model repos, and package references against feeds and blocklists.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from aicl import feeds
from aicl.models import Action, Decision, Match, RequestContext, Stage
from aicl.registry import register_control

_BANNED_PACKAGES = frozenset({
    "torch-triton-nightly",
    "colourama",
    "python-dateutil-fake",
    "jeIlyfish",
    "reqeusts",
})

_BANNED_MODEL_REPOS = frozenset({
    "evil-org/backdoored-llm",
    "attacker/poisoned-weights",
})


def _cfg_val(cfg: Any, key: str, default: Any = None) -> Any:
    if hasattr(cfg, "get"):
        return cfg.get(key, default)
    return getattr(cfg, key, default) if hasattr(cfg, key) else default


@register_control
class SupplyChainControl:
    id: str = "C-SUPPLY"
    stages: tuple[Stage, ...] = (Stage.ingress, Stage.artifact, Stage.tool_call)
    priority: int = 45

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        target_action = Action(_cfg_val(cfg, "action", Action.block))
        threat_ids = list(_cfg_val(cfg, "threat_ids", ["TH-16"]))

        snap = feeds.current()
        sc_sigs = snap.for_set("supply_chain")

        matches: list[Match] = []

        # 1. Check SHA256 of artifact bytes if in artifact stage
        if ctx.artifact:
            art_sha = hashlib.sha256(ctx.artifact).hexdigest().lower()
            for sig in sc_sigs:
                if sig.kind == "sha256" and sig.pattern.lower() == art_sha:
                    matches.append(Match(kind="malicious_sha256", masked=f"[{sig.id}]"))

        # 2. Check model repo names in ctx.model or segments
        if ctx.model:
            for repo in _BANNED_MODEL_REPOS:
                if repo.lower() in ctx.model.lower():
                    matches.append(Match(kind="banned_model_repo", masked=f"[{repo}]"))

        # 3. Check tool args and segments for banned packages / repos
        texts_to_check: list[str] = []
        for seg in ctx.segments:
            texts_to_check.append(seg.text)
            texts_to_check.extend(seg.decoded)
        if ctx.tool_args:
            texts_to_check.append(json.dumps(ctx.tool_args, default=str))

        for text in texts_to_check:
            for pkg in _BANNED_PACKAGES:
                if re.search(rf"\b{re.escape(pkg)}\b", text, re.IGNORECASE):
                    matches.append(Match(kind="malicious_package", masked=f"[{pkg}]"))
            for sig in sc_sigs:
                if sig.kind in ("package", "model_repo") and sig.pattern.lower() in text.lower():
                    matches.append(Match(kind=f"supply_chain_{sig.kind}", masked=f"[{sig.id}]"))

        if matches:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=target_action,
                severity="critical",
                reason=f"supply chain compromise detected ({matches[0].kind})",
                matches=matches,
            )

        return Decision(
            control_id=self.id,
            threat_ids=threat_ids,
            action=Action.allow,
            severity="low",
            reason="supply chain integrity verified",
        )
