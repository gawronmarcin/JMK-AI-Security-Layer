"""Settings for the semantic judge (R3), parsed from the policy `semantic:` block (ARCHITECTURE.md 6.5).

R1's policy loader should call `SemanticSettings.from_policy(policy.semantic)` on every atomic policy swap and
pass the result to `aicl.controls.injection_semantic.configure(...)`. That wiring is a PROPOSAL, not yet agreed
with R1 (the contract only defines `evaluate(ctx, cfg)`, which has no access to top-level policy keys).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping

DEFAULT_OLLAMA_URL = "http://localhost:11434"


@dataclass(frozen=True)
class SemanticSettings:
    base_url: str = DEFAULT_OLLAMA_URL
    model: str = ""
    timeout_ms: int = 1500
    untrusted_segments: bool = True          # always judge untrusted segments
    risk_between: tuple[float, float] = (0.15, 0.85)  # grey zone of deterministic ctx.risk
    sample_rate: float = 0.0                 # share of remaining requests judged anyway
    max_input_chars: int = 4000
    max_segments: int = 3                    # cap judge calls per request (latency guard)

    @property
    def model_ready(self) -> bool:
        """False while the policy still holds the `<TBD-small-model>` placeholder (open decision #1)."""
        return bool(self.model) and not self.model.startswith("<")

    @classmethod
    def from_policy(cls, sem: Mapping[str, Any] | None, env: Mapping[str, str] | None = None) -> "SemanticSettings":
        env = os.environ if env is None else env
        sem = sem or {}
        run_when = sem.get("run_when") or {}
        base_url = env.get(sem.get("base_url_env") or "") or DEFAULT_OLLAMA_URL
        lo, hi = run_when.get("risk_between", (0.15, 0.85))
        return cls(
            base_url=base_url.rstrip("/"),
            model=str(sem.get("model") or ""),
            timeout_ms=int(sem.get("timeout_ms", 1500)),
            untrusted_segments=bool(run_when.get("untrusted_segments", True)),
            risk_between=(float(lo), float(hi)),
            sample_rate=min(1.0, max(0.0, float(run_when.get("sample_rate", 0.0)))),
            max_input_chars=int(sem.get("max_input_chars", 4000)),
            max_segments=int(sem.get("max_segments", 3)),
        )
