"""Policy schema (ARCHITECTURE.md §6) and its compiled, read-only runtime form.

Two layers:
  PolicyFile      - 1:1 with the YAML file. extra="forbid" everywhere except control
                    params and per-level settings, which are control-specific.
  CompiledPolicy  - built once per load: lookups (api key -> identity, control id ->
                    per-profile config) are precomputed so the hot path does no YAML work.

CONTRACT: top-level keys and the control envelope (§6.1-6.3).
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

from aicl.models import Action, Profile, Stage, Trust

PROFILES: tuple[Profile, ...] = ("strict", "balanced", "permissive")

Mode = Literal["enforce", "shadow"]
OnError = Literal["fail_closed", "fail_open"]
Privilege = Literal["low", "medium", "high", "critical"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- Sections ---------------------------------------------------------------------------------


class Meta(_Strict):
    name: str = "policy"
    description: str = ""


class IdentitySpec(_Strict):
    id: str
    api_key_env: str  # the key itself lives in the environment, never in the file
    role: str
    profile: Profile | None = None


class RoleSpec(_Strict):
    models: list[str] = Field(default_factory=list)  # "*" = any
    tools: list[str] = Field(default_factory=list)
    memory_namespaces: list[str] = Field(default_factory=list)
    budget: str | None = None
    may_delegate_to: list[str] = Field(default_factory=list)


class Prices(_Strict):
    input: float = 0.0
    output: float = 0.0


class ModelSpec(_Strict):
    name: str
    provider: Literal["openai_compatible", "ollama"]
    base_url_env: str
    upstream_model: str | None = None  # name sent upstream; defaults to `name`
    local: bool = False
    price_per_1k_tokens: Prices = Field(default_factory=Prices)


class ToolSpec(_Strict):
    # A tool is served either by an HTTP backend (`backend_url_env`, POST {tool, arguments}) or by
    # an MCP server (`mcp_server`, tools/call); MCP tools are named "<server>.<tool name>".
    backend_url_env: str | None = None
    mcp_server: str | None = None
    privilege: Privilege = "low"
    output_trust: Trust = "untrusted"
    arg_schema: dict[str, Any] | None = None
    # Arguments that ARE the action (e.g. send_email `to`): still scanned (blocks, flags and the
    # audit apply) but never redacted, or the call would go to "[REDACTED:email]".
    no_redact_args: list[str] = Field(default_factory=list)


class McpServerSpec(_Strict):
    """An upstream MCP server (Streamable HTTP) proxied at /mcp/<name>."""

    url_env: str  # env var with the server's MCP endpoint URL, e.g. http://localhost:9003/mcp
    bearer_token_env: str | None = None  # env var with a token the gateway sends upstream
    timeout_s: float = Field(default=30.0, gt=0)


class BudgetSpec(_Strict):
    """Every limit is optional; null/omitted = no limit."""

    window: Literal["minute", "hour", "day"] = "day"
    max_tokens: int | None = None
    max_cost_usd: float | None = None
    max_compute_seconds: float | None = None
    max_requests_per_minute: int | None = None
    max_tool_calls_per_session: int | None = None
    max_identical_tool_calls: int | None = None
    loop_window_seconds: int = 60
    max_delegation_depth: int | None = None
    on_exceed: Literal["block"] = "block"
    default_completion_reserve: int = 512


class LevelSpec(BaseModel):
    """`{action: block, threshold: 0.7, ...}` - action plus control-specific settings."""

    model_config = ConfigDict(extra="allow")

    action: Action


class ControlSpec(_Strict):
    """The control envelope (§6.3), same shape for every control."""

    id: str
    threat_ids: list[str] = Field(default_factory=list)
    enabled: bool = True
    mode: Mode | None = None  # overrides the global mode
    on_error: OnError | None = None  # overrides on_error_default
    stages: list[Stage] | None = None  # None = the control's own default stages
    params: dict[str, Any] = Field(default_factory=dict)
    levels: dict[Profile, LevelSpec]

    @model_validator(mode="after")
    def _all_levels(self) -> ControlSpec:
        missing = [p for p in PROFILES if p not in self.levels]
        if missing:
            raise ValueError(f"levels must define every profile, missing: {', '.join(missing)}")
        return self


class RunWhen(_Strict):
    untrusted_segments: bool = True
    risk_between: tuple[float, float] = (0.15, 0.85)
    sample_rate: float = Field(default=0.0, ge=0.0, le=1.0)


class SemanticSpec(_Strict):
    provider: Literal["ollama"] = "ollama"
    base_url_env: str = "AICL_OLLAMA_URL"
    model: str
    timeout_ms: int = 1500
    run_when: RunWhen = Field(default_factory=RunWhen)
    max_input_chars: int = 4000


class TaintSpec(_Strict):
    enabled: bool = True
    blocked_privileges_when_tainted: list[Privilege] = Field(
        default_factory=lambda: list[Privilege](["high", "critical"])
    )
    action: Literal["block", "require_approval"] = "block"
    session_ttl_seconds: int = 3600


class NamespaceSpec(_Strict):
    sensitivity: Literal["public", "internal", "restricted"] = "internal"


class MemorySpec(_Strict):
    namespaces: dict[str, NamespaceSpec] = Field(default_factory=dict)


class FeedRef(_Strict):
    name: str
    path: str | None = None
    url: str | None = None
    refresh_seconds: int = 30
    on_unavailable: Literal["keep_last_good", "empty"] = "keep_last_good"
    signing_key_env: str | None = None

    @model_validator(mode="after")
    def _one_source(self) -> FeedRef:
        if (self.path is None) == (self.url is None):
            raise ValueError("exactly one of `path` or `url` is required")
        return self


class AuditSpec(_Strict):
    path: str = "./data/audit.jsonl"
    content: Literal["masked", "none"] = "masked"
    max_event_bytes: int = 65536
    max_file_bytes: int = 50 * 1024 * 1024
    keep_files: int = 5


# --- Whole file -------------------------------------------------------------------------------


class PolicyFile(_Strict):
    version: Literal[1]
    meta: Meta = Field(default_factory=Meta)
    active_profile: Profile = "balanced"
    mode: Mode = "enforce"
    evaluation: Literal["first_block", "collect_all"] = "first_block"
    on_error_default: OnError = "fail_closed"
    identities: list[IdentitySpec] = Field(default_factory=list)
    roles: dict[str, RoleSpec] = Field(default_factory=dict)
    models: list[ModelSpec] = Field(default_factory=list)
    tools: dict[str, ToolSpec] = Field(default_factory=dict)
    mcp_servers: dict[str, McpServerSpec] = Field(default_factory=dict)
    budgets: dict[str, BudgetSpec] = Field(default_factory=dict)
    controls: dict[str, ControlSpec] = Field(default_factory=dict)
    semantic: SemanticSpec | None = None
    taint: TaintSpec | None = None
    memory: MemorySpec | None = None
    signature_feeds: list[FeedRef] = Field(default_factory=list)
    audit: AuditSpec = Field(default_factory=AuditSpec)

    @model_validator(mode="after")
    def _cross_references(self) -> PolicyFile:
        errors: list[str] = []
        model_names = [m.name for m in self.models]
        errors += _dupes("models", model_names)
        errors += _dupes("identities", [i.id for i in self.identities])
        errors += _dupes("controls (id)", [c.id for c in self.controls.values()])

        for name, t in self.tools.items():
            if (t.backend_url_env is None) == (t.mcp_server is None):
                errors.append(f"tools.{name}: set exactly one of backend_url_env / mcp_server")
            elif t.mcp_server is not None:
                if t.mcp_server not in self.mcp_servers:
                    errors.append(f"tools.{name}.mcp_server: unknown MCP server {t.mcp_server!r}")
                elif not name.startswith(f"{t.mcp_server}."):
                    errors.append(f"tools.{name}: an MCP tool is named '{t.mcp_server}.<tool name>'")

        for i in self.identities:
            if i.role not in self.roles:
                errors.append(f"identities.{i.id}.role: unknown role {i.role!r}")
        for name, r in self.roles.items():
            if r.budget is not None and r.budget not in self.budgets:
                errors.append(f"roles.{name}.budget: unknown budget {r.budget!r}")
            errors += [
                f"roles.{name}.models: unknown model {m!r}"
                for m in r.models
                if m != "*" and m not in model_names
            ]
            errors += [
                f"roles.{name}.tools: unknown tool {t!r}" for t in r.tools if t != "*" and t not in self.tools
            ]
            errors += [
                f"roles.{name}.may_delegate_to: unknown role {d!r}"
                for d in r.may_delegate_to
                if d not in self.roles
            ]
            if self.memory is not None:
                errors += [
                    f"roles.{name}.memory_namespaces: unknown namespace {n!r}"
                    for n in r.memory_namespaces
                    if n != "*" and n not in self.memory.namespaces
                ]
        if errors:
            raise ValueError("; ".join(errors))
        return self


def _dupes(what: str, items: list[str]) -> list[str]:
    seen: set[str] = set()
    dupes = sorted({x for x in items if x in seen or seen.add(x)})  # type: ignore[func-returns-value]
    return [f"{what}: duplicate {d!r}" for d in dupes]


# --- Compiled runtime form --------------------------------------------------------------------

_RESERVED_CFG_KEYS = frozenset({"control_key", "control_id", "threat_ids", "action", "mode", "on_error"})


class ControlLevelConfig(BaseModel):
    """What a control receives as `cfg` (§4.1): the active profile's settings for it.

    Control-specific settings (`params` merged with the level, level wins) are extra
    attributes: `cfg.threshold`, or `cfg.get("threshold", 0.7)` when optional.
    `cfg.get` also returns the envelope fields (`cfg.get("action")`).
    `cfg.policy` gives read access to the whole compiled policy (roles, tools, budgets).

    Frozen: the compiled policy is shared by all requests, so nothing may change it at runtime.
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    control_key: str
    control_id: str
    threat_ids: list[str]
    action: Action
    mode: Mode
    on_error: OnError

    _policy: CompiledPolicy | None = PrivateAttr(default=None)

    def get(self, name: str, default: Any = None) -> Any:
        if name in type(self).model_fields:
            return getattr(self, name)
        return (self.model_extra or {}).get(name, default)

    @property
    def policy(self) -> CompiledPolicy:
        if self._policy is None:
            # AttributeError (not assert) so `getattr(cfg, "policy", None)` works in controls.
            raise AttributeError("ControlLevelConfig is not attached to a CompiledPolicy")
        return self._policy


@dataclass(frozen=True)
class CompiledPolicy:
    raw: PolicyFile
    version: str  # sha256[:12] of the source file
    identities: dict[str, IdentitySpec]  # by id
    identities_by_key: dict[str, IdentitySpec]  # by API key (resolved from env)
    models: dict[str, ModelSpec]  # by name
    controls: dict[str, ControlSpec]  # by control id (e.g. "C-INJ-PAT")
    _levels: dict[tuple[str, Profile], ControlLevelConfig] = field(repr=False)
    warnings: tuple[str, ...] = ()

    def identity_for_key(self, api_key: str) -> IdentitySpec | None:
        return self.identities_by_key.get(api_key)

    def profile_for(self, identity: IdentitySpec | None) -> Profile:
        if identity is not None and identity.profile is not None:
            return identity.profile
        return self.raw.active_profile

    def role(self, name: str | None) -> RoleSpec | None:
        return self.raw.roles.get(name) if name else None

    def budget_for(self, role: str | None) -> BudgetSpec | None:
        r = self.role(role)
        return self.raw.budgets.get(r.budget) if r and r.budget else None

    def role_allows_model(self, role: str | None, model: str) -> bool:
        """`models` in the policy is the allowlist: "*" means any model defined there,
        never an undeclared one (TH-06)."""
        r = self.role(role)
        return r is not None and model in self.models and ("*" in r.models or model in r.models)

    def role_allows_tool(self, role: str | None, tool: str) -> bool:
        r = self.role(role)
        return r is not None and ("*" in r.tools or tool in r.tools)

    def control_spec(self, control_id: str) -> ControlSpec | None:
        return self.controls.get(control_id)

    def level_config(self, control_id: str, profile: Profile) -> ControlLevelConfig | None:
        """None if the control is absent from the policy or disabled."""
        return self._levels.get((control_id, profile))


def compile_policy(
    raw: PolicyFile,
    source: str | bytes,
    env: Mapping[str, str] | None = None,
    known_controls: Any | None = None,
) -> CompiledPolicy:
    """Build the runtime form. Raises ValueError on problems only detectable with the env."""
    env = os.environ if env is None else env
    src = source.encode() if isinstance(source, str) else source
    version = hashlib.sha256(src).hexdigest()[:12]
    warnings: list[str] = []

    by_key: dict[str, IdentitySpec] = {}
    for ident in raw.identities:
        key = env.get(ident.api_key_env)
        if not key:
            warnings.append(
                f"identity {ident.id!r}: env var {ident.api_key_env} not set, identity cannot log in"
            )
            continue
        if key in by_key:
            raise ValueError(f"identities {by_key[key].id!r} and {ident.id!r} share the same API key")
        by_key[key] = ident

    if known_controls is not None:
        known = set(known_controls)
        for key, spec in raw.controls.items():
            if spec.id not in known:
                raise ValueError(
                    f"unknown control id {spec.id!r} (known: {', '.join(sorted(known))})"
                )

    controls: dict[str, ControlSpec] = {}
    levels: dict[tuple[str, Profile], ControlLevelConfig] = {}
    for key, spec in raw.controls.items():
        controls[spec.id] = spec
        if not spec.enabled:
            continue
        for profile in PROFILES:
            level = spec.levels[profile]
            extras = {**spec.params, **(level.model_extra or {})}
            clash = _RESERVED_CFG_KEYS & extras.keys()
            if clash:
                raise ValueError(f"controls.{key}: reserved names used as params: {', '.join(sorted(clash))}")
            levels[(spec.id, profile)] = ControlLevelConfig(
                control_key=key,
                control_id=spec.id,
                threat_ids=spec.threat_ids,
                action=level.action,
                mode=spec.mode or raw.mode,
                on_error=spec.on_error or raw.on_error_default,
                **extras,
            )

    compiled = CompiledPolicy(
        raw=raw,
        version=version,
        identities={i.id: i for i in raw.identities},
        identities_by_key=by_key,
        models={m.name: m for m in raw.models},
        controls=controls,
        _levels=levels,
        warnings=tuple(warnings),
    )
    for cfg in levels.values():
        cfg._policy = compiled
    return compiled
