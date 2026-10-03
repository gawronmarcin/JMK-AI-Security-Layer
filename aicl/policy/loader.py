"""Policy loading: YAML text -> validated PolicyFile -> CompiledPolicy.

Errors are reported as human-readable `field.path: message` lines so a judge editing
the file live sees exactly what is wrong. Hot reload (watcher + atomic swap) builds on
`load_policy_file`.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import yaml
from pydantic import ValidationError

from aicl.policy.schema import CompiledPolicy, PolicyFile, compile_policy


class PolicyError(ValueError):
    """Invalid policy. `errors` holds one readable line per problem."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("invalid policy:\n  " + "\n  ".join(errors))


def _format_validation(exc: ValidationError) -> list[str]:
    lines = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"]) or "<root>"
        msg = err["msg"].removeprefix("Value error, ")
        lines.append(f"{loc}: {msg}")
    return lines


def parse_policy(source: str, env: Mapping[str, str] | None = None) -> CompiledPolicy:
    try:
        data = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise PolicyError([f"YAML syntax: {exc}"]) from exc
    if not isinstance(data, dict):
        raise PolicyError(["<root>: policy must be a YAML mapping"])
    try:
        raw = PolicyFile.model_validate(data)
    except ValidationError as exc:
        raise PolicyError(_format_validation(exc)) from exc
    try:
        return compile_policy(raw, source, env)
    except ValueError as exc:
        raise PolicyError([str(exc)]) from exc


def load_policy_file(path: str | Path, env: Mapping[str, str] | None = None) -> CompiledPolicy:
    return parse_policy(Path(path).read_text(encoding="utf-8"), env)
