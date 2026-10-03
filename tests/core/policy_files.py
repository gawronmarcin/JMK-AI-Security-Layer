"""Policy files for core tests.

Core tests must not depend on a running Ollama (§0 rule 7): the semantic judge is disabled
by default by putting a placeholder model in the policy (`model_ready` is then false).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).parents[2]
DEFAULT_POLICY = REPO / "policies" / "default.yaml"
JUDGE_DISABLED = "<disabled-in-tests>"


def merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    for k, v in overlay.items():
        base[k] = merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
    return base


def write_policy(directory: Path, overlay: dict[str, Any] | None = None, judge: bool = False) -> Path:
    """Default policy + overlay, written to directory/policy.yaml."""
    data = yaml.safe_load(DEFAULT_POLICY.read_text(encoding="utf-8"))
    if not judge:
        data["semantic"]["model"] = JUDGE_DISABLED
    merge(data, overlay or {})
    path = directory / "policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path
