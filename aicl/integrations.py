"""Glue for controls that need policy data outside their (ctx, cfg) envelope.

Each function here builds a Runtime policy listener: called with the compiled policy at
startup and after every hot reload.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from aicl.policy.schema import CompiledPolicy
from aicl.runtime import PolicyListener

log = logging.getLogger(__name__)


def semantic_judge_listener(env: Mapping[str, str]) -> PolicyListener:
    """Pass the policy's `semantic:` block to C-INJ-SEM via its `configure()`.

    The judge is rebuilt only when the semantic settings change: a new judge opens a new
    HTTP client, so unrelated policy edits should not create one.
    """
    last = None

    def configure_semantic_judge(policy: CompiledPolicy) -> None:
        nonlocal last
        try:
            from aicl.controls import injection_semantic
            from aicl.semantic.settings import SemanticSettings
        except ImportError:  # semantic control not installed
            return
        spec = policy.raw.semantic
        settings = SemanticSettings.from_policy(spec.model_dump() if spec is not None else None, env)
        if settings == last:
            return
        injection_semantic.configure(settings)
        last = settings
        log.info("semantic judge configured (model=%r, ready=%s)", settings.model, settings.model_ready)

    return configure_semantic_judge


def classifier_listener(env: Mapping[str, str]) -> PolicyListener:
    """Build the C-INJ-BASTION classifier backend from its control `params`.

    Rebuilt only when the backend settings change (loading a model is expensive); thresholds
    and actions stay in the per-request `cfg`. A disabled or missing control means no backend.
    """
    last = None

    def configure_classifier(policy: CompiledPolicy) -> None:
        nonlocal last
        try:
            from aicl.controls import bastion
            from aicl.semantic.classifier import ClassifierSettings
        except ImportError:
            return
        spec = next((c for c in policy.raw.controls.values() if c.id == bastion.CONTROL_ID), None)
        params = spec.params if spec is not None and spec.enabled else {"backend": "none"}
        settings = ClassifierSettings.from_params(params, env)
        if settings == last:
            return
        bastion.configure(settings)
        last = settings
        log.info("injection classifier configured (backend=%s)", settings.backend)

    return configure_classifier


def embedding_listener(env: Mapping[str, str], base_dir: Path) -> PolicyListener:
    """Build the C-INJ-EMB index from its control `params` (relative paths against `base_dir`).

    Rebuilt only when the embedding settings change; corpus file edits are picked up by the
    index itself (hot reload of the example feed). Thresholds stay in the per-request `cfg`.
    """
    last = None

    def configure_embedding(policy: CompiledPolicy) -> None:
        nonlocal last
        try:
            from aicl.controls import injection_embedding
            from aicl.semantic.embedding import EmbeddingSettings
        except ImportError:
            return
        spec = next((c for c in policy.raw.controls.values() if c.id == injection_embedding.CONTROL_ID), None)
        params = spec.params if spec is not None and spec.enabled else {"backend": "none"}
        settings = EmbeddingSettings.from_params(params, env, base_dir)
        if settings == last:
            return
        injection_embedding.configure(settings)
        last = settings
        log.info("embedding detector configured (backend=%s, model=%s)", settings.backend, settings.model)

    return configure_embedding


def detector_status() -> dict[str, Any]:
    """AI-based detectors as seen by the gateway (for /healthz): classifier backend and judge."""
    out: dict[str, Any] = {}
    try:
        from aicl.controls import bastion, injection_embedding, injection_semantic
    except ImportError:
        return out
    out["embedding"] = injection_embedding.status()
    out["classifier"] = bastion.status()
    out["judge"] = injection_semantic.status()
    return out
