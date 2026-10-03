"""Operacje na polityce dla testów: deep-merge overlayów, wymuszanie profilu,
nadpisania środowiska testowego, generowanie kluczy API.

Polityka bazowa = prawdziwy `policies/default.yaml` (własność R1). Testy NIE
mają osobnej "testowej" polityki — sprawdzamy dokładnie to, co pokażemy jury,
a różnice wyrażamy overlayem per przypadek.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
JUDGE_MODEL = "mock-judge"
LOCAL_MODEL = "mock-local"


def base_policy_path() -> Path:
    return Path(os.environ.get("AICL_TEST_BASE_POLICY", REPO_ROOT / "policies" / "default.yaml"))


def load_base_policy() -> dict[str, Any]:
    return yaml.safe_load(base_policy_path().read_text(encoding="utf-8"))


def deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Rekurencyjny merge. Słowniki łączone, listy i skalary ZASTĘPOWANE.
    Wartość `null` w overlayu USUWA klucz (np. test 'usunięta kontrola = wyłączona', §6.3).
    """
    out = copy.deepcopy(base)
    for key, val in (overlay or {}).items():
        if val is None:
            out.pop(key, None)
        elif isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], val)
        else:
            out[key] = copy.deepcopy(val)
    return out


def force_profile(policy: dict[str, Any], profile: str | None, identity: str | None) -> dict[str, Any]:
    """`profile` w przypadku wymusza active_profile. Ponieważ override identity ma
    pierwszeństwo (§4: identity override > active_profile), ustawiamy go też
    na identity używanej w przypadku — inaczej `research-agent-01` (strict)
    zawsze by wygrywał."""
    if not profile:
        return policy
    p = copy.deepcopy(policy)
    p["active_profile"] = profile
    for ident in p.get("identities", []) or []:
        if identity is None or ident.get("id") == identity:
            if "profile" in ident:
                ident["profile"] = profile
    return p


def _abs(path_str: str) -> str:
    p = Path(path_str)
    return str(p if p.is_absolute() else (REPO_ROOT / p).resolve())


def apply_test_environment(policy: dict[str, Any], workdir: Path) -> dict[str, Any]:
    """Nadpisania, które sprawiają, że polityka działa offline i w izolacji:
    * audit -> plik w katalogu tymczasowym przypadku,
    * względne ścieżki feedów -> bezwzględne (temp policy leży poza repo),
    * model sędziego i modelu lokalnego -> nazwy rozpoznawane przez mock,
    * backend klasyfikatora C-INJ-BASTION -> none (chyba że AICL_TEST_CLASSIFIER_BACKEND).
    """
    p = copy.deepcopy(policy)
    p.setdefault("audit", {})["path"] = str(workdir / "audit.jsonl")
    for feed in p.get("signature_feeds", []) or []:
        if feed.get("path"):
            feed["path"] = _abs(feed["path"])
    if isinstance(p.get("semantic"), dict):
        # testy live podmieniają sędziego na prawdziwy model Ollamy
        p["semantic"]["model"] = os.environ.get("AICL_TEST_JUDGE_MODEL", JUDGE_MODEL)
    for c in (p.get("controls") or {}).values():
        if isinstance(c, dict) and c.get("id") == "C-INJ-BASTION":
            # klasyfikator: domyślnie wyłączony w testach (offline, deterministycznie); live: env
            c.setdefault("params", {})["backend"] = os.environ.get("AICL_TEST_CLASSIFIER_BACKEND", "none")
    for m in p.get("models", []) or []:
        if m.get("provider") == "ollama":
            m["upstream_model"] = LOCAL_MODEL
    return p


def identity_keys(policy: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    """-> ({identity_id: api_key}, {ENV_NAME: api_key}). Klucze są deterministyczne
    i jawnie testowe; nigdy nie trafiają do repo jako 'prawdziwe'."""
    by_id, env = {}, {}
    for ident in policy.get("identities", []) or []:
        key = f"test-key-{ident['id']}"
        by_id[ident["id"]] = key
        if ident.get("api_key_env"):
            env[ident["api_key_env"]] = key
    return by_id, env


def dump(policy: dict[str, Any], path: Path) -> None:
    path.write_text(yaml.safe_dump(policy, sort_keys=False, allow_unicode=True), encoding="utf-8")
