"""Schemat przypadku testowego (CONTRACT §11.3) — walidowany Pydantic v2, extra=forbid.

Literówka w pliku YAML (np. `expcet:` albo `upstream_caled:`) ma zatrzymać
zbieranie testów z czytelnym błędem, a nie po cichu zostać zignorowana —
dokładnie ta sama filozofia co dla polityki (§2).

Pola oznaczone [EXT] to PROPOZYCJE rozszerzeń kontraktu (wymagają zgody
zespołu i wpisu w ARCHITECTURE.md §11.3). Wszystkie są opcjonalne, więc
przypadki napisane wg obecnego kontraktu działają bez zmian.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

Endpoint = Literal["chat", "tool_invoke", "artifact_scan"]
ActionName = Literal["block", "require_approval", "redact", "flag", "allow"]
ProfileName = Literal["strict", "balanced", "permissive"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ArtifactSpec(_Strict):
    """[EXT] Jak zbudować bajty artefaktu dla endpointu artifact_scan."""
    generator: str                                  # nazwa z tests/payloads/artifacts.py
    filename: str | None = None                     # nazwa pliku w uploadzie
    params: dict[str, Any] = Field(default_factory=dict)


class RequestSpec(_Strict):
    endpoint: Endpoint
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any = None
    identity: str | None = None                     # [EXT] nadpisanie identity dla kroku
    auth: Literal["identity", "none", "invalid"] = "identity"   # [EXT]
    artifact: ArtifactSpec | None = None            # [EXT] tylko dla artifact_scan

    @field_validator("headers", mode="before")
    @classmethod
    def _headers_to_str(cls, v: Any) -> Any:
        # YAML zamienia `X-Mock-Scenario: tokens:10:20` poprawnie, ale np. liczby -> str
        return {str(k): str(val) for k, val in (v or {}).items()}


class ExpectSpec(_Strict):
    status: int | None = None
    action: ActionName | None = None
    control_ids: list[str] | None = None            # każde z listy musi zadziałać (podzbiór)
    threat_ids: list[str] | None = None
    upstream_called: bool | None = None
    response_contains: list[str] | None = None
    response_not_contains: list[str] | None = None
    max_overhead_ms: float | None = None


class StepSpec(_Strict):
    request: RequestSpec
    expect: ExpectSpec = Field(default_factory=ExpectSpec)
    repeat: int = Field(default=1, ge=1, le=10_000)  # expect sprawdzane przy KAŻDYM powtórzeniu


class CaseSpec(_Strict):
    id: str
    title: str
    kind: Literal["negative", "positive", "edge"]
    controls: list[str]
    threats: list[str] = Field(default_factory=list)
    profile: ProfileName | None = None
    identity: str | None = None
    policy_overlay: dict[str, Any] = Field(default_factory=dict)
    steps: list[StepSpec] = Field(min_length=1)
    tags: list[str] = Field(default_factory=list)   # [EXT] np. [live], [slow], [e2e]
    xfail: str | None = None                         # [EXT] znany brak — powód (np. "C-SUPPLY P1")

    # wypełniane przez loader
    source: str = ""


def load_case_file(path: Path) -> list[CaseSpec]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: plik przypadków musi być listą YAML")
    cases = []
    for i, item in enumerate(raw):
        try:
            case = CaseSpec.model_validate(item)
        except Exception as e:  # czytelny błąd z nazwą pliku i indeksem
            raise ValueError(f"{path.name}[{i}] ({item.get('id', '?') if isinstance(item, dict) else '?'}): {e}") from e
        case.source = path.name
        cases.append(case)
    return cases


def load_all_cases(cases_dir: Path) -> list[CaseSpec]:
    cases: list[CaseSpec] = []
    for path in sorted(cases_dir.glob("*.yaml")):
        if path.name.startswith("attacks_seed"):   # seedy fuzzera mają inny format
            continue
        cases.extend(load_case_file(path))
    ids = [c.id for c in cases]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise ValueError(f"zduplikowane id przypadków: {dupes}")
    return cases
