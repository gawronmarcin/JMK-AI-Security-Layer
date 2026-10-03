"""R2 content detectors: C-PII-IN, C-PII-OUT, C-SECRET-IN, C-SECRET-OUT.

Target location in the repo: ``aicl/controls/pii_secrets.py`` (auto-registered).

Contract notes (ARCHITECTURE.md v0.2):
  * Controls are pure: they return a Decision, never raise for policy violations,
    never mutate ctx, never log.
  * Match.masked NEVER contains the raw value (section 0 rule 4, section 8).
  * Secrets match on ORIGINAL ``text`` + ``decoded`` (case-sensitive formats break
    under casefolding). PII matches on ``text`` only, with validators (section 5.2).
  * Matches found only in ``decoded`` carry no span (in_decoded=True); the engine
    escalates redact -> block for them (section 4.2 rule 6).
  * Redaction-capable controls return spans into the original ``text``.

``cfg`` is the repo's ControlLevelConfig: ``cfg.action`` plus params merged as extras
(``cfg.types`` from policy ``params.types``). A plain dict is also accepted (unit tests).
"""
from __future__ import annotations

import calendar
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from aicl.models import Action, Decision, Match, Origin, RequestContext, Severity, Stage
from aicl.registry import register_control

# --------------------------------------------------------------------------- #
# Validators
# --------------------------------------------------------------------------- #


def _luhn(raw: str) -> bool:
    digits = re.sub(r"[ -]", "", raw)
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


_PESEL_WEIGHTS = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
_PESEL_CENTURY = {0: 1900, 1: 2000, 2: 2100, 3: 2200, 4: 1800}


def _valid_pesel(raw: str) -> bool:
    if len(raw) != 11 or not raw.isdigit():
        return False
    d = [int(c) for c in raw]
    check = (10 - sum(a * b for a, b in zip(d, _PESEL_WEIGHTS)) % 10) % 10
    if check != d[10]:
        return False
    mm = d[2] * 10 + d[3]
    month = mm % 20
    if not 1 <= month <= 12:
        return False
    year = _PESEL_CENTURY[mm // 20] + d[0] * 10 + d[1]
    day = d[4] * 10 + d[5]
    return 1 <= day <= calendar.monthrange(year, month)[1]


def _valid_iban(raw: str) -> bool:
    s = raw.replace(" ", "").upper()
    if not 15 <= len(s) <= 34 or not s.isalnum():
        return False
    rearranged = s[4:] + s[:4]
    try:
        number = "".join(str(int(c, 36)) for c in rearranged)
    except ValueError:
        return False
    return int(number) % 97 == 1


_PLACEHOLDER_WORDS = ("example", "your", "xxxx", "changeme", "placeholder", "redacted", "dummy")


def _looks_like_secret(value: str) -> bool:
    """Cheap false-positive filter for keyed api keys/tokens."""
    low = value.lower()
    if any(w in low for w in _PLACEHOLDER_WORDS):
        return False
    if len(set(value)) < 6:
        return False
    return any(c.isdigit() for c in value) and any(c.isalpha() for c in value)


def _looks_like_password(value: str) -> bool:
    low = value.lower()
    if low in {"true", "false", "none", "null", "nil", "redacted"}:
        return False
    return not (value[0] in "$<{%*" or set(value) <= {"*"})


# --------------------------------------------------------------------------- #
# Detector registry
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Detector:
    kind: str
    pattern: re.Pattern[str]
    severity: Severity                                 # low | medium | high | critical
    group: int = 0                                  # capture group that is the sensitive value
    validator: Callable[[str], bool] | None = None
    trim_trailing_groups: bool = False              # IBAN: retry without trailing words


def _c(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


_SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# ---- PII (matched on original text, validators keep false positives low) ----
PII_DETECTORS: dict[str, tuple[Detector, ...]] = {
    "email": (
        Detector(
            "email",
            _c(r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}"
               r"(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}(?![\w-])"),
            "low",
        ),
    ),
    "phone_pl": (
        Detector(
            "phone_pl",
            # +48/0048 prefix (any grouping) OR 3-3-3 grouped with separators, mobile-range first digit.
            # Bare 9-digit numbers are deliberately NOT matched (order ids, timestamps).
            _c(r"(?<![\w+])(?:(?:\+|00)48[ -]?\d{3}[ -]?\d{3}[ -]?\d{3}"
               r"|[4-8]\d{2}[ -]\d{3}[ -]\d{3})(?!\d)"),
            "medium",
        ),
    ),
    "pesel": (
        Detector("pesel", _c(r"(?<!\d)\d{11}(?!\d)"), "high", validator=_valid_pesel),
    ),
    "iban": (
        Detector(
            "iban",
            _c(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"),
            "high",
            validator=_valid_iban,
            trim_trailing_groups=True,
        ),
    ),
    "credit_card": (
        Detector(
            "credit_card",
            # first digit 2-6 (card networks) removes most 13+ digit timestamps/ids before Luhn runs
            _c(r"(?<![\d-])[2-6](?:[ -]?\d){12,18}(?![\d-])"),
            "high",
            validator=_luhn,
        ),
    ),
    "ip_address": (
        Detector(
            "ip_address",
            _c(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
               r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d)(?!\.\d)"),
            "low",
        ),
    ),
}

# ---- Secrets (matched on original text + decoded; case-sensitive where the format is) ----
_KEYED_NAMES = (r"api[_-]?key|apikey|secret(?:[_-]?key)?|client[_-]?secret|"
                r"access[_-]?token|auth[_-]?token|token")
SECRET_DETECTORS: dict[str, tuple[Detector, ...]] = {
    "aws_access_key": (
        Detector("aws_access_key", _c(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    ),
    "api_key_generic": (
        # well-known provider prefixes
        Detector(
            "api_key_generic",
            _c(r"\b(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}"
               r"|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b"),
            "high",
        ),
        # keyed assignment: api_key = "...", token: ...
        Detector(
            "api_key_generic",
            _c(rf"\b(?:{_KEYED_NAMES})\b[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{{16,}})", re.IGNORECASE),
            "high",
            group=1,
            validator=_looks_like_secret,
        ),
    ),
    "private_key_block": (
        Detector(
            "private_key_block",
            # whole block when the END line exists, otherwise to end of text (truncated paste)
            _c(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]{0,8192}?"
               r"(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|$)"),
            "critical",
        ),
    ),
    "jwt": (
        Detector(
            "jwt",
            _c(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
            "high",
        ),
    ),
    "password_assignment": (
        Detector(
            "password_assignment",
            # EN + PL keywords: password / passwd / pwd / hasło
            _c(r"\b(?:password|passwd|pwd|has[łl]o)\b[\"']?\s*[:=]\s*[\"']?([^\s\"',;]{4,})", re.IGNORECASE),
            "medium",
            group=1,
            validator=_looks_like_password,
        ),
    ),
}

# --------------------------------------------------------------------------- #
# Masking (Match.masked must never contain the raw value)
# --------------------------------------------------------------------------- #


def _mask(kind: str, raw: str) -> str:
    if kind == "aws_access_key":
        return raw[:4] + "*" * (len(raw) - 4)          # AKIA****************
    if kind == "credit_card":
        digits = re.sub(r"\D", "", raw)
        return "*" * 12 + digits[-4:]
    if kind == "iban":
        return raw.replace(" ", "")[:4] + "*" * 8
    if kind == "email":
        return raw[0] + "***@***"
    if kind == "jwt":
        return "eyJ***"
    if kind == "private_key_block":
        return "[private key block]"
    return "***"


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #


def _scan(text: str, detectors: Iterable[Detector]) -> Iterator[tuple[Detector, int, int, str]]:
    for d in detectors:
        for m in d.pattern.finditer(text):
            raw = m.group(d.group)
            if raw is None:
                continue
            start, end = m.start(d.group), m.end(d.group)
            if d.validator is not None:
                if d.trim_trailing_groups:
                    while raw and not d.validator(raw):
                        raw = raw.rsplit(" ", 1)[0] if " " in raw else ""
                    if not raw:
                        continue
                    end = start + len(raw)
                elif not d.validator(raw):
                    continue
            yield d, start, end, raw


_INPUT_ORIGINS = frozenset({Origin.user, Origin.tool_result, Origin.retrieved, Origin.artifact})
_OUTPUT_ORIGINS = frozenset({Origin.assistant, Origin.tool_result, Origin.retrieved, Origin.artifact})


def _cfg_get(cfg: Any, name: str, default: Any = None) -> Any:
    if cfg is None:
        return default
    if isinstance(cfg, dict):
        return cfg.get(name, default)
    value = getattr(cfg, name, None)
    if value is not None:
        return value
    params = getattr(cfg, "params", None)
    if isinstance(params, dict):
        return params.get(name, default)
    return default


class _ContentControl:
    id: str
    threat_ids: tuple[str, ...]
    stages: tuple[Stage, ...]
    priority: int = 20                       # deterministic, cheap: < 100
    registry: dict[str, tuple[Detector, ...]]
    scan_decoded: bool = False

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        action = Action(_cfg_get(cfg, "action", Action.flag))
        wanted = _cfg_get(cfg, "types", None) or list(self.registry)
        detectors = [d for t in wanted for d in self.registry.get(t, ())]
        origins = _OUTPUT_ORIGINS if ctx.stage == Stage.output else _INPUT_ORIGINS

        matches: list[Match] = []
        seen: set[tuple[str, int, int, int]] = set()
        top_sev: Severity = "low"
        threat_ids = list(_cfg_get(cfg, "threat_ids", None) or self.threat_ids)

        for seg in ctx.segments:
            if seg.origin not in origins:
                continue
            # Dedupe decoded hits by (kind, value), not by kind alone: a plain secret must not hide
            # a *different* encoded secret of the same kind in the same segment.
            values_reported: set[tuple[str, str]] = set()
            for d, start, end, raw in _scan(seg.text, detectors):
                key = (d.kind, seg.idx, start, end)
                if key in seen:
                    continue
                seen.add(key)
                values_reported.add((d.kind, raw))
                matches.append(Match(kind=d.kind, segment_idx=seg.idx, start=start, end=end,
                                     masked=_mask(d.kind, raw)))
                if _SEV_ORDER[d.severity] > _SEV_ORDER[top_sev]:
                    top_sev = d.severity

            if self.scan_decoded:
                for fragment in seg.decoded:
                    for d, _s, _e, raw in _scan(fragment, detectors):
                        if (d.kind, raw) in values_reported:
                            continue                       # same value already reported
                        values_reported.add((d.kind, raw))
                        matches.append(Match(kind=d.kind, segment_idx=seg.idx,
                                             masked=_mask(d.kind, raw), in_decoded=True))
                        if _SEV_ORDER[d.severity] > _SEV_ORDER[top_sev]:
                            top_sev = d.severity

        if not matches:
            return Decision(control_id=self.id, threat_ids=threat_ids,
                            action=Action.allow)

        kinds = sorted({m.kind for m in matches})
        decoded_n = sum(m.in_decoded for m in matches)
        reason = f"{len(matches)} match(es): {', '.join(kinds)}"
        if decoded_n:
            reason += f" ({decoded_n} only in decoded/encoded text)"
        return Decision(control_id=self.id, threat_ids=threat_ids, action=action,
                        severity=top_sev, reason=reason, matches=matches)


@register_control
class PiiInput(_ContentControl):
    id = "C-PII-IN"
    threat_ids = ("TH-03",)
    stages = (Stage.input,)
    registry = PII_DETECTORS


@register_control
class PiiOutput(_ContentControl):
    id = "C-PII-OUT"
    threat_ids = ("TH-05",)
    stages = (Stage.output, Stage.tool_result)
    registry = PII_DETECTORS


@register_control
class SecretsInput(_ContentControl):
    id = "C-SECRET-IN"
    threat_ids = ("TH-04",)
    stages = (Stage.input,)
    registry = SECRET_DETECTORS
    scan_decoded = True


@register_control
class SecretsOutput(_ContentControl):
    id = "C-SECRET-OUT"
    threat_ids = ("TH-04",)
    stages = (Stage.output, Stage.tool_result)
    registry = SECRET_DETECTORS
    scan_decoded = True
