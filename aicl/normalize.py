"""Text normalization done once per segment, before controls run (ARCHITECTURE.md §5.2).

norm    = NFKC -> strip invisible chars -> collapse whitespace -> casefold -> fold homoglyphs
decoded = text recovered from base64 / hex / URL-encoding / rot13 / leetspeak fragments,
          bounded (depth <= 2, <= 16 KB total), NOT casefolded (secrets are case-sensitive)
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from typing import Any
from urllib.parse import unquote

from aicl.models import Origin, Segment, Trust

MAX_DECODE_DEPTH = 2
MAX_DECODED_BYTES = 16 * 1024
_MIN_DECODED_LEN = 4

# Zero-width, bidi overrides, soft hyphen, BOM and C0/C1 controls except whitespace.
_INVISIBLE_RE = re.compile(
    "[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u00ad"
    "\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]"
)
_WS_RE = re.compile(r"\s+")

# Lowercase look-alikes (applied after casefold) mapped to Latin.
_HOMOGLYPHS = str.maketrans(
    {
        # Cyrillic
        "\N{CYRILLIC SMALL LETTER A}": "a",
        "\N{CYRILLIC SMALL LETTER VE}": "b",
        "\N{CYRILLIC SMALL LETTER IE}": "e",
        "\N{CYRILLIC SMALL LETTER IO}": "e",
        "\N{CYRILLIC SMALL LETTER KA}": "k",
        "\N{CYRILLIC SMALL LETTER EM}": "m",
        "\N{CYRILLIC SMALL LETTER EN}": "h",
        "\N{CYRILLIC SMALL LETTER O}": "o",
        "\N{CYRILLIC SMALL LETTER ER}": "p",
        "\N{CYRILLIC SMALL LETTER ES}": "c",
        "\N{CYRILLIC SMALL LETTER TE}": "t",
        "\N{CYRILLIC SMALL LETTER U}": "y",
        "\N{CYRILLIC SMALL LETTER HA}": "x",
        "\N{CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I}": "i",
        "\N{CYRILLIC SMALL LETTER YI}": "i",
        "\N{CYRILLIC SMALL LETTER JE}": "j",
        "\N{CYRILLIC SMALL LETTER DZE}": "s",
        "\N{CYRILLIC SMALL LETTER KOMI DE}": "d",
        "\N{CYRILLIC SMALL LETTER QA}": "q",
        "\N{CYRILLIC SMALL LETTER WE}": "w",
        "\N{CYRILLIC SMALL LETTER SHHA}": "h",
        "\N{CYRILLIC SMALL LETTER PALOCHKA}": "l",
        # Greek
        "\N{GREEK SMALL LETTER ALPHA}": "a",
        "\N{GREEK SMALL LETTER BETA}": "b",
        "\N{GREEK SMALL LETTER EPSILON}": "e",
        "\N{GREEK SMALL LETTER ETA}": "n",
        "\N{GREEK SMALL LETTER IOTA}": "i",
        "\N{GREEK SMALL LETTER KAPPA}": "k",
        "\N{GREEK SMALL LETTER NU}": "v",
        "\N{GREEK SMALL LETTER OMICRON}": "o",
        "\N{GREEK SMALL LETTER RHO}": "p",
        "\N{GREEK SMALL LETTER TAU}": "t",
        "\N{GREEK SMALL LETTER UPSILON}": "u",
        "\N{GREEK SMALL LETTER CHI}": "x",
        "\N{GREEK SMALL LETTER OMEGA}": "w",
        "\N{GREEK LUNATE SIGMA SYMBOL}": "c",
    }
)

_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{16,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_HEX_ESC_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_PCT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_WORD_RE = re.compile(r"[a-z]+")

# Words whose presence after rot13 suggests the fragment really was rot13-encoded.
_ROT13_HINTS = frozenset(
    [
        "the",
        "and",
        "you",
        "ignore",
        "previous",
        "instructions",
        "system",
        "prompt",
        "password",
        "secret",
        "reveal",
        "print",
        "forget",
        "all",
        "rules",
        "key",
        "token",
        "admin",
        "execute",
        "command",
        "delete",
    ]
)


def strip_invisible(text: str) -> str:
    return _INVISIBLE_RE.sub("", unicodedata.normalize("NFKC", text))


def fold(text: str) -> str:
    """Full `norm` pipeline. Also usable by controls on `decoded` fragments."""
    text = _WS_RE.sub(" ", strip_invisible(text)).strip()
    return text.casefold().translate(_HOMOGLYPHS)


def _printable(raw: bytes) -> str | None:
    """UTF-8 text that is mostly printable, else None (random bytes from a false-positive match)."""
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(s) < _MIN_DECODED_LEN:
        return None
    good = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return s if good / len(s) >= 0.9 else None


def _b64(fragment: str) -> str | None:
    frag = fragment.rstrip("=")
    padded = frag + "=" * (-len(frag) % 4)
    try:
        if "-" in frag or "_" in frag:
            raw = base64.urlsafe_b64decode(padded)
        else:
            raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    return _printable(raw)


def _hex(fragment: str) -> str | None:
    try:
        return _printable(bytes.fromhex(fragment.replace("\\x", "")))
    except ValueError:
        return None


def _rot13(text: str) -> str | None:
    rotated = codecs.encode(text, "rot13")
    before = sum(w in _ROT13_HINTS for w in _WORD_RE.findall(text.lower()))
    after = sum(w in _ROT13_HINTS for w in _WORD_RE.findall(rotated.lower()))
    return rotated if after >= 2 and after > before else None


_LEET = str.maketrans("0134578@$", "oieastbas")
_LEET_WORD_RE = re.compile(r"\b(?=\w*[A-Za-z])(?=\w*[0134578])[A-Za-z0134578]{3,}\b")


def _deleet(text: str) -> str | None:
    """'1gn0r3 all pr3v10us' -> 'ignore all previous'. Only when at least two words mix
    letters with look-alike digits, so ordinary numbers and ids are left alone."""
    if len(_LEET_WORD_RE.findall(text)) < 2:
        return None
    out = _LEET_WORD_RE.sub(lambda m: m.group().translate(_LEET), text)
    return out if out != text else None


def _decode_once(text: str) -> list[str]:
    out: list[str] = []
    for m in _B64_RE.finditer(text):
        if (s := _b64(m.group())) is not None:
            out.append(s)
    for rx in (_HEX_RE, _HEX_ESC_RE):
        for m in rx.finditer(text):
            if (s := _hex(m.group())) is not None:
                out.append(s)
    if len(_PCT_RE.findall(text)) >= 3:
        unq = unquote(text)
        if unq != text:
            out.append(unq)
    if (s := _rot13(text)) is not None:
        out.append(s)
    if (s := _deleet(text)) is not None:
        out.append(s)
    return out


def decode_fragments(text: str) -> list[str]:
    """Bounded recursive decoding. Returns unique fragments different from the input."""
    results: list[str] = []
    seen = {text}
    budget = MAX_DECODED_BYTES
    frontier = [strip_invisible(text)]
    for _ in range(MAX_DECODE_DEPTH):
        next_frontier: list[str] = []
        for item in frontier:
            for s in _decode_once(item):
                if s in seen:
                    continue
                size = len(s.encode())
                if size > budget:
                    return results
                budget -= size
                seen.add(s)
                results.append(s)
                next_frontier.append(s)
        frontier = next_frontier
        if not frontier:
            break
    return results


def build_segment(
    idx: int,
    text: str,
    origin: Origin,
    trust: Trust = "trusted",
    meta: dict[str, Any] | None = None,
) -> Segment:
    return Segment(
        idx=idx,
        text=text,
        norm=fold(text),
        decoded=decode_fragments(text),
        origin=origin,
        trust=trust,
        meta=meta or {},
    )
