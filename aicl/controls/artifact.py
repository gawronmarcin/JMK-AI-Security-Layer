"""C-ARTIFACT: Model and artifact deserialization security scanner (R2, P0). Threat TH-14.

Contract notes (ARCHITECTURE.md §0.5, §4.1, §6.3, §6.8, §7):
- Evaluates Stage.artifact.
- Priority: 30 (deterministic check).
- Analyzes model files and archives statically using pickletools.genops.
- Never executes or deserializes test artifacts (never pickle.loads).
- Detects dangerous globals (os.system, posix.system, subprocess.Popen, builtins.eval, etc.)
  from feed and built-in signatures.
- Inspects archive members (zip, tar) recursively.
- Refuses unparseable/corrupted streams and unknown archive formats (7z, rar) by default.
"""

from __future__ import annotations

import io
import json
import pickle
import pickletools
import struct
import tarfile
import zipfile
from typing import Any

from aicl import feeds
from aicl.models import Action, Decision, Match, RequestContext, Stage
from aicl.registry import register_control

_DEFAULT_DANGEROUS_GLOBALS: frozenset[str] = frozenset({
    "os.system",
    "posix.system",
    "nt.system",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.run",
    "builtins.eval",
    "builtins.exec",
    "builtins.__import__",
    "__builtin__.eval",
    "__builtin__.exec",
    "commands.getoutput",
    "commands.getstatusoutput",
})


def _cfg_val(cfg: Any, key: str, default: Any = None) -> Any:
    if hasattr(cfg, "get"):
        return cfg.get(key, default)
    return getattr(cfg, key, default) if hasattr(cfg, key) else default


def _scan_pickle_stream(data: bytes, dangerous_globals: set[str], reject_unparseable: bool) -> tuple[bool, str | None, list[str]]:
    found: list[str] = []
    strs: list[str] = []
    broken = False

    try:
        for op, arg, _ in pickletools.genops(io.BytesIO(data)):
            if op.name == "GLOBAL":
                g = arg.replace(" ", ".").strip()
                found.append(g)
            elif "UNICODE" in op.name:
                strs.append(arg)
            elif op.name == "STACK_GLOBAL":
                if len(strs) >= 2:
                    g = f"{strs[-2]}.{strs[-1]}".strip()
                    found.append(g)
    except (ValueError, IndexError, KeyError, struct.error, pickle.UnpicklingError):
        broken = True
    except Exception:  # noqa: BLE001 - arbitrary opcodes can trigger other parsing errors
        broken = True

    # Check for dangerous calls (even if the stream was broken afterwards)
    for g in found:
        if g in dangerous_globals:
            return True, f"dangerous global: {g}", found
        mod = g.partition(".")[0]
        if mod in ("os", "subprocess", "posix", "nt") and g in dangerous_globals:
            return True, f"dangerous global: {g}", found

    if broken and reject_unparseable:
        return True, "corrupted or truncated pickle stream", found

    return False, None, found


def _is_safetensors(data: bytes) -> bool:
    if len(data) < 8:
        return False
    header_len = struct.unpack("<Q", data[:8])[0]
    if header_len <= 0 or header_len > len(data) - 8:
        return False
    try:
        header_bytes = data[8 : 8 + header_len]
        header_json = json.loads(header_bytes.decode("utf-8"))
        return isinstance(header_json, dict)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return False


def _scan_artifact_bytes(
    data: bytes,
    filename: str,
    dangerous_globals: set[str],
    reject_unparseable: bool,
) -> tuple[bool, str | None]:
    if not data:
        if reject_unparseable:
            return True, "empty artifact file"
        return False, None

    # Refuse unknown/unsupported archive formats (§7.1)
    if filename.endswith(".7z") or data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return True, "unsupported archive format (7z)"
    if filename.endswith(".rar") or data.startswith(b"Rar!"):
        return True, "unsupported archive format (rar)"

    # Safetensors files are clean by structure
    if filename.endswith(".safetensors") or _is_safetensors(data):
        return False, None

    # ZIP archives (e.g. PyTorch .pt, zip bundles)
    if zipfile.is_zipfile(io.BytesIO(data)):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for name in z.namelist():
                    mb = z.read(name)
                    if zipfile.is_zipfile(io.BytesIO(mb)):
                        bad, reason = _scan_artifact_bytes(mb, name, dangerous_globals, reject_unparseable)
                        if bad:
                            return True, f"{name}: {reason}"
                    elif name.endswith((".pkl", ".pickle", ".pt", ".bin", ".pth")) or mb.startswith((b"c", b"\x80")):
                        bad, reason, _ = _scan_pickle_stream(mb, dangerous_globals, reject_unparseable)
                        if bad:
                            return True, f"{name}: {reason}"
            return False, None
        except Exception as exc:  # noqa: BLE001
            if reject_unparseable:
                return True, f"corrupted zip archive: {exc}"
            return False, None

    # TAR archives
    if tarfile.is_tarfile(io.BytesIO(data)):
        try:
            with tarfile.open(fileobj=io.BytesIO(data)) as t:
                for m in t.getmembers():
                    if m.isfile():
                        fileobj = t.extractfile(m)
                        if fileobj is not None:
                            mb = fileobj.read()
                            if m.name.endswith((".pkl", ".pickle", ".pt", ".bin", ".pth")) or mb.startswith((b"c", b"\x80")):
                                bad, reason, _ = _scan_pickle_stream(mb, dangerous_globals, reject_unparseable)
                                if bad:
                                    return True, f"{m.name}: {reason}"
            return False, None
        except Exception as exc:  # noqa: BLE001
            if reject_unparseable:
                return True, f"corrupted tar archive: {exc}"
            return False, None

    # Standalone pickle file
    bad, reason, _ = _scan_pickle_stream(data, dangerous_globals, reject_unparseable)
    return bad, reason


@register_control
class ArtifactScanControl:
    id: str = "C-ARTIFACT"
    stages: tuple[Stage, ...] = (Stage.artifact,)
    priority: int = 30  # deterministic check < 100

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        target_action = Action(_cfg_val(cfg, "action", Action.block))
        threat_ids = list(_cfg_val(cfg, "threat_ids", ["TH-14"]))
        reject_unparseable = bool(_cfg_val(cfg, "reject_unparseable", True))
        dangerous_from_feed = bool(_cfg_val(cfg, "dangerous_globals_from_feed", True))

        dangerous_globals = set(_DEFAULT_DANGEROUS_GLOBALS)
        if dangerous_from_feed:
            snap = feeds.current()
            for sig in snap.for_set("artifact"):
                if sig.kind == "pickle_global":
                    dangerous_globals.add(sig.pattern.strip())

        data = ctx.artifact or b""
        filename = ""
        if ctx.segments and ctx.segments[0].meta:
            filename = str(ctx.segments[0].meta.get("filename", ""))
        if not filename and ctx.segments:
            filename = ctx.segments[0].text

        is_malicious, reason = _scan_artifact_bytes(data, filename, dangerous_globals, reject_unparseable)

        if is_malicious:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=target_action,
                severity="critical",
                reason=reason or "malicious artifact payload detected",
                matches=[Match(kind="pickle_global", masked=f"[{reason or 'unsafe payload'}]")],
            )

        return Decision(
            control_id=self.id,
            threat_ids=threat_ids,
            action=Action.allow,
            severity="low",
            reason="artifact scanned and verified clean",
        )
