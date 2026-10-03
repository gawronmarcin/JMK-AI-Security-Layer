"""C-ARTIFACT: static scanner for model files and archives (R2, P0). Threats TH-14, TH-16.

NEVER deserializes anything (§0.5): pickles are walked opcode by opcode with
pickletools.genops, archives are listed and read as bytes.

What it checks:
  * Format by content, not by file name (a pickle renamed to .safetensors is still a pickle;
    the mismatch itself is reported).
  * Pickle globals against a module-level denylist (os, subprocess, runpy, socket, ...), a list
    of dangerous builtins (eval, exec, getattr, ...) and the feed's `pickle_global` signatures.
    Known-safe torch/numpy/collections globals pass; anything else is reported as unknown.
  * STACK_GLOBAL operands are resolved with a small stack model including the memo
    (PUT/MEMOIZE/GET), so operands fetched from the memo cannot hide the real global.
  * Archives (zip, tar incl. compressed tar): every member is inspected by content, nested
    archives recursively (bounded depth), with limits on entry count and unpacked size and a
    refusal of path traversal entries.
  * Unknown, unsupported (7z, rar, bare gzip/bz2/xz) and unparseable files are refused
    (`reject_unparseable`, §7.1); a broken pickle still reports what was found before the break.
  * SHA-256 of the whole file against the feed's `sha256` signatures (known malicious models).

Outcome per policy level: blocking findings -> `action`; warnings (raw pickle, unknown global,
extension mismatch) -> `flag`, or `action` when the level sets `block_on_warn: true`.
"""

from __future__ import annotations

import hashlib
import io
import json
import pickletools
import re
import struct
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import Any, Literal

from aicl import feeds
from aicl.models import Action, Decision, Match, RequestContext, Stage
from aicl.registry import register_control

# Modules that have no business inside a model file.
DENY_MODULES = frozenset({
    "os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "pty", "ctypes", "runpy",
    "importlib", "webbrowser", "urllib", "urllib2", "http", "httplib", "requests", "pickle",
    "cPickle", "marshal", "code", "codeop", "multiprocessing", "threading", "asyncio", "signal",
    "commands", "popen2", "platform", "pdb", "bdb", "timeit", "tempfile", "glob", "ftplib",
    "smtplib", "telnetlib", "pip", "setuptools", "distutils",
})  # fmt: skip
BUILTIN_MODULES = frozenset({"builtins", "__builtin__"})
DENY_BUILTINS = frozenset({
    "eval", "exec", "execfile", "compile", "__import__", "open", "file", "input", "getattr",
    "setattr", "delattr", "globals", "locals", "vars", "breakpoint", "apply", "memoryview",
})  # fmt: skip
SAFE_BUILTINS = frozenset({
    "set", "frozenset", "slice", "range", "complex", "bytearray", "bytes", "dict", "list",
    "tuple", "int", "float", "bool", "str", "object", "type",
})  # fmt: skip
SAFE_GLOBALS = frozenset({
    "collections.OrderedDict", "collections.defaultdict", "collections.Counter", "_codecs.encode",
    "copyreg._reconstructor", "copy_reg._reconstructor",
    "torch._utils._rebuild_tensor_v2", "torch._utils._rebuild_tensor", "torch._utils._rebuild_parameter",
    "torch._tensor._rebuild_from_type_v2", "torch.Size", "torch.nn.parameter.Parameter",
    "numpy.core.multiarray._reconstruct", "numpy._core.multiarray._reconstruct",
    "numpy.core.multiarray.scalar", "numpy._core.multiarray.scalar", "numpy.ndarray", "numpy.dtype",
})  # fmt: skip
SAFE_GLOBAL_RE = re.compile(
    r"^torch\.(Float|Double|Half|BFloat16|Long|Int|Short|Char|Byte|Bool|Complex\w*)Storage$"
    r"|^torch\.(float|int|uint|bool|bfloat|complex)\d*$"
)

_STRING_OPS = frozenset({
    "STRING", "BINSTRING", "SHORT_BINSTRING", "UNICODE", "BINUNICODE", "SHORT_BINUNICODE",
    "BINUNICODE8", "BINBYTES", "SHORT_BINBYTES", "BINBYTES8",
})  # fmt: skip
_PUT_OPS = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})
_GET_OPS = frozenset({"GET", "BINGET", "LONG_BINGET"})
_MARK = object()  # stack sentinel for MARK

MAX_DEPTH = 3
_PICKLE_EXTS = (".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib")

Level = Literal["block", "warn"]


@dataclass
class Finding:
    level: Level
    code: str
    detail: str


@dataclass
class Scan:
    dangerous_feed: dict[str, str]  # "module.name" or "module" -> signature id
    reject_unparseable: bool
    max_entries: int
    max_unpacked: int
    findings: list[Finding] = field(default_factory=list)
    unpacked: int = 0

    def add(self, level: Level, code: str, detail: str) -> None:
        self.findings.append(Finding(level, code, detail))

    def unparseable(self, code: str, detail: str) -> None:
        self.add("block" if self.reject_unparseable else "warn", code, detail)


# --- pickle ---------------------------------------------------------------------------------


def _judge_global(module: str, name: str, scan: Scan, where: str) -> None:
    full = f"{module}.{name}"
    root = module.split(".")[0]
    tag = f"{where}: " if where else ""
    sig = scan.dangerous_feed.get(full) or scan.dangerous_feed.get(module) or scan.dangerous_feed.get(root)
    if sig:
        scan.add("block", "feed_signature", f"{tag}{full} ({sig})")
    elif root in DENY_MODULES:
        scan.add("block", "dangerous_global", f"{tag}{full}")
    elif root in BUILTIN_MODULES:
        if name in DENY_BUILTINS:
            scan.add("block", "dangerous_global", f"{tag}{full}")
        elif name not in SAFE_BUILTINS:
            scan.add("warn", "unknown_global", f"{tag}{full}")
    elif full not in SAFE_GLOBALS and not SAFE_GLOBAL_RE.match(full):
        scan.add("warn", "unknown_global", f"{tag}{full}")


def _index(arg: Any) -> int:
    return arg if isinstance(arg, int) else int(str(arg))


def scan_pickle(data: bytes, scan: Scan, where: str = "") -> None:
    """Walk the opcodes with a minimal stack model: only strings matter, everything else is
    an opaque item. Dangerous globals found before a parse error still count (§7.1)."""
    stack: list[Any] = []
    memo: dict[int, Any] = {}
    try:
        for op, arg, _pos in pickletools.genops(data):
            name = op.name
            if name in _STRING_OPS:
                stack.append(arg.decode("latin-1") if isinstance(arg, bytes) else str(arg))
            elif name in _PUT_OPS:
                memo[_index(arg)] = stack[-1] if stack else None
            elif name == "MEMOIZE":
                memo[len(memo)] = stack[-1] if stack else None
            elif name in _GET_OPS:
                stack.append(memo.get(_index(arg)))
            elif name == "MARK":
                stack.append(_MARK)
            elif name == "POP":
                if stack:
                    stack.pop()
            elif name == "POP_MARK":
                while stack and stack.pop() is not _MARK:
                    pass
            elif name == "DUP":
                stack.append(stack[-1] if stack else None)
            elif name in ("GLOBAL", "INST"):
                module, _, attr = str(arg).replace("\n", " ").partition(" ")
                _judge_global(module, attr, scan, where)
                stack.append(None)
            elif name == "STACK_GLOBAL":
                attr_item = stack.pop() if stack else None
                module_item = stack.pop() if stack else None
                if isinstance(module_item, str) and isinstance(attr_item, str):
                    _judge_global(module_item, attr_item, scan, where)
                else:
                    scan.add(
                        "warn", "unresolved_global", f"{where or 'pickle'}: STACK_GLOBAL operands unknown"
                    )
                stack.append(None)
            elif name != "STOP":
                stack.append(None)  # any other result: opaque, not a string
    except Exception as exc:  # noqa: BLE001 - corrupted streams raise many exception types
        scan.unparseable("unparseable_pickle", f"{where or 'pickle'}: stream broken ({type(exc).__name__})")


def _parses_as_pickle(data: bytes) -> bool:
    """Protocol 0/1 pickles have no magic number: accept if the stream parses to STOP."""
    try:
        last = None
        for op, _arg, _pos in pickletools.genops(data):
            last = op.name
        return last == "STOP"
    except Exception:  # noqa: BLE001
        return False


# --- formats --------------------------------------------------------------------------------

_COMPRESSED = (b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd")  # gzip, bzip2, xz, zstd


def _is_safetensors(data: bytes) -> bool:
    if len(data) < 10:
        return False
    n = struct.unpack("<Q", data[:8])[0]
    if not 2 <= n <= len(data) - 8 or data[8:9] != b"{":
        return False
    try:
        header = json.loads(data[8 : 8 + n].decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False
    return isinstance(header, dict)


def detect_format(data: bytes) -> str:
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if data[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if data[:4] == b"Rar!":
        return "rar"
    if data[257:262] == b"ustar" or data.startswith(_COMPRESSED):
        try:
            is_tar = tarfile.is_tarfile(io.BytesIO(data))
        except Exception:  # noqa: BLE001 - truncated or exotic compressed data
            is_tar = False
        return "tar" if is_tar else "compressed"
    if data[:4] == b"GGUF":
        return "gguf"
    if data[:6] == b"\x93NUMPY":
        return "npy"
    if data[:4] == b"\x89HDF":
        return "hdf5"
    if _is_safetensors(data):
        return "safetensors"
    if (len(data) > 2 and data[0] == 0x80 and 2 <= data[1] <= 5) or _parses_as_pickle(data):
        return "pickle"
    return "unknown"


_EXPECTED = {
    ".safetensors": {"safetensors"},
    ".gguf": {"gguf"},
    ".npy": {"npy"},
    ".pkl": {"pickle"},
    ".pickle": {"pickle"},
    ".pt": {"zip", "pickle"},
    ".pth": {"zip", "pickle"},
    ".zip": {"zip"},
}


def scan_bytes(data: bytes, name: str, scan: Scan, depth: int = 0) -> None:
    """Inspect one file or archive member. Unknown content is refused only at the top level:
    inside archives it is ordinary data (tensor storages, version files, ...)."""
    top = depth == 0
    if not data:
        if top:
            scan.unparseable("empty", "empty file")
        return
    if depth > MAX_DEPTH:
        scan.add("block", "archive_too_deep", f"{name}: nested deeper than {MAX_DEPTH} archives")
        return
    fmt = detect_format(data)
    ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name.rsplit("/", 1)[-1] else ""
    if ext in _EXPECTED and fmt not in _EXPECTED[ext]:
        scan.add("warn", "extension_mismatch", f"{name}: {ext} file contains {fmt}")

    if fmt == "pickle":
        scan.add("warn", "pickle_format", f"{name or 'file'}: pickle can execute code when loaded")
        scan_pickle(data, scan, name if not top else "")
    elif fmt == "zip":
        _scan_zip(data, name, scan, depth)
    elif fmt == "tar":
        _scan_tar(data, name, scan, depth)
    elif fmt in ("7z", "rar", "compressed"):
        scan.add("block", "unsupported_archive", f"{name or 'file'}: {fmt} archives are not inspected")
    elif fmt == "npy":
        _scan_npy(data, name, scan)
    elif fmt == "hdf5":
        scan.add("warn", "format_not_inspected", f"{name or 'file'}: HDF5 contents are not inspected")
    elif fmt == "unknown" and top:
        scan.unparseable("unknown_format", "could not identify the file format")


def _safe_member(name: str) -> bool:
    parts = name.replace("\\", "/").split("/")
    return not (name.startswith(("/", "\\")) or ".." in parts or (len(name) > 1 and name[1] == ":"))


def _scan_zip(data: bytes, name: str, scan: Scan, depth: int) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except (zipfile.BadZipFile, ValueError) as exc:
        scan.unparseable("bad_archive", f"{name or 'zip'}: {type(exc).__name__}")
        return
    if len(infos) > scan.max_entries:
        scan.add("block", "too_many_entries", f"{name or 'zip'}: {len(infos)} entries")
        return
    declared = sum(i.file_size for i in infos)
    if declared > scan.max_unpacked - scan.unpacked or (
        declared > 16 * 1024 * 1024 and declared / max(len(data), 1) > 200
    ):
        scan.add("block", "decompression_bomb", f"{name or 'zip'}: expands to {declared} bytes")
        return
    for info in infos:
        if not _safe_member(info.filename):
            scan.add("block", "path_traversal", f"{name or 'zip'}: {info.filename}")
            continue
        if info.is_dir():
            continue
        try:
            member = zf.read(info)
        except Exception as exc:  # noqa: BLE001 - bad CRC, unsupported compression, ...
            scan.unparseable("bad_archive", f"{info.filename}: {type(exc).__name__}")
            continue
        scan.unpacked += len(member)
        if scan.unpacked > scan.max_unpacked:
            scan.add("block", "decompression_bomb", f"{name or 'zip'}: unpacked size over limit")
            return
        _scan_member(member, info.filename, scan, depth)


def _scan_tar(data: bytes, name: str, scan: Scan, depth: int) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            _scan_tar_members(tf, name, scan, depth)
    except Exception as exc:  # noqa: BLE001
        scan.unparseable("bad_archive", f"{name or 'tar'}: {type(exc).__name__}")


def _scan_tar_members(tf: tarfile.TarFile, name: str, scan: Scan, depth: int) -> None:
    members = tf.getmembers()
    if len(members) > scan.max_entries:
        scan.add("block", "too_many_entries", f"{name or 'tar'}: {len(members)} entries")
        return
    for m in members:
        if not _safe_member(m.name) or m.issym() or m.islnk():
            scan.add("block", "path_traversal", f"{name or 'tar'}: {m.name}")
            continue
        if not m.isfile():
            continue
        if m.size > scan.max_unpacked - scan.unpacked:
            scan.add("block", "decompression_bomb", f"{name or 'tar'}: unpacked size over limit")
            return
        fileobj = tf.extractfile(m)
        if fileobj is None:
            continue
        member = fileobj.read()
        scan.unpacked += len(member)
        _scan_member(member, m.name, scan, depth)


def _scan_member(member: bytes, member_name: str, scan: Scan, depth: int) -> None:
    fmt = detect_format(member)
    if fmt in ("pickle", "zip", "tar", "7z", "rar", "compressed", "npy") or member_name.endswith(
        _PICKLE_EXTS
    ):
        scan_bytes(member, member_name, scan, depth + 1)


def _scan_npy(data: bytes, name: str, scan: Scan) -> None:
    """.npy with an object dtype stores a pickle after the header."""
    try:
        major = data[6]
        hlen = struct.unpack("<H", data[8:10])[0] if major == 1 else struct.unpack("<I", data[8:12])[0]
        start = (10 if major == 1 else 12) + hlen
        header = data[(10 if major == 1 else 12) : start].decode("latin-1")
    except (IndexError, struct.error):
        scan.unparseable("unparseable_npy", f"{name or 'npy'}: bad header")
        return
    if "'O'" in header or "|O" in header:
        scan.add("warn", "pickle_format", f"{name or 'npy'}: object array (pickle inside)")
        scan_pickle(data[start:], scan, name or "npy")


# --- control ----------------------------------------------------------------------------------


def _cfg_val(cfg: Any, key: str, default: Any = None) -> Any:
    if hasattr(cfg, "get"):
        return cfg.get(key, default)
    return getattr(cfg, key, default) if hasattr(cfg, key) else default


def scan_artifact(
    data: bytes,
    filename: str,
    *,
    dangerous_feed: dict[str, str] | None = None,
    bad_hashes: dict[str, str] | None = None,
    reject_unparseable: bool = True,
    max_entries: int = 2000,
    max_unpacked: int = 512 * 1024 * 1024,
) -> Scan:
    scan = Scan(dict(dangerous_feed or {}), reject_unparseable, max_entries, max_unpacked)
    digest = hashlib.sha256(data).hexdigest()
    if bad_hashes and digest in bad_hashes:
        scan.add("block", "known_malicious_hash", f"sha256 {digest[:16]}... ({bad_hashes[digest]})")
    scan_bytes(data, filename, scan)
    return scan


@register_control
class ArtifactScanControl:
    id: str = "C-ARTIFACT"
    stages: tuple[Stage, ...] = (Stage.artifact,)
    priority: int = 30  # deterministic check < 100

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        target_action = Action(_cfg_val(cfg, "action", Action.block))
        threat_ids = list(_cfg_val(cfg, "threat_ids", ["TH-14"]))

        dangerous: dict[str, str] = {}
        bad_hashes: dict[str, str] = {}
        if bool(_cfg_val(cfg, "dangerous_globals_from_feed", True)):
            for sig in feeds.current().signatures:
                if sig.kind == "pickle_global":
                    dangerous[sig.pattern.strip()] = sig.id
                elif sig.kind == "sha256":
                    bad_hashes[sig.pattern.lower()] = sig.id

        filename = ""
        if ctx.segments:
            filename = str(ctx.segments[0].meta.get("filename") or ctx.segments[0].text)
        scan = scan_artifact(
            ctx.artifact or b"",
            filename,
            dangerous_feed=dangerous,
            bad_hashes=bad_hashes,
            reject_unparseable=bool(_cfg_val(cfg, "reject_unparseable", True)),
            max_entries=int(_cfg_val(cfg, "max_archive_entries", 2000)),
            max_unpacked=int(_cfg_val(cfg, "max_unpacked_bytes", 512 * 1024 * 1024)),
        )

        blocking = [f for f in scan.findings if f.level == "block"]
        warnings = [f for f in scan.findings if f.level == "warn"]
        matches = [Match(kind=f.code, masked=f.detail[:120]) for f in blocking + warnings][:20]
        if blocking:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=target_action,
                severity="critical",
                reason=f"unsafe artifact: {blocking[0].detail}",
                matches=matches,
            )
        if warnings and target_action != Action.allow:
            block_on_warn = bool(_cfg_val(cfg, "block_on_warn", False))
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=target_action if block_on_warn else Action.flag,
                severity="medium",
                reason=f"artifact needs review: {warnings[0].detail}",
                matches=matches,
            )
        return Decision(
            control_id=self.id,
            threat_ids=threat_ids,
            action=Action.allow,
            reason="artifact scanned, nothing unsafe found",
        )
