"""C-ARTIFACT scanner unit tests and /v1/artifacts/scan size handling.
All payloads are built from opcodes or pickle.dumps and are NEVER loaded (§0.5)."""

from __future__ import annotations

import hashlib
import io
import struct
import tarfile

import pytest

from aicl.controls.artifact import detect_format, scan_artifact
from tests.payloads import artifacts as A


def verdict(data: bytes, name: str = "model.pkl", **kw) -> tuple[str, set[str]]:
    scan = scan_artifact(data, name, **kw)
    codes = {f.code for f in scan.findings}
    if any(f.level == "block" for f in scan.findings):
        return "block", codes
    return ("warn" if scan.findings else "allow"), codes


def _u(s: str) -> bytes:
    b = s.encode()
    return b"\x8c" + bytes([len(b)]) + b


def test_stack_model_survives_decoy_pushed_after_memo_get():
    # GET os, GET system, push decoy, POP decoy, STACK_GLOBAL -> still os.system
    data = (b"\x80\x04" + _u("os") + b"\x94" + b"0" + _u("system") + b"\x94" + b"0"
            + b"h\x00" + b"h\x01" + _u("decoy") + b"0" + b"\x93" + _u("x") + b"\x85R.")  # fmt: skip
    assert verdict(data) == ("block", {"dangerous_global", "pickle_format"})


@pytest.mark.parametrize("module,name", [("builtins", "getattr"), ("os", "execv"), ("socket", "socket")])
def test_denylist_is_module_level_and_covers_dangerous_builtins(module, name):
    assert verdict(A.pickle_custom_global(module=module, name=name)[0])[0] == "block"


def test_unknown_global_is_a_warning_not_a_block():
    assert verdict(A.pickle_custom_global(module="mylib.models", name="Net")[0]) == (
        "warn",
        {"unknown_global", "pickle_format"},
    )


def test_extension_mismatch_is_reported_and_content_still_scanned():
    v, codes = verdict(A.pickle_os_system_p0()[0], "weights.safetensors")
    assert v == "block" and {"extension_mismatch", "dangerous_global"} <= codes


def test_safetensors_is_clean():
    data, name = A.safetensors_benign()
    assert detect_format(data) == "safetensors" and verdict(data, name) == ("allow", set())


def test_npy_object_array_pickle_is_scanned():
    payload = A.pickle_os_system_p4()[0]
    header = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,), }".ljust(118) + b"\n"
    data = b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header + payload
    assert verdict(data, "arr.npy")[0] == "block"


def test_tar_with_symlink_or_traversal_is_refused():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        link = tarfile.TarInfo("model/data.pkl")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        t.addfile(link)
    assert verdict(buf.getvalue(), "model.tar") == ("block", {"path_traversal"})


def test_known_malicious_hash_from_feed():
    data = A.pickle_benign()[0]
    digest = hashlib.sha256(data).hexdigest()
    assert "known_malicious_hash" in verdict(data, bad_hashes={digest: "SIG-HASH-1"})[1]


def test_feed_pickle_global_signature_is_named():
    scan = scan_artifact(A.pickle_custom_global(module="evil_pkg", name="run")[0], "m.pkl",
                         dangerous_feed={"evil_pkg.run": "SIG-PKL-099"})  # fmt: skip
    assert any(f.code == "feed_signature" and "SIG-PKL-099" in f.detail for f in scan.findings)


def test_unknown_format_refused_only_when_configured():
    assert verdict(b"just some text file", "notes.txt")[0] == "block"
    assert verdict(b"just some text file", "notes.txt", reject_unparseable=False)[0] == "warn"


# --- through the gateway ------------------------------------------------------------------------


@pytest.mark.gateway
async def test_raw_upload_larger_than_body_limit_is_accepted(gateway):
    # max_body_bytes (1 MB) protects JSON endpoints; uploads use max_artifact_bytes (100 MB).
    data, name = A.safetensors_benign()
    big = data[:8] + data[8:] + b"\x00" * (2 * 1024 * 1024)  # still a valid header, extra tensor bytes
    async with gateway(profile="balanced") as gw:
        r = await gw.client.post("/v1/artifacts/scan", content=big,
                                 headers={**gw.auth("support-agent-01"), "X-AICL-Filename": name})  # fmt: skip
    assert r.status_code == 200, r.text
    assert r.json()["verdict"] == "clean" and r.json()["size"] == len(big)


@pytest.mark.gateway
async def test_upload_over_artifact_limit_is_rejected_before_parsing(gateway):
    overlay = {"controls": {"size_limits": {"params": {"max_artifact_bytes": 1024}}}}
    async with gateway(overlay=overlay, profile="balanced") as gw:
        h = gw.auth("support-agent-01")
        raw = await gw.client.post("/v1/artifacts/scan", content=b"\x00" * 4096, headers=h)
        multi = await gw.client.post("/v1/artifacts/scan", headers=h,
                                     files={"file": ("m.pkl", b"\x00" * (200 * 1024), "application/octet-stream")})  # fmt: skip
    for r in (raw, multi):
        assert r.status_code == 403 and r.json()["error"]["control_id"] == "C-SIZE"


@pytest.mark.gateway
async def test_strict_profile_blocks_on_warnings(gateway):
    data, name = A.pickle_benign()  # raw pickle: a warning only
    async with gateway(profile="strict") as gw:
        r = await gw.client.post("/v1/artifacts/scan", headers=gw.auth("support-agent-01"),
                                 files={"file": (name, data, "application/octet-stream")})  # fmt: skip
    assert r.status_code == 403 and r.json()["error"]["control_id"] == "C-ARTIFACT"


@pytest.mark.gateway
async def test_flagged_verdict_lists_findings(gateway):
    data, name = A.pickle_benign()
    async with gateway(profile="balanced") as gw:
        r = await gw.client.post("/v1/artifacts/scan", headers=gw.auth("support-agent-01"),
                                 files={"file": (name, data, "application/octet-stream")})  # fmt: skip
    assert r.status_code == 200 and r.headers["x-aicl-action"] == "flag"
    assert r.json()["verdict"] == "flagged" and "pickle_format" in r.json()["findings"]
