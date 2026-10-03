"""Sanity generatorów artefaktów — wyłącznie STATYCZNIE (pickletools.genops), nigdy pickle.loads."""

from __future__ import annotations

import io
import pickletools
import zipfile

import pytest

from tests.payloads import artifacts as A


def _globals(data: bytes) -> tuple[set[str], bool]:
    found, strs, broken = set(), [], False
    try:
        for op, arg, _ in pickletools.genops(io.BytesIO(data)):
            if op.name == "GLOBAL":
                found.add(arg.replace(" ", "."))
            elif "UNICODE" in op.name:
                strs.append(arg)
            elif op.name == "STACK_GLOBAL":
                found.add(f"{strs[-2]}.{strs[-1]}")
    except Exception:
        broken = True
    return found, broken


@pytest.mark.parametrize("gen,expected", [
    ("pickle_os_system_p0", "os.system"), ("pickle_os_system_p4", "os.system"),
    ("pickle_posix_system", "posix.system"), ("pickle_subprocess_popen", "subprocess.Popen"),
    ("pickle_builtins_eval", "builtins.eval")])
def test_malicious_pickles_contain_global(gen, expected):
    found, broken = _globals(A.build(gen)[0])
    assert expected in found and not broken


def test_broken_stream_keeps_payload_before_break():
    found, broken = _globals(A.build("pickle_broken_after_payload")[0])
    assert broken and "os.system" in found


def test_benign_pickle_has_no_globals():
    found, broken = _globals(A.build("pickle_benign")[0])
    assert not found and not broken


def test_torch_like_zip_layout():
    data, name = A.build("torch_like_zip_malicious")
    assert name.endswith(".pt")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        assert "archive/data.pkl" in z.namelist()
