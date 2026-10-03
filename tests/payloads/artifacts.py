"""Generatory artefaktów do testów C-ARTIFACT / C-SUPPLY (TH-14, TH-16).

BEZPIECZEŃSTWO (ARCHITECTURE.md §0.5):
  * Te bajty NIGDY nie są ładowane (`pickle.loads`, `torch.load`, `joblib.load`).
  * Złośliwe pickle budujemy RĘCZNIE z opkodów — nic nie jest wykonywane ani
    nawet importowane. Sprawdzamy je wyłącznie statycznie (`pickletools.genops`).
  * Uwaga dla R2: `pickle.dumps(obj_z___reduce__(os.system))` na Linuksie zapisuje
    moduł `posix`, a nie `os` (os.system is posix.system). Feed musi zawierać oba
    warianty (`posix.system`, `nt.system`) — mamy na to osobne przypadki edge.

Rejestr GENERATORS: nazwa -> funkcja(**params) -> (bytes, sugerowana_nazwa_pliku).
Nazwy są używane w YAML: `artifact: {generator: pickle_os_system_p0}`.
"""

from __future__ import annotations

import io
import json
import pickle
import struct
import tarfile
import zipfile
from typing import Callable

CMD = "echo AICL-TEST-ONLY"   # komenda-atrapa; i tak nigdy nie zostanie uruchomiona


# --------------------------------------------------------------- budowanie opkodów
def _p0_global_reduce(module: str, name: str, arg: str = CMD) -> bytes:
    """Protokół 0: GLOBAL 'module name' + MARK + STRING + TUPLE + REDUCE + STOP."""
    return (f"c{module}\n{name}\n(S'{arg}'\ntR.").encode()


def _short_unicode(s: str) -> bytes:
    b = s.encode()
    return b"\x8c" + bytes([len(b)]) + b          # SHORT_BINUNICODE


def _p4_stack_global_reduce(module: str, name: str, arg: str = CMD) -> bytes:
    """Protokół 4: PROTO 4, SHORT_BINUNICODE x2, STACK_GLOBAL, arg, TUPLE1, REDUCE, STOP."""
    return (b"\x80\x04" + _short_unicode(module) + b"\x94" + _short_unicode(name) + b"\x94"
            + b"\x93" + _short_unicode(arg) + b"\x85" + b"R" + b".")


def pickle_benign(**_) -> tuple[bytes, str]:
    data = {"weights": [0.1, 0.2, 0.3], "layers": 3, "name": "tiny-model"}
    return pickle.dumps(data, protocol=4), "model.pkl"


def pickle_os_system_p0(**_) -> tuple[bytes, str]:
    return _p0_global_reduce("os", "system"), "model.pkl"


def pickle_os_system_p4(**_) -> tuple[bytes, str]:
    return _p4_stack_global_reduce("os", "system"), "model.pkl"


def pickle_posix_system(**_) -> tuple[bytes, str]:
    return _p4_stack_global_reduce("posix", "system"), "model.pkl"


def pickle_subprocess_popen(**_) -> tuple[bytes, str]:
    return _p4_stack_global_reduce("subprocess", "Popen"), "model.pkl"


def pickle_builtins_eval(**_) -> tuple[bytes, str]:
    return _p4_stack_global_reduce("builtins", "eval", "__import__('os').getcwd()"), "model.pkl"


def pickle_custom_global(module: str = "os", name: str = "system", **_) -> tuple[bytes, str]:
    return _p4_stack_global_reduce(module, name), "model.pkl"


def pickle_broken_after_payload(**_) -> tuple[bytes, str]:
    """Niebezpieczne wywołanie PRZED miejscem uszkodzenia (§7.1: liczy się!)."""
    good = _p4_stack_global_reduce("os", "system")[:-1]       # bez STOP
    return good + b"\xff\xfe\x00garbage-to-break-genops", "model.pkl"


def pickle_truncated_benign(**_) -> tuple[bytes, str]:
    """Uszkodzony, ale bez niebezpiecznych opkodów -> reject_unparseable decyduje."""
    data, _ = pickle_benign()
    return data[: len(data) // 2], "model.pkl"


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def torch_like_zip_malicious(**_) -> tuple[bytes, str]:
    """Układ jak w formacie torch.save (zip z archive/data.pkl)."""
    return _zip({"archive/data.pkl": pickle_os_system_p4()[0],
                 "archive/version": b"3\n"}), "model.pt"


def torch_like_zip_benign(**_) -> tuple[bytes, str]:
    return _zip({"archive/data.pkl": pickle_benign()[0], "archive/version": b"3\n"}), "model.pt"


def nested_zip_malicious(**_) -> tuple[bytes, str]:
    inner = _zip({"payload.pkl": pickle_os_system_p0()[0]})
    return _zip({"bundle/inner.zip": inner, "README.txt": b"nothing to see"}), "bundle.zip"


def tar_malicious(**_) -> tuple[bytes, str]:
    buf = io.BytesIO()
    data = pickle_os_system_p0()[0]
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        info = tarfile.TarInfo("model/data.pkl")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    return buf.getvalue(), "model.tar.gz"


def unknown_archive_7z(**_) -> tuple[bytes, str]:
    """Nieznany format archiwum -> ma być odrzucony, nie pominięty (§7.1)."""
    return b"7z\xbc\xaf\x27\x1c\x00\x04" + b"\x00" * 64, "model.7z"


def safetensors_benign(**_) -> tuple[bytes, str]:
    header = json.dumps({"w": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}}).encode()
    return struct.pack("<Q", len(header)) + header + struct.pack("<2f", 0.5, 1.5), "model.safetensors"


def empty_file(**_) -> tuple[bytes, str]:
    return b"", "empty.pkl"


GENERATORS: dict[str, Callable[..., tuple[bytes, str]]] = {
    f.__name__: f for f in (
        pickle_benign, pickle_os_system_p0, pickle_os_system_p4, pickle_posix_system,
        pickle_subprocess_popen, pickle_builtins_eval, pickle_custom_global,
        pickle_broken_after_payload, pickle_truncated_benign,
        torch_like_zip_malicious, torch_like_zip_benign, nested_zip_malicious,
        tar_malicious, unknown_archive_7z, safetensors_benign, empty_file,
    )
}


def build(generator: str, **params) -> tuple[bytes, str]:
    if generator not in GENERATORS:
        raise KeyError(f"nieznany generator artefaktu: {generator}; dostępne: {sorted(GENERATORS)}")
    return GENERATORS[generator](**params)
