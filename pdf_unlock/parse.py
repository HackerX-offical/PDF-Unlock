"""Parse PDF encryption metadata without needing the password."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_OBJ_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj\b(.*?)endobj", re.S)
_ENCRYPT_REF_RE = re.compile(rb"/Encrypt\s+(\d+)\s+(\d+)\s+R")
_ID_RE = re.compile(rb"/ID\s*\[\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*\]")


@dataclass(frozen=True)
class EncryptInfo:
    path: Path
    revision: int
    version: int
    length: int
    permissions: int
    o_entry: bytes
    u_entry: bytes
    file_id: bytes
    encrypted: bool = True

    @property
    def supports_fast_verify(self) -> bool:
        """True when native RC4 R2/R3 verification applies."""
        return self.encrypted and self.revision in (2, 3) and self.version <= 2

    @property
    def summary(self) -> str:
        if not self.encrypted:
            return "not encrypted"
        algo = "RC4" if self.version <= 2 else f"V{self.version}"
        return (
            f"{algo} R{self.revision} {self.length}-bit | "
            f"P={self.permissions} | ID={self.file_id.hex()[:16]}…"
        )


def _extract_objects(data: bytes) -> dict[tuple[int, int], bytes]:
    return {
        (int(m.group(1)), int(m.group(2))): m.group(3)
        for m in _OBJ_RE.finditer(data)
    }


def parse_encrypt_info(path: Path | str) -> EncryptInfo:
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"PDF not found: {path}")

    data = path.read_bytes()
    if not data.startswith(b"%PDF"):
        raise ValueError(f"Not a PDF file: {path}")

    ref = _ENCRYPT_REF_RE.search(data)
    if not ref:
        return EncryptInfo(
            path=path,
            revision=0,
            version=0,
            length=0,
            permissions=0,
            o_entry=b"",
            u_entry=b"",
            file_id=b"",
            encrypted=False,
        )

    objs = _extract_objects(data)
    enc = objs.get((int(ref.group(1)), int(ref.group(2))))
    if enc is None:
        raise ValueError(f"Encrypt object missing in {path.name}")

    o_m = re.search(rb"/O\s*<([0-9A-Fa-f]+)>", enc)
    u_m = re.search(rb"/U\s*<([0-9A-Fa-f]+)>", enc)
    p_m = re.search(rb"/P\s+(-?\d+)", enc)
    l_m = re.search(rb"/Length\s+(\d+)", enc)
    r_m = re.search(rb"/R\s+(\d+)", enc)
    v_m = re.search(rb"/V\s+(\d+)", enc)
    id_m = _ID_RE.search(data)

    if not all((o_m, u_m, p_m, r_m, v_m, id_m)):
        raise ValueError(f"Incomplete Encrypt dict in {path.name}")

    assert o_m and u_m and p_m and r_m and v_m and id_m
    return EncryptInfo(
        path=path,
        revision=int(r_m.group(1)),
        version=int(v_m.group(1)),
        length=int(l_m.group(1)) if l_m else 40,
        permissions=int(p_m.group(1)),
        o_entry=bytes.fromhex(o_m.group(1).decode()),
        u_entry=bytes.fromhex(u_m.group(1).decode()),
        file_id=bytes.fromhex(id_m.group(1).decode()),
        encrypted=True,
    )


def collect_pdfs(target: Path | str) -> list[Path]:
    target = Path(target).expanduser().resolve()
    if target.is_file():
        if target.suffix.lower() != ".pdf":
            raise ValueError(f"Expected a .pdf file, got: {target}")
        return [target]
    if target.is_dir():
        pdfs = sorted(p for p in target.rglob("*.pdf") if p.is_file())
        if not pdfs:
            raise FileNotFoundError(f"No PDF files under: {target}")
        return pdfs
    raise FileNotFoundError(f"Path does not exist: {target}")
