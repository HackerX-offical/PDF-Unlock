"""Write decrypted (or copied) PDFs to an output directory."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from shutil import which


@dataclass(frozen=True)
class DecryptResult:
    source: Path
    output: Path | None
    ok: bool
    detail: str


def _destination(source: Path, output_dir: Path, *, fallback_prefix: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    dest = output_dir / source.name
    if dest.resolve() == source.resolve() or dest.exists():
        dest = output_dir / f"{fallback_prefix}{source.name}"
    return dest


def decrypt_pdf(source: Path, output_dir: Path, password: str) -> DecryptResult:
    source = source.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    dest = _destination(source, output_dir, fallback_prefix="unlocked_")

    qpdf = which("qpdf")
    if qpdf:
        proc = subprocess.run(
            [qpdf, f"--password={password}", "--decrypt", str(source), str(dest)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0 and dest.is_file():
            return DecryptResult(source, dest, True, "qpdf")

    try:
        import pikepdf
    except ImportError as exc:
        return DecryptResult(source, None, False, f"no decrypt backend: {exc}")

    try:
        with pikepdf.open(source, password=password) as pdf:
            pdf.save(dest)
        return DecryptResult(source, dest, True, "pikepdf")
    except Exception as exc:  # noqa: BLE001 — surface any open/save failure
        return DecryptResult(source, None, False, str(exc))


def copy_unencrypted(source: Path, output_dir: Path) -> DecryptResult:
    source = source.expanduser().resolve()
    dest = _destination(
        source,
        output_dir.expanduser().resolve(),
        fallback_prefix="copy_",
    )
    shutil.copy2(source, dest)
    return DecryptResult(source, dest, True, "copied (already unlocked)")
