"""Attack orchestration: try candidate streams until a password verifies."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from pdf_unlock.candidates import (
    alnum_candidates,
    bundled_common_passwords,
    digit_candidates,
    dob_candidates,
    filename_candidates,
    load_wordlist,
    unique,
)
from pdf_unlock.crypto import verify_password
from pdf_unlock.parse import EncryptInfo

ProgressCb = Callable[[str, int, float], None]
StageCb = Callable[[str], None]


@dataclass
class AttackConfig:
    max_digit_len: int = 8
    max_alnum_len: int = 0
    dob_year_start: int = 1950
    dob_year_end: int = 2030
    workers: int = 4
    run_digits: bool = True
    run_alnum: bool = False
    run_dob: bool = True
    extra_wordlist: Path | None = None


@dataclass
class CrackResult:
    password: str | None
    method: str
    attempts: int = 0
    elapsed_sec: float = 0.0
    tried_stages: list[str] = field(default_factory=list)

    @property
    def found(self) -> bool:
        return self.password is not None


def _info_to_meta(info: EncryptInfo) -> dict:
    return {
        "path": str(info.path),
        "revision": info.revision,
        "version": info.version,
        "length": info.length,
        "permissions": info.permissions,
        "o_entry": info.o_entry,
        "u_entry": info.u_entry,
        "file_id": info.file_id,
        "encrypted": info.encrypted,
    }


def _meta_to_info(meta: dict) -> EncryptInfo:
    return EncryptInfo(
        path=Path(meta["path"]),
        revision=meta["revision"],
        version=meta["version"],
        length=meta["length"],
        permissions=meta["permissions"],
        o_entry=meta["o_entry"],
        u_entry=meta["u_entry"],
        file_id=meta["file_id"],
        encrypted=meta["encrypted"],
    )


def _worker_batch(args: tuple[list[str], dict]) -> str | None:
    passwords, meta = args
    info = _meta_to_info(meta)
    for password in passwords:
        if verify_password(password, info):
            return password
    return None


def _chunked(items: list[str], size: int) -> Iterator[list[str]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


def _dispatch_wave(
    pool: ProcessPoolExecutor,
    wave: list[str],
    meta: dict,
    chunk: int,
) -> str | None:
    futures = [
        pool.submit(_worker_batch, (piece, meta)) for piece in _chunked(wave, chunk)
    ]
    for future in as_completed(futures):
        hit = future.result()
        if hit is not None:
            for other in futures:
                other.cancel()
            return hit
    return None


def _run_stream(
    name: str,
    info: EncryptInfo,
    candidates: Iterable[str],
    *,
    workers: int,
    on_progress: ProgressCb | None = None,
    batch_size: int = 4000,
) -> tuple[str | None, int]:
    started = time.time()
    attempts = 0
    meta = _info_to_meta(info)

    def report() -> None:
        if on_progress:
            on_progress(name, attempts, time.time() - started)

    use_pool = workers > 1 and info.supports_fast_verify

    if not use_pool:
        for password in unique(candidates):
            attempts += 1
            if verify_password(password, info):
                report()
                return password, attempts
            if attempts % 5000 == 0:
                report()
        report()
        return None, attempts

    wave: list[str] = []
    wave_target = batch_size * workers
    chunk = max(500, batch_size // 2)

    with ProcessPoolExecutor(max_workers=workers) as pool:
        for password in unique(candidates):
            wave.append(password)
            if len(wave) < wave_target:
                continue
            hit = _dispatch_wave(pool, wave, meta, chunk)
            attempts += len(wave)
            report()
            if hit is not None:
                return hit, attempts
            wave.clear()
        if wave:
            hit = _dispatch_wave(pool, wave, meta, chunk)
            attempts += len(wave)
            report()
            if hit is not None:
                return hit, attempts

    report()
    return None, attempts


def crack_password(
    info: EncryptInfo,
    config: AttackConfig,
    on_progress: ProgressCb | None = None,
    on_stage: StageCb | None = None,
) -> CrackResult:
    if not info.encrypted:
        return CrackResult(password="", method="unencrypted", tried_stages=["unencrypted"])

    stages: list[str] = []
    total = 0
    started = time.time()

    def stage(name: str) -> None:
        stages.append(name)
        if on_stage:
            on_stage(name)

    def succeed(password: str, method: str) -> CrackResult:
        return CrackResult(
            password=password,
            method=method,
            attempts=total,
            elapsed_sec=time.time() - started,
            tried_stages=stages,
        )

    stage("common")
    password, count = _run_stream(
        "common", info, bundled_common_passwords(), workers=1, on_progress=on_progress
    )
    total += count
    if password is not None:
        return succeed(password, "common")

    stage("filename")
    password, count = _run_stream(
        "filename",
        info,
        filename_candidates(info.path),
        workers=1,
        on_progress=on_progress,
    )
    total += count
    if password is not None:
        return succeed(password, "filename")

    if config.extra_wordlist and config.extra_wordlist.is_file():
        stage("wordlist")
        password, count = _run_stream(
            "wordlist",
            info,
            load_wordlist(config.extra_wordlist),
            workers=config.workers,
            on_progress=on_progress,
        )
        total += count
        if password is not None:
            return succeed(password, "wordlist")

    if config.run_dob:
        stage("dob")
        password, count = _run_stream(
            "dob",
            info,
            dob_candidates(config.dob_year_start, config.dob_year_end),
            workers=config.workers,
            on_progress=on_progress,
        )
        total += count
        if password is not None:
            return succeed(password, "dob")

    if config.run_digits and config.max_digit_len > 0:
        stage(f"digits(1-{config.max_digit_len})")
        password, count = _run_stream(
            "digits",
            info,
            digit_candidates(config.max_digit_len),
            workers=config.workers,
            on_progress=on_progress,
        )
        total += count
        if password is not None:
            return succeed(password, "digits")

    if config.run_alnum and config.max_alnum_len > 0:
        stage(f"alnum(1-{config.max_alnum_len})")
        password, count = _run_stream(
            "alnum",
            info,
            alnum_candidates(config.max_alnum_len),
            workers=config.workers,
            on_progress=on_progress,
        )
        total += count
        if password is not None:
            return succeed(password, "alnum")

    return CrackResult(
        password=None,
        method="failed",
        attempts=total,
        elapsed_sec=time.time() - started,
        tried_stages=stages,
    )
