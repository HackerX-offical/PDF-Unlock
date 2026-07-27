"""End-to-end unlock pipeline for one or many PDFs."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from pdf_unlock.attacks import AttackConfig, CrackResult, crack_password
from pdf_unlock.crypto import verify_password
from pdf_unlock.decrypt import copy_unencrypted, decrypt_pdf
from pdf_unlock.parse import EncryptInfo, collect_pdfs, parse_encrypt_info

SUCCESS_STATUSES = frozenset({"unlocked", "already unlocked (copied)"})


@dataclass
class FileOutcome:
    path: Path
    encrypt: EncryptInfo
    crack: CrackResult
    output: Path | None
    status: str

    @property
    def ok(self) -> bool:
        return self.status in SUCCESS_STATUSES


def _format_password(password: str | None) -> str:
    if password is None:
        return ""
    return "(empty)" if password == "" else password


def _progress(stage: str, attempts: int, elapsed: float) -> None:
    rate = attempts / elapsed if elapsed > 0 else 0.0
    print(f"\r  [{stage}] tried {attempts:,}  ({rate:,.0f}/s)   ", end="", flush=True)


def _empty_encrypt(path: Path) -> EncryptInfo:
    return EncryptInfo(path, 0, 0, 0, 0, b"", b"", b"", encrypted=False)


def process_one(
    path: Path,
    output_dir: Path,
    config: AttackConfig,
    *,
    known_passwords: list[str] | None = None,
) -> FileOutcome:
    print()
    print(f"── {path.name}")

    try:
        info = parse_encrypt_info(path)
    except Exception as exc:  # noqa: BLE001
        print(f"  ERROR parsing: {exc}")
        return FileOutcome(
            path,
            _empty_encrypt(path),
            CrackResult(None, "parse-error"),
            None,
            f"parse-error: {exc}",
        )

    print(f"  Encryption: {info.summary}")

    if not info.encrypted:
        result = copy_unencrypted(path, output_dir)
        return FileOutcome(
            path,
            info,
            CrackResult("", "unencrypted"),
            result.output,
            "already unlocked (copied)",
        )

    if not info.supports_fast_verify:
        print(
            "  Note: newer encryption — fast RC4 verifier unavailable; "
            "wordlist / library checks still run."
        )

    if known_passwords:
        print("  Stage → known-from-siblings")
        for password in known_passwords:
            if not verify_password(password, info):
                continue
            print(f"  FOUND password: {_format_password(password)}  via sibling-reuse")
            decrypted = decrypt_pdf(path, output_dir, password)
            crack = CrackResult(password, "sibling-reuse", 1, 0.0, ["sibling-reuse"])
            if decrypted.ok:
                print(f"  Wrote: {decrypted.output}  [{decrypted.detail}]")
                return FileOutcome(path, info, crack, decrypted.output, "unlocked")
            return FileOutcome(
                path,
                info,
                crack,
                None,
                f"decrypt-failed: {decrypted.detail}",
            )

    def on_stage(name: str) -> None:
        print(f"\n  Stage → {name}")

    crack = crack_password(info, config, on_progress=_progress, on_stage=on_stage)
    print()

    if not crack.found:
        print(
            f"  FAILED after {crack.attempts:,} attempts "
            f"in {crack.elapsed_sec:.1f}s (stages: {', '.join(crack.tried_stages)})"
        )
        return FileOutcome(path, info, crack, None, "password not found")

    print(
        f"  FOUND password: {_format_password(crack.password)}  via {crack.method} "
        f"({crack.attempts:,} attempts, {crack.elapsed_sec:.1f}s)"
    )
    decrypted = decrypt_pdf(path, output_dir, crack.password or "")
    if decrypted.ok:
        print(f"  Wrote: {decrypted.output}  [{decrypted.detail}]")
        return FileOutcome(path, info, crack, decrypted.output, "unlocked")
    print(f"  Decrypt failed: {decrypted.detail}")
    return FileOutcome(
        path, info, crack, None, f"decrypt-failed: {decrypted.detail}"
    )


def print_report(outcomes: list[FileOutcome], elapsed: float) -> None:
    succeeded = [item for item in outcomes if item.ok]
    failed = [item for item in outcomes if not item.ok]

    print()
    print("=" * 60)
    print("  RESULT")
    print("=" * 60)
    print(f"  Processed : {len(outcomes)}")
    print(f"  Succeeded : {len(succeeded)}")
    print(f"  Failed    : {len(failed)}")
    print(f"  Time      : {elapsed:.1f}s")
    print()
    for item in outcomes:
        line = f"  • {item.path.name}: {item.status}"
        if item.crack.found:
            line += (
                f" | password={_format_password(item.crack.password)}"
                f" | method={item.crack.method}"
            )
        if item.output:
            line += f" | out={item.output}"
        print(line)
    print("=" * 60)


def plan_summary(config: AttackConfig) -> str:
    parts = ["common", "filename"]
    if config.extra_wordlist:
        parts.append("wordlist")
    if config.run_dob:
        parts.append("dob")
    if config.run_digits and config.max_digit_len > 0:
        parts.append(f"digits(1-{config.max_digit_len})")
    if config.run_alnum and config.max_alnum_len > 0:
        parts.append(f"alnum(1-{config.max_alnum_len})")
    return " → ".join(parts) + " → done"


def run_pipeline(
    source: Path,
    output_dir: Path,
    config: AttackConfig,
) -> list[FileOutcome]:
    pdfs = collect_pdfs(source)
    print()
    print(f"Input  : {source.resolve()}")
    print(f"Output : {output_dir.resolve()}")
    print(f"PDFs   : {len(pdfs)}")
    print(f"Plan   : {plan_summary(config)}")

    started = time.time()
    outcomes: list[FileOutcome] = []
    known: list[str] = []

    for pdf in pdfs:
        outcome = process_one(pdf, output_dir, config, known_passwords=known)
        outcomes.append(outcome)
        if outcome.crack.found and outcome.crack.password is not None:
            if outcome.crack.password not in known:
                known.append(outcome.crack.password)

    print_report(outcomes, time.time() - started)
    return outcomes
