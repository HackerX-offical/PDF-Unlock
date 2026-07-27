"""Interactive prompts and CLI argument parsing."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from pdf_unlock import __version__
from pdf_unlock.attacks import AttackConfig
from pdf_unlock.pipeline import SUCCESS_STATUSES, run_pipeline


def _prompt(label: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        raw = input(f"{label}{suffix}: ").strip().strip("'\"")
        if raw:
            return raw
        if default is not None:
            return default
        print("  Please enter a value.")


def _prompt_yes_no(label: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    raw = input(f"{label} [{hint}]: ").strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes"}


def _prompt_int(label: str, default: int, minimum: int = 0, maximum: int = 32) -> int:
    while True:
        raw = input(f"{label} [{default}]: ").strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            print("  Enter a number.")
            continue
        if minimum <= value <= maximum:
            return value
        print(f"  Enter a number between {minimum} and {maximum}.")


def interactive_config() -> tuple[Path, Path, AttackConfig]:
    print()
    print("=" * 60)
    print(f"  PDF Unlock Tool  v{__version__}")
    print("  Recover forgotten PDF passwords and write unlocked copies")
    print("=" * 60)
    print()

    source = Path(_prompt("PDF file or folder path")).expanduser()
    while not source.exists():
        print(f"  Path not found: {source}")
        source = Path(_prompt("PDF file or folder path")).expanduser()

    default_out = (
        (source.parent / "unlocked").resolve()
        if source.is_file()
        else (source / "unlocked").resolve()
    )
    output = Path(
        _prompt("Output folder for unlocked PDFs", str(default_out))
    ).expanduser()

    print()
    print("Attack options (press Enter to accept defaults):")
    max_digits = _prompt_int("Max digit password length to brute-force", 8, 0, 10)
    run_dob = _prompt_yes_no("Try date-of-birth patterns (DDMMYYYY etc.)", True)
    run_alnum = _prompt_yes_no("Also brute-force short a-z0-9 (slow)", False)
    max_alnum = _prompt_int("Max alnum length", 3, 1, 5) if run_alnum else 0
    workers = _prompt_int(
        "Parallel workers",
        max(1, (os.cpu_count() or 4) // 2),
        1,
        32,
    )

    wordlist_raw = input(
        "Optional extra wordlist path (Enter to skip): "
    ).strip().strip("'\"")
    extra = Path(wordlist_raw).expanduser() if wordlist_raw else None

    print()
    input("Press Enter to start… ")

    config = AttackConfig(
        max_digit_len=max_digits,
        max_alnum_len=max_alnum,
        run_digits=max_digits > 0,
        run_dob=run_dob,
        run_alnum=run_alnum,
        workers=workers,
        extra_wordlist=extra,
    )
    return source, output, config


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="unlock-pdf",
        description="Recover PDF passwords and write decrypted copies.",
    )
    parser.add_argument("-i", "--input", help="PDF file or folder")
    parser.add_argument("-o", "--output", help="Output folder for unlocked PDFs")
    parser.add_argument("--max-digits", type=int, default=8)
    parser.add_argument(
        "--max-alnum",
        type=int,
        default=0,
        help="0 disables alphanumeric brute-force",
    )
    parser.add_argument("--no-dob", action="store_true", help="Skip date-pattern attack")
    parser.add_argument(
        "--workers",
        type=int,
        default=max(1, (os.cpu_count() or 4) // 2),
    )
    parser.add_argument("--wordlist", type=Path, help="Extra password wordlist")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Non-interactive (requires --input and --output)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if args.yes or (args.input and args.output):
        if not args.input or not args.output:
            print(
                "Non-interactive mode requires --input and --output",
                file=sys.stderr,
            )
            return 2
        source = Path(args.input).expanduser()
        output = Path(args.output).expanduser()
        config = AttackConfig(
            max_digit_len=args.max_digits,
            max_alnum_len=args.max_alnum,
            run_digits=args.max_digits > 0,
            run_dob=not args.no_dob,
            run_alnum=args.max_alnum > 0,
            workers=args.workers,
            extra_wordlist=args.wordlist,
        )
    else:
        source, output, config = interactive_config()

    try:
        outcomes = run_pipeline(source, output, config)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0 if any(item.status in SUCCESS_STATUSES for item in outcomes) else 1


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
