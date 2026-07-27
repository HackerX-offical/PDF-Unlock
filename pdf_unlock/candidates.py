"""Password candidate generators."""

from __future__ import annotations

import itertools
import string
from collections.abc import Iterable, Iterator
from importlib import resources
from pathlib import Path


def unique(seq: Iterable[str]) -> Iterator[str]:
    seen: set[str] = set()
    for item in seq:
        if item not in seen:
            seen.add(item)
            yield item


def load_wordlist(path: Path) -> list[str]:
    lines: list[str] = []
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            password = line.strip()
            if password:
                lines.append(password)
    return lines


def bundled_common_passwords() -> list[str]:
    """Built-in common list; empty string first (open with no password)."""
    text = resources.files("pdf_unlock.data").joinpath("common.txt").read_text(
        encoding="utf-8"
    )
    return [""] + [line.strip() for line in text.splitlines() if line.strip()]


def filename_candidates(path: Path) -> list[str]:
    stem = path.stem
    parts = [stem]
    lower = stem.lower()
    for prefix in ("receipt", "invoice", "order", "doc", "file"):
        if lower.startswith(prefix):
            rest = stem[len(prefix) :].lstrip("_- ")
            parts.append(rest)
    digits = "".join(ch if ch.isdigit() else " " for ch in stem).split()
    parts.extend(digits)
    for run in digits:
        if len(run) > 4:
            parts.extend((run[-4:], run[-6:], run[-8:], run[:6], run[:8]))

    years = [str(year) for year in range(2018, 2031)]
    suffixes = ("!", "@", "#", "123", "1234", "@123")
    out: list[str] = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        out.append(part)
        for year in years:
            out.append(f"{part}{year}")
            out.append(f"{year}{part}")
        for suffix in suffixes:
            out.append(f"{part}{suffix}")
    return list(unique(out))


def dob_candidates(year_start: int, year_end: int) -> Iterator[str]:
    """DDMMYYYY / YYYYMMDD / DDMMYY — recent years first."""
    years = list(range(year_start, year_end + 1))
    years.sort(key=lambda year: (0 if 1990 <= year <= year_end else 1, -year))
    for year in years:
        for month in range(1, 13):
            for day in range(1, 32):
                if month in (4, 6, 9, 11) and day > 30:
                    continue
                if month == 2 and day > 29:
                    continue
                yield f"{day:02d}{month:02d}{year}"
                yield f"{year}{month:02d}{day:02d}"
                yield f"{day:02d}{month:02d}{year % 100:02d}"


def digit_candidates(max_len: int) -> Iterator[str]:
    for length in range(1, max_len + 1):
        for tup in itertools.product("0123456789", repeat=length):
            yield "".join(tup)


def alnum_candidates(max_len: int) -> Iterator[str]:
    alphabet = string.ascii_lowercase + string.digits
    for length in range(1, max_len + 1):
        for tup in itertools.product(alphabet, repeat=length):
            yield "".join(tup)
