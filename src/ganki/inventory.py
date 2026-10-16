"""Search, sort and page through the installed packages (pure functions, no I/O)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from ganki.collectors.apt import Package

PAGE_SIZE = 100
MAX_QUERY_CHARS = 100
SORTS = ("size", "name", "date")
_EPOCH = datetime.min.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class Page:
    """One page of a filtered inventory, plus totals for the whole selection."""

    items: list[Package]
    number: int  # 1-based
    pages: int
    total: int  # packages matching the filters
    total_kib: int  # their combined installed size


def select(
    packages: list[Package], query: str = "", manual_only: bool = False, sort: str = "size"
) -> list[Package]:
    """Filter by text (name or description) and origin, then sort."""
    text = query.strip().lower()[:MAX_QUERY_CHARS]
    chosen = [
        p
        for p in packages
        if (not manual_only or p.manual)
        and (not text or text in p.name.lower() or text in p.description.lower())
    ]
    if sort == "name":
        return sorted(chosen, key=lambda p: p.name)
    if sort == "date":
        return sorted(chosen, key=lambda p: p.installed_at or _EPOCH, reverse=True)
    return sorted(chosen, key=lambda p: (-p.size_kib, p.name))


def paginate(selected: list[Package], number: int = 1, size: int = PAGE_SIZE) -> Page:
    """Slice one page out of ``selected``; out-of-range numbers are clamped."""
    pages = max(1, -(-len(selected) // size))
    number = min(max(number, 1), pages)
    start = (number - 1) * size
    return Page(
        items=selected[start : start + size],
        number=number,
        pages=pages,
        total=len(selected),
        total_kib=sum(p.size_kib for p in selected),
    )


def human_size(kib: int) -> str:
    """``1536`` -> ``1.5 MiB``."""
    value = float(kib)
    for unit in ("KiB", "MiB", "GiB"):
        if value < 1024:
            return f"{value:.0f} {unit}" if unit == "KiB" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"
