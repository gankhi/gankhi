"""Debian package version comparison (a pure-Python port of dpkg's algorithm).

Needed to decide whether an installed version is older than the version that
fixes a vulnerability. Python's string or tuple comparison gets this wrong:
``1.0~rc1 < 1.0``, ``1.10 > 1.9``, ``1:0.5 > 2.0`` and so on.

Format: ``[epoch:]upstream_version[-debian_revision]``.
"""

from __future__ import annotations


def _order(char: str) -> int:
    """Sort weight of one character inside a non-digit run (dpkg ``order``)."""
    if char == "":  # end of string sorts before everything except "~"
        return 0
    if char == "~":  # tilde sorts before even the end of the string
        return -1
    if char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256  # punctuation sorts after letters


def _compare_part(a: str, b: str) -> int:
    """Compare one version part (upstream or revision), dpkg ``verrevcmp``."""
    i = j = 0
    while i < len(a) or j < len(b):
        # Non-digit run: compared character by character with _order().
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i] if i < len(a) else "")
            bc = _order(b[j] if j < len(b) else "")
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        # Digit run: compared as numbers (skip leading zeros, longer run wins).
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if first_diff == 0:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def _split(version: str) -> tuple[int, str, str]:
    """Split ``[epoch:]upstream[-revision]`` into its three parts."""
    epoch = 0
    head, sep, rest = version.partition(":")
    if sep and head.isdigit():
        epoch = int(head)
        version = rest
    upstream, sep, revision = version.rpartition("-")
    if not sep:  # no hyphen: whole string is upstream, revision is empty
        upstream, revision = version, ""
    return epoch, upstream, revision


def compare(a: str, b: str) -> int:
    """Return -1, 0 or 1 if version ``a`` is older than, equal to, or newer than ``b``."""
    epoch_a, upstream_a, revision_a = _split(a.strip())
    epoch_b, upstream_b, revision_b = _split(b.strip())
    if epoch_a != epoch_b:
        return -1 if epoch_a < epoch_b else 1
    result = _compare_part(upstream_a, upstream_b)
    if result:
        return result
    return _compare_part(revision_a, revision_b)
