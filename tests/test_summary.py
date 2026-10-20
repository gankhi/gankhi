# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Tests for grouping findings per package and telling kernels apart."""

from gankhi.osv import Finding
from gankhi.summary import (
    OLD_KERNEL,
    PROGRAM,
    RUNNING_KERNEL,
    running_kernel_abi,
    summarize,
)


def finding(cve, source="openssl", installed="1.0", fixed="2.0", priority="medium", pro=None):
    return Finding(cve, source, (source,), installed, fixed, pro, priority, "summary")


def test_running_kernel_abi_drops_the_flavour():
    assert running_kernel_abi("6.8.0-137-generic") == "6.8.0-137"
    assert running_kernel_abi("") is None
    assert running_kernel_abi("weird") is None


def test_findings_are_grouped_per_package_with_counts():
    findings = [
        finding("CVE-1", priority="high"),
        finding("CVE-2", priority="low", fixed=None),
        finding("CVE-3", priority="medium", fixed="3.0"),
    ]
    (risk,) = summarize(findings)
    assert risk.cve_count == 3
    assert risk.top_priority == "high"
    assert risk.by_priority == {"high": 1, "medium": 1, "low": 1}
    assert (risk.fix_available, risk.fix_with_pro, risk.no_fix) == (2, 0, 1)
    assert risk.target_version == "3.0"  # the version that fixes everything fixable
    assert risk.kind == PROGRAM


def test_target_version_compares_debian_versions_not_text():
    findings = [finding("CVE-1", fixed="1.9"), finding("CVE-2", fixed="1.10")]
    assert summarize(findings)[0].target_version == "1.10"


def test_kernels_are_split_into_running_and_old():
    findings = [
        finding("CVE-1", "linux", "6.8.0-137.137"),
        finding("CVE-1", "linux", "6.8.0-31.31"),
        finding("CVE-2", "linux", "6.8.0-31.31"),
    ]
    kinds = {r.installed_version: r.kind for r in summarize(findings, "6.8.0-137-generic")}
    assert kinds == {"6.8.0-137.137": RUNNING_KERNEL, "6.8.0-31.31": OLD_KERNEL}


def test_without_a_running_kernel_nothing_is_called_old():
    risks = summarize([finding("CVE-1", "linux", "6.8.0-31.31")], "")
    assert risks[0].kind == PROGRAM


def test_non_kernel_packages_are_never_old_kernels():
    risks = summarize([finding("CVE-1", "openssl", "6.8.0-31.31")], "6.8.0-137-generic")
    assert risks[0].kind == PROGRAM


def test_old_kernels_sort_last_even_if_urgent():
    findings = [
        finding("CVE-1", "linux", "6.8.0-31.31", priority="critical"),
        finding("CVE-2", "zlib", "1", priority="low"),
    ]
    order = [r.source_package for r in summarize(findings, "6.8.0-137-generic")]
    assert order == ["zlib", "linux"]


def test_pro_only_fix_is_counted_separately():
    risk = summarize([finding("CVE-1", fixed=None, pro="1~esm1")])[0]
    assert (risk.fix_available, risk.fix_with_pro, risk.no_fix) == (0, 1, 0)
    assert risk.target_version is None


def test_has_fix_tells_fixable_from_unfixable():
    assert summarize([finding("CVE-1")])[0].has_fix
    assert summarize([finding("CVE-1", fixed=None, pro="1~esm1")])[0].has_fix
    assert not summarize([finding("CVE-1", fixed=None)])[0].has_fix
