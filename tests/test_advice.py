# ruff: noqa: S101
# (pytest tests rely on bare asserts)
from ganki import advice
from ganki.tools import CveLine, Tool


def tool(name, summaries=(), priority="high", total=None):
    cves = tuple(
        CveLine(f"CVE-1-{n}", priority, text, None, "no_fix") for n, text in enumerate(summaries)
    )
    return Tool(
        name=name, version="1", size_kib=1, description="", is_program=True, state="VULNERABLE",
        top_priority=priority, cve_count=total or len(cves), unfixable=len(cves), cves=cves,
    )  # fmt: skip


def explain(item, kind="no_fix", lang="en"):
    return advice.paragraphs(item, kind, lang, lambda p: p, "GENERIC")


def test_each_kind_of_program_gets_its_own_explanation():
    names = ["nodejs", "virtualbox-7.0", "firefox", "apache2", "openssl", "vlc", "docker.io"]
    texts = {name: explain(tool(name)) for name in names}
    assert len({tuple(t) for t in texts.values()}) == len(names)  # all different
    assert "GENERIC" not in sum(texts.values(), [])
    assert any("JavaScript" in p for p in texts["nodejs"])
    assert any("virtual machine" in p for p in texts["virtualbox-7.0"])


def test_an_unknown_program_falls_back_to_the_general_advice():
    assert explain(tool("some-odd-tool"))[-1] == "GENERIC"


def test_the_notices_own_words_are_summarised():
    item = tool(
        "nodejs",
        ["Allows remote code execution via crafted input", "Denial of service in the parser"],
        priority="critical",
        total=5,
    )
    first = explain(item)[0]
    assert "running someone else's code" in first and "crashes or freezes" in first
    assert "critical" in first and "first 2 of 5" in first


def test_words_inside_other_words_do_not_count():
    assert advice.notice_kinds(["The change is applied twice"], "en") == []


def test_malware_gets_the_removal_advice_and_no_profile_text():
    text = " ".join(explain(tool("express"), "malware"))
    assert "malicious" in text and "remove it now" in text


def test_pip_and_npm_packages_use_their_own_profile():
    class Ext:
        name, tool, top_priority, cve_count, cves = "left-pad", "npm", "", 0, ()

    assert any("JavaScript package" in p for p in explain(Ext(), "ext_no_fix"))


def test_every_text_exists_in_both_languages():
    for profile, languages in advice.PROFILE_TEXT.items():
        assert set(languages) == {"es", "en"}, profile
        assert all(all(part.strip() for part in pair) for pair in languages.values()), profile
    assert advice.TAILS["es"].keys() == advice.TAILS["en"].keys()
    assert {profile for _p, profile in advice.PROFILES} | {"pip", "npm"} == set(advice.PROFILE_TEXT)
    assert all({"es", "en"} <= set(names) for _k, _p, names in advice.KINDS)


def test_no_sentence_ends_with_two_periods():
    for kind in ("fixed", "no_fix", "eol", "ext_fix", "ext_no_fix"):
        for name in ("virtualbox", "nodejs", "vim"):
            for lang in ("es", "en"):
                assert all(".." not in p for p in explain(tool(name), kind, lang)), (kind, name)


ORACLE = (
    "Vulnerability in the Oracle VM VirtualBox component (subcomponent: Core). Easily "
    "exploitable vulnerability allows low privileged attacker with logon to the infrastructure"
)
KERNEL = "allows guest OS users to cause a denial of service (host OS panic or hang)"


def test_precautions_follow_how_the_notices_say_the_problem_is_reached():
    text = " ".join(explain(tool("virtualbox-qt", [ORACLE, KERNEL])))
    assert "inside the virtual machine" in text  # from the "guest OS users" notice
    assert "access to an account on your computer" in text  # from "logon to the infrastructure"
    assert "network" not in text.split("How it can be used")[1]  # nothing says it is remote


def test_without_conditions_in_the_notices_the_precaution_is_declared_general():
    text = " ".join(explain(tool("nodejs", ["Something happens in the parser"])))
    assert "do not say under which conditions" in text


def test_the_update_line_depends_on_the_data():
    from dataclasses import replace

    base = tool("virtualbox", [ORACLE])
    assert any("nothing to update" in p for p in explain(base))
    newer = replace(base, update_to="7.0.20")
    assert any("A newer version is available (7.0.20)" in p for p in explain(newer))
    assert not any("nothing to update" in p for p in explain(newer))


def test_a_fixed_notice_keeps_the_update_advice_and_skips_the_conditions():
    text = " ".join(explain(tool("virtualbox", [ORACLE]), "fixed"))
    assert "How it can be used" not in text and "Press Update" in text


def test_a_program_unknown_to_ganki_still_gets_precautions_from_its_own_notices():
    text = " ".join(explain(tool("some-new-program", [ORACLE])))
    assert "access to an account on your computer" in text and "GENERIC" not in text
    plain = explain(tool("some-new-program", ["Something happens"]))
    assert plain[-1] == "GENERIC"  # nothing to go on: the general advice
