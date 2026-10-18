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
        top_priority=priority, cve_count=total or len(cves),
        unfixable=total or len(cves), cves=cves,
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
ORACLE_OLD = (
    "Vulnerability in the Oracle VM VirtualBox component. Supported versions that are "
    "affected are Prior to 5.2.10"
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


def test_a_program_not_known_by_name_is_recognised_by_what_it_says_it_is():
    assert advice.profile_for("netsurf", description="small web browser") == "browser"
    assert advice.profile_for("virt-thing", description="a hypervisor frontend") == "virtual"
    assert advice.profile_for("zzz", description="reads your e-mail client data") == "messages"


def test_a_program_not_known_by_name_or_description_uses_its_section():
    assert advice.profile_for("zzz", description="does things", section="universe/mail") == (
        "messages"
    )
    assert advice.profile_for("zzz", description="does things", section="libs") is None


def test_the_section_reaches_the_explanation():
    from dataclasses import replace

    item = replace(tool("zzz", [KERNEL]), description="does things", section="net")
    assert any("servers or repositories you point it to" in p for p in explain(item))


class App:
    def __init__(self, name, tool_name):
        self.name, self.tool = name, tool_name


def test_a_snap_explains_that_ganki_does_not_check_it_and_what_to_do():
    text = " ".join(advice.sandboxed_paragraphs(App("firefox", "snap"), "en"))
    assert "cannot tell you whether it has known flaws" in text
    assert "snap checks and updates its apps by itself" in text
    assert "A browser reads content from any website" in text  # browser-specific
    assert "Good practice" not in text  # no premise about a missing patch


def test_a_flatpak_says_it_does_not_update_itself():
    text = " ".join(advice.sandboxed_paragraphs(App("Firefox", "flatpak"), "es"))
    assert "no se actualiza solo" in text and "flatpak update" in text


def test_an_unknown_sandboxed_app_says_so():
    last = advice.sandboxed_paragraphs(App("Weird Thing", "snap"), "en")[-1]
    assert "does not recognise" in last
    assert set(advice.SANDBOXED_TEXT["es"]) == set(advice.SANDBOXED_TEXT["en"])


def versioned(name, installed, summaries, component="main"):
    from dataclasses import replace

    return replace(tool(name, summaries), installed_version=installed, component=component)


def test_a_notice_about_older_versions_is_flagged_when_the_installed_one_is_newer():
    item = versioned("virtualbox-qt", "7.0.16-dfsg-2ubuntu1.3", [ORACLE_OLD, KERNEL])
    text = " ".join(explain(item))
    assert "1 of the notices say" in text and "prior to 5.2.10" in text
    assert "(7.0.16)" in text and "probably do not affect you" in text


def test_it_is_not_flagged_when_the_installed_version_is_inside_the_range():
    item = versioned("virtualbox", "5.2.4-dfsg-1", [ORACLE_OLD])
    assert "probably do not affect you" not in " ".join(explain(item))


def test_a_notice_about_another_program_is_never_used_for_the_version_hint():
    kernel_text = "The Linux kernel before 4.17.2 has a flaw in a virtualbox driver"
    item = versioned("nodejs", "20.1.0", ["nodejs is mentioned? no", kernel_text])
    assert "probably do not affect you" not in " ".join(explain(item))
    other = versioned("virtualbox", "7.0.16", ["An issue in the Linux kernel before 4.17.2"])
    assert "probably do not affect you" not in " ".join(explain(other))


def test_community_components_say_ubuntu_does_not_promise_security_fixes():
    text = " ".join(explain(versioned("virtualbox", "7.0", [ORACLE], component="multiverse")))
    assert 'comes from "multiverse"' in text
    assert "comes from" not in " ".join(explain(versioned("virtualbox", "7.0", [ORACLE])))


def test_the_hints_exist_in_both_languages():
    assert {"older", "community"} <= set(advice.TAILS["es"]) & set(advice.TAILS["en"])
    item = versioned("virtualbox", "7.0.16-1", [ORACLE_OLD], component="multiverse")
    assert "Probablemente no te afectan" in " ".join(explain(item, lang="es"))


def _mixed_tool():
    cves = (
        CveLine("CVE-1", "medium", "Crafted file causes a buffer overflow", "2", "fix_available"),
        CveLine("CVE-2", "low", "Denial of service in the parser", None, "no_fix"),
    )
    return Tool(
        name="vim-common", version="1", size_kib=1, description="", is_program=True,
        state="VULNERABLE", update_to="2", top_priority="medium", cve_count=42, fixable=40,
        unfixable=2, fixed_in="2", cves=cves,
    )  # fmt: skip


def test_each_label_of_a_mixed_row_talks_only_about_its_own_notices():
    item = _mixed_tool()
    fixed = explain(item, "fixed")
    open_ = explain(item, "no_fix")
    assert "memory errors" in fixed[0] and "first 1 of 40" in fixed[0]
    assert "crashes or freezes" in open_[0] and "first 1 of 2" in open_[0]
    assert "memory errors" not in open_[0]
    assert "The highest priority is low" in open_[0]  # not the medium of the other notice
    assert any("update with the button" in p for p in fixed)
    # updating does not fix the open ones, so that label must not tell the person to update
    assert not any("update with the button" in p for p in open_)


def test_a_row_with_no_fix_but_a_newer_version_does_not_promise_that_it_helps():
    item = _mixed_tool()
    item = Tool(**{**item.__dict__, "fixed_in": None, "fixable": 0, "unfixable": 2})
    text = " ".join(explain(item, "no_fix"))
    assert "does not fix these" in text and "update with the button" not in text


def _outdated(name, origin, security=False, description=""):
    return Tool(
        name=name, version="1", size_kib=1, description=description, is_program=True,
        state="OUTDATED", update_to="2", update_origin=origin, update_security=security,
    )  # fmt: skip


def test_an_update_from_the_security_channel_is_important():
    info = advice.update_info(_outdated("bash", "noble-updates,noble-security", True), "en")
    assert info["kind"] == "imp" and info["tag"] == "Important update"
    assert "security" in info["hint"]


def test_a_browser_update_is_important_and_says_when_ganki_has_no_notices_for_it():
    brave = _outdated("brave-browser", "stable", description="Web browser from Brave")
    info = advice.update_info(brave, "en")
    assert info["kind"] == "imp" and "exposed" in info["hint"]
    assert any("does not come from Ubuntu" in p for p in info["more"])  # honest about the gap
    ubuntu = _outdated("firefox-esr", "noble-updates", description="Web browser")
    assert not any(
        "does not come from Ubuntu" in p for p in advice.update_info(ubuntu, "en")["more"]
    )


def test_any_other_update_is_a_plain_update():
    info = advice.update_info(_outdated("vim", "noble-updates"), "es")
    assert info["kind"] == "info" and info["tag"] == "Actualización"
    assert "no es urgente" in " ".join(info["more"])
    outside = advice.update_info(_outdated("some-tool", "stable"), "es")
    assert any("no viene de Ubuntu" in p for p in outside["more"])
