# ruff: noqa: S101
"""Real actions: what may run, in what order, and what is kept. Nothing touches the system."""

import threading

import pytest

from ganki import executor, runner
from ganki.runner import CommandNotAllowedError, privileged_apt, run_privileged


def test_privileged_commands_are_written_out_exactly():
    assert privileged_apt("remove", "vlc") == [
        "/usr/bin/pkexec",
        "/usr/bin/env",
        "DEBIAN_FRONTEND=noninteractive",
        "/usr/bin/apt-get",
        "remove",
        "-y",
        "vlc",
    ]
    head = ["/usr/bin/pkexec", "/usr/bin/env", "DEBIAN_FRONTEND=noninteractive", "/usr/bin/apt-get"]
    keep = ["-o", "Dpkg::Options::=--force-confold"]
    assert privileged_apt("update", "vim") == [
        *head,
        "install",
        "--only-upgrade",
        "-y",
        *keep,
        "vim",
    ]
    assert privileged_apt("all") == [*head, "full-upgrade", "-y", *keep]
    assert privileged_apt("clean") == [*head, "clean"]
    assert privileged_apt("autoremove") == [*head, "autoremove", "-y"]


@pytest.mark.parametrize(
    "args",
    [
        ["/usr/bin/pkexec", "/bin/sh", "-c", "id"],
        ["/usr/bin/pkexec", "/usr/bin/apt-get", "remove", "-y", "vlc"],  # not the env form
        [*privileged_apt("remove", "vlc"), "bash"],  # extra package
        [*privileged_apt("remove", "vlc"), "--purge"],
        privileged_apt("remove", "-rf"),
        privileged_apt("remove", "vlc;reboot"),
        privileged_apt("remove", "Vlc"),
        privileged_apt("update", ""),
        [*privileged_apt("clean"), "--purge"],
        [*privileged_apt("clean")[:-1], "autoclean"],
        [*privileged_apt("autoremove"), "--purge"],
        [*privileged_apt("autoremove"), "vlc"],
        ["/usr/bin/sudo", "apt-get", "remove", "vlc"],
        [],
    ],
)
def test_run_privileged_refuses_anything_that_is_not_exactly_allowed(args):
    with pytest.raises(CommandNotAllowedError):
        run_privileged(args, lambda _line: None)


def test_pkexec_cannot_go_through_the_read_only_runner():
    with pytest.raises(CommandNotAllowedError):
        runner.run(privileged_apt("remove", "vlc"))


def test_run_privileged_streams_lines_and_closes_stdin(monkeypatch):
    seen = {}

    class FakeProcess:
        stdout = iter(["Removing vlc ...\n", "Done\n"])

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

    def fake_popen(args, **kwargs):
        seen["args"] = args
        seen["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(runner.subprocess, "Popen", fake_popen)
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-leak")
    lines = []
    assert run_privileged(privileged_apt("remove", "vlc"), lines.append) == 0
    assert lines == ["Removing vlc ...", "Done"]
    assert seen["kwargs"]["stdin"] == runner.subprocess.DEVNULL
    assert seen["kwargs"]["env"]["DISPLAY"] == ":0"
    assert "AWS_SECRET_ACCESS_KEY" not in seen["kwargs"]["env"]


def test_snapshot_lists_installed_packages_in_set_selections_format(tmp_path, monkeypatch):
    monkeypatch.setattr(executor.runner, "run", lambda _args: "bash\tii \nold\trc \nvlc\tii \n\n")
    path = executor.write_snapshot(tmp_path / "snaps")
    assert path.read_text() == "bash\tinstall\nvlc\tinstall\n"
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def finished(job):
    for _ in range(200):
        if job.state != executor.RUNNING:
            return
        threading.Event().wait(0.01)
    raise AssertionError("action did not finish")


def make_job(tmp_path, monkeypatch, run_command, **kwargs):
    monkeypatch.setattr(executor.runner, "run", lambda _args: "vlc\tii \n")
    return executor.ActionJob(run_command, tmp_path, is_available=lambda: True, **kwargs)


def test_job_saves_the_list_first_then_runs_and_keeps_the_output(tmp_path, monkeypatch):
    order = []

    def fake(args, on_line):
        order.append(("run", list(tmp_path.iterdir())))
        on_line("Removing vlc")
        return 0

    done = []
    job = make_job(tmp_path, monkeypatch, fake, on_done=lambda: done.append(True))
    assert job.start("remove", "vlc")
    finished(job)
    assert job.state == executor.DONE and job.lines[0] == "Removing vlc"
    assert order[0][1], "the list of programs must exist before apt runs"
    assert job.snapshot.startswith(str(tmp_path)) and done == [True]
    assert job.command.endswith("apt-get remove -y vlc")


def test_job_reports_failure_and_exit_code(tmp_path, monkeypatch):
    job = make_job(tmp_path, monkeypatch, lambda args, on_line: 100)
    job.start("update", "vim")
    finished(job)
    assert job.state == executor.FAILED and job.returncode == 100


def test_job_hides_internal_errors_from_the_screen(tmp_path, monkeypatch):
    def broken(args, on_line):
        raise OSError("/home/secret exploded")

    job = make_job(tmp_path, monkeypatch, broken)
    job.start("remove", "vlc")
    finished(job)
    assert job.state == executor.FAILED
    assert "secret" not in str(job.status())


def test_only_one_action_runs_at_a_time(tmp_path, monkeypatch):
    release = threading.Event()

    def slow(args, on_line):
        release.wait(2)
        return 0

    job = make_job(tmp_path, monkeypatch, slow)
    assert job.start("remove", "vlc")
    assert not job.start("remove", "vim")
    release.set()
    finished(job)


def test_nothing_runs_without_the_password_window_tool(tmp_path):
    job = executor.ActionJob(lambda *_: 0, tmp_path, is_available=lambda: False)
    assert not job.start("remove", "vlc")
    assert job.state == executor.IDLE


def test_only_the_newest_snapshots_are_kept(tmp_path):
    for day in range(1, 26):
        (tmp_path / f"programas-202610{day:02d}-120000.txt").write_text("x")
    (tmp_path / "notas-mias.txt").write_text("mine")
    executor.prune_snapshots(tmp_path)
    kept = sorted(p.name for p in tmp_path.glob("programas-*.txt"))
    assert len(kept) == executor.KEEP_SNAPSHOTS
    assert kept[0] == "programas-20261006-120000.txt"  # the 5 oldest are gone
    assert (tmp_path / "notas-mias.txt").exists()


def test_a_package_name_cannot_carry_a_newline_or_an_option():
    from ganki.runner import valid_package

    assert valid_package("vim") == "vim"
    assert valid_package("libc6:amd64") == "libc6:amd64"
    assert valid_package("vim-") is None  # apt would read it as "remove vim"
    assert valid_package("g++") == "g++"
    for bad in ("vim\n", "vim\n--purge", "-vim", "--purge", "vim foo", "", "A", "vim;ls"):
        assert valid_package(bad) is None


def test_privileged_removal_refuses_a_name_with_a_trailing_newline():
    for args in (privileged_apt("remove", "vim\n"), privileged_apt("update", "vim\n")):
        with pytest.raises(CommandNotAllowedError):
            run_privileged(args, lambda _line: None)


def test_simulations_refuse_a_package_with_a_trailing_newline():
    from ganki.runner import run

    with pytest.raises(CommandNotAllowedError):
        run(["/usr/bin/apt-get", "-s", "remove", "vim\n"])


def test_the_command_that_runs_is_rebuilt_not_the_callers_list(monkeypatch):
    seen = {}

    class Fake:
        stdout = iter([])

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

    def popen(argv, **_kwargs):
        seen["argv"] = argv
        return Fake()

    monkeypatch.setattr("ganki.runner.subprocess.Popen", popen)
    given = privileged_apt("remove", "vim")
    run_privileged(given, lambda _line: None)
    assert seen["argv"] == given and seen["argv"] is not given


def test_the_copy_for_undoing_lives_where_the_system_empties_it(tmp_path, monkeypatch):
    runtime = tmp_path / "run-user"
    runtime.mkdir()
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    assert executor.snapshot_dir() == runtime / "ganki" / "snapshots"
    # without a runtime folder: a private temporary one, never the home folder
    monkeypatch.delenv("XDG_RUNTIME_DIR")
    monkeypatch.setattr(executor, "_fallback_dir", None)
    monkeypatch.setattr("tempfile.tempdir", str(tmp_path))
    folder = executor.snapshot_dir()
    assert str(folder).startswith(str(tmp_path)) and ".local" not in str(folder)
    assert oct(folder.parent.stat().st_mode & 0o777) == "0o700"
    assert executor.snapshot_dir() == folder  # the same folder for the whole run


def test_cleaning_the_cache_does_not_save_the_program_list(tmp_path, monkeypatch):
    job = make_job(tmp_path, monkeypatch, lambda _args, _on_line: 0)
    assert job.start("clean", "")
    finished(job)
    assert job.state == executor.DONE and job.snapshot == "" and not list(tmp_path.iterdir())
    assert job.command.endswith("apt-get clean")
