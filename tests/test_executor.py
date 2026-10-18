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
