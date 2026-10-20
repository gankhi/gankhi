# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Opening a folder of Downloads: only folders, only inside Downloads."""

from gankhi import folders


def make_downloads(tmp_path):
    base = tmp_path / "Downloads"
    (base / "fotos").mkdir(parents=True)
    (base / "fotos" / "a.jpg").write_text("x")
    (base / "suelto.pdf").write_text("x")
    return base


def test_a_file_shows_the_folder_that_holds_it(tmp_path):
    base = make_downloads(tmp_path)
    assert folders.folder_to_open(base, "fotos/a.jpg") == (base / "fotos").resolve()
    assert folders.folder_to_open(base, "fotos") == (base / "fotos").resolve()
    assert folders.folder_to_open(base, "suelto.pdf") == base.resolve()


def test_paths_that_leave_downloads_are_refused(tmp_path):
    base = make_downloads(tmp_path)
    (tmp_path / "secreto").mkdir()
    (base / "atajo").symlink_to(tmp_path / "secreto")
    for bad in (
        "",
        "..",
        "../secreto",
        "fotos/../../secreto",
        "/etc",
        "atajo",
        "no-existe",
        "a\x00b",
    ):
        assert folders.folder_to_open(base, bad) is None, bad


def test_open_folder_needs_a_real_folder_and_the_system_tool(tmp_path, monkeypatch):
    assert not folders.open_folder(tmp_path / "missing")
    monkeypatch.setattr(folders, "XDG_OPEN", str(tmp_path / "no-such-tool"))
    assert not folders.open_folder(tmp_path)


def test_a_file_is_selected_in_its_folder_and_a_folder_is_opened(tmp_path, monkeypatch):
    base = make_downloads(tmp_path)
    calls = []
    monkeypatch.setattr(
        folders, "_select_in_file_manager", lambda t: calls.append(("select", t)) or True
    )
    monkeypatch.setattr(folders, "open_folder", lambda f: calls.append(("open", f)) or True)
    target = folders.inside_downloads(base, "suelto.pdf")
    assert folders.show_in_file_manager(target)
    assert folders.show_in_file_manager(folders.inside_downloads(base, "fotos"))
    assert calls == [("select", target), ("open", (base / "fotos").resolve())]


def test_if_the_file_manager_cannot_select_it_the_folder_is_opened(tmp_path, monkeypatch):
    base = make_downloads(tmp_path)
    opened = []
    monkeypatch.setattr(folders, "_select_in_file_manager", lambda t: False)
    monkeypatch.setattr(folders, "open_folder", lambda f: opened.append(f) or True)
    assert folders.show_in_file_manager(folders.inside_downloads(base, "fotos/a.jpg"))
    assert opened == [(base / "fotos").resolve()]


def test_the_selection_request_is_one_fixed_command_with_an_encoded_address(tmp_path, monkeypatch):
    import subprocess

    seen = []
    monkeypatch.setattr(folders, "DBUS_SEND", "/bin/true")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda argv, **kw: seen.append(argv) or subprocess.CompletedProcess(argv, 0),
    )
    odd = tmp_path / "a,b:c d.zip"
    odd.write_text("x")
    assert folders._select_in_file_manager(odd)
    argv = seen[0]
    assert argv[0] == "/bin/true" and argv[-1] == "string:"
    item = argv[-2]
    assert item.startswith("array:string:file://") and "," not in item.split("file://")[1]
