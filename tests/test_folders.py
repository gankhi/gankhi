# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Opening a folder of Downloads: only folders, only inside Downloads."""

from ganki import folders


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
