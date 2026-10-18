# ruff: noqa: S101
"""Looking inside a kind of download (read-only)."""

import os

from ganki import downloads
from test_web import BASE, build, login, make_result, wait_until_done


def make_folder(tmp_path):
    root = tmp_path / "Downloads"
    (root / "datasets" / "deep").mkdir(parents=True)
    (root / "datasets" / "a.bin").write_bytes(b"x" * 5000)
    (root / "datasets" / "deep" / "b.bin").write_bytes(b"x" * 3000)
    (root / "video.mp4").write_bytes(b"x" * 9000)
    (root / "NOEXT").write_bytes(b"x" * 100)
    (root / "photo.png").write_bytes(b"x" * 700)  # another kind: must not appear under "other"
    os.symlink(root / "video.mp4", root / "link.mp4")
    return root


def test_detail_lists_folders_biggest_files_and_types(tmp_path):
    root = make_folder(tmp_path)
    detail = downloads.group_detail(root, "other")
    assert (detail.files, detail.size_bytes) == (4, 17100)
    names = [(f.name, f.is_folder, f.files, f.size_bytes) for f in detail.folders]
    assert names[0] == ("video.mp4", False, 1, 9000)
    assert ("datasets", True, 2, 8000) in names
    assert [f.path for f in detail.biggest][:2] == ["video.mp4", os.path.join("datasets", "a.bin")]
    kinds = {k.extension: k.files for k in detail.kinds}
    assert kinds == {".mp4": 1, ".bin": 2, "": 1}


def test_symlinks_and_other_kinds_are_left_out(tmp_path):
    root = make_folder(tmp_path)
    paths = [f.path for f in downloads.group_detail(root, "other").biggest]
    assert "link.mp4" not in paths and "photo.png" not in paths
    assert [f.path for f in downloads.group_detail(root, "images").biggest] == ["photo.png"]


def test_the_lists_are_short_and_names_are_cut(tmp_path):
    root = tmp_path / "Downloads"
    root.mkdir()
    for number in range(downloads.TOP_ITEMS + 10):
        (root / f"f{number}.bin").write_bytes(b"x" * (number + 1))
    (root / ("n" * 200 + ".bin")).write_bytes(b"x")
    detail = downloads.group_detail(root, "other")
    assert len(detail.biggest) == downloads.TOP_ITEMS
    assert all(len(f.path) <= downloads.MAX_NAME_CHARS for f in detail.biggest)
    assert all(len(f.name) <= downloads.MAX_NAME_CHARS for f in detail.folders)


def test_an_empty_or_missing_folder_is_fine(tmp_path):
    assert downloads.group_detail(tmp_path / "nothing", "other").files == 0


def with_folder(tmp_path, monkeypatch):
    root = make_folder(tmp_path)
    monkeypatch.setattr(downloads, "downloads_dir", lambda *a, **k: root)
    client = login(build().test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    return client


def test_detail_page_shows_what_is_inside(tmp_path, monkeypatch):
    client = with_folder(tmp_path, monkeypatch)
    response = client.get("/downloads/other", base_url=BASE)
    html = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "datasets/" in html and "video.mp4" in html and ".bin" in html
    assert str(tmp_path) not in html  # relative names only, never the full path
    assert "Content-Security-Policy" in response.headers


def test_detail_page_escapes_file_names(tmp_path, monkeypatch):
    root = tmp_path / "Downloads"
    root.mkdir()
    (root / "<img src=x onerror=alert(1)>.bin").write_bytes(b"x")
    monkeypatch.setattr(downloads, "downloads_dir", lambda *a, **k: root)
    client = login(build().test_client())
    html = client.get("/downloads/other", base_url=BASE).get_data(as_text=True)
    assert "<img src=x" not in html and "&lt;img src=x" in html


def test_unknown_kind_and_missing_session(tmp_path, monkeypatch):
    client = with_folder(tmp_path, monkeypatch)
    assert client.get("/downloads/../etc", base_url=BASE).status_code == 404
    assert client.get("/downloads/nonsense", base_url=BASE).status_code == 404
    assert build().test_client().get("/downloads/other", base_url=BASE).status_code == 403


def test_the_downloads_card_links_each_kind():
    client = login(build().test_client())
    client.get("/", base_url=BASE)
    wait_until_done(client)
    html = client.get("/", base_url=BASE).get_data(as_text=True)
    for group in make_result().download_groups:
        assert f'href="/downloads/{group.key}"' in html
