# ruff: noqa: S101
# (pytest tests rely on bare asserts)
"""Tests for the feed downloader, with a fake opener (no real network)."""

import io
import urllib.error

import pytest

import ganki.feed as feed

URL = "https://example.test/osv-all.tar.xz"


class FakeResponse:
    def __init__(self, body, headers):
        self._buffer = io.BytesIO(body)
        self.headers = headers

    def read(self, size=-1):
        return self._buffer.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def make_opener(body=b"DATA", headers=None, error_code=None):
    sent = []

    def opener(request, timeout=None):
        sent.append(request)
        if error_code is not None:
            raise urllib.error.HTTPError(request.full_url, error_code, "x", {}, None)
        return FakeResponse(body, headers or {"ETag": '"v1"', "Last-Modified": "Fri, 16 Oct 2026"})

    opener.sent = sent
    return opener


def test_first_call_downloads_and_stores_metadata(tmp_path):
    status = feed.refresh(URL, tmp_path, opener=make_opener())
    assert status.downloaded is True
    assert status.path.read_bytes() == b"DATA"
    assert status.last_modified == "Fri, 16 Oct 2026"


def test_second_call_is_conditional_and_reuses_cache_on_304(tmp_path):
    feed.refresh(URL, tmp_path, opener=make_opener())
    opener = make_opener(error_code=304)
    status = feed.refresh(URL, tmp_path, opener=opener)
    assert status.downloaded is False
    assert status.path.read_bytes() == b"DATA"
    sent = opener.sent[0]
    assert sent.get_header("If-none-match") == '"v1"'
    assert sent.get_header("If-modified-since") == "Fri, 16 Oct 2026"


def test_newer_feed_replaces_the_cached_copy(tmp_path):
    feed.refresh(URL, tmp_path, opener=make_opener(b"OLD"))
    status = feed.refresh(URL, tmp_path, opener=make_opener(b"NEW"))
    assert status.downloaded is True
    assert status.path.read_bytes() == b"NEW"


def test_non_https_url_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="HTTPS"):
        feed.refresh("http://example.test/feed", tmp_path, opener=make_opener())


def test_other_http_errors_are_not_swallowed(tmp_path):
    with pytest.raises(urllib.error.HTTPError):
        feed.refresh(URL, tmp_path, opener=make_opener(error_code=500))


def test_declared_size_over_limit_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(feed, "MAX_DOWNLOAD_BYTES", 10)
    opener = make_opener(headers={"Content-Length": "11"})
    with pytest.raises(ValueError, match="larger"):
        feed.refresh(URL, tmp_path, opener=opener)
    assert list(tmp_path.iterdir()) == []


def test_stream_over_limit_leaves_no_partial_file(tmp_path, monkeypatch):
    monkeypatch.setattr(feed, "MAX_DOWNLOAD_BYTES", 10)
    with pytest.raises(ValueError, match="exceeded"):
        feed.refresh(URL, tmp_path, opener=make_opener(body=b"x" * 50))
    assert list(tmp_path.iterdir()) == []
