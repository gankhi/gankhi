# ruff: noqa: S101
"""The natural voice: only Ganki's own sentences reach Piper, and only from a private folder."""

import subprocess

from ganki import narration, speech
from test_web import BASE, login, make_result, wait_until_done


def installed(tmp_path):
    (tmp_path / "venv" / "bin").mkdir(parents=True)
    (tmp_path / "venv" / "bin" / "python").write_text("")
    (tmp_path / "es_AR-daniela-high.onnx").write_text("")
    (tmp_path / "en_US-lessac-medium.onnx").write_text("")
    return tmp_path


class Recorder:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def __call__(self, argv):
        self.calls.append(argv)
        if self.fail:
            raise subprocess.CalledProcessError(1, argv)
        return b"RIFFfake"


def test_not_available_without_the_voice_folder(tmp_path):
    speaker = speech.Speaker(tmp_path, synth=Recorder())
    assert not speaker.available("es")
    assert speaker.speak("es", "hola") is None


def test_the_command_is_fixed_and_the_text_cannot_be_an_option(tmp_path):
    rec = Recorder()
    speaker = speech.Speaker(installed(tmp_path), synth=rec)
    assert speaker.speak("es", "--output-raw  hola\n mundo") == b"RIFFfake"
    argv = rec.calls[0]
    assert argv[1:3] == ["-m", "piper"]
    assert argv[-2] == "--"  # everything after is text, never an option
    assert argv[-1] == "--output-raw hola mundo"
    assert argv[argv.index("-m", 3) + 1].endswith("es_AR-daniela-high.onnx")


def test_same_text_is_synthesised_once(tmp_path):
    rec = Recorder()
    speaker = speech.Speaker(installed(tmp_path), synth=rec)
    speaker.speak("es", "hola")
    speaker.speak("es", "hola")
    assert len(rec.calls) == 1


def test_a_failing_voice_returns_none(tmp_path):
    speaker = speech.Speaker(installed(tmp_path), synth=Recorder(fail=True))
    assert speaker.speak("es", "hola") is None


def test_long_text_is_cut(tmp_path):
    rec = Recorder()
    speech.Speaker(installed(tmp_path), synth=rec).speak("es", "a " * 5000)
    assert len(rec.calls[0][-1]) <= speech.MAX_TEXT_CHARS


def make_client(tmp_path, installed_voice=True, fail=False):
    from ganki.web.app import create_app
    from test_web import PORT, SECRET, make_result  # noqa: F401

    rec = Recorder(fail)
    folder = installed(tmp_path) if installed_voice else tmp_path
    app = create_app(make_result, SECRET, PORT, speaker=speech.Speaker(folder, synth=rec))
    return login(app.test_client()), rec


def test_speak_endpoint_builds_the_text_itself(tmp_path):
    client, rec = make_client(tmp_path)
    client.get("/", base_url=BASE)
    wait_until_done(client)
    response = client.get("/api/speak?seg=2&x=ignored", base_url=BASE)
    assert response.status_code == 200
    assert response.mimetype == "audio/wav"
    expected = narration.build(make_result(), "en")[2].text
    assert rec.calls[0][-1] == " ".join(expected.split())


def test_speak_by_section_skips_intro_and_outro(tmp_path):
    client, rec = make_client(tmp_path)
    client.get("/", base_url=BASE)
    wait_until_done(client)
    assert client.get("/api/speak?section=tools", base_url=BASE).status_code == 200
    spoken = rec.calls[0][-1]
    assert "That is all" not in spoken


def test_speak_rejects_bad_requests(tmp_path):
    client, _ = make_client(tmp_path)
    client.get("/", base_url=BASE)
    wait_until_done(client)
    assert client.get("/api/speak", base_url=BASE).status_code == 400
    assert client.get("/api/speak?seg=999", base_url=BASE).status_code == 400
    assert client.get("/api/speak?seg=-1", base_url=BASE).status_code == 400


def test_speak_without_the_voice_installed_is_unavailable(tmp_path):
    client, _ = make_client(tmp_path, installed_voice=False)
    client.get("/", base_url=BASE)
    wait_until_done(client)
    assert client.get("/api/speak?seg=0", base_url=BASE).status_code == 503


def test_speak_needs_the_session(tmp_path):
    from ganki.web.app import create_app
    from test_web import PORT, SECRET

    app = create_app(make_result, SECRET, PORT, speaker=speech.Speaker(installed(tmp_path)))
    assert app.test_client().get("/api/speak?scanning=1", base_url=BASE).status_code == 403


def test_page_tells_the_assistant_whether_the_voice_exists(tmp_path):
    with_voice, _ = make_client(tmp_path)
    html = with_voice.get("/", base_url=BASE).get_data(as_text=True)
    assert 'data-natural="1"' in html
    without, _ = make_client(tmp_path / "nothing", installed_voice=False)
    assert 'data-natural="0"' in without.get("/", base_url=BASE).get_data(as_text=True)


def test_csp_only_adds_media_from_this_server(tmp_path):
    client, _ = make_client(tmp_path)
    csp = client.get("/", base_url=BASE).headers["Content-Security-Policy"]
    assert "media-src 'self';" in csp
    assert "unsafe" not in csp and "default-src 'none'" in csp
