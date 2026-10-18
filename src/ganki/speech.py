"""Natural local voice, made by Piper on this computer. Nothing is sent anywhere.

Piper is optional. ``scripts/install-voice.sh`` puts it, and one voice file, in a folder
of its own under Ganki's data folder. Ganki only uses it if it finds both there.

Only text that Ganki itself wrote (the narration) is ever given to Piper: the web layer
builds the text from the scan and never passes on anything the browser sent.
"""

from __future__ import annotations

import hashlib
import logging
import os
import subprocess  # noqa: S404  (one fixed command, no shell)
import tempfile
import threading
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path

log = logging.getLogger(__name__)

VOICE_NAMES = {"es": "es_AR-daniela-high", "en": "en_US-lessac-medium"}
MAX_TEXT_CHARS = 2000
TIMEOUT_SECONDS = 60
CACHE_ENTRIES = 24

Synth = Callable[[list[str]], bytes]


def default_voice_dir() -> Path:
    data = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(data) / "ganki" / "voice"


def _run_piper(argv: list[str]) -> bytes:
    """Run the one command built by ``Speaker`` and return the audio it wrote."""
    out = Path(argv[argv.index("-f") + 1])
    subprocess.run(  # noqa: S603  (argv comes only from Speaker._command)
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=TIMEOUT_SECONDS,
        check=True,
        env={"PATH": "/usr/bin:/bin"},
    )
    return out.read_bytes()


class Speaker:
    """Turns Ganki's own sentences into spoken audio (WAV)."""

    def __init__(self, voice_dir: Path | None = None, synth: Synth = _run_piper) -> None:
        self.voice_dir = voice_dir or default_voice_dir()
        self._synth = synth
        self._lock = threading.Lock()  # one voice at a time: it is heavy on a small PC
        self._cache: OrderedDict[str, bytes] = OrderedDict()

    def _python(self) -> Path:
        return self.voice_dir / "venv" / "bin" / "python"

    def _model(self, lang: str) -> Path:
        return self.voice_dir / f"{VOICE_NAMES.get(lang, VOICE_NAMES['en'])}.onnx"

    def available(self, lang: str) -> bool:
        return self._python().is_file() and self._model(lang).is_file()

    def _command(self, lang: str, text: str, out: Path) -> list[str]:
        return [
            str(self._python()),
            "-m",
            "piper",
            "-m",
            str(self._model(lang)),
            "-f",
            str(out),
            "--",
            text,
        ]

    def speak(self, lang: str, text: str) -> bytes | None:
        """Audio for ``text``, or ``None`` if the voice is missing or failed."""
        text = " ".join(text.split())[:MAX_TEXT_CHARS]
        if not text or not self.available(lang):
            return None
        key = hashlib.sha256(f"{lang}\0{text}".encode()).hexdigest()
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
            with tempfile.TemporaryDirectory(prefix="ganki-voice-") as folder:
                out = Path(folder) / "speech.wav"
                try:
                    audio = self._synth(self._command(lang, text, out))
                except (OSError, subprocess.SubprocessError):
                    log.warning("The local voice failed.", exc_info=True)
                    return None
            self._cache[key] = audio
            while len(self._cache) > CACHE_ENTRIES:
                self._cache.popitem(last=False)
            return audio
