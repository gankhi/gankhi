#!/usr/bin/env bash
# Add a natural voice (Piper, "daniela", Argentine Spanish) to Ganki.
#
# - Optional. Without it Ganki still shows captions.
# - No sudo: everything goes inside ~/.local/share/ganki/voice (its own private folder).
# - Downloads ONCE, now: the Piper program from PyPI and the voice file (about 110 MB)
#   from Hugging Face. After that the voice works with no internet and nothing is sent.
# Run scripts/uninstall.sh (or delete that folder) to remove it.
#
# Usage: scripts/install-voice.sh [--yes]

set -euo pipefail

DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
VOICE_DIR="$DATA_HOME/ganki/voice"
VOICE="es_AR-daniela-high"

say() { printf '%s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -ne 0 ] || die "do not run this as root or with sudo."
[ -n "${HOME:-}" ] || die "HOME is not set."
case "$VOICE_DIR" in "$HOME"/*) ;; *) die "refusing to install outside your home folder: $VOICE_DIR" ;; esac
command -v python3 >/dev/null || die "python3 was not found."
python3 -c 'import venv, ensurepip' 2>/dev/null \
    || die "the Python venv module is missing. On Ubuntu: sudo apt install python3-venv"

say "Ganki will add a natural voice:"
say "  folder   : $VOICE_DIR"
say "  download : piper-tts (PyPI) and the voice $VOICE (Hugging Face), about 110 MB, once"
if [ "${1:-}" != "--yes" ] && [ "${1:-}" != "-y" ]; then
    printf 'Continue? [y/N] '
    read -r answer
    case "$answer" in y|Y|yes|s|S|si|sí) ;; *) say "Cancelled. Nothing was changed."; exit 0 ;; esac
fi

mkdir -p "$VOICE_DIR"
chmod 700 "$VOICE_DIR"
[ -x "$VOICE_DIR/venv/bin/python" ] || python3 -m venv "$VOICE_DIR/venv"
"$VOICE_DIR/venv/bin/pip" install --quiet --upgrade pip piper-tts
(cd "$VOICE_DIR" && ./venv/bin/python -m piper.download_voices "$VOICE") \
    || die "the voice could not be downloaded. Check your connection and try again."
[ -f "$VOICE_DIR/$VOICE.onnx" ] || die "the voice file is missing after the download."

say "Testing the voice..."
"$VOICE_DIR/venv/bin/python" -m piper -m "$VOICE_DIR/$VOICE.onnx" -f "$VOICE_DIR/test.wav" -- \
    "Hola. Ya podés usar la voz natural de Ganki." >/dev/null 2>&1 \
    || die "the voice was installed but did not run."
rm -f "$VOICE_DIR/test.wav"
say "Done. Open Ganki again and tap the voice button."
