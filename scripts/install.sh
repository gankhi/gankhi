#!/usr/bin/env bash
# Install Ganki for the current user only.
#
# - No sudo: everything goes inside your home folder (~/.local).
# - Creates a private Python environment, so no system package is touched.
# - Adds a "Ganki" entry to your applications menu and a `ganki` command.
# Run it again later to update; run scripts/uninstall.sh to remove it.
#
# Usage: scripts/install.sh [--yes] [--no-desktop]
#   --no-desktop  do not put a shortcut on your Desktop

set -euo pipefail

DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
APP_DIR="$DATA_HOME/ganki"
BIN_DIR="$HOME/.local/bin"
DESKTOP_DIR="$DATA_HOME/applications"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

say() { printf '%s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

assume_yes=false
desktop_shortcut=true
for arg in "$@"; do
    case "$arg" in
        --yes|-y) assume_yes=true ;;
        --no-desktop) desktop_shortcut=false ;;
        -h|--help) sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $arg" ;;
    esac
done

[ "$(id -u)" -ne 0 ] || die "do not run this as root or with sudo. It installs for your user only."
[ -n "${HOME:-}" ] || die "HOME is not set."
for dir in "$APP_DIR" "$BIN_DIR" "$DESKTOP_DIR"; do
    case "$dir" in "$HOME"/*) ;; *) die "refusing to install outside your home folder: $dir" ;; esac
done

command -v python3 >/dev/null || die "python3 was not found."
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
    || die "Python 3.10 or newer is required."
python3 -c 'import venv, ensurepip' 2>/dev/null \
    || die "the Python venv module is missing. On Ubuntu: sudo apt install python3-venv"

# The Desktop folder, wherever the system language put it (Desktop, Escritorio, ...).
desktop_dir=""
if [ "$desktop_shortcut" = true ]; then
    configured="$(sed -n 's/^XDG_DESKTOP_DIR="\(.*\)"$/\1/p' "$HOME/.config/user-dirs.dirs" 2>/dev/null | head -n 1)" || configured=""
    candidate="${configured//\$HOME/$HOME}"
    [ -n "$candidate" ] || candidate="$HOME/Desktop"
    case "$candidate" in "$HOME"/*) [ -d "$candidate" ] && desktop_dir="$candidate" ;; esac
fi

say "Ganki will be installed for your user only:"
say "  program files : $APP_DIR"
say "  command       : $BIN_DIR/ganki"
say "  menu entry    : $DESKTOP_DIR/ganki.desktop"
[ -n "$desktop_dir" ] && say "  desktop icons : $desktop_dir/Ganki.desktop and Ganki-elegir-navegador.desktop"
if [ "$assume_yes" = false ]; then
    read -r -p "Continue? [y/N] (s/y = yes) " answer
    case "$answer" in y|Y|yes|YES|s|S|si|SI|Si|sí|Sí) ;; *) say "Cancelled. Nothing was changed."; exit 0 ;; esac
fi

mkdir -p "$APP_DIR" "$BIN_DIR" "$DESKTOP_DIR"
# Older versions could add a natural voice here. It is gone now: remove what it left.
rm -rf -- "$APP_DIR/voice"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/python" -m pip install --quiet --upgrade pip

# Build from a throw-away copy: pip writes work files next to the code it builds,
# and the checkout may be read-only or owned by someone else.
build_dir="$(mktemp -d)"
trap 'rm -rf -- "$build_dir"' EXIT
cp -R -- "$SRC/pyproject.toml" "$SRC/README.md" "$SRC/LICENSE" "$SRC/src" "$build_dir/"
"$APP_DIR/venv/bin/python" -m pip install --quiet --upgrade "$build_dir"
# Same version number but new code (a git pull) is not reinstalled by --upgrade alone.
"$APP_DIR/venv/bin/python" -m pip install --quiet --force-reinstall --no-deps "$build_dir"

ln -sfn "$APP_DIR/venv/bin/ganki" "$BIN_DIR/ganki"
# The icon is referenced by its full path: that works on every desktop without
# having to refresh an icon cache.
install -m 644 "$SRC/packaging/ganki.svg" "$APP_DIR/ganki.svg"

# Quote the path as the desktop-entry format requires (spaces, and % written as %%).
exec_path="${BIN_DIR//%/%%}/ganki"
icon_path="$APP_DIR/ganki.svg"
make_launcher() {  # make_launcher <template name> <destination>
    sed -e "s|@EXEC@|\"$exec_path\"|" -e "s|@ICON@|$icon_path|" \
        "$SRC/packaging/$1" > "$2"
}
make_launcher ganki.desktop.in "$DESKTOP_DIR/ganki.desktop"
make_launcher ganki-choose.desktop.in "$DESKTOP_DIR/ganki-choose-browser.desktop"
chmod 644 "$DESKTOP_DIR/ganki.desktop" "$DESKTOP_DIR/ganki-choose-browser.desktop"
if command -v update-desktop-database >/dev/null; then
    update-desktop-database "$DESKTOP_DIR" >/dev/null 2>&1 || true
fi

if [ -n "$desktop_dir" ]; then
    make_launcher ganki.desktop.in "$desktop_dir/Ganki.desktop"
    make_launcher ganki-choose.desktop.in "$desktop_dir/Ganki-elegir-navegador.desktop"
    for icon in Ganki.desktop Ganki-elegir-navegador.desktop; do
        chmod 755 "$desktop_dir/$icon"  # desktops only run launchers marked executable
        if command -v gio >/dev/null; then  # "trust" it so the desktop does not ask on first click
            gio set "$desktop_dir/$icon" metadata::trusted true >/dev/null 2>&1 || true
        fi
    done
fi

say ""
say "Done. Open Ganki from your applications menu, or run: ganki"
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) say "Note: $BIN_DIR is not in your PATH yet. Log out and in again, or use the menu entry." ;;
esac
