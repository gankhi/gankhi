#!/usr/bin/env bash
# Remove what scripts/install.sh added. It only touches Ganki's own files inside
# your home folder. The downloaded vulnerability data (~/.cache/ganki) is kept
# unless you pass --purge.
#
# Usage: scripts/uninstall.sh [--yes] [--purge]

set -euo pipefail

DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
APP_DIR="$DATA_HOME/ganki"
BIN_LINK="$HOME/.local/bin/ganki"
DESKTOP_FILE="$DATA_HOME/applications/ganki.desktop"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/ganki"

say() { printf '%s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

assume_yes=false
purge=false
for arg in "$@"; do
    case "$arg" in
        --yes|-y) assume_yes=true ;;
        --purge) purge=true ;;
        -h|--help) sed -n '2,7p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $arg" ;;
    esac
done

[ -n "${HOME:-}" ] || die "HOME is not set."
for path in "$APP_DIR" "$BIN_LINK" "$DESKTOP_FILE" "$CACHE_DIR"; do
    case "$path" in "$HOME"/*) ;; *) die "refusing to remove anything outside your home folder: $path" ;; esac
done

say "This will remove:"
say "  $APP_DIR"
say "  $BIN_LINK"
say "  $DESKTOP_FILE"
say "  Ganki.desktop on your Desktop folder, if it is there"
[ "$purge" = true ] && say "  $CACHE_DIR (downloaded vulnerability data)"
if [ "$assume_yes" = false ]; then
    read -r -p "Continue? [y/N] " answer
    case "$answer" in y|Y|yes|YES) ;; *) say "Cancelled. Nothing was changed."; exit 0 ;; esac
fi

rm -rf -- "$APP_DIR"
rm -f -- "$BIN_LINK" "$DESKTOP_FILE"
# Remove the Desktop shortcut only if it is ours (it launches the ganki command).
configured="$(sed -n 's/^XDG_DESKTOP_DIR="\(.*\)"$/\1/p' "$HOME/.config/user-dirs.dirs" 2>/dev/null | head -n 1)"
for folder in "${configured//\$HOME/$HOME}" "$HOME/Desktop"; do
    shortcut="$folder/Ganki.desktop"
    case "$shortcut" in "$HOME"/*) ;; *) continue ;; esac
    if [ -f "$shortcut" ] && grep -q '/ganki"$' "$shortcut"; then rm -f -- "$shortcut"; fi
done
[ "$purge" = true ] && rm -rf -- "$CACHE_DIR"
say "Ganki was removed."
