# Ganki

A local dashboard for Linux that shows what is installed on your computer, what is out of date, and what you can safely clean up to free disk space.

> **Status: early development (alpha).** Nothing in this repository modifies your system yet. The first milestone is a read-only inventory of installed software.

[Leer en español](README.es.md)

## Goals

- Inventory of installed software (apt first; snap, flatpak, pip, npm and Docker later) with version, size and install date.
- Show which programs are outdated and which have known vulnerabilities.
- Find large downloads, screenshots and duplicate files, grouped by type.
- Free disk space through explicit, reversible actions.
- Run entirely on your own machine, in your browser, with no data leaving it.

## Design principles

- **Read-only first.** Features that only show information come before any feature that changes the system.
- **Preview before acting.** Every removal shows exactly what will be affected and how much space it frees.
- **Protected items.** Essential system packages cannot be removed from the interface.
- **Reversible by default.** Files go to the trash, and the package list is saved before changes.
- **Local only.** The web interface will listen on `127.0.0.1` only.
- **Reuse, don't reinvent.** Ganki coordinates proven tools instead of reimplementing them.

## Roadmap

- [x] Read-only apt inventory
- [x] Update and vulnerability status
- [x] Web dashboard (English and Spanish)
- [x] Downloads by type
- [x] Packaging (installer and desktop launcher)
- [ ] Screenshots and duplicates view
- [ ] Docker images
- [ ] Guarded removal and cleanup actions

## Install and run

From a copy of this repository, without `sudo` (everything goes inside your home folder):

```
scripts/install.sh
```

Then open **Ganki** from your applications menu, or run `ganki` in a terminal. It opens in your browser and only accepts connections from your own computer. Close it with `Ctrl+C` in its terminal. To remove it: `scripts/uninstall.sh`.

Each start creates a new secret key that is kept out of the terminal: the browser opens with it, and a copy is saved in `~/.cache/ganki/dashboard-url`, readable only by you.

## Requirements

Debian/Ubuntu-based Linux and Python 3.10 or newer. Developed on an Ubuntu 24.04 base.

## Development notes

Behavior that touches the system is meant to be covered by automated tests and static analysis; the roadmap shows what exists today.

## License

MIT. See [LICENSE](LICENSE).
