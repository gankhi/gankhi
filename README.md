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

- [ ] Read-only apt inventory
- [ ] Update and vulnerability status
- [ ] Web dashboard (English and Spanish)
- [ ] Downloads, screenshots and duplicates view
- [ ] Guarded removal and cleanup actions
- [ ] Packaging (installer and desktop launcher)

## Requirements

Debian/Ubuntu-based Linux and Python 3.10 or newer. Developed on an Ubuntu 24.04 base.

## Development notes

This project is developed with the help of AI coding assistants. Behavior that touches the system is meant to be covered by automated tests and static analysis; the roadmap shows what exists today.

## License

MIT. See [LICENSE](LICENSE).
