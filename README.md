# Ganki

A local dashboard for Linux that shows what is installed on your computer, what is out of date, and what you can safely clean up to free disk space.

> **Status: first public version (0.1.0).** Ganki can change your system: it can update or remove programs, empty apt's download cache and remove unused packages. Every change shows a preview first and needs your confirmation, and there is no undo button. It has been tested on Ubuntu 24.04-based Linux only.

[Leer en español](README.es.md)

## Goals

- Inventory of installed software (apt, snap, flatpak, pip and npm; Docker later) with version, size and install date.
- Show which programs are outdated and which have known vulnerabilities.
- Show large downloads grouped by type and open their folder so you can review them (screenshots and duplicate files later).
- Free disk space through explicit actions that always show a preview first.
- Run entirely on your own machine, in your browser, with no data leaving it.

## Design principles

- **Read-only first.** Features that only show information come before any feature that changes the system.
- **Preview before acting.** Every change shows exactly what will be affected and, when apt can tell, how much space it frees.
- **Protected items.** Essential system packages cannot be removed from the interface.
- **Your files stay yours.** Ganki never deletes your files: it opens their folder so you decide. Before a package change it saves a temporary copy of the package list as a record (there is no undo button).
- **Local only.** The web interface listens on `127.0.0.1` only.
- **Reuse, don't reinvent.** Ganki coordinates proven tools instead of reimplementing them.

## Roadmap

- [x] Read-only apt inventory
- [x] Update and vulnerability status
- [x] Web dashboard (English and Spanish)
- [x] Downloads by type
- [x] Python (pip) and npm packages, checked against the public OSV lists
- [x] Packaging (installer and desktop launcher)
- [ ] Screenshots and duplicates view
- [ ] Docker images
- [x] Guarded update, removal and cleanup actions (apt)

## What Ganki downloads

Two kinds of public files, only when they changed, and never anything about your computer:
Canonical's Ubuntu vulnerability list, and, only if you have packages installed with `pip` or
`npm`, the OSV list of that ecosystem (`osv-vulnerabilities.storage.googleapis.com`). The names
and versions of what you have installed are compared on your computer and never sent.

## Install and run

From a copy of this repository, without `sudo` (everything goes inside your home folder):

```
git clone https://github.com/gankigit/ganki.git
cd ganki
scripts/install.sh
```

Then open **Ganki** from your applications menu, or run `ganki` in a terminal. It opens in your browser and only accepts connections from your own computer. Close it with `Ctrl+C` in its terminal. If you have more than one browser installed, a small window asks which one to use and can remember the choice. Use the second icon **Ganki (choose browser)** to be asked again. To remove it: `scripts/uninstall.sh`.

Each start creates a new secret key that is kept out of the terminal: the browser opens with it, and a copy is saved in `~/.cache/ganki/dashboard-url`, readable only by you.

### Ways to open Ganki

| You want to | Do this |
|---|---|
| Open it in your default browser | Double-click the **Ganki** icon, or choose it in the applications menu. |
| Open it a second time | Click the icon again: it reopens the copy that is already running. |
| Choose the browser | With more than one browser installed, a small window asks which one to use (it lists the browsers it finds, or lets you pick a program from your files) and can remember the choice. To be asked again, or to undo a remembered choice, use the second icon **Ganki (choose browser)** and answer "Always ask" (or run `ganki --ask-browser`). Do not use your file manager's "Open with" on the icon: that tries to open the launcher file itself, and a browser just downloads it. |
| Always use one browser, without the window | In a terminal: `BROWSER=librewolf ganki` (the command of your browser). |
| Open it by hand | In a terminal: `ganki --no-open`, then paste the whole address saved in `~/.cache/ganki/dashboard-url` into any browser. |

Typing `127.0.0.1:PORT` alone does not work, and that is on purpose: the address carries a secret key that changes on every start, so other programs on your computer cannot read your data. If a page says the key is missing, open Ganki from the icon or with one of the ways above.

## Requirements

Debian/Ubuntu-based Linux and Python 3.10 or newer. Developed and tested on an Ubuntu 24.04 base. Windows and macOS are not supported.

## Development notes

Behavior that touches the system is meant to be covered by automated tests and static analysis; the roadmap shows what exists today.

## License

MIT. See [LICENSE](LICENSE).
