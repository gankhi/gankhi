# Changelog

All notable changes to Ganki. Dates are written year-month-day.

## 0.1.0 (2026-10-18)

First public version.

### What it does
- Lists the programs installed with apt and checks them against Ubuntu's public security
  list, on your own computer. Nothing about your programs is sent anywhere.
- Checks Python (pip) and Node (npm) packages against the public OSV lists. The lists are
  downloaded only if you have packages installed with those tools.
- Lists snap and flatpak apps. It does not check them: they carry their own libraries.
- Shows disk, memory and updates, and estimates what you can recover (old kernels, apt
  cache, orphaned packages, Downloads).
- Explains the result out loud, in Spanish and English, with a local voice (optional).
- Writes a PDF report, coloured by priority and grouped by family.
- Updates or removes a program only after a preview and your explicit confirmation. The
  password is asked by the system's own window, never by Ganki.

### Safe by design
- Listens only on `127.0.0.1`, with a random access key.
- Runs only a fixed list of read-only commands. The commands that change the system are
  written out exactly and nothing else is accepted.
- No account, no analytics, no outside resources in the page.

### Install
- `scripts/install.sh` installs Ganki without sudo.
- `scripts/install-voice.sh` (optional) adds the Spanish and English voices, about 170 MB.
