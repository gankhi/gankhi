# Changelog

All notable changes to Gankhi. Dates are written year-month-day.

## 0.1.0 (2026-10-20)

First public version. (During development the project was called Ganki; the installer moves an old copy to the new name and keeps its settings.)

### What it does
- Lists the programs installed with apt and checks them against Ubuntu's public security
  list, on your own computer. Nothing about your programs is sent anywhere.
- Checks Python (pip) and Node (npm) packages against the public OSV lists. The lists are
  downloaded only if you have packages installed with those tools.
- Lists snap and flatpak apps. It does not check them: they carry their own libraries.
- Shows disk, memory and updates, and estimates what you can recover (old kernels, apt
  cache, orphaned packages, Downloads).
- Explains the result in writing, section by section, in Spanish and English.
- Writes a PDF report, coloured by priority and grouped by family.
- Updates or removes a program, empties apt's download cache and removes unused packages
  (old kernels, orphans) only after a preview and your explicit confirmation. The password
  is asked by the system's own window, never by Gankhi. Gankhi refuses a change that would
  remove software the system depends on.
- Opens the folder of a large download so you can look at the file and delete it yourself.
  Gankhi never deletes your files.
- Puts what matters first: updates that fix critical or high notices, and security updates
  from Ubuntu, come before the rest.

### Safe by design
- Listens only on `127.0.0.1`, with a random access key.
- Runs only a fixed list of read-only commands. The commands that change the system are
  written out exactly and nothing else is accepted.
- No account, no analytics, no outside resources in the page.

### Known limits
- Linux only (Debian/Ubuntu-based). Tested on an Ubuntu 24.04 base.
- There is no undo button. A temporary copy of the package list is saved before a change,
  as a record; going back means reinstalling by hand.
- The update and remove commands shown for snap and flatpak apps are meant to be copied
  and run by you; they have not been exercised in the automated tests.
- Closing the terminal window that opens with Gankhi stops it.

### Install
- `scripts/install.sh` installs Gankhi without sudo.
