# Changelog

All notable changes to Gankhi. Dates are written year-month-day.

## Unreleased

### Added
- Programs that come from outside Ubuntu (another apt repository, a `.deb` file, snap, flatpak) are shown as "Not checked" instead of "up to date", with their own filter, a segment in the summary ring, a section in the page and in the PDF report, and a sentence from the assistant.
- A package with a newer version that does not fix its vulnerabilities no longer shows "No fix yet" next to a highlighted Update button: it says "A newer version exists, but it does not fix these vulnerabilities yet" and the button is not highlighted. When there is nothing to update, the Update button is no longer shown (it used to appear disabled).
- An Ubuntu package that is only out of date (a newer version is out) is no longer taken for a loose `.deb` file: apt stops listing the installed version in any repository, and Gankhi now uses where the newer version comes from. Those packages are checked against Ubuntu's notices again, and a package from another repository shows that repository.
- A button in the "Not checked" section copies the list with a strict question to paste into an AI of your choice. It asks only for a 3-column table (program, whether your version is vulnerable with CVE links, command to update) with no removal commands and no extra explanations (Gankhi's own Remove button checks what depends on a program). It tells the AI to search the web instead of answering from memory, and to say "Not reported yet" instead of "No" so a missing answer is not mistaken for a safe program. It must search each program one by one and never fill the whole column with the same answer. Gankhi sends nothing.
- Every program that was not checked has its own "Copy question for an AI" button, in its row of the tools list, in the snap and flatpak apps section and in the "Not checked" section. It copies a question about that program only, with the same strict answer format. The button that copies the whole list stays.
- The preview before updating or removing a program shows two commands to copy that tell what uses it: which installed programs depend on it, and what it needs. Gankhi does not run them. The Python rows show `python3 -m pip show` with the real package name instead of a placeholder.
- When a change is running, the main page shows which one and its output as it goes, and reloads when it ends. If you press the button of another preview meanwhile, that page shows the change in progress and says when the button works again, instead of only refusing. The browser console no longer logs a "409 conflict" for it.
- The copy button goes back to its label a couple of seconds after copying, ready for another copy.
- The "Not checked" section lists only what Gankhi cannot update for you (snap and flatpak). Programs from other apt repositories or `.deb` files already appear in the tools list with an Update option, so the section only points to them. The text to copy for an AI still lists them, since whether a program can be updated says nothing about its vulnerabilities, and now also asks for the removal command.
- The Python and npm section lists every package (the ones without notices fold away), in the page and in the PDF report.
- The assistant and the header count the same: system programs plus Python and npm packages.
- The preview and the Downloads detail pages have an ES/EN switch.
- Each part of the programs ring (up to date, outdated, with vulnerabilities, not checked) opens its own list.
- Column titles stay in view while you scroll the page (on screens wide enough for the tables to fit).
- While a change runs, a clear "working" notice; when it ends, a "finished" notice and the output folded away.

### Changed
- A package that comes from another repository is no longer compared with Ubuntu's notices, which are about Ubuntu's own builds.
- Known limit: repositories that reuse Ubuntu's release name (Docker, PPAs) are not told apart.

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
- Linux only (Ubuntu and derivatives; plain Debian has no vulnerability check). Tested on an Ubuntu 24.04 base.
- There is no undo button. A temporary copy of the package list is saved before a change,
  as a record; going back means reinstalling by hand.
- The update and remove commands shown for snap and flatpak apps are meant to be copied
  and run by you; they have not been exercised in the automated tests.
- Closing the terminal window that opens with Gankhi stops it.

### Install
- `scripts/install.sh` installs Gankhi without sudo.
