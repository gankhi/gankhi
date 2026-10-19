# Security Policy

Ganki is a local tool that can inspect and remove software and files on your
machine, so security reports are taken seriously.

## Supported versions

Ganki is young (0.1.x). Only the latest release and the latest commit on `main`
receive fixes.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

1. Preferred: use GitHub's private reporting. Go to the **Security** tab of this
   repository and choose **Report a vulnerability**.
2. Alternative: email gankigit@proton.me with the subject `Ganki security`.

Please include what you found, how to reproduce it, and the impact you expect.
This is a volunteer project: I aim to acknowledge reports within 7 days and will
keep you informed about the fix. Reporters are credited unless they prefer not to be.

## Design principles that count as security bugs when broken

- The web interface listens only on `127.0.0.1`, behind a random access key, a
  host check, a same-origin check on every change, and a strict content policy.
- No command is run through a shell; only an allowlist of fixed commands with
  fixed arguments. The few that change the system (update, remove, clean,
  autoremove) go through the system's own password window (`pkexec`), and
  nothing else is accepted, even from a crafted request.
- Protected packages (the system, the running kernel, essential software) cannot
  be removed or dragged out by another removal, even by a crafted request.
- Package names are validated strictly and must belong to the latest scan.
- Ganki never deletes files itself. For downloads it can only open a folder
  inside Downloads in the file manager; paths are resolved and checked first.
- Vulnerability data is read in memory, never extracted to disk, and is only
  ever treated as data.
- Nothing about your computer leaves it. The only network use is downloading
  the public vulnerability lists.

## Known limits

- Anything that already runs as your user can read the access key file
  (`~/.cache/ganki/dashboard-url`, mode 600) and use Ganki. That is true of any
  local tool.
- The vulnerability lists are fetched over HTTPS but are not signed.
- The optional voice installer downloads Piper (version pinned, wheels only) and
  voice files from Hugging Face without a checksum.
