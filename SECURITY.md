# Security Policy

Ganki is a local tool that can inspect and remove software and files on your
machine, so security reports are taken seriously.

## Supported versions

The project is in early development (alpha). Only the latest commit on `main`
receives fixes.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

1. Preferred: use GitHub's private reporting. Go to the **Security** tab of this
   repository and choose **Report a vulnerability**.
2. Alternative: email gankigit@proton.me with the subject `Ganki security`.

Please include what you found, how to reproduce it, and the impact you expect.
This is a volunteer project: I aim to acknowledge reports within 7 days and will
keep you informed about the fix. Reporters are credited unless they prefer not to be.

## Design principles that count as security bugs when broken

- The web interface listens only on `127.0.0.1`.
- No command is run through a shell; only an allowlist of fixed commands.
- Protected packages and paths cannot be removed, even by a crafted request.
- File paths are resolved and validated before any deletion; deletions go to the
  trash first.
