# Security

## Reporting

Open a private security advisory on GitHub, or email the maintainer. Please do
not open public issues for vulnerabilities.

## Design notes for reviewers

The properties below are load-bearing; a change that weakens one is a bug even
if everything still works:

- **Secrets never cross IPC.** No Tauri command returns a password or
  passphrase to the webview. `credential_save` accepts one (user just typed
  it) and writes it to Windows Credential Manager; there is deliberately no
  `credential_read` command.
- **Changed host keys are refused, not prompted.** Only *unknown* keys get a
  trust-on-first-use dialog. `%APPDATA%\skiff\known_hosts` is standard OpenSSH
  format; a changed key requires manually editing that file.
- **Port forwards bind 127.0.0.1 only.**
- **`open_logs_folder` takes no path argument** — a parameterised open() would
  be a shell-execute primitive if the webview were ever compromised.
- **Transcripts are plaintext.** Anything visible on screen lands on disk.
  Retention (30 days / 500 files) prunes on launch; treat the logs directory
  as sensitive as the sessions were.
