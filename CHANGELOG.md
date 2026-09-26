# Changelog

All notable changes to Skiff are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions use
[Semantic Versioning](https://semver.org/).

## [0.4.0] - 2026-09-26

### Security

Full remediation of the 2026-09-24 Codex security audit (18 findings), each
fixed via a focused PR with a cross-read and CI green on macOS/Linux/Windows:

- Host-key verification fails closed on a corrupt store and enforces `@revoked`
  keys (matched by key material, robust to any host-pattern form).
- Vault secrets and AI API keys are bound to backend-owned destinations/origins
  (recorded at save time), so a compromised frontend cannot redirect a saved
  password or key to an attacker-chosen host.
- Downloads reject symlink/junction ancestors; disconnect awaits full teardown
  and terminates live forward tunnels.
- Catalogue, settings, upload, and snapshot/capture writes are atomic and never
  delete the original before replacing it; transcripts and captures are created
  owner-only (`0700`/`0600`) and refuse to follow planted symlinks.
- Resource caps on the logger and AI stream; key-install success requires a
  clean exit; `read_log` rejects drive-relative/ADS names and symlinks.
- Password kept in `Zeroizing` across all auth paths; Windows credential blob
  wiped before free. `cargo audit` runs in CI.

### Added

- Transfer panel with a full per-file failure list and one-click retry.
- Right-click the host sidebar to create a New Connection or New Folder.
- Capture a command's output to a file (per-host, hidden exec channel).
- Interactive keyboard-interactive auth: OTP / 2FA / challenge prompts are
  surfaced in the UI; the stored password stays in the backend and Cancel truly
  aborts authentication.

### Fixed

- SFTP handle exhaustion on large recursive transfers (handles now closed after
  each file, both directions).

## [0.3.1] - 2026-09-24

- Security hardening pass (server-side).

## [0.3.0] - 2026-09-24

- Initial cross-platform release (Windows, Linux, macOS/arm64).
