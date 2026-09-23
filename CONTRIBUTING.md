# Contributing

## Setup

Node 20+, Rust (MSVC), VS Build Tools C++ workload.

```
npm install
npm run tauri dev
```

## Ground rules

- `npm run tauri build -- --no-bundle` must succeed and `cargo test` must pass.
- Read SECURITY.md before touching auth, credentials, host keys, or IPC —
  those invariants are the project.
- Frontend/backend payload types mirror each other (`src/types.ts` vs
  `src-tauri/src/ssh.rs` serde structs). Change both together.
- Terminal panes must never be unmounted while their session lives —
  scrollback dies with them. See TerminalDeck for why the tree is shaped the
  way it is.
- Seed/example data uses documentation address ranges (RFC 5737). Never
  commit a real hostname, IP, or credential — including in comments and
  commit messages.
