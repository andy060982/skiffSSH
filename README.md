# Skiff

A fast, small SSH terminal and SFTP client for Windows, built for network and
systems administrators. Tauri + React front end, Rust back end — a single
**~4.7 MB** portable executable using ~30 MB of memory.

> Built by an infrastructure admin who spends the day in Palo Alto firewalls,
> ESXi hosts, switches, and Linux boxes — and wanted one tool that treats
> network appliances as first-class citizens, not an afterthought.

## Features

**Terminal**
- xterm.js with WebGL rendering, 10k-line scrollback that survives tab switches
- Split panes — side by side or stacked, resizable, per-pane tmux sessions
- Broadcast mode: type once, send to every pane in a tab
- PuTTY-style right-click paste, copy-on-select, `Ctrl+Shift+F` find in scrollback
- Per-host **snippets** with `Ctrl+Shift+1–9` shortcuts

**Connections**
- Password, **private key**, and **SSH agent** auth (Windows OpenSSH agent + Pageant)
- **ProxyJump** through any saved host
- **Local port forwarding** (`ssh -L`) with a per-session tunnel manager, bound to 127.0.0.1 only
- Keepalives detect dropped links in ~45 s; one-click reconnect
- On-connect command presets: tmux/screen keep-alive, PAN-OS terminal width and pager, Cisco paging

**Files**
- Dual-pane SFTP with recursive directory transfers and byte-accurate progress
- Drag files from Explorer to upload
- Transfer queue survives switching back to the terminal

**Network-engineer tooling**
- Built-in ping, traceroute (live-streamed), TCP port check (open/closed/filtered), DNS lookup — from the workstation, for when SSH *can't* connect
- One-click reachability sweep of every saved host's SSH port
- **Config snapshots**: capture a device's running config over a hidden exec channel, keep timestamped history, diff any two — "what changed since Tuesday" in two clicks
- Quick connect (`Ctrl+Shift+P`) for one-off boxes; nothing saved
- Credential sharing: many hosts, one vault entry — password rotations are one edit

**Operator safety**
- Host keys: trust-on-first-use with a fingerprint prompt; a **changed** key is refused outright, never prompted
- Per-host accent colors — make production *look* different before you type
- Session transcripts, ANSI-stripped and flushed per chunk, with an in-app history browser and automatic retention (30 days / 500 files)
- Colorblind-safe UI: status is carried by glyph shape first, hue second

**Security model**
- Passwords and key passphrases live in **Windows Credential Manager**, never in config files
- No IPC command returns a secret to the UI — the front end only ever passes a host id
- `hosts.json` is topology only, safe to export and share
- Restored tabs come back **disconnected** — the app never dials your infrastructure on launch

## Install

Grab `skiff.exe` from Releases — it is portable, no installer needed.
Requires the WebView2 runtime (preinstalled on Windows 10/11).

## Build from source

Prerequisites: Node 20+, Rust (MSVC toolchain), VS Build Tools with the C++ workload.

```
npm install
npm run tauri build -- --no-bundle
# → src-tauri/target/release/skiff.exe
```

`npm run tauri dev` runs with hot reload and devtools.

## Data locations

| Path | Contents |
|---|---|
| `%APPDATA%\skiff\hosts.json` | Host catalogue (no secrets) |
| `%APPDATA%\skiff\known_hosts` | Trusted host keys (OpenSSH format) |
| `%APPDATA%\skiff\sessions.json` | Tabs to restore on launch |
| `%APPDATA%\skiff\logs\` | Session transcripts (plaintext — treat accordingly) |
| Windows Credential Manager | Passwords / key passphrases, as `skiff:host:<id>` |

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned work and the reasoning behind
rejected features.

## Known limitations

- Windows only for now (the credential store and agent integration are Win32)
- No remote/dynamic port forwarding yet (`-R` / `-D`)
- Transcripts are lossy for full-screen programs (vim, top) — inherent to flattening a terminal into a text log
- PuTTY `.ppk` keys must be exported to OpenSSH format first

## License

MIT — see [LICENSE](LICENSE).
