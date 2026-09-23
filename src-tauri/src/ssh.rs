//! SSH transport, PTY I/O, and SFTP, built on russh (pure Rust — no libssh2 or
//! OpenSSL system dependency, so the Windows build needs no vcpkg).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use russh::client::{self, Handle};
use crate::utils::known_hosts::{self, HostKeyStatus};
use crate::utils::session_log::SessionLog;
use russh::{ChannelMsg, ChannelWriteHalf};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::FileType;
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{oneshot, Mutex};

use crate::credentials;

/// How long a host-key prompt waits for a human before giving up. Long enough
/// to read a fingerprint off a phone, short enough that a forgotten dialog does
/// not pin a connection task forever.
const HOST_KEY_PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Minimum gap between progress events for one transfer. At 64 KB chunks an
/// unthrottled emit would fire ~16k times per gigabyte; the IPC bridge and
/// React would both spend more time on bookkeeping than on the transfer.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

const CHUNK: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("no open session {0}")]
    NoSession(String),
    #[error("session {0} has no shell channel")]
    NoShell(String),
    #[error("session {0} is disconnected")]
    Disconnected(String),
    #[error("authentication failed for {0}")]
    AuthFailed(String),
    #[error("host key for {host} was rejected")]
    HostKeyRejected { host: String },
    #[error("no answer to the host key prompt for {host}")]
    HostKeyTimeout { host: String },
    #[error(
        "host key for {host} CHANGED (known_hosts line {line}). This is either a rebuilt \
         server or an interception attempt. Skiff will not connect until the old entry is \
         removed by hand."
    )]
    ChangedHostKey { host: String, line: usize },
    #[error("{0}")]
    PartialTransfer(String),
    #[error(transparent)]
    KnownHosts(#[from] crate::utils::known_hosts::KnownHostsError),
    #[error(transparent)]
    Credential(#[from] credentials::CredError),
    #[error(transparent)]
    Russh(#[from] russh::Error),
    #[error(transparent)]
    Sftp(#[from] russh_sftp::client::error::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/* ------------------------------------------------------------------ payloads */

/// Serialised to the frontend. Mirrors `FileEntry` in src/types.ts — change the
/// two together.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    pub name: String,
    /// "file" | "directory" | "symlink"
    pub kind: &'static str,
    pub size: u64,
    /// Unix epoch seconds, or null when the server omits mtime.
    pub modified: Option<u32>,
    pub mode: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirListing {
    pub path: String,
    pub entries: Vec<FileEntry>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferProgress {
    pub session_id: String,
    pub file_path: String,
    pub bytes_transferred: u64,
    /// 0 when the server declines to report a size; the UI must treat that as
    /// indeterminate rather than dividing by zero.
    pub total_bytes: u64,
    pub direction: &'static str,
    pub done: bool,
}

/// Connection lifecycle, pushed to the frontend on `ssh://status`.
///
/// Without this the UI has no way to learn a session died: the tab keeps its
/// "connected" dot, the status bar keeps claiming a live link, and the first
/// hint of trouble is a keystroke that goes nowhere.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStatusEvent {
    pub session_id: String,
    /// "connected" | "disconnected" | "error"
    pub status: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyRequest {
    pub request_id: String,
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub key_type: String,
    /// OpenSSH-style SHA256 fingerprint — the exact string `ssh-keygen -lf`
    /// prints, so it can be compared against an out-of-band source verbatim.
    pub fingerprint: String,
}

/// One active local port-forward, as reported to the UI.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardInfo {
    pub id: String,
    pub session_id: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    /// "local" (ssh -L) or "socks" (ssh -D).
    pub kind: &'static str,
}

/// Bastion to tunnel through, resolved by the frontend from the catalogue.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JumpParams {
    pub host_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: String,
    pub key_path: Option<String>,
}

/* -------------------------------------------------------------- host keys */

/// Bridges the async Handler to a human decision in the UI.
///
/// `check_server_key` runs inside russh's connection task and cannot block, so
/// it parks on a oneshot while the frontend shows a dialog. The matching sender
/// is handed back by the `host_key_respond` command.
#[derive(Default)]
pub struct HostKeyPrompts {
    pending: DashMap<String, oneshot::Sender<bool>>,
}

impl HostKeyPrompts {
    /// Resolve a prompt. Returns false if the id is unknown — a stale dialog
    /// answered after a timeout, which is not an error worth surfacing.
    pub fn respond(&self, request_id: &str, accept: bool) -> bool {
        match self.pending.remove(request_id) {
            Some((_, tx)) => tx.send(accept).is_ok(),
            None => false,
        }
    }

    fn register(&self, request_id: String) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        self.pending.insert(request_id, tx);
        rx
    }

    fn cancel(&self, request_id: &str) {
        self.pending.remove(request_id);
    }
}

/// Host key policy.
///
/// russh's default handler rejects every key, and the tempting "fix" is to
/// return `Ok(true)` — which silently disables the one check that detects a
/// man-in-the-middle. Instead:
///
///   * known and matching  -> accept silently
///   * known and DIFFERENT -> refuse outright, no prompt. A changed key is the
///     one case where a click-through is genuinely dangerous, and OpenSSH
///     refuses here too. Clearing it should require deliberate manual action.
///   * unknown             -> ask a human, showing the SHA256 fingerprint, and
///     record the answer in known_hosts on acceptance (trust on first use).
struct ClientHandler {
    host: String,
    /// Resolved peer address, shown alongside the hostname so the user can see
    /// *which* machine answered — the distinction that matters when a name
    /// resolves somewhere unexpected.
    ip: String,
    port: u16,
    app: AppHandle,
    prompts: Arc<HostKeyPrompts>,
}

impl client::Handler for ClientHandler {
    type Error = SshError;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Tri-state, and the mapping is the whole security property:
        //   Trusted -> accept silently
        //   Changed -> refuse, never prompt
        //   Unknown -> ask a human
        match known_hosts::check(&self.host, self.port, server_public_key) {
            Ok(HostKeyStatus::Trusted) => return Ok(true),
            Ok(HostKeyStatus::Changed { line }) => {
                return Err(SshError::ChangedHostKey {
                    host: self.host.clone(),
                    line,
                })
            }
            Ok(HostKeyStatus::Unknown) => { /* fall through and ask */ }
            Err(e) => return Err(SshError::KnownHosts(e)),
        }

        let request_id = format!("hk-{}-{}", self.host, Instant::now().elapsed().as_nanos());
        let fingerprint = server_public_key
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string();

        let rx = self.prompts.register(request_id.clone());

        self.app
            .emit(
                "ssh://host-key-prompt",
                HostKeyRequest {
                    request_id: request_id.clone(),
                    host: self.host.clone(),
                    ip: self.ip.clone(),
                    port: self.port,
                    key_type: server_public_key.algorithm().to_string(),
                    fingerprint,
                },
            )
            .map_err(|_| SshError::HostKeyRejected {
                host: self.host.clone(),
            })?;

        match tokio::time::timeout(HOST_KEY_PROMPT_TIMEOUT, rx).await {
            Ok(Ok(true)) => {
                // Trust on first use, recorded so the next connection is silent.
                // Same store the check above reads — writing anywhere else would
                // mean re-prompting forever.
                known_hosts::trust(&self.host, self.port, server_public_key)?;
                Ok(true)
            }
            Ok(Ok(false)) => Err(SshError::HostKeyRejected {
                host: self.host.clone(),
            }),
            // Sender dropped, or nobody answered in time.
            Ok(Err(_)) => Err(SshError::HostKeyRejected {
                host: self.host.clone(),
            }),
            Err(_) => {
                self.prompts.cancel(&request_id);
                Err(SshError::HostKeyTimeout {
                    host: self.host.clone(),
                })
            }
        }
    }
}

/* -------------------------------------------------------------- session */

pub struct Session {
    handle: Handle<ClientHandler>,
    /// Write half of the interactive shell channel. Split from the Channel so
    /// the read half can be owned by a pump task while writes and window-change
    /// requests still work — `into_stream()` would consume the Channel and take
    /// `window_change` with it, leaving no way to resize.
    shell: Mutex<Option<ChannelWriteHalf<client::Msg>>>,
    sftp: Mutex<Option<Arc<SftpSession>>>,
    /// The bastion connection, when this session rides a jump host. Held only
    /// so it is not dropped: dropping the jump Handle closes the tunnel under
    /// the target session's feet.
    _jump: Option<Handle<ClientHandler>>,
    /// Cleared by the output pump when the channel ends. Checked before every
    /// write so input into a dead session fails loudly instead of vanishing
    /// into a closed channel.
    alive: AtomicBool,
}

#[derive(Default)]
pub struct Registry {
    sessions: DashMap<String, Arc<Session>>,
    /// Active local forwards: id -> (info, listener task). Aborting the task
    /// closes the listener; established tunnels drain on their own.
    forwards: DashMap<String, (ForwardInfo, tokio::task::JoinHandle<()>)>,
}

impl Registry {
    fn get(&self, id: &str) -> Result<Arc<Session>, SshError> {
        self.sessions
            .get(id)
            .map(|r| Arc::clone(r.value()))
            .ok_or_else(|| SshError::NoSession(id.to_string()))
    }

    pub fn remove(&self, id: &str) {
        self.sessions.remove(id);
        // A forward's transport is this session; with it gone the listener
        // would sit accepting connections it can never tunnel, forever. Sweep
        // them here so closing a tab tears down its tunnels too.
        let doomed: Vec<String> = self
            .forwards
            .iter()
            .filter(|e| e.value().0.session_id == id)
            .map(|e| e.key().clone())
            .collect();
        for fid in doomed {
            if let Some((_, (_, task))) = self.forwards.remove(&fid) {
                task.abort();
            }
        }
    }

    /// Open a connection, authenticate, and start an interactive shell.
    ///
    /// The password is read from the Windows Credential Manager here, held in a
    /// zeroizing buffer, and dropped as soon as authentication returns. It is
    /// never a parameter, never logged, and never sent to the webview.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        &self,
        app: AppHandle,
        prompts: Arc<HostKeyPrompts>,
        session_id: &str,
        host_id: &str,
        host: &str,
        port: u16,
        username: &str,
        cols: u32,
        rows: u32,
        startup_commands: &[String],
        auth: &str,
        key_path: Option<&str>,
        jump: Option<JumpParams>,
        one_shot_password: Option<&str>,
    ) -> Result<(), SshError> {
        // Resolve first so the prompt can show which machine actually answered.
        // Best-effort: a failure here is not fatal, the connect below will
        // produce a better error than we could.
        let ip = tokio::net::lookup_host((host, port))
            .await
            .ok()
            .and_then(|mut addrs| addrs.next())
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| host.to_string());

        // Keepalives are what make a dropped link *detectable*. Without them a
        // VPN drop or an idle firewall timeout leaves the socket open forever:
        // the read half never returns, so nothing ever reports a disconnect and
        // the UI keeps showing a live session. Three missed 15s keepalives tears
        // the connection down after ~45s.
        let config = Arc::new(client::Config {
            keepalive_interval: Some(Duration::from_secs(15)),
            keepalive_max: 3,
            nodelay: true,
            ..client::Config::default()
        });
        let self_prompts = Arc::clone(&prompts);
        let handler = ClientHandler {
            host: host.to_string(),
            ip,
            port,
            app: app.clone(),
            prompts,
        };

        // With a jump host: dial the bastion, authenticate there, then open a
        // direct-tcpip channel to the real target and run the SSH handshake
        // over that stream — exactly what OpenSSH's ProxyJump does. The
        // bastion's own host key is checked and prompted like any other.
        let (mut handle, jump_handle) = match jump {
            Some(j) => {
                let jump_config = Arc::new(client::Config {
                    keepalive_interval: Some(Duration::from_secs(15)),
                    keepalive_max: 3,
                    nodelay: true,
                    ..client::Config::default()
                });
                let jump_ip = tokio::net::lookup_host((j.host.as_str(), j.port))
                    .await
                    .ok()
                    .and_then(|mut a| a.next())
                    .map(|a| a.ip().to_string())
                    .unwrap_or_else(|| j.host.clone());
                let jump_handler = ClientHandler {
                    host: j.host.clone(),
                    ip: jump_ip,
                    port: j.port,
                    app: app.clone(),
                    prompts: Arc::clone(&self_prompts),
                };
                let mut jh =
                    client::connect(jump_config, (j.host.as_str(), j.port), jump_handler).await?;
                authenticate(&mut jh, &j.host_id, &j.username, &j.auth, j.key_path.as_deref(), None)
                    .await?;

                let tunnel = jh
                    .channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0)
                    .await?;
                let h =
                    client::connect_stream(config, tunnel.into_stream(), handler).await?;
                (h, Some(jh))
            }
            None => (
                client::connect(config, (host, port), handler).await?,
                None,
            ),
        };

        authenticate(&mut handle, host_id, username, auth, key_path, one_shot_password).await?;

        // Interactive shell on its own channel.
        let channel = handle.channel_open_session().await?;
        let (mut read_half, write_half) = channel.split();

        write_half
            .request_pty(true, "xterm-256color", cols, rows, 0, 0, &[])
            .await?;
        write_half.request_shell(true).await?;

        // Optional first line of input. Written as input rather than via
        // request_exec so it degrades gracefully: if the command does not exist
        // the user sees "command not found" and still has a working shell,
        // whereas a failed exec would close the channel and look like a broken
        // connection.
        // Order matters and is the user's: a `tmux new-session` first means every
        // later line runs *inside* tmux, which is usually what is wanted.
        for cmd in startup_commands.iter().map(|c| c.trim()).filter(|c| !c.is_empty()) {
            let line = format!("{cmd}
");
            write_half.data(line.as_bytes()).await?;
        }

        // Output pump. Emits on the per-session topic TerminalPane subscribes
        // to. stderr (ExtendedData) is interleaved into the same stream, which
        // is what a real terminal does — separating it would reorder output.
        let pump_app = app.clone();
        let topic = format!("ssh://{session_id}");

        // Transcript. Opened here rather than inside the task so a failure is
        // visible immediately, and degraded to None rather than propagated:
        // losing a log must never take down a working connection.
        let mut log = SessionLog::create(host, username).ok();
        if let Some(l) = log.as_ref() {
            let _ = pump_app.emit(
                &topic,
                format!(
                    "\x1b[38;5;244mlogging to {}\x1b[0m\r\n",
                    l.path().display()
                ),
            );
        }

        // The session is registered BEFORE the pump starts so the pump can hold
        // a handle to it and clear the liveness flag when the channel ends.
        let session = Arc::new(Session {
            handle,
            shell: Mutex::new(Some(write_half)),
            sftp: Mutex::new(None),
            _jump: jump_handle,
            alive: AtomicBool::new(true),
        });
        self.sessions
            .insert(session_id.to_string(), Arc::clone(&session));

        let pump_session = Arc::clone(&session);
        let sid = session_id.to_string();

        tokio::spawn(async move {
            // Distinguishes a clean logout from a link that died under us. The
            // difference matters to the user: one is expected, the other means
            // "your VPN dropped" or "the firewall timed you out".
            let mut reason = "connection closed by remote";

            while let Some(msg) = read_half.wait().await {
                match msg {
                    ChannelMsg::Data { ref data }
                    | ChannelMsg::ExtendedData { ref data, .. } => {
                        // Logged before display, so anything that reaches the
                        // screen is already durable if the app dies next.
                        if let Some(l) = log.as_mut() {
                            l.append(data);
                        }

                        // from_utf8_lossy, not from_utf8: a chunk boundary can
                        // split a multi-byte sequence, and dropping the whole
                        // chunk over one partial codepoint would corrupt the
                        // screen far worse than a replacement character.
                        let text = String::from_utf8_lossy(data).to_string();
                        let _ = pump_app.emit(&topic, text);
                    }
                    ChannelMsg::Eof | ChannelMsg::Close => {
                        reason = "session closed";
                        break;
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        reason = if exit_status == 0 {
                            "shell exited"
                        } else {
                            "shell exited with an error"
                        };
                    }
                    _ => {}
                }
            }

            // Reaching here with no Eof/Close means `wait()` returned None: the
            // transport itself went away — keepalive failure, reset, or a
            // dropped route. That is the case the UI most needs told about.
            pump_session.alive.store(false, Ordering::Relaxed);

            if let Some(l) = log.as_mut() {
                l.footer(reason);
            }

            let _ = pump_app.emit(
                &topic,
                format!("\r\n\x1b[38;2;242;178;92m\u{25cf} disconnected\x1b[0m {reason}\r\n"),
            );
            let _ = pump_app.emit(
                "ssh://status",
                SessionStatusEvent {
                    session_id: sid,
                    status: "disconnected",
                    detail: reason.to_string(),
                },
            );
        });

        Ok(())
    }

    /* ------------------------------------------------------------ phase 1 */

    /// Raw terminal input straight to the PTY.
    ///
    /// Bytes, not a string: arrow keys arrive as "\x1b[A", Ctrl+C as 0x03, and
    /// a paste as one block. Anything that re-encodes on the way through breaks
    /// every full-screen program that relies on raw mode.
    pub async fn write(&self, session_id: &str, data: &[u8]) -> Result<(), SshError> {
        let session = self.get(session_id)?;
        // A write to a channel whose transport has gone is silently discarded by
        // russh, which is how a dead session managed to look alive.
        if !session.alive.load(Ordering::Relaxed) {
            return Err(SshError::Disconnected(session_id.to_string()));
        }
        let guard = session.shell.lock().await;
        let shell = guard
            .as_ref()
            .ok_or_else(|| SshError::NoShell(session_id.to_string()))?;
        shell.data(data).await?;
        Ok(())
    }

    /// Forward a window-size change as a real SSH `window-change` request.
    /// Without it the remote keeps drawing to the old geometry and full-screen
    /// programs wrap at the wrong column.
    ///
    /// Note: russh has no `request_pty_size`; `window_change` is the method, and
    /// it takes pixel dimensions too (0 means "unspecified", which every server
    /// accepts).
    pub async fn resize(&self, session_id: &str, cols: u32, rows: u32) -> Result<(), SshError> {
        let session = self.get(session_id)?;
        if !session.alive.load(Ordering::Relaxed) {
            return Err(SshError::Disconnected(session_id.to_string()));
        }
        let guard = session.shell.lock().await;
        let shell = guard
            .as_ref()
            .ok_or_else(|| SshError::NoShell(session_id.to_string()))?;
        shell.window_change(cols, rows, 0, 0).await?;
        Ok(())
    }

    /* --------------------------------------------------------------- sftp */

    /// The SFTP subsystem rides the existing SSH connection rather than opening
    /// a second one, and starts lazily: a session that only uses the terminal
    /// never pays for it. Cached because channel setup costs a round trip.
    async fn sftp(&self, session_id: &str) -> Result<Arc<SftpSession>, SshError> {
        let session = self.get(session_id)?;
        if !session.alive.load(Ordering::Relaxed) {
            return Err(SshError::Disconnected(session_id.to_string()));
        }
        let mut guard = session.sftp.lock().await;
        if let Some(existing) = guard.as_ref() {
            return Ok(Arc::clone(existing));
        }

        let channel = session.handle.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = Arc::new(SftpSession::new(channel.into_stream()).await?);
        *guard = Some(Arc::clone(&sftp));
        Ok(sftp)
    }

    pub async fn list_dir(&self, session_id: &str, path: &str) -> Result<DirListing, SshError> {
        let sftp = self.sftp(session_id).await?;

        // Resolve first so the pane shows the real location: the server may
        // return something different for ".", "~", or a symlinked directory.
        let canonical = sftp
            .canonicalize(path)
            .await
            .unwrap_or_else(|_| path.to_string());

        let mut entries = vec![FileEntry {
            name: "..".into(),
            kind: "directory",
            size: 0,
            modified: None,
            mode: String::new(),
        }];

        for entry in sftp.read_dir(&canonical).await? {
            let meta = entry.metadata();
            let kind = match entry.file_type() {
                FileType::Dir => "directory",
                FileType::Symlink => "symlink",
                _ => "file",
            };
            entries.push(FileEntry {
                name: entry.file_name(),
                kind,
                size: meta.size.unwrap_or(0),
                modified: meta.mtime,
                mode: mode_string(meta.permissions, kind),
            });
        }

        Ok(DirListing {
            path: canonical,
            entries,
        })
    }

    /// Whether a remote path exists — the overwrite guard asks before a
    /// transfer clobbers something already there.
    pub async fn sftp_exists(&self, session_id: &str, path: &str) -> Result<bool, SshError> {
        let sftp = self.sftp(session_id).await?;
        Ok(sftp.metadata(path).await.is_ok())
    }

    /// Rename a remote file or directory. SFTP rename is not a copy — it is
    /// the server's own rename, atomic where the filesystem allows.
    pub async fn sftp_rename(&self, session_id: &str, from: &str, to: &str) -> Result<(), SshError> {
        let sftp = self.sftp(session_id).await?;
        sftp.rename(from, to).await?;
        Ok(())
    }

    /// Delete a remote file, or an EMPTY remote directory.
    ///
    /// Deliberately not recursive: `rm -rf` semantics from a GUI click is how
    /// production directories die. A non-empty directory fails with the
    /// server's error and the UI says so; recursive delete stays a deliberate
    /// terminal act.
    pub async fn sftp_delete(&self, session_id: &str, path: &str, is_dir: bool) -> Result<(), SshError> {
        let sftp = self.sftp(session_id).await?;
        if is_dir {
            sftp.remove_dir(path).await?;
        } else {
            sftp.remove_file(path).await?;
        }
        Ok(())
    }

    /// Create a remote directory.
    pub async fn sftp_mkdir(&self, session_id: &str, path: &str) -> Result<(), SshError> {
        let sftp = self.sftp(session_id).await?;
        sftp.create_dir(path).await?;
        Ok(())
    }

    /* ------------------------------------------------------------ phase 2 */

    /// Download, streamed and reporting byte-accurate progress.
    ///
    /// Streaming rather than read-to-end is not only about memory: it is what
    /// makes progress reportable at all. Chunks are 64 KB; events are throttled
    /// to one per PROGRESS_INTERVAL with a guaranteed final event so the UI
    /// always lands on 100%.
    pub async fn download(
        &self,
        app: &AppHandle,
        session_id: &str,
        remote: &str,
        local: &str,
    ) -> Result<u64, SshError> {
        let sftp = self.sftp(session_id).await?;

        // A directory recurses; a file copies directly. Walking the tree
        // iteratively (a worklist, not async recursion) keeps this a plain
        // function with no Box::pin ceremony.
        let is_dir = sftp
            .metadata(remote)
            .await
            .map(|m| m.file_type().is_dir())
            .unwrap_or(false);

        if !is_dir {
            return copy_remote_file(&sftp, app, session_id, remote, local).await;
        }

        let mut total = 0u64;
        let mut failed: Vec<String> = Vec::new();
        let mut dirs = vec![(remote.to_string(), local.to_string())];
        while let Some((rdir, ldir)) = dirs.pop() {
            tokio::fs::create_dir_all(&ldir).await?;
            for entry in sftp.read_dir(&rdir).await? {
                let name = entry.file_name();
                let rpath = format!("{}/{}", rdir.trim_end_matches('/'), name);
                let lpath = std::path::Path::new(&ldir)
                    .join(&name)
                    .to_string_lossy()
                    .to_string();
                let ft = entry.file_type();
                if ft.is_dir() {
                    dirs.push((rpath, lpath));
                } else if ft.is_symlink() {
                    // A symlink in a tree walk is skipped, not followed: SFTP
                    // open() on a dir-symlink fails, and following file links
                    // can duplicate or even loop. Recorded so the user learns
                    // it was left behind rather than silently missing it.
                    failed.push(format!("{rpath} (symlink, skipped)"));
                } else {
                    // One unreadable file must not abort the other 499: keep
                    // walking, collect what failed, report the tally at the end.
                    match copy_remote_file(&sftp, app, session_id, &rpath, &lpath).await {
                        Ok(n) => total += n,
                        Err(e) => failed.push(format!("{rpath}: {e}")),
                    }
                }
            }
        }
        if failed.is_empty() {
            Ok(total)
        } else {
            Err(SshError::PartialTransfer(format!(
                "copied {} bytes; {} item(s) not transferred — first: {}",
                total,
                failed.len(),
                failed[0]
            )))
        }
    }

    /// Upload, same streaming and reporting contract, directory-aware.
    pub async fn upload(
        &self,
        app: &AppHandle,
        session_id: &str,
        local: &str,
        remote: &str,
    ) -> Result<u64, SshError> {
        let sftp = self.sftp(session_id).await?;

        let is_dir = tokio::fs::metadata(local)
            .await
            .map(|m| m.is_dir())
            .unwrap_or(false);

        if !is_dir {
            return copy_local_file(&sftp, app, session_id, local, remote).await;
        }

        let mut total = 0u64;
        let mut failed: Vec<String> = Vec::new();
        let mut dirs = vec![(local.to_string(), remote.to_string())];
        while let Some((ldir, rdir)) = dirs.pop() {
            // create_dir on an existing directory is an error over SFTP; ignore
            // it so re-uploading into a partially-present tree just works.
            let _ = sftp.create_dir(&rdir).await;
            let mut rd = tokio::fs::read_dir(&ldir).await?;
            while let Some(entry) = rd.next_entry().await? {
                let name = entry.file_name().to_string_lossy().to_string();
                let lpath = entry.path().to_string_lossy().to_string();
                let rpath = format!("{}/{}", rdir.trim_end_matches('/'), name);
                let ft = entry.file_type().await?;
                if ft.is_dir() {
                    dirs.push((lpath, rpath));
                } else if ft.is_symlink() {
                    failed.push(format!("{lpath} (symlink, skipped)"));
                } else {
                    match copy_local_file(&sftp, app, session_id, &lpath, &rpath).await {
                        Ok(n) => total += n,
                        Err(e) => failed.push(format!("{lpath}: {e}")),
                    }
                }
            }
        }
        if failed.is_empty() {
            Ok(total)
        } else {
            Err(SshError::PartialTransfer(format!(
                "copied {} bytes; {} item(s) not transferred — first: {}",
                total,
                failed.len(),
                failed[0]
            )))
        }
    }
}

impl Registry {
    /// Start a local forward: listen on 127.0.0.1:local_port, and for every
    /// connection open a direct-tcpip channel to remote_host:remote_port over
    /// the session's SSH transport — `ssh -L`, in app form.
    ///
    /// Binds 127.0.0.1 only, never 0.0.0.0: a forward into a management VLAN
    /// must not turn the operator's workstation into an open relay for
    /// whatever else is on the office network.
    pub async fn forward_start(
        &self,
        session_id: &str,
        local_port: u16,
        remote_host: &str,
        remote_port: u16,
    ) -> Result<ForwardInfo, SshError> {
        let session = self.get(session_id)?;
        if !session.alive.load(Ordering::Relaxed) {
            return Err(SshError::Disconnected(session_id.to_string()));
        }

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", local_port)).await?;
        // Port 0 means "pick one"; report what was actually bound.
        let bound = listener.local_addr()?.port();

        let info = ForwardInfo {
            id: format!("fw-{session_id}-{bound}"),
            session_id: session_id.to_string(),
            local_port: bound,
            remote_host: remote_host.to_string(),
            remote_port,
            kind: "local",
        };

        let sess = Arc::clone(&session);
        let rhost = remote_host.to_string();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut tcp, peer)) = listener.accept().await else { break };
                let Ok(channel) = sess
                    .handle
                    .channel_open_direct_tcpip(
                        rhost.clone(),
                        remote_port as u32,
                        peer.ip().to_string(),
                        peer.port() as u32,
                    )
                    .await
                else {
                    // Remote refused (nothing listening there, or policy).
                    // Drop this client and keep the listener alive.
                    continue;
                };
                tokio::spawn(async move {
                    let mut stream = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
                });
            }
        });

        self.forwards
            .insert(info.id.clone(), (info.clone(), task));
        Ok(info)
    }

    pub fn forward_stop(&self, forward_id: &str) {
        if let Some((_, (_, task))) = self.forwards.remove(forward_id) {
            task.abort();
        }
    }

    /// Start a SOCKS5 proxy (`ssh -D`): every connection made through it is
    /// tunnelled over this session and egresses from the REMOTE side. Point a
    /// browser's proxy at it and you are browsing from the server's network —
    /// the standard way to reach web UIs on an isolated management VLAN.
    ///
    /// Deliberately minimal SOCKS5: no-auth only (it binds 127.0.0.1, the
    /// boundary is the machine), CONNECT only (BIND and UDP-associate are
    /// refused with the proper reply code). That subset is what browsers and
    /// curl actually use.
    pub async fn forward_start_socks(
        &self,
        session_id: &str,
        local_port: u16,
    ) -> Result<ForwardInfo, SshError> {
        let session = self.get(session_id)?;
        if !session.alive.load(Ordering::Relaxed) {
            return Err(SshError::Disconnected(session_id.to_string()));
        }

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", local_port)).await?;
        let bound = listener.local_addr()?.port();

        let info = ForwardInfo {
            id: format!("socks-{session_id}-{bound}"),
            session_id: session_id.to_string(),
            local_port: bound,
            remote_host: "(dynamic)".into(),
            remote_port: 0,
            kind: "socks",
        };

        let sess = Arc::clone(&session);
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, peer)) = listener.accept().await else { break };
                let sess = Arc::clone(&sess);
                tokio::spawn(async move {
                    let _ = socks5_serve(sess, tcp, peer).await;
                });
            }
        });

        self.forwards.insert(info.id.clone(), (info.clone(), task));
        Ok(info)
    }

    pub fn forwards_list(&self, session_id: Option<&str>) -> Vec<ForwardInfo> {
        self.forwards
            .iter()
            .map(|e| e.value().0.clone())
            .filter(|f| session_id.is_none_or(|sid| f.session_id == sid))
            .collect()
    }
}

impl Registry {
    /// Run one command on a fresh exec channel and capture its output.
    ///
    /// Exec, not the interactive shell: capturing through the user's live
    /// terminal would splatter a full config dump across whatever they were
    /// doing. A separate channel keeps the capture invisible and gives a clean
    /// EOF to stop at. The trade-off is that some appliances only speak
    /// interactive shells and refuse exec — those fail here with the server's
    /// own error, which the UI surfaces as "this device may not support
    /// command capture".
    pub async fn exec_capture(
        &self,
        session_id: &str,
        command: &str,
        timeout_secs: u64,
    ) -> Result<String, SshError> {
        let session = self.get(session_id)?;
        if !session.alive.load(Ordering::Relaxed) {
            return Err(SshError::Disconnected(session_id.to_string()));
        }

        let mut channel = session.handle.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut out: Vec<u8> = Vec::new();
        let collect = async {
            while let Some(msg) = channel.wait().await {
                match msg {
                    ChannelMsg::Data { ref data }
                    | ChannelMsg::ExtendedData { ref data, .. } => {
                        out.extend_from_slice(data);
                        // A config dump has a sane bound; a runaway command
                        // (someone snapshots `tail -f`) must not eat RAM
                        // until the timeout.
                        if out.len() > 16 * 1024 * 1024 {
                            break;
                        }
                    }
                    ChannelMsg::Eof | ChannelMsg::Close => break,
                    _ => {}
                }
            }
        };
        // The timeout is the guard against commands that never EOF.
        let _ = tokio::time::timeout(Duration::from_secs(timeout_secs), collect).await;

        let (clean, _) = crate::utils::session_log::strip_ansi(&out);
        Ok(String::from_utf8_lossy(&clean).to_string())
    }
}

/// Authenticate an open handle by the host's configured method.
///
/// Shared between the target connection and a jump-host connection so the
/// bastion supports the same three methods as any other host.
async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    host_id: &str,
    username: &str,
    auth: &str,
    key_path: Option<&str>,
    one_shot_password: Option<&str>,
) -> Result<(), SshError> {
    let authed = match auth {
        // Private key file. The Credential Manager entry for this host, if
        // present, is used as the key's passphrase — one vault slot per host,
        // meaning either "password" or "key passphrase" depending on the auth
        // method, never both.
        "key" => {
            let path = key_path.ok_or_else(|| {
                SshError::AuthFailed(format!("{username}: no key file configured"))
            })?;
            let passphrase = credentials::read_secret(host_id).ok();
            let key = russh::keys::load_secret_key(path, passphrase.as_ref().map(|p| p.as_str()))
                .map_err(|e| SshError::AuthFailed(format!("could not load key {path}: {e}")))?;
            // RSA needs the strongest hash the server advertises; rsa-sha1 is
            // refused by modern OpenSSH. Non-RSA ignores it.
            let hash_alg = handle.best_supported_rsa_hash().await?.flatten();
            let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
            handle.authenticate_publickey(username, key).await?
        }

        // Running SSH agent: the OpenSSH agent service pipe, then Pageant.
        // Keys never leave the agent; it only signs.
        "agent" => {
            let hash_alg = handle.best_supported_rsa_hash().await?.flatten();
            match agent_auth(handle, username, hash_alg).await? {
                Some(result) => result,
                None => {
                    return Err(SshError::AuthFailed(format!(
                        "{username}: no SSH agent reachable (tried the OpenSSH agent                          pipe and Pageant), or the agent holds no accepted keys"
                    )))
                }
            }
        }

        // Password (default). A one-shot password (quick connect, never saved)
        // takes precedence over the vault; it lives only for this call.
        //
        // On failure, keyboard-interactive is tried with the same secret.
        // That fallback is what makes TACACS+-fronted network gear work:
        // many appliances advertise ONLY keyboard-interactive and then ask a
        // single hidden "Password:" question. Users should not need to know
        // which of the two dances their firewall does.
        _ => {
            let pw: String = match one_shot_password {
                Some(p) => p.to_string(),
                None => credentials::read_secret(host_id)?.as_str().to_string(),
            };
            let result = handle.authenticate_password(username, pw.as_str()).await?;
            let result = if matches!(result, russh::client::AuthResult::Success) {
                result
            } else {
                keyboard_interactive_with_password(handle, username, &pw).await?
            };
            // Best-effort wipe of the working copy.
            let mut pw = pw;
            unsafe { pw.as_mut_vec().fill(0) };
            result
        }
    };

    if !matches!(authed, russh::client::AuthResult::Success) {
        return Err(SshError::AuthFailed(username.to_string()));
    }
    Ok(())
}

/// Keyboard-interactive auth, answering every hidden prompt with the
/// password on hand.
///
/// Covers the overwhelmingly common case (TACACS+/RADIUS asking one hidden
/// "Password:" question). A prompt that ECHOES (an OTP or challenge code we
/// could not possibly know) is answered with an empty string and will fail
/// authentication — honestly — rather than hang the connect; interactive
/// prompting through the UI is roadmap work.
async fn keyboard_interactive_with_password(
    handle: &mut Handle<ClientHandler>,
    username: &str,
    password: &str,
) -> Result<russh::client::AuthResult, SshError> {
    use russh::client::KeyboardInteractiveAuthResponse as Kb;

    let mut reply = handle
        .authenticate_keyboard_interactive_start(username, None)
        .await?;

    // A server may send several rounds; cap them so a misbehaving one cannot
    // loop us forever.
    for _ in 0..5 {
        match reply {
            Kb::Success => return Ok(russh::client::AuthResult::Success),
            Kb::Failure { remaining_methods, partial_success } => {
                return Ok(russh::client::AuthResult::Failure {
                    remaining_methods,
                    partial_success,
                })
            }
            Kb::InfoRequest { prompts, .. } => {
                let answers: Vec<String> = prompts
                    .iter()
                    .map(|p| if p.echo { String::new() } else { password.to_string() })
                    .collect();
                reply = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?;
            }
        }
    }
    Err(SshError::AuthFailed(format!(
        "{username}: keyboard-interactive did not converge after 5 rounds"
    )))
}

/// ssh-copy-id, in one call: connect with a password, append a public key to
/// the server's authorized_keys, disconnect. Turns "generate a key" into
/// "generate and it works" without the copy/paste/assemble ritual.
///
/// A throwaway connection, not a Registry session — no shell, no pump, no tab.
/// The password is one-shot and never stored. The host-key check still runs
/// (first-time hosts prompt exactly as a normal connect would).
///
/// POSIX-sh only: it does the mkdir/grep-dedup/append/chmod dance a Unix host
/// understands. Network appliances (PAN-OS, IOS) manage keys through their own
/// config and are out of scope here — the UI offers the copyable command for
/// those.
#[allow(clippy::too_many_arguments)]
pub async fn copy_id(
    app: AppHandle,
    prompts: Arc<HostKeyPrompts>,
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    public_key: &str,
) -> Result<(), SshError> {
    let key = public_key.trim();
    // The key is wrapped in single quotes in the remote command; a quote in it
    // would break out. Generated keys never contain one, but guard anyway.
    if key.contains('\'') || key.contains('\n') {
        return Err(SshError::AuthFailed(
            "public key contains illegal characters".into(),
        ));
    }

    let ip = tokio::net::lookup_host((host, port))
        .await
        .ok()
        .and_then(|mut a| a.next())
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| host.to_string());

    let config = Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(15)),
        nodelay: true,
        ..client::Config::default()
    });
    let handler = ClientHandler {
        host: host.to_string(),
        ip,
        port,
        app,
        prompts,
    };
    let mut handle = client::connect(config, (host, port), handler).await?;

    // Password (with keyboard-interactive fallback), one-shot. host_id "" is
    // never consulted because the one-shot password is supplied.
    authenticate(&mut handle, "", username, "password", None, Some(password)).await?;

    // grep -qxF: only append if the exact line is not already present, so
    // running this twice does not duplicate the key.
    let cmd = format!(
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys &&          grep -qxF '{key}' ~/.ssh/authorized_keys || printf '%s\n' '{key}' >> ~/.ssh/authorized_keys;          chmod 600 ~/.ssh/authorized_keys && echo SKIFF_KEY_OK"
    );

    let mut channel = handle.channel_open_session().await?;
    channel.exec(true, cmd).await?;
    let mut out = Vec::new();
    let collect = async {
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { ref data } | ChannelMsg::ExtendedData { ref data, .. } => {
                    out.extend_from_slice(data)
                }
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(20), collect).await;

    if String::from_utf8_lossy(&out).contains("SKIFF_KEY_OK") {
        Ok(())
    } else {
        Err(SshError::AuthFailed(format!(
            "install command did not confirm success: {}",
            String::from_utf8_lossy(&out).chars().take(200).collect::<String>()
        )))
    }
}

/// Try every identity a running SSH agent offers.
///
/// Returns `Ok(None)` when no agent is reachable or no key was accepted —
/// distinct from an SSH-level error, so the caller can produce a message that
/// says what to actually do (start the agent, add a key) rather than a generic
/// failure. Tries the Windows OpenSSH agent service first because it is the
/// one Windows ships; Pageant second for the PuTTY crowd.
async fn agent_auth(
    handle: &mut Handle<ClientHandler>,
    username: &str,
    hash_alg: Option<russh::keys::HashAlg>,
) -> Result<Option<russh::client::AuthResult>, SshError> {
    use russh::keys::agent::client::AgentClient;

    // OpenSSH agent for Windows: fixed, documented pipe name.
    if let Ok(mut agent) = AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await {
        if let Ok(identities) = agent.request_identities().await {
            for key in identities {
                let result = handle
                    .authenticate_publickey_with(username, key, hash_alg, &mut agent)
                    .await
                    .map_err(|e| SshError::AuthFailed(format!("agent signing failed: {e}")))?;
                if matches!(result, russh::client::AuthResult::Success) {
                    return Ok(Some(result));
                }
            }
        }
    }

    // Pageant (PuTTY). connect_pageant never fails to construct; a missing
    // Pageant surfaces when the identity request errors, which lands us in
    // the Ok(None) fall-through below.
    let mut pageant = AgentClient::connect_pageant().await;
    if let Ok(identities) = pageant.request_identities().await {
        for key in identities {
            let result = handle
                .authenticate_publickey_with(username, key, hash_alg, &mut pageant)
                .await
                .map_err(|e| SshError::AuthFailed(format!("pageant signing failed: {e}")))?;
            if matches!(result, russh::client::AuthResult::Success) {
                return Ok(Some(result));
            }
        }
    }

    Ok(None)
}

/// Copy one remote file to a local path, streaming with progress.
async fn copy_remote_file(
    sftp: &SftpSession,
    app: &AppHandle,
    session_id: &str,
    remote: &str,
    local: &str,
) -> Result<u64, SshError> {
    let total = sftp.metadata(remote).await.ok().and_then(|m| m.size).unwrap_or(0);
    let mut src = sftp.open(remote).await?;
    let mut dst = tokio::fs::File::create(local).await?;

    let mut reporter = Reporter::new(app, session_id, remote, total, "download");
    let mut buf = vec![0u8; CHUNK];
    let mut done = 0u64;
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n]).await?;
        done += n as u64;
        reporter.tick(done);
    }
    dst.flush().await?;
    reporter.finish(done);
    Ok(done)
}

/// Copy one local file to a remote path, streaming with progress.
async fn copy_local_file(
    sftp: &SftpSession,
    app: &AppHandle,
    session_id: &str,
    local: &str,
    remote: &str,
) -> Result<u64, SshError> {
    let total = tokio::fs::metadata(local).await.map(|m| m.len()).unwrap_or(0);
    let mut src = tokio::fs::File::open(local).await?;
    let mut dst = sftp.create(remote).await?;

    let mut reporter = Reporter::new(app, session_id, local, total, "upload");
    let mut buf = vec![0u8; CHUNK];
    let mut done = 0u64;
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n]).await?;
        done += n as u64;
        reporter.tick(done);
    }
    dst.flush().await?;
    reporter.finish(done);
    Ok(done)
}

/* ------------------------------------------------------------- progress */

/// Throttled progress emitter. Kept as a small struct so both transfer
/// directions share one policy instead of duplicating the timing logic.
struct Reporter<'a> {
    app: &'a AppHandle,
    payload: TransferProgress,
    last: Instant,
}

impl<'a> Reporter<'a> {
    fn new(
        app: &'a AppHandle,
        session_id: &str,
        file_path: &str,
        total_bytes: u64,
        direction: &'static str,
    ) -> Self {
        let payload = TransferProgress {
            session_id: session_id.to_string(),
            file_path: file_path.to_string(),
            bytes_transferred: 0,
            total_bytes,
            direction,
            done: false,
        };
        // Emit once immediately so the row appears with a denominator rather
        // than sitting blank until the first interval elapses.
        let _ = app.emit("sftp://progress", payload.clone());
        Self {
            app,
            payload,
            last: Instant::now(),
        }
    }

    fn tick(&mut self, bytes: u64) {
        if self.last.elapsed() < PROGRESS_INTERVAL {
            return;
        }
        self.last = Instant::now();
        self.payload.bytes_transferred = bytes;
        let _ = self.app.emit("sftp://progress", self.payload.clone());
    }

    /// Always emitted, regardless of throttling, so the UI never stalls at 97%.
    fn finish(&mut self, bytes: u64) {
        self.payload.bytes_transferred = bytes;
        if self.payload.total_bytes == 0 {
            self.payload.total_bytes = bytes;
        }
        self.payload.done = true;
        let _ = self.app.emit("sftp://progress", self.payload.clone());
    }
}

/// One SOCKS5 CONNECT conversation, then a bidirectional pump.
async fn socks5_serve(
    session: Arc<Session>,
    mut tcp: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
) -> Result<(), SshError> {
    use tokio::io::AsyncReadExt as _;
    use tokio::io::AsyncWriteExt as _;

    // Greeting: VER, NMETHODS, methods[...]. Reply: no-auth (0x00).
    let mut head = [0u8; 2];
    tcp.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Ok(()); // not SOCKS5; drop silently
    }
    let mut methods = vec![0u8; head[1] as usize];
    tcp.read_exact(&mut methods).await?;
    tcp.write_all(&[5, 0]).await?;

    // Request: VER, CMD, RSV, ATYP, addr..., port.
    let mut req = [0u8; 4];
    tcp.read_exact(&mut req).await?;
    let host = match req[3] {
        1 => {
            let mut b = [0u8; 4];
            tcp.read_exact(&mut b).await?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            tcp.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            tcp.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).to_string()
        }
        4 => {
            let mut b = [0u8; 16];
            tcp.read_exact(&mut b).await?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        _ => {
            // Address type not supported.
            let _ = tcp.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            return Ok(());
        }
    };
    let mut pb = [0u8; 2];
    tcp.read_exact(&mut pb).await?;
    let port = u16::from_be_bytes(pb);

    if req[1] != 1 {
        // Only CONNECT; refuse BIND/UDP with "command not supported".
        let _ = tcp.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        return Ok(());
    }

    match session
        .handle
        .channel_open_direct_tcpip(host, port as u32, peer.ip().to_string(), peer.port() as u32)
        .await
    {
        Ok(channel) => {
            tcp.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
        }
        Err(_) => {
            // Host unreachable from the remote side.
            let _ = tcp.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        }
    }
    Ok(())
}

/// Render POSIX permission bits as `drwxr-xr-x`.
fn mode_string(permissions: Option<u32>, kind: &str) -> String {
    let Some(bits) = permissions else {
        return String::new();
    };
    let lead = match kind {
        "directory" => 'd',
        "symlink" => 'l',
        _ => '-',
    };
    let rwx = |shift: u32| {
        let v = (bits >> shift) & 0b111;
        format!(
            "{}{}{}",
            if v & 0b100 != 0 { 'r' } else { '-' },
            if v & 0b010 != 0 { 'w' } else { '-' },
            if v & 0b001 != 0 { 'x' } else { '-' },
        )
    };
    format!("{lead}{}{}{}", rwx(6), rwx(3), rwx(0))
}
