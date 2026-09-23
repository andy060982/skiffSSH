mod credentials;
mod utils;
mod ssh;

use std::time::UNIX_EPOCH;

use tauri::{AppHandle, Manager, State};

use ssh::{DirListing, FileEntry, HostKeyPrompts, Registry};
use std::sync::Arc;

/// Commands return `Result<_, String>`: Tauri needs a serialisable error, and a
/// rendered message is what the UI shows. Note what is *not* here — no command
/// accepts or returns a password.
type CmdResult<T> = Result<T, String>;

/* ------------------------------------------------------------------ session */

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn ssh_connect(
    app: AppHandle,
    registry: State<'_, Registry>,
    prompts: State<'_, Arc<HostKeyPrompts>>,
    session_id: String,
    host_id: String,
    host: String,
    port: u16,
    username: String,
    cols: u32,
    rows: u32,
    startup_commands: Option<Vec<String>>,
    auth: Option<String>,
    key_path: Option<String>,
    jump: Option<ssh::JumpParams>,
    one_shot_password: Option<String>,
) -> CmdResult<()> {
    registry
        .connect(
            app,
            Arc::clone(&prompts),
            &session_id,
            &host_id,
            &host,
            port,
            &username,
            cols,
            rows,
            &startup_commands.unwrap_or_default(),
            auth.as_deref().unwrap_or("password"),
            key_path.as_deref(),
            jump,
            one_shot_password.as_deref(),
        )
        .await
        .map_err(|e| e.to_string())
}

/// Answer a host-key prompt raised by the `ssh://host-key-prompt` event.
///
/// Accepting records the key in known_hosts, so this is the only path by which
/// a new host becomes trusted. There is deliberately no command to accept a
/// *changed* key: that requires editing known_hosts by hand.
#[tauri::command]
async fn host_key_respond(
    prompts: State<'_, Arc<HostKeyPrompts>>,
    request_id: String,
    accept: bool,
) -> CmdResult<()> {
    prompts.respond(&request_id, accept);
    Ok(())
}

/// Keystrokes from the terminal grid.
///
/// `data` is already-encoded terminal input, not a key name: arrow keys arrive
/// as "\x1b[A", Ctrl+C as 0x03, a paste as one block. Write the bytes verbatim —
/// interpreting them here breaks every full-screen program (vim, less, top)
/// that relies on raw mode. Bytes rather than a String because a PTY carries
/// sequences that are not valid UTF-8, which a String round-trip would mangle.
#[tauri::command]
async fn ssh_write(
    registry: State<'_, Registry>,
    session_id: String,
    data: Vec<u8>,
) -> CmdResult<()> {
    registry
        .write(&session_id, &data)
        .await
        .map_err(|e| e.to_string())
}

/// Window-size change from the frontend ResizeObserver, forwarded as a real SSH
/// `window-change` request. Without it the remote keeps drawing to the old
/// geometry and full-screen programs wrap at the wrong column.
#[tauri::command]
async fn ssh_resize(
    registry: State<'_, Registry>,
    session_id: String,
    cols: u32,
    rows: u32,
) -> CmdResult<()> {
    registry
        .resize(&session_id, cols, rows)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn ssh_disconnect(registry: State<'_, Registry>, session_id: String) -> CmdResult<()> {
    registry.remove(&session_id);
    Ok(())
}

/* --------------------------------------------------------------------- sftp */

#[tauri::command]
async fn sftp_list(
    registry: State<'_, Registry>,
    session_id: String,
    path: String,
) -> CmdResult<DirListing> {
    registry
        .list_dir(&session_id, &path)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn sftp_get(
    app: AppHandle,
    registry: State<'_, Registry>,
    session_id: String,
    remote_path: String,
    local_path: String,
) -> CmdResult<u64> {
    registry
        .download(&app, &session_id, &remote_path, &local_path)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn sftp_put(
    app: AppHandle,
    registry: State<'_, Registry>,
    session_id: String,
    local_path: String,
    remote_path: String,
) -> CmdResult<u64> {
    registry
        .upload(&app, &session_id, &local_path, &remote_path)
        .await
        .map_err(|e| e.to_string())
}

/* ----------------------------------------------------------------- tunnels */

/// Start a local port-forward (`ssh -L`) over an open session.
#[tauri::command]
async fn forward_start(
    registry: State<'_, Registry>,
    session_id: String,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
) -> CmdResult<ssh::ForwardInfo> {
    registry
        .forward_start(&session_id, local_port, &remote_host, remote_port)
        .await
        .map_err(|e| e.to_string())
}

/// Start a SOCKS5 dynamic proxy (`ssh -D`) over an open session.
#[tauri::command]
async fn forward_start_socks(
    registry: State<'_, Registry>,
    session_id: String,
    local_port: u16,
) -> CmdResult<ssh::ForwardInfo> {
    registry
        .forward_start_socks(&session_id, local_port)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn forward_stop(registry: State<'_, Registry>, forward_id: String) -> CmdResult<()> {
    registry.forward_stop(&forward_id);
    Ok(())
}

#[tauri::command]
async fn forwards_list(
    registry: State<'_, Registry>,
    session_id: Option<String>,
) -> CmdResult<Vec<ssh::ForwardInfo>> {
    Ok(registry.forwards_list(session_id.as_deref()))
}

/// Existence check for the overwrite guard. `remote` picks the side; local
/// checks need no session.
#[tauri::command]
async fn path_exists(
    registry: State<'_, Registry>,
    session_id: Option<String>,
    path: String,
    remote: bool,
) -> CmdResult<bool> {
    if remote {
        let sid = session_id.ok_or("session required for remote check")?;
        registry.sftp_exists(&sid, &path).await.map_err(|e| e.to_string())
    } else {
        Ok(std::fs::metadata(&path).is_ok())
    }
}

#[tauri::command]
async fn sftp_rename(
    registry: State<'_, Registry>,
    session_id: String,
    from: String,
    to: String,
) -> CmdResult<()> {
    registry.sftp_rename(&session_id, &from, &to).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn sftp_delete(
    registry: State<'_, Registry>,
    session_id: String,
    path: String,
    is_dir: bool,
) -> CmdResult<()> {
    registry.sftp_delete(&session_id, &path, is_dir).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn sftp_mkdir(
    registry: State<'_, Registry>,
    session_id: String,
    path: String,
) -> CmdResult<()> {
    registry.sftp_mkdir(&session_id, &path).await.map_err(|e| e.to_string())
}

/// Local-side mutations, mirroring the sftp_* trio so the two panes offer the
/// same menu. Delete is not recursive here either, for the same reason.
#[tauri::command]
async fn local_rename(from: String, to: String) -> CmdResult<()> {
    std::fs::rename(&from, &to).map_err(|e| e.to_string())
}

#[tauri::command]
async fn local_delete(path: String, is_dir: bool) -> CmdResult<()> {
    if is_dir {
        std::fs::remove_dir(&path).map_err(|e| e.to_string())
    } else {
        std::fs::remove_file(&path).map_err(|e| e.to_string())
    }
}

#[tauri::command]
async fn local_mkdir(path: String) -> CmdResult<()> {
    std::fs::create_dir(&path).map_err(|e| e.to_string())
}

/* -------------------------------------------------------------------- local */

/// Local half of the dual pane. Deliberately mirrors `sftp_list`'s shape so the
/// two panes are the same component with a different data source.
#[tauri::command]
async fn local_list(path: String) -> CmdResult<DirListing> {
    let dir = std::path::Path::new(&path);
    let canonical = dir
        .canonicalize()
        .map(|p| {
            // Strip the \\?\ verbatim prefix Windows adds; it is correct but
            // renders badly in a path bar.
            p.to_string_lossy()
                .trim_start_matches(r"\\?\")
                .to_string()
        })
        .unwrap_or_else(|_| path.clone());

    let mut entries = vec![FileEntry {
        name: "..".into(),
        kind: "directory",
        size: 0,
        modified: None,
        mode: String::new(),
    }];

    let read = std::fs::read_dir(&canonical).map_err(|e| format!("{canonical}: {e}"))?;
    for item in read.flatten() {
        let meta = match item.metadata() {
            Ok(m) => m,
            // A file can vanish or be locked between listing and stat; skipping
            // one entry beats failing the whole directory.
            Err(_) => continue,
        };
        let kind = if meta.is_dir() {
            "directory"
        } else if meta.file_type().is_symlink() {
            "symlink"
        } else {
            "file"
        };
        entries.push(FileEntry {
            name: item.file_name().to_string_lossy().to_string(),
            kind,
            size: meta.len(),
            modified: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as u32),
            mode: if meta.permissions().readonly() {
                "read-only".into()
            } else {
                String::new()
            },
        });
    }

    Ok(DirListing {
        path: canonical,
        entries,
    })
}

/* --------------------------------------------------------------- catalogue */

/// Load the saved-host tree. `None` means "no file yet" — a first run, not a
/// failure; the frontend seeds from its defaults in that case.
#[tauri::command]
async fn hosts_load() -> CmdResult<Option<serde_json::Value>> {
    utils::hosts::load().map_err(|e| e.to_string())
}

#[tauri::command]
async fn hosts_save(tree: serde_json::Value) -> CmdResult<()> {
    utils::hosts::save(&tree).map_err(|e| e.to_string())
}

/// Tabs open at last exit, so a restart can offer them again.
#[tauri::command]
async fn sessions_load() -> CmdResult<Option<serde_json::Value>> {
    utils::hosts::load_sessions().map_err(|e| e.to_string())
}

#[tauri::command]
async fn sessions_save(list: serde_json::Value) -> CmdResult<()> {
    utils::hosts::save_sessions(&list).map_err(|e| e.to_string())
}

/// Tail of the last transcript for a host, for replay into a reconnected tab.
///
/// Host-keyed rather than session-keyed: session ids are per-connection, and the
/// point is to bridge ACROSS connections.
#[tauri::command]
async fn session_history(host: String, max_bytes: usize) -> CmdResult<Option<String>> {
    utils::session_log::latest_transcript(&host, max_bytes).map_err(|e| e.to_string())
}

/// List past session transcripts (newest first) for the history browser.
#[tauri::command]
async fn logs_list() -> CmdResult<Vec<utils::session_log::LogEntry>> {
    utils::session_log::list().map_err(|e| e.to_string())
}

/// Open the transcript directory in Explorer.
///
/// Fixed target, not a parameter: an `open(path)` command reachable from the
/// webview is a shell-execute primitive for anything that ever gets script
/// injection. This one can open exactly one folder and nothing else.
#[tauri::command]
async fn open_logs_folder() -> CmdResult<()> {
    let dir = utils::session_log::logs_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::process::Command::new("explorer")
        .arg(&dir)
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Read one transcript by its bare filename.
#[tauri::command]
async fn log_read(name: String) -> CmdResult<String> {
    utils::session_log::read_log(&name).map_err(|e| e.to_string())
}

/// Export the host catalogue to Documents\skiff-hosts.json and reveal it.
///
/// Topology only — names, addresses, folders, snippets. Passwords live in the
/// Credential Manager and are structurally absent from hosts.json, so an
/// export cannot leak a secret even by mistake. That boundary is the reason
/// export is safe to offer as one click.
#[tauri::command]
async fn hosts_export() -> CmdResult<String> {
    let tree = utils::hosts::load()
        .map_err(|e| e.to_string())?
        .ok_or("no host catalogue to export")?;

    let docs = std::env::var_os("USERPROFILE")
        .map(|p| std::path::PathBuf::from(p).join("Documents"))
        .ok_or("cannot resolve Documents folder")?;
    let path = docs.join("skiff-hosts.json");
    let text = serde_json::to_string_pretty(&tree).map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| e.to_string())?;

    // Reveal rather than open: the point is "here is the file to copy".
    let _ = std::process::Command::new("explorer")
        .arg("/select,")
        .arg(&path)
        .spawn();
    Ok(path.to_string_lossy().to_string())
}

/* ---------------------------------------------------------------- network */

/// Start ping or traceroute against a target; output streams on `net://{run_id}`.
#[tauri::command]
async fn net_tool_start(
    app: AppHandle,
    tools: State<'_, utils::nettools::NetTools>,
    run_id: String,
    tool: String,
    target: String,
) -> CmdResult<()> {
    tools.start_process_tool(app, run_id, &tool, &target)
}

#[tauri::command]
async fn net_tool_cancel(
    tools: State<'_, utils::nettools::NetTools>,
    run_id: String,
) -> CmdResult<()> {
    tools.cancel(&run_id);
    Ok(())
}

/// TCP port check: OPEN / CLOSED (refused) / FILTERED (timeout).
#[tauri::command]
async fn net_port_check(target: String, port: u16) -> CmdResult<String> {
    utils::nettools::NetTools::port_check(&target, port, 3000).await
}

/// Resolve a name through the OS resolver.
#[tauri::command]
async fn net_dns_lookup(target: String) -> CmdResult<Vec<String>> {
    utils::nettools::NetTools::dns_lookup(&target).await
}

/// Probe many hosts' SSH ports concurrently (reachability sweep).
#[tauri::command]
async fn hosts_probe(
    targets: Vec<(String, String, u16)>,
) -> CmdResult<Vec<utils::nettools::ProbeResult>> {
    Ok(utils::nettools::probe_hosts(targets).await)
}

/* ---------------------------------------------------------------- configs */

/// Capture a device's config over a fresh exec channel and store a snapshot.
#[tauri::command]
async fn config_snapshot(
    registry: State<'_, Registry>,
    session_id: String,
    host: String,
    command: String,
) -> CmdResult<utils::configs::SnapshotResult> {
    let output = registry
        .exec_capture(&session_id, &command, 60)
        .await
        .map_err(|e| e.to_string())?;
    if output.trim().is_empty() {
        return Err(
            "capture returned nothing — the device may not support exec-channel commands"
                .to_string(),
        );
    }
    utils::configs::save_snapshot(&host, &output).map_err(|e| e.to_string())
}

#[tauri::command]
async fn config_list(host: String) -> CmdResult<Vec<utils::configs::SnapshotInfo>> {
    utils::configs::list_snapshots(&host).map_err(|e| e.to_string())
}

#[tauri::command]
async fn config_diff(host: String, older: String, newer: String) -> CmdResult<String> {
    utils::configs::diff_snapshots(&host, &older, &newer).map_err(|e| e.to_string())
}

#[tauri::command]
async fn config_read(host: String, name: String) -> CmdResult<String> {
    utils::configs::read_snapshot(&host, &name).map_err(|e| e.to_string())
}

/// Generate an Ed25519 keypair into ~/.ssh, returning the private-key path
/// and the public key line to paste into a server's authorized_keys.
///
/// Ed25519 only, on purpose: it is the modern default, has no parameter
/// choices to get wrong, and every server worth reaching supports it. The
/// private key is written unencrypted (russh loads it without a prompt);
/// the file inherits the user-profile ACL, which on Windows is the same
/// protection ssh-keygen's output gets.
/// Install a public key on a host via a one-shot password connection
/// (ssh-copy-id). The password is used once, never stored.
#[tauri::command]
async fn ssh_copy_id(
    app: AppHandle,
    prompts: State<'_, Arc<HostKeyPrompts>>,
    host: String,
    port: u16,
    username: String,
    password: String,
    public_key: String,
) -> CmdResult<()> {
    ssh::copy_id(
        app,
        std::sync::Arc::clone(&prompts),
        &host,
        port,
        &username,
        &password,
        &public_key,
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
async fn ssh_keygen(comment: String) -> CmdResult<serde_json::Value> {
    use russh::keys::ssh_key::{self, rand_core::OsRng, LineEnding};

    let home = std::env::var_os("USERPROFILE").ok_or("no USERPROFILE")?;
    let dir = std::path::PathBuf::from(home).join(".ssh");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    // Never clobber an existing key: a keypair someone already deployed to
    // twenty servers is irreplaceable. Pick the first free suffixed name.
    let mut path = dir.join("skiff_ed25519");
    let mut n = 1;
    while path.exists() {
        path = dir.join(format!("skiff_ed25519_{n}"));
        n += 1;
    }

    let mut key = ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519)
        .map_err(|e| e.to_string())?;
    key.set_comment(&comment);

    key.write_openssh_file(&path, LineEnding::LF)
        .map_err(|e| e.to_string())?;

    let public = key
        .public_key()
        .to_openssh()
        .map_err(|e| e.to_string())?;
    let pub_path = path.with_extension("pub");
    std::fs::write(&pub_path, format!("{public}
")).map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "privatePath": path.to_string_lossy(),
        "publicKey": public,
    }))
}

/* --------------------------------------------------------------------- ai */

/// Start a streaming chat with the configured provider; deltas arrive on
/// `ai://{run_id}`. The webview supplies the visible context; the key comes
/// from the vault and never returns.
#[tauri::command]
async fn ai_chat(
    app: AppHandle,
    run_id: String,
    cfg: utils::ai::ProviderConfig,
    profile: String,
    system_context: String,
    messages: Vec<utils::ai::ChatMessage>,
) -> CmdResult<()> {
    tokio::spawn(utils::ai::chat(app, run_id, cfg, profile, system_context, messages));
    Ok(())
}

#[tauri::command]
async fn ai_key_save(profile: String, key: String) -> CmdResult<()> {
    utils::ai::save_key(&profile, &key)
}

#[tauri::command]
async fn ai_key_status(profile: String) -> CmdResult<bool> {
    Ok(utils::ai::key_exists(&profile))
}

/// Provider settings (kind/baseUrl/model — never the key) as opaque JSON at
/// %APPDATA%\skiffi.json, same pattern as the host catalogue.
#[tauri::command]
async fn ai_config_load() -> CmdResult<Option<serde_json::Value>> {
    utils::hosts::load_named("ai.json").map_err(|e| e.to_string())
}

#[tauri::command]
async fn ai_config_save(config: serde_json::Value) -> CmdResult<()> {
    utils::hosts::save_named("ai.json", &config).map_err(|e| e.to_string())
}

/* -------------------------------------------------------------- credentials */

/// Save a password to the Windows Credential Manager.
///
/// This is the one command that accepts a secret, and only because the user
/// just typed it into the host editor. It goes straight into the OS vault and
/// is never echoed back: there is deliberately no `credential_read` command.
#[tauri::command]
async fn credential_save(host_id: String, username: String, password: String) -> CmdResult<()> {
    credentials::write_secret(&host_id, &username, &password).map_err(|e| e.to_string())
}

/// Whether a password is stored, without decrypting it — lets the UI show
/// "password saved" with no plaintext in the webview.
#[tauri::command]
async fn credential_status(host_id: String) -> CmdResult<bool> {
    Ok(credentials::has_secret(&host_id))
}

#[tauri::command]
async fn credential_delete(host_id: String) -> CmdResult<()> {
    credentials::delete_secret(&host_id).map_err(|e| e.to_string())
}

/* --------------------------------------------------------------------- run */

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            app.manage(Registry::default());
            app.manage(Arc::new(HostKeyPrompts::default()));
            app.manage(utils::nettools::NetTools::default());

            // Prune old transcripts on launch. Defaults chosen to keep a useful
            // window of history without letting plaintext firewall logs pile up
            // indefinitely: 30 days, and at most 500 files. Runs off-thread so a
            // large logs directory never delays the window appearing.
            std::thread::spawn(|| {
                let n = utils::session_log::prune(30, 500);
                if n > 0 {
                    eprintln!("skiff: pruned {n} old session log(s)");
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            ssh_connect,
            ssh_write,
            ssh_resize,
            ssh_disconnect,
            host_key_respond,
            sftp_list,
            sftp_get,
            sftp_put,
            local_list,
            path_exists,
            sftp_rename,
            sftp_delete,
            sftp_mkdir,
            local_rename,
            local_delete,
            local_mkdir,
            forward_start,
            forward_start_socks,
            forward_stop,
            forwards_list,
            net_tool_start,
            net_tool_cancel,
            net_port_check,
            net_dns_lookup,
            hosts_probe,
            config_snapshot,
            config_list,
            config_diff,
            config_read,
            ssh_keygen,
            ssh_copy_id,
            ai_chat,
            ai_key_save,
            ai_key_status,
            ai_config_load,
            ai_config_save,
            hosts_load,
            hosts_save,
            hosts_export,
            sessions_load,
            sessions_save,
            session_history,
            logs_list,
            open_logs_folder,
            log_read,
            credential_save,
            credential_status,
            credential_delete,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
