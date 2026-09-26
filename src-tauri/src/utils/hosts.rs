//! Persistence for the saved-host catalogue.
//!
//! The tree is stored as opaque JSON. Rust deliberately does **not** model
//! `HostNode`: the shape is a recursive folder/host union owned by the
//! frontend, and duplicating it here would mean every UI-side field addition
//! becomes a two-language change plus a migration. Nothing in the backend needs
//! to interpret the tree — `ssh_connect` receives the individual fields it
//! needs as arguments — so persisting it verbatim is both simpler and harder to
//! get out of sync.
//!
//! Secrets are never in this file. Passwords live in the Credential Manager,
//! keyed by host id; this holds names, addresses, ports, usernames, and auth
//! *method*. That separation is why this file can be plain, readable JSON.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde_json::Value;

use super::known_hosts::KnownHostsError;

/// Serialises every catalogue/settings write so two concurrent saves can neither
/// interleave on a shared scratch file nor race on the final replace.
static WRITE_LOCK: Mutex<()> = Mutex::new(());
/// Makes each temp filename unique even within a burst of same-process saves.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Write `contents` to `path` as atomically as the platform allows.
///
/// A unique temp sibling is written in full, then rename-replaced over the
/// destination. `std::fs::rename` is an atomic replace on Unix and on modern
/// Windows. Only if that direct replace fails do we take the fallback — and the
/// fallback never *deletes* the original: it moves it aside to a backup first,
/// so at no instant is the destination gone, and if the second rename fails the
/// original is restored. A crash in the tiny window leaves either the new file
/// in place or the original recoverable at its `.bak` sibling — never nothing.
/// The whole operation is serialised process-wide.
fn write_atomic(path: &Path, contents: &str) -> Result<(), KnownHostsError> {
    let _guard = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let n = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp.{}.{}", std::process::id(), n));
    std::fs::write(&tmp, contents).map_err(|source| KnownHostsError::Io {
        path: tmp.clone(),
        source,
    })?;

    if std::fs::rename(&tmp, path).is_err() {
        // Move the original ASIDE (not delete) before putting the new file in
        // place, so a crash between the two renames cannot lose the catalogue.
        let bak = path.with_extension(format!("bak.{}.{}", std::process::id(), n));
        let had_original = path.exists();
        if had_original {
            std::fs::rename(path, &bak).map_err(|source| {
                let _ = std::fs::remove_file(&tmp);
                KnownHostsError::Io {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
        }
        match std::fs::rename(&tmp, path) {
            Ok(()) => {
                if had_original {
                    let _ = std::fs::remove_file(&bak);
                }
            }
            Err(source) => {
                // Put the original back rather than leave the destination empty.
                if had_original {
                    let _ = std::fs::rename(&bak, path);
                }
                let _ = std::fs::remove_file(&tmp);
                return Err(KnownHostsError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
    }
    Ok(())
}

/// `%APPDATA%\skiff\hosts.json`, beside known_hosts.
fn hosts_path() -> Result<PathBuf, KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    Ok(store
        .parent()
        .ok_or(KnownHostsError::NoAppDataDir)?
        .join("hosts.json"))
}

/// Read the catalogue. Returns `None` when no file exists yet, which the
/// frontend treats as "seed from defaults" rather than as an error — a first
/// run must not look like a failure.
pub fn load() -> Result<Option<Value>, KnownHostsError> {
    let path = hosts_path()?;
    if !path.exists() {
        return Ok(None);
    }

    let text = std::fs::read_to_string(&path).map_err(|source| KnownHostsError::Io {
        path: path.clone(),
        source,
    })?;

    // A corrupt file must not brick the app. Report it as absent and let the
    // next save overwrite; the alternative is a user who cannot start the
    // program and cannot reach the UI that would fix it. Before treating it as
    // absent, preserve the original bytes to `hosts.json.corrupt` so a bad
    // hand-edit is recoverable rather than silently discarded on the next save.
    match serde_json::from_str(&text) {
        Ok(value) => Ok(Some(value)),
        Err(_) => {
            let backup = path.with_extension("json.corrupt");
            let _ = std::fs::write(&backup, &text);
            eprintln!(
                "skiff: hosts.json is not valid JSON; backed up to {} and starting from defaults",
                backup.display()
            );
            Ok(None)
        }
    }
}

/// Write the catalogue atomically. Losing the host list to a mid-write crash
/// would be a real data-loss bug, so this goes through `write_atomic`
/// (unique temp, rename-replace, process-wide serialisation).
pub fn save(tree: &Value) -> Result<(), KnownHostsError> {
    let path = hosts_path()?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| KnownHostsError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let pretty = serde_json::to_string_pretty(tree)
        .map_err(|e| KnownHostsError::Parse(e.to_string()))?;
    write_atomic(&path, &pretty)
}

/* -------------------------------------------------------------------------- */

/// Confirm that sending the vault secret keyed by `cred_id` to `host:port` as
/// `username` matches a connection the user actually saved.
///
/// The catalogue is the authority. A saved host uses vault entry `cred_id` when
/// its own `id` equals `cred_id` (its own secret) OR its `credentialId` borrows
/// `cred_id` (the "same password as fw-01" feature). In either case the only
/// destination that entry is authorized for is that record's own
/// `hostname`/`port`/`username`.
///
/// Returns `false` when there is no catalogue or no matching record — so a
/// compromised frontend that pairs a saved host's password id with an
/// attacker-controlled destination matches nothing, and the secret is never
/// sent there. This deliberately reads a few fields of the otherwise-opaque
/// tree (see the module header): a security binding is worth the coupling.
pub fn binding_is_authorized(cred_id: &str, host: &str, port: u16, username: &str) -> bool {
    match load() {
        Ok(Some(tree)) => binding_in_tree(&tree, cred_id, host, port, username),
        // No catalogue (or unreadable) → cannot authorize sending a secret.
        _ => false,
    }
}

/// Pure form of [`binding_is_authorized`] over an already-parsed tree, so the
/// authorization rule can be tested without touching the vault or disk.
fn binding_in_tree(tree: &Value, cred_id: &str, host: &str, port: u16, username: &str) -> bool {
    let mut ok = false;
    walk_hosts(tree, &mut |node| {
        if ok {
            return;
        }
        let id = node.get("id").and_then(Value::as_str);
        let borrows = node.get("credentialId").and_then(Value::as_str);
        if id != Some(cred_id) && borrows != Some(cred_id) {
            return;
        }
        let h = node.get("hostname").and_then(Value::as_str);
        let p = node.get("port").and_then(Value::as_u64);
        let u = node.get("username").and_then(Value::as_str);
        if h == Some(host) && p == Some(u64::from(port)) && u == Some(username) {
            ok = true;
        }
    });
    ok
}

/// Visit every `kind: "host"` object in the opaque catalogue tree, descending
/// folders and an array root. Reads only the shape the security binding needs.
fn walk_hosts(node: &Value, visit: &mut impl FnMut(&Value)) {
    if let Some(arr) = node.as_array() {
        for child in arr {
            walk_hosts(child, visit);
        }
        return;
    }
    match node.get("kind").and_then(Value::as_str) {
        Some("host") => visit(node),
        Some("folder") => {
            if let Some(children) = node.get("children").and_then(Value::as_array) {
                for child in children {
                    walk_hosts(child, visit);
                }
            }
        }
        _ => {}
    }
}

/* -------------------------------------------------------------------------- */

/// `%APPDATA%\skiff\sessions.json` — which hosts were open when the app last
/// closed.
///
/// Only host ids and view mode are recorded. A TCP connection cannot be
/// serialised, so "restore" means *reconnect*, and anything that was running
/// remotely is gone unless it lived inside tmux or screen.
fn sessions_path() -> Result<PathBuf, KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    Ok(store
        .parent()
        .ok_or(KnownHostsError::NoAppDataDir)?
        .join("sessions.json"))
}

pub fn load_sessions() -> Result<Option<Value>, KnownHostsError> {
    let path = sessions_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).map_err(|source| KnownHostsError::Io {
        path: path.clone(),
        source,
    })?;
    Ok(serde_json::from_str(&text).ok())
}

pub fn save_sessions(list: &Value) -> Result<(), KnownHostsError> {
    let path = sessions_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| KnownHostsError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let text = serde_json::to_string_pretty(list)
        .map_err(|e| KnownHostsError::Parse(e.to_string()))?;
    write_atomic(&path, &text)
}

/* -------------------------------------------------------------------------- */

/// Generic sibling-file persistence in the skiff data dir, for small settings
/// files (ai.json). Same corrupt-file-tolerant contract as the catalogue.
pub fn load_named(name: &str) -> Result<Option<Value>, KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    let path = store
        .parent()
        .ok_or(KnownHostsError::NoAppDataDir)?
        .join(name);
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).map_err(|source| KnownHostsError::Io {
        path: path.clone(),
        source,
    })?;
    Ok(serde_json::from_str(&text).ok())
}

pub fn save_named(name: &str, value: &Value) -> Result<(), KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    let dir = store.parent().ok_or(KnownHostsError::NoAppDataDir)?;
    std::fs::create_dir_all(dir).map_err(|source| KnownHostsError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let path = dir.join(name);
    let text =
        serde_json::to_string_pretty(value).map_err(|e| KnownHostsError::Parse(e.to_string()))?;
    write_atomic(&path, &text)
}

#[cfg(test)]
mod tests {
    use super::binding_in_tree;
    use serde_json::json;

    fn catalogue() -> serde_json::Value {
        json!([
            { "kind": "host", "id": "fw-01", "hostname": "fw-01.corp", "port": 22, "username": "admin" },
            { "kind": "folder", "id": "f1", "name": "DMZ", "children": [
                // Borrows fw-01's vault entry ("same password as fw-01").
                { "kind": "host", "id": "fw-02", "hostname": "fw-02.corp", "port": 2222,
                  "username": "admin", "credentialId": "fw-01" }
            ]}
        ])
    }

    #[test]
    fn own_entry_binds_only_to_its_own_destination() {
        let t = catalogue();
        // fw-01's credential to fw-01's own destination: authorized.
        assert!(binding_in_tree(&t, "fw-01", "fw-01.corp", 22, "admin"));
        // Same credential aimed at a DIFFERENT host/port/user: refused.
        assert!(!binding_in_tree(&t, "fw-01", "attacker.example", 22, "admin"));
        assert!(!binding_in_tree(&t, "fw-01", "fw-01.corp", 23, "admin"));
        assert!(!binding_in_tree(&t, "fw-01", "fw-01.corp", 22, "root"));
    }

    #[test]
    fn borrowed_entry_binds_to_the_borrowers_destination() {
        let t = catalogue();
        // fw-02 borrows fw-01's entry; connecting fw-02 passes cred_id=fw-01
        // with fw-02's own destination — authorized (nested in a folder).
        assert!(binding_in_tree(&t, "fw-01", "fw-02.corp", 2222, "admin"));
        // But fw-01's entry may not be sent to an unrelated destination just
        // because a borrower exists.
        assert!(!binding_in_tree(&t, "fw-01", "fw-02.corp", 22, "admin"));
    }

    #[test]
    fn unknown_credential_is_never_authorized() {
        let t = catalogue();
        assert!(!binding_in_tree(&t, "ghost", "fw-01.corp", 22, "admin"));
    }
}
