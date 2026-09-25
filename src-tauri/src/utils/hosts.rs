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
/// Windows; only if that fails do we fall back to remove-then-rename, and the
/// unique temp (never the shared one the old code used) is still intact on disk
/// if we crash in that narrow window. The whole operation is serialised
/// process-wide, so concurrent saves cannot lose data or clobber each other.
fn write_atomic(path: &Path, contents: &str) -> Result<(), KnownHostsError> {
    let _guard = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let n = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp.{}.{}", std::process::id(), n));
    std::fs::write(&tmp, contents).map_err(|source| KnownHostsError::Io {
        path: tmp.clone(),
        source,
    })?;

    if std::fs::rename(&tmp, path).is_err() {
        if path.exists() {
            std::fs::remove_file(path).map_err(|source| KnownHostsError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        }
        std::fs::rename(&tmp, path).map_err(|source| {
            // Do not leave the scratch file behind if the replace truly failed.
            let _ = std::fs::remove_file(&tmp);
            KnownHostsError::Io {
                path: path.to_path_buf(),
                source,
            }
        })?;
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
