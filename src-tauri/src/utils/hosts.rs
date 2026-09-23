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

use std::path::PathBuf;

use serde_json::Value;

use super::known_hosts::KnownHostsError;

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
    // program and cannot reach the UI that would fix it.
    Ok(serde_json::from_str(&text).ok())
}

/// Write the catalogue atomically.
///
/// Write-to-temp-then-rename, because the naive truncate-and-write loses the
/// entire host list if the process dies mid-write — and on Windows `rename`
/// over an existing file needs the remove-then-rename dance or `ReplaceFileW`.
/// `fs::rename` on Windows fails if the destination exists, so the temp file is
/// persisted with `std::fs::rename` only after the original is removed, and the
/// window between the two is the one failure mode left.
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

    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, pretty).map_err(|source| KnownHostsError::Io {
        path: tmp.clone(),
        source,
    })?;

    if path.exists() {
        std::fs::remove_file(&path).map_err(|source| KnownHostsError::Io {
            path: path.clone(),
            source,
        })?;
    }

    std::fs::rename(&tmp, &path).map_err(|source| KnownHostsError::Io {
        path: path.clone(),
        source,
    })
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
    std::fs::write(&path, text).map_err(|source| KnownHostsError::Io { path, source })
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
    std::fs::write(&path, text).map_err(|source| KnownHostsError::Io { path, source })
}
