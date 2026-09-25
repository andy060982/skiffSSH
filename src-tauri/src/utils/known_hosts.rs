//! OpenSSH-compatible `known_hosts` storage.
//!
//! # What is stored, and what is not
//!
//! This file records the server's **full public key**, not its fingerprint.
//! That distinction is load-bearing: a fingerprint is a one-way SHA256 hash, so
//! a file of fingerprints could never be read by `ssh`, `ssh-keygen -F`, or any
//! other OpenSSH tool, and could not be used to verify a key by any means other
//! than re-hashing. The fingerprint is a *human comparison aid* and belongs in
//! the UI; the key itself belongs on disk.
//!
//! Format is therefore the standard one line per host:
//!
//! ```text
//! hostname ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
//! [hostname]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
//! ```
//!
//! with the bracketed form used whenever the port is not 22, exactly as
//! OpenSSH writes it. The resulting file can be concatenated onto
//! `~/.ssh/known_hosts` or consumed by `ssh` directly.
//!
//! # Why not russh's default path
//!
//! `russh::keys::known_hosts::check_known_hosts` resolves to
//! `%USERPROFILE%\ssh\known_hosts` on Windows — note the missing dot, which is
//! not where OpenSSH for Windows actually looks. Owning the path explicitly
//! avoids that quirk and keeps Skiff's trust store separate from the system
//! one, so a mistake here can never corrupt the file `ssh` itself depends on.
//!
//! Parsing and serialisation are delegated to russh's implementation rather
//! than hand-rolled: known_hosts has more edge cases than it looks (hashed
//! hostnames, `@revoked` and `@cert-authority` markers, comma-separated host
//! lists, CRLF), and a subtly wrong parser here is a security bug, not a
//! cosmetic one.

use std::path::{Path, PathBuf};

use russh::keys::known_hosts::{check_known_hosts_path, learn_known_hosts_path};
use russh::keys::ssh_key::PublicKey;

#[derive(Debug, thiserror::Error)]
pub enum KnownHostsError {
    #[error("could not locate the application data directory")]
    NoAppDataDir,
    #[error("known_hosts store at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("known_hosts store is malformed: {0}")]
    Parse(String),
}

/// Result of checking a presented host key against the store.
///
/// Three states, not two. Collapsing `Unknown` and `Changed` into a single
/// "not trusted" is the mistake that leads to prompting on a changed key, which
/// is precisely the case where a prompt must never appear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyStatus {
    /// Recorded, and the presented key matches.
    Trusted,
    /// No entry for this host — a first connection.
    Unknown,
    /// An entry exists with a *different* key (any algorithm) for this host, or
    /// no stored key matches. Either the server was rebuilt or the connection is
    /// being intercepted — refuse, never prompt.
    Changed { line: usize },
    /// The presented key is explicitly revoked (`@revoked` line). Refuse
    /// unconditionally — this beats any matching trust entry.
    Revoked { line: usize },
}

/// `%APPDATA%\skiff\known_hosts` on Windows.
///
/// Roaming rather than Local on purpose: host trust is a user decision that
/// should follow the user to another domain-joined machine, unlike the
/// credentials in the vault, which are deliberately machine-local.
#[cfg(target_os = "windows")]
pub fn store_path() -> Result<PathBuf, KnownHostsError> {
    let appdata = std::env::var_os("APPDATA").ok_or(KnownHostsError::NoAppDataDir)?;
    Ok(PathBuf::from(appdata).join("skiff").join("known_hosts"))
}

#[cfg(not(target_os = "windows"))]
pub fn store_path() -> Result<PathBuf, KnownHostsError> {
    let home = std::env::var_os("HOME").ok_or(KnownHostsError::NoAppDataDir)?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("skiff")
        .join("known_hosts"))
}

/// Create the directory and an empty file if either is missing, and return the
/// path. Safe to call repeatedly; never truncates an existing store.
pub fn ensure_store() -> Result<PathBuf, KnownHostsError> {
    let path = store_path()?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| KnownHostsError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    if !path.exists() {
        // create_new rather than File::create: if two sessions race to first
        // connection, the loser must not truncate the winner's file.
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(KnownHostsError::Io {
                    path: path.clone(),
                    source,
                })
            }
        }
    }

    Ok(path)
}

/// Check a presented key against the store.
///
/// A missing or unreadable store is reported as `Unknown` rather than an error:
/// a first run has no file, and that must lead to a prompt, not a failure.
/// Genuine IO problems still surface when `trust` tries to write.
pub fn check(host: &str, port: u16, key: &PublicKey) -> Result<HostKeyStatus, KnownHostsError> {
    let path = ensure_store()?;
    classify(host, port, key, &path)
}

fn classify(
    host: &str,
    port: u16,
    key: &PublicKey,
    path: &Path,
) -> Result<HostKeyStatus, KnownHostsError> {
    // Revocation wins over everything: an explicitly `@revoked` key is refused
    // even if the same key also appears as a normal trust entry.
    if let Some(line) = revoked_line(host, port, key, path)? {
        return Ok(HostKeyStatus::Revoked { line });
    }

    match check_known_hosts_path(host, port, key, path) {
        Ok(true) => Ok(HostKeyStatus::Trusted),
        Ok(false) => {
            // russh found no key on file matching the presented one. That is
            // NOT automatically "unknown host": russh only reports KeyChanged
            // for a *same-algorithm* mismatch, so a host we already trust that
            // presents a different-algorithm key (a classic downgrade/
            // interception move) also lands here. Distinguish:
            //   - host has no entry at all   -> genuinely first use -> prompt
            //   - host IS on file, key isn't -> treat as Changed -> refuse,
            //     never a silent trust prompt. Recovery is explicit: remove the
            //     host's known_hosts line, then reconnect to re-trust.
            match host_entry_line(host, port, path)? {
                Some(line) => Ok(HostKeyStatus::Changed { line }),
                None => Ok(HostKeyStatus::Unknown),
            }
        }
        Err(russh::keys::Error::KeyChanged { line }) => Ok(HostKeyStatus::Changed { line }),
        // Any OTHER error — an unreadable or corrupt store, a malformed line —
        // is propagated, NOT downgraded to a trust prompt. The store exists by
        // this point (ensure_store created it), so a read/parse failure here is
        // a real problem: fail closed and make the user fix the file rather than
        // let a parse error masquerade as a first-use connection.
        Err(e) => Err(KnownHostsError::Parse(format!(
            "could not verify {host}:{port} against the known_hosts store: {e}"
        ))),
    }
}

/// The 1-based line of a `@revoked` entry naming this host whose key matches the
/// presented one, if any. Read/parse failure of the store propagates (fail
/// closed); an unparseable individual `@revoked` line is skipped, not fatal.
fn revoked_line(
    host: &str,
    port: u16,
    key: &PublicKey,
    path: &Path,
) -> Result<Option<usize>, KnownHostsError> {
    let needle = if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    };
    let text = std::fs::read_to_string(path).map_err(|source| KnownHostsError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        if !matches!(fields.next(), Some(m) if m.eq_ignore_ascii_case("@revoked")) {
            continue;
        }
        let Some(host_field) = fields.next() else { continue };
        if !host_field.split(',').any(|h| h.eq_ignore_ascii_case(&needle)) {
            continue;
        }
        let (Some(key_type), Some(b64)) = (fields.next(), fields.next()) else {
            continue;
        };
        // Reassemble the "type base64" openssh form and compare key material.
        if let Ok(revoked) = PublicKey::from_openssh(&format!("{key_type} {b64}")) {
            if revoked.key_data() == key.key_data() {
                return Ok(Some(i + 1));
            }
        }
    }
    Ok(None)
}

/// The 1-based line number of the first known_hosts entry naming this host
/// (plaintext host fields only — hashed `|1|…` entries can't be matched by
/// name, but Skiff writes plaintext). `None` if the host is absent entirely.
fn host_entry_line(host: &str, port: u16, path: &Path) -> Result<Option<usize>, KnownHostsError> {
    let needle = if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    };
    // Propagate a read failure rather than swallowing it: a store that exists
    // but can't be read must fail the check closed, not report "host absent"
    // (which routes to a trust prompt).
    let text = std::fs::read_to_string(path).map_err(|source| KnownHostsError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(mut first) = fields.next() else { continue };
        // Skip an @revoked / @cert-authority marker to reach the host field.
        if first.starts_with('@') {
            first = match fields.next() {
                Some(f) => f,
                None => continue,
            };
        }
        // Host field may be a comma-separated list of patterns.
        if first.split(',').any(|h| h.eq_ignore_ascii_case(&needle)) {
            return Ok(Some(i + 1));
        }
    }
    Ok(None)
}

/// Append a host's public key to the store, creating the directory and file if
/// needed. Called only after a human has accepted the fingerprint.
///
/// Refuses to append over a *changed* key: re-recording one would leave two
/// conflicting entries and make every later check ambiguous. Replacing a
/// changed key is a deliberate, manual act.
pub fn trust(host: &str, port: u16, key: &PublicKey) -> Result<(), KnownHostsError> {
    let path = ensure_store()?;

    match classify(host, port, key, &path)? {
        HostKeyStatus::Changed { line } => {
            return Err(KnownHostsError::Parse(format!(
                "{host}:{port} already has a different key on line {line}; \
                 remove it by hand before trusting a new one"
            )))
        }
        HostKeyStatus::Revoked { line } => {
            return Err(KnownHostsError::Parse(format!(
                "{host}:{port} presented a key that is revoked on line {line}; \
                 refusing to trust it"
            )))
        }
        HostKeyStatus::Trusted | HostKeyStatus::Unknown => {}
    }

    // russh handles the details that are easy to get wrong: appending a leading
    // newline when the file does not end in one, and the [host]:port form for
    // non-default ports.
    learn_known_hosts_path(host, port, key, &path).map_err(|e| match e {
        russh::keys::Error::IO(source) => KnownHostsError::Io {
            path: path.clone(),
            source,
        },
        other => KnownHostsError::Parse(other.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_path_is_under_appdata() {
        // Only asserts shape; the directory need not exist.
        let p = store_path().expect("path resolves");
        assert!(p.ends_with("skiff/known_hosts") || p.ends_with(r"skiff\known_hosts"));
    }

    #[test]
    fn ensure_store_is_idempotent() {
        let a = ensure_store().expect("first call");
        let b = ensure_store().expect("second call");
        assert_eq!(a, b);
        assert!(a.exists());
    }
}
