//! "Capture command output to file" — run one command over a fresh, hidden exec
//! channel (see `Registry::exec_capture`) and store the output timestamped under
//! `<appdata>/skiff/captures/<host>/`. One plain-text file per capture — the
//! same greppable, Skiff-independent storage as config snapshots, but for an
//! arbitrary command (a `show tech-support`, a `dmesg`, a big log) rather than
//! the host's saved config command.

use serde::Serialize;
use std::path::PathBuf;

use super::known_hosts::KnownHostsError;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureResult {
    pub path: String,
    pub bytes: u64,
    pub lines: usize,
}

/// Reduce an arbitrary string to a safe filesystem component: alphanumerics,
/// '-' and '.' kept, everything else '_'. An all-dots result (which would be a
/// path-traversal component) is neutralised so the path can never escape the
/// captures root.
fn slug(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .collect();
    if out.chars().all(|c| c == '.') {
        "_".repeat(out.len().max(1))
    } else {
        out
    }
}

fn captures_dir(host: &str) -> Result<PathBuf, KnownHostsError> {
    let store = super::known_hosts::store_path()?;
    Ok(store
        .parent()
        .ok_or(KnownHostsError::NoAppDataDir)?
        .join("captures")
        .join(slug(host)))
}

/// Save one command capture. The filename is a short slug of the command plus a
/// timestamp, so several captures on one host stay distinguishable at a glance.
pub fn save_capture(host: &str, command: &str, content: &str) -> Result<CaptureResult, KnownHostsError> {
    let dir = captures_dir(host)?;
    std::fs::create_dir_all(&dir).map_err(|source| KnownHostsError::Io {
        path: dir.clone(),
        source,
    })?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Cap the command slug so a long command line can't blow the filename limit.
    let mut cmd_slug = slug(command);
    cmd_slug.truncate(40);
    let name = format!("{}-{}.txt", cmd_slug.trim_matches('_'), super::session_log::timestamp_for(now));
    let path = dir.join(&name);
    std::fs::write(&path, content).map_err(|source| KnownHostsError::Io {
        path: path.clone(),
        source,
    })?;

    Ok(CaptureResult {
        path: path.to_string_lossy().to_string(),
        bytes: content.len() as u64,
        lines: content.lines().count(),
    })
}
