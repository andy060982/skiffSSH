//! Small OS-integration shims kept behind one API so the rest of the backend
//! stays platform-agnostic.
//!
//! Each opens a **fixed or Rust-computed** path — never a webview-supplied
//! string used as a shell target — so this stays a "reveal this folder"
//! primitive, not a general execute-anything one.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The file-manager program for the current platform.
#[cfg(target_os = "windows")]
const FILE_MANAGER: &str = "explorer";
#[cfg(target_os = "macos")]
const FILE_MANAGER: &str = "open";
#[cfg(all(unix, not(target_os = "macos")))]
const FILE_MANAGER: &str = "xdg-open";

/// Open a directory in the platform's file manager.
pub fn open_dir(path: &Path) -> std::io::Result<()> {
    Command::new(FILE_MANAGER).arg(path).spawn().map(|_| ())
}

/// Reveal (and, where supported, select) a single file in the file manager.
///
/// Windows and macOS can select the file itself; Linux has no portable
/// select-in-file-manager, so it opens the containing folder instead.
pub fn reveal_file(path: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        Command::new("explorer").arg("/select,").arg(path).spawn().map(|_| ())
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open").arg("-R").arg(path).spawn().map(|_| ())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let dir = path.parent().unwrap_or(path);
        Command::new("xdg-open").arg(dir).spawn().map(|_| ())
    }
}

/// The current user's home directory, resolved through the platform's own
/// environment variable (`USERPROFILE` on Windows, `HOME` on macOS/Linux).
/// Keeping this in one place stops Windows-only assumptions (`USERPROFILE`)
/// from leaking into cross-platform code paths like key generation.
pub fn home_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

/// Best-effort user "Documents" directory for exports. Falls back to the home
/// directory when there is no Documents folder.
pub fn documents_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        home_dir().map(|p| p.join("Documents"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        home_dir().map(|home| {
            let docs = home.join("Documents");
            if docs.is_dir() {
                docs
            } else {
                home
            }
        })
    }
}
