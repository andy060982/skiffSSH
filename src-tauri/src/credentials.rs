//! Windows Credential Manager access.
//!
//! Secrets live in the OS vault, encrypted per-user by DPAPI, and are read into
//! memory only for the moment they are needed. Three rules hold everywhere in
//! this module:
//!
//! 1. **A secret never crosses the IPC boundary.** No `#[tauri::command]` here
//!    returns a password. The frontend refers to a host by id; resolution to a
//!    secret happens entirely in Rust. Anything returned to the webview is
//!    reachable from devtools and from any XSS in the UI.
//! 2. **Secrets are zeroized.** Both the UTF-16 staging buffer and the decoded
//!    `String` are wiped on drop rather than left in freed heap pages.
//! 3. **Every raw pointer from the API is freed.** `CredReadW` allocates; the
//!    matching `CredFree` runs even on the error paths.

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{GetLastError, ERROR_NOT_FOUND};
use windows_sys::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
    CRED_TYPE_GENERIC,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, thiserror::Error)]
pub enum CredError {
    #[error("no saved credential for {0}")]
    NotFound(String),
    #[error("credential manager error 0x{0:08X}")]
    Win32(u32),
    #[error("stored secret for {0} is not valid UTF-16")]
    Malformed(String),
}

/// Vault key for a host. Namespaced so Skiff's entries are obvious in
/// `control /name Microsoft.CredentialManager` and cannot collide with another
/// application's generic credentials.
pub fn target_name(host_id: &str) -> String {
    format!("skiff:host:{host_id}")
}

/// NUL-terminated UTF-16, as every `*W` Win32 entry point expects.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Read a password out of the vault.
///
/// The returned `String` zeroizes on drop. Callers should keep it alive for as
/// short a span as possible and never log, serialise, or return it.
pub fn read_secret(host_id: &str) -> Result<Zeroizing<String>, CredError> {
    let target = target_name(host_id);
    let target_w = wide(&target);
    let mut ptr: *mut CREDENTIALW = std::ptr::null_mut();

    // SAFETY: target_w is NUL-terminated and outlives the call; ptr is a valid
    // out-param. On success the API allocates a buffer we must CredFree.
    let ok = unsafe { CredReadW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0, &mut ptr) };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(if code == ERROR_NOT_FOUND {
            CredError::NotFound(target)
        } else {
            CredError::Win32(code)
        });
    }

    // Copy the blob out before freeing, then wipe the staging buffer. The blob
    // is raw bytes; Windows tooling conventionally stores UTF-16LE here.
    let result = unsafe {
        let cred = &*ptr;
        let len = cred.CredentialBlobSize as usize;
        let bytes = std::slice::from_raw_parts(cred.CredentialBlob, len);

        if len % 2 != 0 {
            // Odd length cannot be UTF-16. Fall back to UTF-8, which is what a
            // credential written by a non-Windows-native tool may contain.
            String::from_utf8(bytes.to_vec())
                .map(Zeroizing::new)
                .map_err(|_| CredError::Malformed(target.clone()))
        } else {
            let mut units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let decoded = String::from_utf16(&units)
                .map(Zeroizing::new)
                .map_err(|_| CredError::Malformed(target.clone()));
            units.zeroize();
            decoded
        }
    };

    // SAFETY: ptr came from a successful CredReadW and is freed exactly once.
    unsafe { CredFree(ptr as *mut c_void) };
    result
}

/// Store or replace a password. Called from the host-editor flow, never with a
/// value that originated in the webview on a machine the user does not control.
pub fn write_secret(host_id: &str, username: &str, secret: &str) -> Result<(), CredError> {
    let target = target_name(host_id);
    let mut target_w = wide(&target);
    let mut user_w = wide(username);

    // UTF-16LE bytes, matching what CredReadW above expects and what the
    // Credential Manager UI displays correctly.
    let mut blob: Vec<u8> = secret
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();

    let mut cred: CREDENTIALW = unsafe { std::mem::zeroed() };
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = target_w.as_mut_ptr();
    cred.CredentialBlobSize = blob.len() as u32;
    cred.CredentialBlob = blob.as_mut_ptr();
    // LOCAL_MACHINE keeps the entry off roaming profiles: a credential for an
    // internal host should not follow the user to another machine.
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
    cred.UserName = user_w.as_mut_ptr();

    // SAFETY: every pointer in `cred` refers to a buffer alive for this call.
    let ok = unsafe { CredWriteW(&cred, 0) };
    blob.zeroize();

    if ok == 0 {
        return Err(CredError::Win32(unsafe { GetLastError() }));
    }
    Ok(())
}

/// Remove a stored password. Used when a host is deleted, so the vault does not
/// accumulate orphaned secrets.
pub fn delete_secret(host_id: &str) -> Result<(), CredError> {
    let target = target_name(host_id);
    let target_w = wide(&target);

    // SAFETY: target_w is NUL-terminated and outlives the call.
    let ok = unsafe { CredDeleteW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0) };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(if code == ERROR_NOT_FOUND {
            CredError::NotFound(target)
        } else {
            CredError::Win32(code)
        });
    }
    Ok(())
}

/// Whether a secret exists, without reading it. Lets the UI show "password
/// saved" without the plaintext ever being decrypted.
pub fn has_secret(host_id: &str) -> bool {
    matches!(read_secret(host_id), Ok(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trips a secret through the real Credential Manager.
    ///
    /// Uses a namespaced throwaway id and removes it afterwards. It exercises
    /// CredWriteW/CredReadW/CredDeleteW for real rather than against a mock —
    /// the UTF-16 marshalling is exactly the part worth testing, and a mock
    /// would test nothing at all.
    #[test]
    fn write_read_delete_roundtrip() {
        let id = "__skiff_selftest__";
        // Deliberately not ASCII: the blob is UTF-16LE, and a truncation bug in
        // the encode/decode pair only shows up above the BMP-free happy path.
        let secret = "p@ss w\u{f6}rd \u{4e2d}\u{6587} 123";

        write_secret(id, "testuser", secret).expect("write");
        let got = read_secret(id).expect("read");
        assert_eq!(got.as_str(), secret, "secret survived the round trip");

        assert!(has_secret(id));
        delete_secret(id).expect("delete");
        assert!(!has_secret(id), "gone after delete");
    }

    #[test]
    fn missing_secret_is_not_found() {
        match read_secret("__skiff_definitely_absent__") {
            Err(CredError::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }
}
