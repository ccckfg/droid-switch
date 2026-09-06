//! Access Factory Droid's encryption key from the operating system keyring.
//!
//! On desktop platforms (Windows, macOS, Linux with SecretService), Factory
//! Droid stores its AES-256 encryption key in the system credential store
//! under the service name `Factory CLI` and username `auth-encryption-key`.
//! The ciphertext is written to `~/.factory/auth.v2.keyring`.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

/// Service name used by Factory Droid in the system keyring.
pub const KEYRING_SERVICE: &str = "Factory CLI";
/// Account / user name used by Factory Droid in the system keyring.
pub const KEYRING_USER: &str = "auth-encryption-key";
/// Optional environment variable override for the encryption key (base64 encoded 32 bytes).
pub const ENV_KEY_OVERRIDE: &str = "FACTORY_ENCRYPTION_KEY";

/// Decode a base64 string into a 32-byte AES key.
pub fn decode_key_b64(raw: &str) -> Option<Vec<u8>> {
    let bytes = B64.decode(raw.trim()).ok()?;
    if bytes.len() == 32 {
        Some(bytes)
    } else {
        None
    }
}

/// Retrieve the 32-byte AES encryption key from the environment or the OS credential store.
pub fn get_factory_encryption_key() -> Option<Vec<u8>> {
    // 1. Check environment variable override (useful in headless/CI/tests).
    if let Ok(key_b64) = std::env::var(ENV_KEY_OVERRIDE) {
        if let Some(k) = decode_key_b64(&key_b64) {
            return Some(k);
        }
    }

    // 2. OS-specific credential store lookup.
    #[cfg(windows)]
    {
        if let Some(k) = windows::read_key() {
            return Some(k);
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(k) = macos::read_key() {
            return Some(k);
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(k) = linux::read_key() {
            return Some(k);
        }
    }

    None
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::ptr;
    use windows_sys::Win32::Security::Credentials::{
        CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
    };

    pub fn read_key() -> Option<Vec<u8>> {
        // Factory CLI (via keytar) formats the target name as "service/user" on Windows.
        let target_name = format!("{}/{}", KEYRING_SERVICE, KEYRING_USER);
        let wide: Vec<u16> = target_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let mut cred_ptr: *mut CREDENTIALW = ptr::null_mut();
            if CredReadW(wide.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred_ptr) != 0
                && !cred_ptr.is_null()
            {
                let cred = *cred_ptr;
                let slice = std::slice::from_raw_parts(
                    cred.CredentialBlob,
                    cred.CredentialBlobSize as usize,
                );
                let result = if let Ok(s) = std::str::from_utf8(slice) {
                    decode_key_b64(s)
                } else {
                    None
                };
                CredFree(cred_ptr as *const _);
                return result;
            }
        }
        None
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::process::Command;

    pub fn read_key() -> Option<Vec<u8>> {
        let out = Command::new("/usr/bin/security")
            .args([
                "find-generic-password",
                "-s",
                KEYRING_SERVICE,
                "-a",
                KEYRING_USER,
                "-w",
            ])
            .output()
            .ok()?;
        if out.status.success() {
            let s = std::str::from_utf8(&out.stdout).ok()?;
            decode_key_b64(s)
        } else {
            None
        }
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod linux {
    use super::*;
    use std::process::Command;

    pub fn read_key() -> Option<Vec<u8>> {
        let out = Command::new("secret-tool")
            .args([
                "lookup",
                "service",
                KEYRING_SERVICE,
                "account",
                KEYRING_USER,
            ])
            .output()
            .ok()?;
        if out.status.success() {
            let s = std::str::from_utf8(&out.stdout).ok()?;
            decode_key_b64(s)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_key_b64() {
        let valid = "KOpm+glR32RdW8GxbQd/yZVIlocxyKzyD9mK2s8JI5Q=";
        let decoded = decode_key_b64(valid);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap().len(), 32);

        let invalid = "aW52YWxpZA==";
        assert!(decode_key_b64(invalid).is_none());
    }

    #[test]
    fn test_env_override() {
        let valid = "KOpm+glR32RdW8GxbQd/yZVIlocxyKzyD9mK2s8JI5Q=";
        std::env::set_var(ENV_KEY_OVERRIDE, valid);
        let key = get_factory_encryption_key();
        assert!(key.is_some());
        assert_eq!(key.unwrap().len(), 32);
        std::env::remove_var(ENV_KEY_OVERRIDE);
    }
}
