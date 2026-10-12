//! Lossless credential updates using the existing Factory encryption format.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{rand_core::RngCore, Aead, OsRng};
use aes_gcm::{Aes256Gcm, KeyInit};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::Value;

use crate::api::models::WorkOsAuthResponse;
use crate::factory::{decrypt_payload, AuthTokens};
use crate::keyring;
use crate::paths::{AUTH_LEGACY, AUTH_READ_ORDER, AUTH_V2_FILE, AUTH_V2_KEY};

pub struct CredentialBundle {
    path: PathBuf,
    original: Vec<u8>,
    payload: Value,
    key: Option<Vec<u8>>,
    pub tokens: AuthTokens,
}

impl CredentialBundle {
    pub fn load(dir: &Path) -> Result<Self> {
        let local_key = fs::read_to_string(dir.join(AUTH_V2_KEY))
            .ok()
            .and_then(|s| keyring::decode_key_b64(&s));
        let os_key = keyring::get_factory_encryption_key();
        // Factory's current keyring file takes precedence over legacy copies.
        for &name in AUTH_READ_ORDER {
            let path = dir.join(name);
            let Ok(original) = fs::read(&path) else {
                continue;
            };
            let Ok(raw) = std::str::from_utf8(&original) else {
                continue;
            };
            let keys = if name == AUTH_V2_FILE {
                [local_key.as_ref(), os_key.as_ref()]
            } else {
                [os_key.as_ref(), local_key.as_ref()]
            };
            for key in keys.into_iter().flatten() {
                let Ok(decoded) = decrypt_payload(raw, key) else {
                    continue;
                };
                if let Ok(bundle) =
                    Self::parse(path.clone(), original.clone(), &decoded, Some(key.clone()))
                {
                    return Ok(bundle);
                }
            }
        }
        let path = dir.join(AUTH_LEGACY);
        let original = fs::read(&path)
            .context("no readable credential bundle; log in with droid and import again")?;
        let raw = std::str::from_utf8(&original).context("invalid legacy credential encoding")?;
        Self::parse(path.clone(), original.clone(), raw, None)
    }

    fn parse(path: PathBuf, original: Vec<u8>, raw: &str, key: Option<Vec<u8>>) -> Result<Self> {
        let payload: Value = serde_json::from_str(raw).context("invalid credential JSON")?;
        let tokens: AuthTokens = serde_json::from_value(payload.clone())
            .context("credential token fields are missing")?;
        Ok(Self {
            path,
            original,
            payload,
            key,
            tokens,
        })
    }

    /// Save both rotated tokens before issuing any further API requests.
    pub fn persist_refresh(&mut self, auth: WorkOsAuthResponse) -> Result<()> {
        let refresh = auth
            .refresh_token
            .filter(|s| !s.trim().is_empty())
            .context("refresh response omitted the new refresh token")?;
        let object = self
            .payload
            .as_object_mut()
            .context("invalid credential object")?;
        object.insert(
            "access_token".into(),
            Value::String(auth.access_token.clone()),
        );
        object.insert("refresh_token".into(), Value::String(refresh.clone()));
        let json = serde_json::to_vec(&self.payload)?;
        let output = match &self.key {
            Some(key) => encrypt(&json, key)?,
            None => json,
        };
        if fs::read(&self.path)? != self.original {
            bail!("credentials changed during refresh; refusing to overwrite a newer login");
        }
        atomic_write(&self.path, &output)?;
        self.original = output;
        self.tokens = AuthTokens {
            access_token: auth.access_token,
            refresh_token: Some(refresh),
        };
        Ok(())
    }
}

fn encrypt(payload: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid encryption key"))?;
    let mut nonce = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| anyhow::anyhow!("could not generate encryption nonce"))?;
    let encrypted = cipher
        .encrypt((&nonce).into(), payload)
        .map_err(|_| anyhow::anyhow!("could not encrypt refreshed credentials"))?;
    let (ciphertext, tag) = encrypted.split_at(encrypted.len() - 16);
    Ok(format!(
        "{}:{}:{}",
        B64.encode(nonce),
        B64.encode(tag),
        B64.encode(ciphertext)
    )
    .into_bytes())
}

pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().context("credential path has no parent")?;
    fs::create_dir_all(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    temp.write_all(contents)?;
    temp.as_file().sync_all()?;
    temp.persist(path)
        .map_err(|e| e.error)
        .context("atomically save credentials")?;
    Ok(())
}
