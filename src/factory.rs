//! Read identifying info (email, token expiry) from a Factory droid auth bundle.
//!
//! `~/.factory/auth.v2.file` is `AES-256-GCM(key=auth.v2.key)` of a JSON
//! payload `{ "access_token": "<JWT>", "refresh_token": "..." }`. The on-disk
//! format is three colon-separated base64 segments: `iv:tag:ciphertext`,
//! where `iv` is 16 bytes and `tag` is 16 bytes.
//!
//! `auth.encrypted` is a legacy plaintext JSON variant we use as a fallback.

use std::fs;
use std::path::Path;

use aes_gcm::aead::generic_array::typenum::{U12, U16};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::aes::Aes256;
use aes_gcm::{AesGcm, KeyInit};

// Factory's TypeScript code (node:crypto) uses a 16-byte IV. The de-facto
// standard for AES-GCM is 12, and our test helpers also produce 12-byte IVs,
// so we accept both.
type Aes256Gcm12 = AesGcm<Aes256, U12>;
type Aes256Gcm16 = AesGcm<Aes256, U16>;
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Identity decoded from a Factory auth bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub email: Option<String>,
    pub subject: Option<String>,
    /// Token `exp` claim as UTC datetime, if present.
    pub expires_at: Option<DateTime<Utc>>,
}

impl Identity {
    pub fn unknown() -> Self {
        Self {
            email: None,
            subject: None,
            expires_at: None,
        }
    }

    pub fn display_email(&self) -> String {
        self.email
            .clone()
            .or_else(|| self.subject.clone())
            .unwrap_or_else(|| "-".to_string())
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        matches!(self.expires_at, Some(exp) if exp <= now)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

pub type AuthPayload = AuthTokens;

#[derive(Deserialize)]
struct JwtClaims {
    email: Option<String>,
    sub: Option<String>,
    exp: Option<i64>,
}

/// Decrypt a 3-segment AES-GCM string (`iv:tag:ciphertext` in base64) using `key`.
pub fn decrypt_payload(raw: &str, key: &[u8]) -> Result<String> {
    let parts: Vec<&str> = raw.trim().split(':').collect();
    if parts.len() != 3 {
        return Err(anyhow!(
            "auth payload must have 3 colon-separated segments, got {}",
            parts.len()
        ));
    }
    let iv = B64.decode(parts[0]).context("decode iv")?;
    let tag = B64.decode(parts[1]).context("decode tag")?;
    let ct = B64.decode(parts[2]).context("decode ciphertext")?;

    let mut combined = ct;
    combined.extend_from_slice(&tag);

    let pt = match iv.len() {
        12 => {
            let cipher =
                Aes256Gcm12::new_from_slice(key).map_err(|e| anyhow!("invalid key: {e}"))?;
            let nonce = GenericArray::<u8, U12>::from_slice(&iv);
            cipher.decrypt(nonce, combined.as_ref())
        }
        16 => {
            let cipher =
                Aes256Gcm16::new_from_slice(key).map_err(|e| anyhow!("invalid key: {e}"))?;
            let nonce = GenericArray::<u8, U16>::from_slice(&iv);
            cipher.decrypt(nonce, combined.as_ref())
        }
        n => return Err(anyhow!("unsupported IV length {n} (expected 12 or 16)")),
    }
    .map_err(|_| anyhow!("AES-GCM decryption failed (wrong key or corrupt file)"))?;

    String::from_utf8(pt).context("decrypted payload is not UTF-8")
}

/// Decrypt `auth.v2.file` using `auth.v2.key` and return the JSON payload.
pub fn decrypt_v2(auth_v2_file: &Path, auth_v2_key: &Path) -> Result<String> {
    let key_b64 = fs::read_to_string(auth_v2_key)
        .with_context(|| format!("read key file {}", auth_v2_key.display()))?;
    let key = B64
        .decode(key_b64.trim())
        .context("decode auth.v2.key (base64)")?;
    if key.len() != 32 {
        return Err(anyhow!(
            "auth.v2.key must decode to 32 bytes (got {})",
            key.len()
        ));
    }

    let raw = fs::read_to_string(auth_v2_file)
        .with_context(|| format!("read {}", auth_v2_file.display()))?;
    decrypt_payload(&raw, &key)
}

/// Decode email + expiry from a JWT access token. Does NOT verify the
/// signature - we only use it to identify the account.
pub fn identity_from_jwt(jwt: &str) -> Result<Identity> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("not a JWT (expected 3 segments)"));
    }
    let payload = B64URL.decode(parts[1]).context("decode JWT payload")?;
    let claims: JwtClaims = serde_json::from_slice(&payload).context("parse JWT claims")?;
    Ok(Identity {
        email: claims.email,
        subject: claims.sub,
        expires_at: claims.exp.and_then(|s| DateTime::from_timestamp(s, 0)),
    })
}

/// Best-effort identity for a directory containing Factory auth files.
/// Tries `auth.v2.file` + `auth.v2.key` first, then `auth.v2.keyring` with
/// OS keyring / local key, falling back to legacy `auth.encrypted`.
/// Never panics; returns `Identity::unknown()` if everything fails.
pub fn identity_from_dir(dir: &Path) -> Identity {
    if let Some(tokens) = tokens_from_dir(dir) {
        if let Ok(id) = identity_from_jwt(&tokens.access_token) {
            return id;
        }
    }
    Identity::unknown()
}

/// Extract access and refresh tokens from a directory containing Factory auth files.
pub fn tokens_from_dir(dir: &Path) -> Option<AuthTokens> {
    crate::auth::storage::CredentialBundle::load(dir)
        .ok()
        .map(|b| b.tokens)
}

/// Test helpers for synthesizing valid Factory auth bundles.
///
/// Public so integration tests can use it. Not part of the stable API.
#[doc(hidden)]
pub mod testing;

#[cfg(test)]
mod tests;
