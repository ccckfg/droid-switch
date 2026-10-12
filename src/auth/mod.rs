//! Shared refresh policy for quota queries and account switching.

pub mod accounts;
pub mod lock;
pub mod storage;

use anyhow::{bail, Context, Result};
use chrono::Utc;

use crate::api::{client, config};
use crate::factory::identity_from_jwt;
use storage::CredentialBundle;

pub fn refresh_if_needed(bundle: &mut CredentialBundle, force: bool) -> Result<bool> {
    let before = identity_from_jwt(&bundle.tokens.access_token)
        .context("cannot identify saved account; log in with droid and import again")?;
    let near_expiry = before
        .expires_at
        .map(|exp| exp.timestamp() <= Utc::now().timestamp() + config::REFRESH_MARGIN_SECS)
        .unwrap_or(true);
    if !force && !near_expiry {
        return Ok(false);
    }
    if config::is_no_network() {
        bail!("access token needs refresh but DSW_NO_NETWORK is enabled; enable network access or refresh with Droid");
    }
    let refresh = bundle
        .tokens
        .refresh_token
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .context(
            "login required: profile has no refresh token; log in with droid and import again",
        )?;
    let auth = client::refresh_access_token(&client::create_agent(), refresh)?;
    let after = identity_from_jwt(&auth.access_token)
        .context("refresh returned an invalid access token")?;
    if !accounts::identities_match(&before, &after) {
        bail!("refresh returned a different account; refusing to replace saved credentials");
    }
    if after.is_expired(Utc::now()) || after.expires_at.is_none() {
        bail!("refresh returned an expired or undated access token");
    }
    bundle.persist_refresh(auth)?;
    Ok(true)
}
